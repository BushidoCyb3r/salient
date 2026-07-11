package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// ResponderCardinalityQuery counts, per responder value, the number of
// distinct client values within a dataset (§6.2). A plain terms agg
// suffices: responders (servers) are few, so no composite pagination is
// needed. responderField/clientField are usually fm.DestinationIP/
// fm.SourceIP for conn-shaped datasets, but a dataset with its own ECS
// mapping (e.g. Zeek dhcp.log's server.address/client.address) passes its
// own fields — the aggregation shape is identical either way.
func ResponderCardinalityQuery(fm FieldMap, datasets []string, window time.Duration, scope []string, responderField, clientField string) (string, error) {
	filters := []any{
		rangeFilter(fm.Timestamp, window),
		map[string]any{"terms": map[string]any{fm.DatasetField: datasets}},
	}
	if sf := scopeFilter(fm, scope); sf != nil {
		filters = append(filters, sf)
	}
	q := map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
		"aggs": map[string]any{
			"responders": map[string]any{
				"terms": map[string]any{"field": responderField, "size": config.ResponderTermsSize},
				"aggs": map[string]any{
					"clients":      map[string]any{"cardinality": map[string]any{"field": clientField}},
					"sample_hosts": map[string]any{"terms": map[string]any{"field": clientField, "size": config.RoleSampleHostsSize}},
				},
			},
		},
	}
	return marshal(q)
}

// ResponderCardinality runs the query for one dataset group and returns
// per-responder evidence. An empty result (no such dataset) is not an error —
// callers degrade role inference gracefully.
func (c *Client) ResponderCardinality(ctx context.Context, fm FieldMap, datasets []string, window time.Duration, scope []string, responderField, clientField string) (map[string]graph.RoleEvidence, error) {
	if len(datasets) == 0 {
		return map[string]graph.RoleEvidence{}, nil
	}
	body, err := ResponderCardinalityQuery(fm, datasets, window, scope, responderField, clientField)
	if err != nil {
		return nil, err
	}
	res, err := c.search(ctx, fm.IndexPattern, body)
	if err != nil {
		return nil, err
	}
	aggs, err := aggregations(res)
	if err != nil {
		return nil, err
	}
	raw, ok := aggs["responders"]
	if !ok {
		return map[string]graph.RoleEvidence{}, nil
	}
	var agg struct {
		Buckets []struct {
			Key     string `json:"key"`
			Clients struct {
				Value int64 `json:"value"`
			} `json:"clients"`
			SampleHosts struct {
				Buckets []termsBucket `json:"buckets"`
			} `json:"sample_hosts"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding responder buckets: %w", err)
	}
	out := make(map[string]graph.RoleEvidence, len(agg.Buckets))
	for _, b := range agg.Buckets {
		var hosts []string
		for _, h := range b.SampleHosts.Buckets {
			hosts = append(hosts, h.Key)
		}
		out[b.Key] = graph.RoleEvidence{Clients: b.Clients.Value, SampleHosts: hosts}
	}
	return out, nil
}

// FetchEvidence runs every role-evidence query needed for inference (§7),
// using whichever dataset candidates exist. Missing datasets yield empty maps
// so inference simply won't assert those roles.
func (c *Client) FetchEvidence(ctx context.Context, fm FieldMap, window time.Duration, scope []string) (graph.Evidence, error) {
	var ev graph.Evidence
	var err error
	if ev.Kerberos, err = c.ResponderCardinality(ctx, fm, fm.Datasets.Kerberos, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	if ev.DNS, err = c.ResponderCardinality(ctx, fm, fm.Datasets.DNS, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	if ev.SMB, err = c.ResponderCardinality(ctx, fm, fm.Datasets.SMB, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	if ev.HTTP, err = c.ResponderCardinality(ctx, fm, fm.Datasets.HTTP, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	if ev.SSL, err = c.ResponderCardinality(ctx, fm, fm.Datasets.SSL, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	if ev.LDAP, err = c.ResponderCardinality(ctx, fm, fm.Datasets.LDAP, window, scope, fm.DestinationIP, fm.SourceIP); err != nil {
		return ev, err
	}
	// DHCP uses its own ECS mapping (server.address/client.address), not
	// the conn-shaped destination/source IP fields the other datasets use.
	if ev.DHCP, err = c.ResponderCardinality(ctx, fm, fm.Datasets.DHCP, window, scope, fm.DHCPServer, fm.DHCPClient); err != nil {
		return ev, err
	}
	return ev, nil
}
