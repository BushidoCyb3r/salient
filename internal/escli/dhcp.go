package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
)

// DHCPLease is per-leased-IP identity evidence: the hostname the client
// offered in its DHCP request and its NIC MAC, when present. Either field
// may be empty — not every client sends a hostname, and the MAC field can
// be absent from the grid entirely (same caveat as node MAC/vendor lookup).
type DHCPLease struct {
	Hostname string
	MAC      string
}

// DHCPLeasesQuery aggregates, per assigned IP, the most-seen hostname and
// MAC from DHCP lease records — real lease identity, not a guess from
// conn-log traffic shape.
func DHCPLeasesQuery(fm FieldMap, window time.Duration) (string, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.DHCP}},
					map[string]any{"exists": map[string]any{"field": fm.DHCPAssignedIP}},
				},
			},
		},
		"aggs": map[string]any{
			"by_ip": map[string]any{
				"terms": map[string]any{"field": fm.DHCPAssignedIP, "size": config.ResponderTermsSize},
				"aggs": map[string]any{
					"top_hostname": map[string]any{"terms": map[string]any{"field": fm.DHCPHostname, "size": 1}},
					"top_mac":      map[string]any{"terms": map[string]any{"field": fm.DHCPHostMAC, "size": 1}},
				},
			},
		},
	}
	return marshal(q)
}

// FetchDHCPLeases returns leased IP → lease identity evidence. Absence of
// the DHCP dataset or its identity fields yields an empty map, not an
// error — nodes simply carry no hostname/MAC from this source.
func (c *Client) FetchDHCPLeases(ctx context.Context, fm FieldMap, window time.Duration) (map[string]DHCPLease, error) {
	if len(fm.Datasets.DHCP) == 0 {
		return map[string]DHCPLease{}, nil
	}
	body, err := DHCPLeasesQuery(fm, window)
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
	raw, ok := aggs["by_ip"]
	if !ok {
		return map[string]DHCPLease{}, nil
	}
	var agg struct {
		Buckets []struct {
			Key         string      `json:"key"`
			TopHostname termsSubAgg `json:"top_hostname"`
			TopMAC      termsSubAgg `json:"top_mac"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding DHCP lease buckets: %w", err)
	}
	out := make(map[string]DHCPLease, len(agg.Buckets))
	for _, b := range agg.Buckets {
		lease := DHCPLease{Hostname: b.TopHostname.top(), MAC: b.TopMAC.top()}
		if lease.Hostname == "" && lease.MAC == "" {
			continue
		}
		out[b.Key] = lease
	}
	return out, nil
}

// termsSubAgg is a top-N terms sub-aggregation; top() returns the leading
// bucket's key, or "" if the sub-agg produced no buckets (field missing on
// every doc in this group).
type termsSubAgg struct {
	Buckets []struct {
		Key string `json:"key"`
	} `json:"buckets"`
}

func (t termsSubAgg) top() string {
	if len(t.Buckets) == 0 {
		return ""
	}
	return t.Buckets[0].Key
}
