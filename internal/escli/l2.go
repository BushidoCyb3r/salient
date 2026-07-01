package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

// GatewayCandidatesQuery (§6.3/§8.4 primary): per sensor, terms on the
// responder MAC with a cardinality of responder IPs. A MAC answering for many
// IPs on a segment is that segment's gateway/router.
func GatewayCandidatesQuery(fm FieldMap, window time.Duration) (string, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.Conn}},
					map[string]any{"exists": map[string]any{"field": fm.DestinationMAC}},
				},
			},
		},
		"aggs": map[string]any{
			"by_sensor": map[string]any{
				"terms": map[string]any{"field": fm.ObserverName, "size": config.SensorTermsSize, "missing": ""},
				"aggs": map[string]any{
					"macs": map[string]any{
						"terms": map[string]any{"field": fm.DestinationMAC, "size": 50},
						"aggs": map[string]any{
							"ips": map[string]any{"cardinality": map[string]any{"field": fm.DestinationIP}},
						},
					},
				},
			},
		},
	}
	return marshal(q)
}

// FetchGatewayCandidates returns MACs answering for ≥K distinct IPs per
// sensor. Absence of MAC fields yields an empty slice, not an error — the
// caller records nothing and maps fall back to heuristic gateways.
func (c *Client) FetchGatewayCandidates(ctx context.Context, fm FieldMap, window time.Duration) ([]graph.L2Gateway, error) {
	body, err := GatewayCandidatesQuery(fm, window)
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
	raw, ok := aggs["by_sensor"]
	if !ok {
		return nil, nil
	}
	var agg struct {
		Buckets []struct {
			Key  string `json:"key"`
			Macs struct {
				Buckets []struct {
					Key string `json:"key"`
					IPs struct {
						Value int64 `json:"value"`
					} `json:"ips"`
				} `json:"buckets"`
			} `json:"macs"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding gateway candidates: %w", err)
	}
	var out []graph.L2Gateway
	for _, sensor := range agg.Buckets {
		for _, mac := range sensor.Macs.Buckets {
			if mac.IPs.Value >= config.GatewayMACMinIPs {
				out = append(out, graph.L2Gateway{MAC: mac.Key, Sensor: sensor.Key, IPCount: mac.IPs.Value})
			}
		}
	}
	return out, nil
}
