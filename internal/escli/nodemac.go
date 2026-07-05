package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
)

// NodeMACsQuery aggregates, per responder IP, its most-seen destination MAC,
// plus a top-level MAC→IP-count agg used to identify (and exclude) gateway
// MACs that answer for many IPs.
func NodeMACsQuery(fm FieldMap, window time.Duration) (string, error) {
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
			"by_ip": map[string]any{
				"terms": map[string]any{"field": fm.DestinationIP, "size": config.ResponderTermsSize},
				"aggs": map[string]any{
					"top_mac": map[string]any{
						"terms": map[string]any{"field": fm.DestinationMAC, "size": 1},
					},
				},
			},
			"gw_macs": map[string]any{
				"terms": map[string]any{"field": fm.DestinationMAC, "size": config.GatewayMACTermsSize},
				"aggs": map[string]any{
					"ips": map[string]any{"cardinality": map[string]any{"field": fm.DestinationIP}},
				},
			},
		},
	}
	return marshal(q)
}

// FetchNodeMACs returns responder IP → its own NIC MAC. MACs that answer for
// ≥ GatewayMACMinIPs distinct IPs are gateways forwarding traffic, not host
// NICs, and are excluded. Absence of MAC fields yields an empty map, not an
// error — nodes simply carry no vendor.
func (c *Client) FetchNodeMACs(ctx context.Context, fm FieldMap, window time.Duration) (map[string]string, error) {
	body, err := NodeMACsQuery(fm, window)
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
	gatewayMAC := map[string]bool{}
	if raw, ok := aggs["gw_macs"]; ok {
		var gw struct {
			Buckets []struct {
				Key string `json:"key"`
				IPs struct {
					Value int64 `json:"value"`
				} `json:"ips"`
			} `json:"buckets"`
		}
		if err := json.Unmarshal(raw, &gw); err != nil {
			return nil, fmt.Errorf("decoding gateway MAC counts: %w", err)
		}
		for _, b := range gw.Buckets {
			if b.IPs.Value >= config.GatewayMACMinIPs {
				gatewayMAC[b.Key] = true
			}
		}
	}
	raw, ok := aggs["by_ip"]
	if !ok {
		return map[string]string{}, nil
	}
	var agg struct {
		Buckets []struct {
			Key    string `json:"key"`
			TopMAC struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"top_mac"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding node MACs: %w", err)
	}
	out := make(map[string]string, len(agg.Buckets))
	for _, b := range agg.Buckets {
		if len(b.TopMAC.Buckets) == 0 {
			continue
		}
		mac := b.TopMAC.Buckets[0].Key
		if mac == "" || gatewayMAC[mac] {
			continue
		}
		out[b.Key] = mac
	}
	return out, nil
}
