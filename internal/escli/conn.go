package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// EdgeAggQuery builds one page of the composite conn aggregation (§6.1).
// Sources: (source.ip, destination.ip, destination.port). Sub-aggs: byte
// sums, first/last timestamp, sensor terms. doc_count is the connection
// count. afterKey pages the composite; pass nil for the first page.
func EdgeAggQuery(fm FieldMap, window time.Duration, scope []string, pageSize int, afterKey map[string]any) (string, error) {
	filters := []any{
		rangeFilter(fm.Timestamp, window),
		map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.Conn}},
	}
	if sf := scopeFilter(fm, scope); sf != nil {
		filters = append(filters, sf)
	}
	composite := map[string]any{
		"size": pageSize,
		"sources": []any{
			source("src", fm.SourceIP),
			source("dst", fm.DestinationIP),
			source("port", fm.DestinationPort),
		},
	}
	if afterKey != nil {
		composite["after"] = afterKey
	}
	q := map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
		"aggs": map[string]any{
			"edges": map[string]any{
				"composite": composite,
				"aggs": map[string]any{
					"bytes_out": map[string]any{"sum": map[string]any{"field": fm.SourceBytes}},
					"bytes_in":  map[string]any{"sum": map[string]any{"field": fm.DestinationBytes}},
					"first":     map[string]any{"min": map[string]any{"field": fm.Timestamp}},
					"last":      map[string]any{"max": map[string]any{"field": fm.Timestamp}},
					"sensors":   map[string]any{"terms": map[string]any{"field": fm.ObserverName, "size": 20}},
					"states":    map[string]any{"terms": map[string]any{"field": fm.ConnState, "size": 16}},
					"protos":    map[string]any{"terms": map[string]any{"field": fm.Service, "size": 8}},
				},
			},
		},
	}
	return marshal(q)
}

func source(name, field string) map[string]any {
	return map[string]any{name: map[string]any{"terms": map[string]any{"field": field}}}
}

// scopeFilter builds an OR of CIDR filters over source or destination IP.
// Empty scope means no restriction.
func scopeFilter(fm FieldMap, scope []string) map[string]any {
	if len(scope) == 0 {
		return nil
	}
	var should []any
	for _, cidr := range scope {
		should = append(should,
			map[string]any{"term": map[string]any{fm.SourceIP: map[string]any{"value": cidr}}},
			map[string]any{"term": map[string]any{fm.DestinationIP: map[string]any{"value": cidr}}},
		)
	}
	// ES `term` on an ip field with a CIDR value matches the range.
	return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}
}

// FetchEdges runs the composite aggregation to completion, paging on
// after_key, and returns typed edges. Stops with a loud warning at maxEdges.
func (c *Client) FetchEdges(ctx context.Context, fm FieldMap, window time.Duration, scope []string, maxEdges int) ([]graph.Edge, bool, error) {
	var edges []graph.Edge
	var after map[string]any
	truncated := false
	for {
		body, err := EdgeAggQuery(fm, window, scope, config.CompositePageSize, after)
		if err != nil {
			return nil, false, err
		}
		res, err := c.search(ctx, fm.IndexPattern, body)
		if err != nil {
			return nil, false, err
		}
		total, err := hitsTotal(res)
		if err != nil {
			return nil, false, err
		}
		page, nextAfter, err := parseEdgePage(res)
		if err != nil {
			return nil, false, err
		}
		if total > 0 && len(page) == 0 && len(edges) == 0 {
			return nil, false, fmt.Errorf("conn edge aggregation: %w", ErrZeroBuckets)
		}
		edges = append(edges, page...)
		if len(edges) >= maxEdges {
			truncated = true
			edges = edges[:maxEdges]
			break
		}
		if nextAfter == nil {
			break
		}
		after = nextAfter
	}
	return edges, truncated, nil
}

func parseEdgePage(res map[string]json.RawMessage) ([]graph.Edge, map[string]any, error) {
	aggs, err := aggregations(res)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := aggs["edges"]
	if !ok {
		return nil, nil, nil
	}
	var agg struct {
		AfterKey map[string]any `json:"after_key"`
		Buckets  []struct {
			Key struct {
				Src  string      `json:"src"`
				Dst  string      `json:"dst"`
				Port json.Number `json:"port"`
			} `json:"key"`
			DocCount int64 `json:"doc_count"`
			BytesOut struct {
				Value float64 `json:"value"`
			} `json:"bytes_out"`
			BytesIn struct {
				Value float64 `json:"value"`
			} `json:"bytes_in"`
			First struct {
				Value float64 `json:"value"`
			} `json:"first"`
			Last struct {
				Value float64 `json:"value"`
			} `json:"last"`
			Sensors struct {
				Buckets []termsBucket `json:"buckets"`
			} `json:"sensors"`
			States struct {
				Buckets []termsBucket `json:"buckets"`
			} `json:"states"`
			Protos struct {
				Buckets []termsBucket `json:"buckets"`
			} `json:"protos"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, nil, fmt.Errorf("decoding edge buckets: %w", err)
	}
	edges := make([]graph.Edge, 0, len(agg.Buckets))
	for _, b := range agg.Buckets {
		port64, _ := b.Key.Port.Int64()
		port := uint16(port64)
		var sensors []string
		for _, s := range b.Sensors.Buckets {
			sensors = append(sensors, s.Key)
		}
		states := make(map[string]int64, len(b.States.Buckets))
		for _, s := range b.States.Buckets {
			states[s.Key] = s.DocCount
		}
		var protos []string
		for _, p := range b.Protos.Buckets {
			protos = append(protos, p.Key)
		}
		edges = append(edges, graph.Edge{
			Src:       b.Key.Src,
			Dst:       b.Key.Dst,
			Port:      port,
			Service:   config.ServiceName(port),
			ConnCount: b.DocCount,
			BytesOut:  int64(b.BytesOut.Value),
			BytesIn:   int64(b.BytesIn.Value),
			FirstSeen: epochMillis(b.First.Value),
			LastSeen:  epochMillis(b.Last.Value),
			Sensors:   sensors,
			Evidence:  graph.ClassifyEvidence(states, protos, int64(b.BytesIn.Value)),
		})
	}
	// A full page implies more may remain; ES only omits after_key when done.
	if len(agg.Buckets) == 0 {
		return edges, nil, nil
	}
	return edges, agg.AfterKey, nil
}

func epochMillis(v float64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(v)).UTC()
}
