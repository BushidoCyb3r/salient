package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// TemporalQuery builds the second-pass histogram for one responder (§6.1):
// a 1h date_histogram over conn docs where destination.ip = ip. Folding into
// hour-of-day/day-of-week happens client-side in the operator's timezone, so
// no scripts are needed on the grid.
func TemporalQuery(fm FieldMap, window time.Duration, ip string) (string, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.Conn}},
					map[string]any{"term": map[string]any{fm.DestinationIP: map[string]any{"value": ip}}},
				},
			},
		},
		"aggs": map[string]any{
			"hist": map[string]any{
				"date_histogram": map[string]any{"field": fm.Timestamp, "fixed_interval": "1h"},
			},
		},
	}
	return marshal(q)
}

// FetchTemporal fetches and folds the activity histogram for one responder
// into the given timezone, returning a classified profile.
func (c *Client) FetchTemporal(ctx context.Context, fm FieldMap, window time.Duration, ip string, loc *time.Location) (*graph.TemporalProfile, error) {
	body, err := TemporalQuery(fm, window, ip)
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
	raw, ok := aggs["hist"]
	if !ok {
		return nil, nil
	}
	var agg struct {
		Buckets []struct {
			Key      int64 `json:"key"` // epoch millis of bucket start
			DocCount int64 `json:"doc_count"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding temporal buckets: %w", err)
	}
	var p graph.TemporalProfile
	for _, b := range agg.Buckets {
		t := time.UnixMilli(b.Key).In(loc)
		p.HourHistogram[t.Hour()] += b.DocCount
		p.DowHistogram[int(t.Weekday())] += b.DocCount
	}
	p.Class = graph.ClassifyTemporal(p.HourHistogram, p.DowHistogram)
	return &p, nil
}
