package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Query builders return JSON bodies as (string, error) so they are
// assertable in tests without a live grid (DEFILADE_PLAN.md §15).

// DatasetCountsQuery aggregates document counts per dataset value within
// the lookback window.
func DatasetCountsQuery(fm FieldMap, window time.Duration, termsSize int) (string, error) {
	return termsAggQuery(fm, window, termsSize, "datasets", fm.DatasetField)
}

// SensorsQuery aggregates observer.name values within the window.
func SensorsQuery(fm FieldMap, window time.Duration, termsSize int) (string, error) {
	return termsAggQuery(fm, window, termsSize, "sensors", fm.ObserverName)
}

// termsAggQuery builds a windowed terms aggregation over field, named aggName.
func termsAggQuery(fm FieldMap, window time.Duration, termsSize int, aggName, field string) (string, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{rangeFilter(fm.Timestamp, window)},
			},
		},
		"aggs": map[string]any{
			aggName: map[string]any{
				"terms": map[string]any{"field": field, "size": termsSize},
			},
		},
	}
	return marshal(q)
}

// MACCoverageQuery counts, within the conn dataset candidates and window,
// total docs and docs where each MAC field exists. The answer decides
// whether gateway inference can use MAC convergence (§8.4 primary) or must
// fall back to the cross-subnet heuristic.
func MACCoverageQuery(fm FieldMap, window time.Duration) (string, error) {
	q := map[string]any{
		"size": 0,
		// ES caps hits.total at 10,000 by default; this total is the
		// denominator of the coverage percentages, so it must be exact.
		"track_total_hits": true,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.Conn}},
				},
			},
		},
		"aggs": map[string]any{
			"src_mac_present": map[string]any{
				"filter": map[string]any{"exists": map[string]any{"field": fm.SourceMAC}},
			},
			"dst_mac_present": map[string]any{
				"filter": map[string]any{"exists": map[string]any{"field": fm.DestinationMAC}},
			},
		},
	}
	return marshal(q)
}

// HasWritePrivilegesQuery asks whether the current key holds any
// write-class privilege on the pattern.
func HasWritePrivilegesQuery(pattern string) (string, error) {
	q := map[string]any{
		"index": []any{
			map[string]any{
				"names":      []string{pattern},
				"privileges": []string{"write", "index", "create", "create_doc", "create_index", "delete", "delete_index"},
			},
		},
	}
	return marshal(q)
}

func rangeFilter(tsField string, window time.Duration) map[string]any {
	return map[string]any{
		"range": map[string]any{
			tsField: map[string]any{"gte": fmt.Sprintf("now-%ds", int64(window.Seconds()))},
		},
	}
}

func marshal(q map[string]any) (string, error) {
	b, err := json.Marshal(q)
	if err != nil {
		return "", fmt.Errorf("building query: %w", err)
	}
	return string(b), nil
}

// DatasetCount is one observed dataset value and its document count.
type DatasetCount struct {
	Dataset string
	Docs    int64
}

// DatasetCounts runs the dataset discovery aggregation. Returns
// ErrZeroBuckets when the pattern holds documents but the dataset field
// produced no buckets — the wrong-fieldmap signature.
func (c *Client) DatasetCounts(ctx context.Context, fm FieldMap, window time.Duration, termsSize int) ([]DatasetCount, error) {
	body, err := DatasetCountsQuery(fm, window, termsSize)
	if err != nil {
		return nil, err
	}
	res, err := c.search(ctx, fm.IndexPattern, body)
	if err != nil {
		return nil, err
	}
	total, err := hitsTotal(res)
	if err != nil {
		return nil, err
	}
	buckets, err := termsBuckets(res, "datasets")
	if err != nil {
		return nil, err
	}
	if total > 0 && len(buckets) == 0 {
		return nil, fmt.Errorf("dataset field %q: %w", fm.DatasetField, ErrZeroBuckets)
	}
	out := make([]DatasetCount, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, DatasetCount{Dataset: b.Key, Docs: b.DocCount})
	}
	return out, nil
}

// Sensors runs the observer.name aggregation. Zero buckets over nonzero
// docs is reported as a warning condition by the caller, not an error:
// a grid genuinely may not populate observer.name.
func (c *Client) Sensors(ctx context.Context, fm FieldMap, window time.Duration, termsSize int) ([]DatasetCount, error) {
	body, err := SensorsQuery(fm, window, termsSize)
	if err != nil {
		return nil, err
	}
	res, err := c.search(ctx, fm.IndexPattern, body)
	if err != nil {
		return nil, err
	}
	buckets, err := termsBuckets(res, "sensors")
	if err != nil {
		return nil, err
	}
	out := make([]DatasetCount, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, DatasetCount{Dataset: b.Key, Docs: b.DocCount})
	}
	return out, nil
}

// MACCoverage summarizes L2 evidence availability in conn logs.
type MACCoverage struct {
	ConnDocs   int64
	SrcMACDocs int64
	DstMACDocs int64
}

// MACCoverage runs the L2 presence probe over the conn dataset.
func (c *Client) MACCoverage(ctx context.Context, fm FieldMap, window time.Duration) (MACCoverage, error) {
	var cov MACCoverage
	body, err := MACCoverageQuery(fm, window)
	if err != nil {
		return cov, err
	}
	res, err := c.search(ctx, fm.IndexPattern, body)
	if err != nil {
		return cov, err
	}
	cov.ConnDocs, err = hitsTotal(res)
	if err != nil {
		return cov, err
	}
	cov.SrcMACDocs, err = filterAggCount(res, "src_mac_present")
	if err != nil {
		return cov, err
	}
	cov.DstMACDocs, err = filterAggCount(res, "dst_mac_present")
	if err != nil {
		return cov, err
	}
	return cov, nil
}

// --- response parsing helpers ---

type termsBucket struct {
	Key      string `json:"key"`
	DocCount int64  `json:"doc_count"`
}

func hitsTotal(res map[string]json.RawMessage) (int64, error) {
	raw, ok := res["hits"]
	if !ok {
		return 0, fmt.Errorf("search response missing hits section")
	}
	var hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
	}
	if err := json.Unmarshal(raw, &hits); err != nil {
		return 0, fmt.Errorf("decoding hits.total: %w", err)
	}
	return hits.Total.Value, nil
}

func aggregations(res map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	raw, ok := res["aggregations"]
	if !ok {
		return map[string]json.RawMessage{}, nil
	}
	var aggs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &aggs); err != nil {
		return nil, fmt.Errorf("decoding aggregations: %w", err)
	}
	return aggs, nil
}

func termsBuckets(res map[string]json.RawMessage, name string) ([]termsBucket, error) {
	aggs, err := aggregations(res)
	if err != nil {
		return nil, err
	}
	raw, ok := aggs[name]
	if !ok {
		return nil, nil
	}
	var agg struct {
		Buckets []termsBucket `json:"buckets"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return nil, fmt.Errorf("decoding %s buckets: %w", name, err)
	}
	return agg.Buckets, nil
}

func filterAggCount(res map[string]json.RawMessage, name string) (int64, error) {
	aggs, err := aggregations(res)
	if err != nil {
		return 0, err
	}
	raw, ok := aggs[name]
	if !ok {
		return 0, nil
	}
	var agg struct {
		DocCount int64 `json:"doc_count"`
	}
	if err := json.Unmarshal(raw, &agg); err != nil {
		return 0, fmt.Errorf("decoding %s doc_count: %w", name, err)
	}
	return agg.DocCount, nil
}
