package escli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newMockES returns an httptest server that dispatches on URL path. Every
// response carries the X-Elastic-Product header the client validates.
func newMockES(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range handlers {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cli, err := New(Config{ESURL: srv.URL, APIKey: "dGVzdDp0ZXN0", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return srv, cli
}

func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestInfoAuthOK(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/": jsonHandler(200, `{"cluster_name":"securityonion","version":{"number":"8.14.3"}}`),
	})
	info, err := cli.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ClusterName != "securityonion" || info.Version.Number != "8.14.3" {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestInfoAuthFailure(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/": jsonHandler(401, `{"error":"unauthorized"}`),
	})
	_, err := cli.Info(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 auth error, got: %v", err)
	}
}

func TestDatasetCounts(t *testing.T) {
	var captured string
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			captured = string(b)
			jsonHandler(200, `{
				"hits": {"total": {"value": 5000}},
				"aggregations": {"datasets": {"buckets": [
					{"key": "conn", "doc_count": 4000},
					{"key": "dns", "doc_count": 1000}
				]}}
			}`)(w, r)
		},
	})
	got, err := cli.DatasetCounts(context.Background(), DefaultFieldMap(), 24*time.Hour, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Dataset != "conn" || got[0].Docs != 4000 {
		t.Errorf("unexpected counts: %+v", got)
	}
	if !strings.Contains(captured, `"event.dataset"`) {
		t.Errorf("query does not use fieldmap dataset field: %s", captured)
	}
}

// The wrong-fieldmap signature: documents exist but the aggregation field
// produced no buckets. Must fail loudly, never return an empty result.
func TestDatasetCountsZeroBucketsIsLoudError(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{
			"hits": {"total": {"value": 123456}},
			"aggregations": {"datasets": {"buckets": []}}
		}`),
	})
	_, err := cli.DatasetCounts(context.Background(), DefaultFieldMap(), 24*time.Hour, 200)
	if !errors.Is(err, ErrZeroBuckets) {
		t.Fatalf("expected ErrZeroBuckets, got: %v", err)
	}
}

func TestDatasetCountsEmptyIndexIsNotAnError(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{
			"hits": {"total": {"value": 0}},
			"aggregations": {"datasets": {"buckets": []}}
		}`),
	})
	got, err := cli.DatasetCounts(context.Background(), DefaultFieldMap(), 24*time.Hour, 200)
	if err != nil {
		t.Fatalf("empty grid must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no datasets, got %+v", got)
	}
}

func TestMACCoverage(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{
			"hits": {"total": {"value": 1000}},
			"aggregations": {
				"src_mac_present": {"doc_count": 900},
				"dst_mac_present": {"doc_count": 850}
			}
		}`),
	})
	cov, err := cli.MACCoverage(context.Background(), DefaultFieldMap(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cov.ConnDocs != 1000 || cov.SrcMACDocs != 900 || cov.DstMACDocs != 850 {
		t.Errorf("unexpected coverage: %+v", cov)
	}
}

func TestResolveIndices(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/_resolve/index/logs-*": jsonHandler(200, `{
			"indices": [{"name": ".ds-logs-zeek-backing"}],
			"data_streams": [{"name": "logs-zeek-so"}]
		}`),
	})
	got, err := cli.ResolveIndices(context.Background(), "logs-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].DataStream || got[0].Name != "logs-zeek-so" {
		t.Errorf("unexpected indices: %+v", got)
	}
}

func TestFieldPresence(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_field_caps": jsonHandler(200, `{
			"fields": {
				"source.ip": {"ip": {"type": "ip"}},
				"destination.ip": {"ip": {"type": "ip"}}
			}
		}`),
	})
	got, err := cli.FieldPresence(context.Background(), "logs-*", []string{"source.ip", "destination.ip", "source.mac"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["source.ip"] || !got["destination.ip"] || got["source.mac"] {
		t.Errorf("unexpected presence: %+v", got)
	}
}

func TestCheckWritePrivilegesWarnsOnWritableKey(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/_security/user/_has_privileges": jsonHandler(200, `{
			"has_all_requested": false,
			"index": {"logs-*": {"read": true, "write": true, "delete": false}}
		}`),
	})
	check, err := cli.CheckWritePrivileges(context.Background(), "logs-*")
	if err != nil {
		t.Fatal(err)
	}
	if !check.CanWrite {
		t.Error("writable key not detected")
	}
}

func TestCheckWritePrivilegesIndeterminateWhenSecurityAPIDenied(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/_security/user/_has_privileges": jsonHandler(403, `{"error":"forbidden"}`),
	})
	check, err := cli.CheckWritePrivileges(context.Background(), "logs-*")
	if err != nil {
		t.Fatal(err)
	}
	if !check.Indeterminate || check.CanWrite {
		t.Errorf("expected indeterminate result, got %+v", check)
	}
}

func TestQueryBuildersProduceValidJSON(t *testing.T) {
	fm := DefaultFieldMap()
	for name, build := range map[string]func() (string, error){
		"datasets": func() (string, error) { return DatasetCountsQuery(fm, 24*time.Hour, 200) },
		"sensors":  func() (string, error) { return SensorsQuery(fm, 24*time.Hour, 100) },
		"mac":      func() (string, error) { return MACCoverageQuery(fm, 24*time.Hour) },
		"privs":    func() (string, error) { return HasWritePrivilegesQuery("logs-*") },
	} {
		body, err := build()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Errorf("%s: invalid JSON: %v", name, err)
		}
	}
}

func TestWritePrivilegeQueryIncludesCreateDoc(t *testing.T) {
	body, err := HasWritePrivilegesQuery("logs-*")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"create_doc"`) {
		t.Fatalf("write privilege query omitted create_doc: %s", body)
	}
}

func TestMACCoverageQueryScopesToConnDataset(t *testing.T) {
	body, err := MACCoverageQuery(DefaultFieldMap(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"zeek.conn"`) || !strings.Contains(body, `"conn"`) {
		t.Errorf("MAC probe not scoped to conn dataset candidates: %s", body)
	}
}

func TestDecodeJSONWithLimit(t *testing.T) {
	var dst map[string]any
	err := decodeJSONWithLimit(strings.NewReader(`{"value":"too large"}`), &dst, 8)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want response limit error, got %v", err)
	}
}
