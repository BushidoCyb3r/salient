package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockGrid answers the _search surface RunScan drives, plus GET / for
// Connect. Dispatches on request-body substrings like testdata/fakees.
func mockGrid(t *testing.T) string {
	t.Helper()
	wrap := func(aggs string) string {
		return `{"took":1,"hits":{"total":{"value":1000}},"aggregations":` + aggs + `}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `{"cluster_name":"fake-grid","version":{"number":"8.14.0"}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		switch {
		case strings.Contains(b, `"edges"`):
			var sb strings.Builder
			edges := []struct {
				src, dst string
				port     int
			}{
				{"10.0.3.30", "10.0.1.10", 88}, {"10.0.3.31", "10.0.1.10", 88},
				{"10.0.3.30", "10.0.1.11", 53}, {"10.0.3.30", "10.0.1.20", 445},
			}
			for i, e := range edges {
				if i > 0 {
					sb.WriteString(",")
				}
				fmt.Fprintf(&sb, `{"key":{"src":%q,"dst":%q,"port":%d},"doc_count":%d,
					"bytes_out":{"value":900},"bytes_in":{"value":4000},
					"first":{"value":1780000000000},"last":{"value":1780080000000},
					"sensors":{"buckets":[{"key":"so-sensor-1","doc_count":%d}]}}`,
					e.src, e.dst, e.port, 100+i, 100+i)
			}
			io.WriteString(w, wrap(`{"edges":{"buckets":[`+sb.String()+`]}}`))
		case strings.Contains(b, `"responders"`):
			io.WriteString(w, wrap(`{"responders":{"buckets":[{"key":"10.0.1.10","doc_count":1500,
				"clients":{"value":15},"sample_hosts":{"buckets":[{"key":"10.0.3.30","doc_count":5}]}}]}}`))
		default:
			io.WriteString(w, wrap(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestConnectStoresClient(t *testing.T) {
	a := &App{ctx: context.Background(), DataDir: t.TempDir()}
	info, err := a.Connect(ConnectRequest{ESURL: mockGrid(t), APIKey: "dGVzdDp0ZXN0"})
	if err != nil {
		t.Fatal(err)
	}
	if info.ClusterName != "fake-grid" {
		t.Fatalf("Connect() cluster = %q, want fake-grid", info.ClusterName)
	}
	if a.cli == nil {
		t.Fatal("Connect() left a.cli nil")
	}
}

func TestRunScanRequiresConnect(t *testing.T) {
	a := &App{ctx: context.Background(), DataDir: t.TempDir()}
	if _, err := a.RunScan(ScanRequest{Window: "1h"}); err == nil {
		t.Fatal("RunScan() before Connect should error")
	}
}

func TestRunScanEmitsProgressAndDone(t *testing.T) {
	var events []string
	a := &App{
		ctx:     context.Background(),
		DataDir: t.TempDir(),
		emitFn:  func(event string, data ...interface{}) { events = append(events, event) },
	}
	if _, err := a.Connect(ConnectRequest{ESURL: mockGrid(t), APIKey: "dGVzdDp0ZXN0"}); err != nil {
		t.Fatal(err)
	}
	res, err := a.RunScan(ScanRequest{Window: "336h", TZ: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SnapshotPath == "" || len(res.Snapshot.Nodes) == 0 {
		t.Fatalf("RunScan() = %#v", res)
	}
	if countEvent(events, "scan:progress") == 0 || countEvent(events, "scan:done") != 1 {
		t.Fatalf("events = %v, want progress + one done", events)
	}
	// cancel func must be cleared after the run so a second scan can start.
	if a.cancel != nil {
		t.Fatal("RunScan() left a.cancel set")
	}
}

func TestRunScanBadWindow(t *testing.T) {
	a := &App{ctx: context.Background(), DataDir: t.TempDir()}
	if _, err := a.Connect(ConnectRequest{ESURL: mockGrid(t), APIKey: "dGVzdDp0ZXN0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunScan(ScanRequest{Window: "not-a-duration"}); err == nil {
		t.Fatal("RunScan() with bad window should error")
	}
}

func countEvent(events []string, name string) int {
	n := 0
	for _, e := range events {
		if e == name {
			n++
		}
	}
	return n
}
