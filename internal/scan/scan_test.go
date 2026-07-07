package scan_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/escli"
	"github.com/BushidoCyb3r/salient/internal/scan"
)

// mockGrid answers just the _search surface scan.Run drives, dispatching on
// request-body substrings the way testdata/fakees does. Only the edge
// aggregation must be non-empty; every other query degrades gracefully.
func mockGrid(t *testing.T) *escli.Client {
	t.Helper()
	wrap := func(aggs string) string {
		return `{"took":1,"hits":{"total":{"value":1000}},"aggregations":` + aggs + `}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
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
		case strings.Contains(b, `"sensors"`):
			io.WriteString(w, wrap(`{"sensors":{"buckets":[{"key":"so-sensor-1","doc_count":9000}]}}`))
		default:
			io.WriteString(w, wrap(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	cli, err := escli.New(escli.Config{ESURL: srv.URL, APIKey: "dGVzdDp0ZXN0", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func TestRunProducesSnapshotAndOrderedStages(t *testing.T) {
	cli := mockGrid(t)
	fm, err := escli.LoadFieldMap("")
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	res, err := scan.Run(
		context.Background(), cli, fm,
		escli.ClusterInfo{ClusterName: "fake-grid"},
		scan.Options{Window: 336 * time.Hour, TZ: "UTC"},
		t.TempDir(),
		func(s scan.Stage) { stages = append(stages, s.Name) },
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Snapshot.Nodes) == 0 {
		t.Fatal("scan produced no nodes")
	}
	if res.SnapshotPath == "" || res.ReportPath == "" || res.MapPath == "" {
		t.Fatalf("missing artifact paths: %+v", res)
	}
	// The save/report/map stages must fire in order at the end.
	want := []string{"aggregating-edges", "scoring", "saving", "report", "map"}
	if !isSubsequence(want, stages) {
		t.Fatalf("stages %v missing ordered subsequence %v", stages, want)
	}
}

func TestRunNoEdgesIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"hits":{"total":{"value":0}},"aggregations":{"edges":{"buckets":[]}}}`)
	}))
	defer srv.Close()
	cli, err := escli.New(escli.Config{ESURL: srv.URL, APIKey: "dGVzdDp0ZXN0", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fm, _ := escli.LoadFieldMap("")
	_, err = scan.Run(context.Background(), cli, fm, escli.ClusterInfo{ClusterName: "empty"},
		scan.Options{Window: time.Hour, TZ: "UTC"}, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "no edges observed") {
		t.Fatalf("want no-edges error, got %v", err)
	}
}

func isSubsequence(want, got []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && g == want[i] {
			i++
		}
	}
	return i == len(want)
}
