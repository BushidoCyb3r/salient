package scan_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		case strings.Contains(b, `"pairs"`):
			io.WriteString(w, wrap(`{"pairs":{"buckets":[{"key":{"dst":"10.0.1.10","name":"dc1.corp"}}]}}`))
		case strings.Contains(b, `"sensors"`):
			io.WriteString(w, wrap(`{"sensors":{"buckets":[{"key":"so-sensor-1","doc_count":9000}]}}`))
		case strings.Contains(b, `"top_hostname"`):
			io.WriteString(w, wrap(`{"by_ip":{"buckets":[{"key":"10.0.1.10","top_hostname":{"buckets":[{"key":"dc1.corp"}]},"top_mac":{"buckets":[]}}]}}`))
		case strings.Contains(b, `"zeek.x509"`):
			io.WriteString(w, `{"hits":{"hits":[{"_source":{"message":"{\"fingerprint\":\"tls-fp-1\"}","x509":{"san_dns":["dc1.corp"],"certificate":{"subject":"CN=dc1.corp,O=Test"}}}}]}}`)
		case strings.Contains(b, `"zeek.ssh"`):
			io.WriteString(w, `{"hits":{"hits":[{"_source":{"destination":{"ip":"10.0.1.10"},"ssh":{"host_key":"ssh-ed25519 AAAA-test"}}}]}}`)
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
	stem := strings.TrimSuffix(filepath.Base(res.SnapshotPath), ".json.gz")
	if filepath.Base(res.ReportPath) != stem+".html" || filepath.Base(res.MapPath) != stem+".html" {
		t.Fatalf("scan artifacts do not share identity: %+v", res)
	}
	// The save/report/map stages must fire in order at the end.
	want := []string{"aggregating-edges", "scoring", "saving", "report", "map"}
	if !isSubsequence(want, stages) {
		t.Fatalf("stages %v missing ordered subsequence %v", stages, want)
	}
}

func TestRunPopulatesHostnameFromDHCPLease(t *testing.T) {
	cli := mockGrid(t)
	fm, err := escli.LoadFieldMap("")
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(
		context.Background(), cli, fm,
		escli.ClusterInfo{ClusterName: "fake-grid"},
		scan.Options{Window: 336 * time.Hour, TZ: "UTC"},
		t.TempDir(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range res.Snapshot.Nodes {
		if n.IP == "10.0.1.10" {
			if len(n.Hostnames) == 1 && n.Hostnames[0] == "dc1.corp" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected 10.0.1.10 to carry hostname dc1.corp from its DHCP lease")
	}
}

func TestRunPopulatesTLSAndSSHIdentity(t *testing.T) {
	cli := mockGrid(t)
	fm, err := escli.LoadFieldMap("")
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(
		context.Background(), cli, fm,
		escli.ClusterInfo{ClusterName: "fake-grid"},
		scan.Options{Window: 336 * time.Hour, TZ: "UTC"},
		t.TempDir(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range res.Snapshot.Nodes {
		if n.IP != "10.0.1.10" {
			continue
		}
		if len(n.TLSFingerprints) != 1 || n.TLSFingerprints[0] != "tls-fp-1" {
			t.Fatalf("TLS fingerprints = %#v", n.TLSFingerprints)
		}
		if len(n.SSHHostKeys) != 1 || n.SSHHostKeys[0] != "ssh-ed25519 AAAA-test" {
			t.Fatalf("SSH host keys = %#v", n.SSHHostKeys)
		}
		return
	}
	t.Fatal("expected 10.0.1.10 in snapshot")
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

func TestRunRejectsNegativeMaxEdges(t *testing.T) {
	_, err := scan.Run(context.Background(), nil, escli.FieldMap{}, escli.ClusterInfo{},
		scan.Options{MaxEdges: -1}, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "max edges") {
		t.Fatalf("want max-edges validation error, got %v", err)
	}
}

func TestRunCancellationDuringEnrichmentWritesNoArtifacts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), `"edges"`):
			io.WriteString(w, `{"hits":{"total":{"value":1}},"aggregations":{"edges":{"buckets":[{"key":{"src":"10.0.0.1","dst":"10.0.0.2","port":443},"doc_count":1,"bytes_in":{"value":1},"states":{"buckets":[{"key":"SF","doc_count":1}]}}]}}}`)
		case strings.Contains(string(body), `"gw_macs"`):
			cancel()
			io.WriteString(w, `{"hits":{"total":{"value":0}},"aggregations":{}}`)
		default:
			io.WriteString(w, `{"hits":{"total":{"value":0}},"aggregations":{}}`)
		}
	}))
	defer srv.Close()
	cli, err := escli.New(escli.Config{ESURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fm := escli.DefaultFieldMap()
	dataDir := t.TempDir()
	_, err = scan.Run(ctx, cli, fm, escli.ClusterInfo{}, scan.Options{Window: time.Hour, TZ: "UTC"}, dataDir, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context cancellation, got %v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled scan wrote artifacts: %v", entries)
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
