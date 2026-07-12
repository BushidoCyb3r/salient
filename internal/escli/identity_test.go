package escli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchTLSFingerprintsMatchesServerNameToCerts(t *testing.T) {
	var pairCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		switch {
		case strings.Contains(b, `"pairs"`):
			pairCalls++
			if strings.Contains(b, `"after"`) {
				io.WriteString(w, `{"hits":{"total":{"value":2}},"aggregations":{"pairs":{"buckets":[{"key":{"dst":"10.0.0.10","name":"other.example.com"}}]}}}`)
				return
			}
			io.WriteString(w, `{"hits":{"total":{"value":2}},"aggregations":{"pairs":{"after_key":{"dst":"10.0.0.10","name":"app.example.com"},"buckets":[{"key":{"dst":"10.0.0.10","name":"app.example.com"}}]}}}`)
		case strings.Contains(b, `"zeek.x509"`):
			io.WriteString(w, `{"hits":{"hits":[
				{"_source":{"message":"{\"fingerprint\":\"fp-1\"}","x509":{"san_dns":["app.example.com"],"certificate":{"subject":"CN=app.example.com,O=Example"}}}},
				{"_source":{"message":"{\"fingerprint\":\"fp-2\"}","x509":{"san_dns":["*.example.com"],"certificate":{"subject":"CN=ignored,O=Example"}}}}
			]}}`)
		default:
			t.Fatalf("unexpected search body: %s", b)
		}
	}))
	defer srv.Close()
	cli, err := New(Config{ESURL: srv.URL, APIKey: "dGVzdDp0ZXN0", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fm := DefaultFieldMap()
	got, err := cli.FetchTLSFingerprints(context.Background(), fm, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pairCalls != 2 {
		t.Fatalf("pair aggregation calls = %d, want 2", pairCalls)
	}
	want := []string{"fp-1", "fp-2"}
	if len(got["10.0.0.10"]) != len(want) {
		t.Fatalf("TLS fingerprints = %#v", got)
	}
	for i := range want {
		if got["10.0.0.10"][i] != want[i] {
			t.Fatalf("TLS fingerprints = %#v, want %#v", got["10.0.0.10"], want)
		}
	}
}

func TestFetchSSHHostKeysRespectsFieldMapOverrides(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"zeek.ssh"`) {
			t.Fatalf("unexpected search body: %s", string(body))
		}
		io.WriteString(w, `{"hits":{"hits":[
			{"_source":{"dst":{"addr":"10.0.0.20"},"ssh_server":{"key":"ssh-ed25519 AAAA-first"}}},
			{"_source":{"dst":{"addr":"10.0.0.20"},"ssh_server":{"key":"ssh-ed25519 AAAA-second"}}},
			{"_source":{"dst":{"addr":"10.0.0.20"},"ssh_server":{"key":"ssh-ed25519 AAAA-first"}}}
		]}}`)
	}))
	defer srv.Close()
	cli, err := New(Config{ESURL: srv.URL, APIKey: "dGVzdDp0ZXN0", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fm := DefaultFieldMap()
	fm.DestinationIP = "dst.addr"
	fm.SSHHostKey = "ssh_server.key"
	got, err := cli.FetchSSHHostKeys(context.Background(), fm, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh-ed25519 AAAA-first", "ssh-ed25519 AAAA-second"}
	if len(got["10.0.0.20"]) != len(want) {
		t.Fatalf("SSH host keys = %#v", got)
	}
	for i := range want {
		if got["10.0.0.20"][i] != want[i] {
			t.Fatalf("SSH host keys = %#v, want %#v", got["10.0.0.20"], want)
		}
	}
}
