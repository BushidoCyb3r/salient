package escli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// FetchEdges must loop on after_key and stitch pages together.
func TestFetchEdgesPagination(t *testing.T) {
	var calls atomic.Int32
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": func(w http.ResponseWriter, r *http.Request) {
			n := calls.Add(1)
			var body string
			if n == 1 {
				body = `{"hits":{"total":{"value":100}},"aggregations":{"edges":{
					"after_key":{"src":"10.0.0.1","dst":"10.0.0.2","port":445},
					"buckets":[{"key":{"src":"10.0.0.1","dst":"10.0.0.2","port":445},"doc_count":10,
						"bytes_out":{"value":1000},"bytes_in":{"value":2000},
						"first":{"value":1750000000000},"last":{"value":1750086400000},
						"sensors":{"buckets":[{"key":"s1","doc_count":10}]}}]}}}`
			} else {
				body = `{"hits":{"total":{"value":100}},"aggregations":{"edges":{
					"buckets":[{"key":{"src":"10.0.0.3","dst":"10.0.0.2","port":88},"doc_count":5,
						"bytes_out":{"value":10},"bytes_in":{"value":20},
						"first":{"value":1750000000000},"last":{"value":1750086400000},
						"sensors":{"buckets":[]}}]}}}`
			}
			jsonHandler(200, body)(w, r)
		},
	})
	edges, truncated, err := cli.FetchEdges(context.Background(), DefaultFieldMap(), 24*time.Hour, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("unexpected truncation")
	}
	if len(edges) != 2 || calls.Load() != 2 {
		t.Fatalf("want 2 edges over 2 pages, got %d edges, %d calls", len(edges), calls.Load())
	}
	e := edges[0]
	if e.Src != "10.0.0.1" || e.Dst != "10.0.0.2" || e.Port != 445 || e.Service != "smb" ||
		e.ConnCount != 10 || e.BytesOut != 1000 || e.BytesIn != 2000 || e.Sensors[0] != "s1" {
		t.Errorf("bad first edge: %+v", e)
	}
	if e.FirstSeen.IsZero() || !e.LastSeen.After(e.FirstSeen) {
		t.Errorf("bad timestamps: %v %v", e.FirstSeen, e.LastSeen)
	}
}

func TestFetchEdgesMaxEdgesTruncates(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": func(w http.ResponseWriter, r *http.Request) {
			// Always claims another page exists.
			jsonHandler(200, fmt.Sprintf(`{"hits":{"total":{"value":100}},"aggregations":{"edges":{
				"after_key":{"src":"x","dst":"y","port":1},
				"buckets":[{"key":{"src":"10.0.0.1","dst":"10.0.0.2","port":80},"doc_count":1,
					"bytes_out":{"value":0},"bytes_in":{"value":0},
					"first":{"value":1750000000000},"last":{"value":1750000000000},
					"sensors":{"buckets":[]}}]}}}`))(w, r)
		},
	})
	edges, truncated, err := cli.FetchEdges(context.Background(), DefaultFieldMap(), 24*time.Hour, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(edges) != 3 {
		t.Fatalf("want truncation at 3, got %d truncated=%v", len(edges), truncated)
	}
}

// Wrong fieldmap on the edge agg = docs exist, zero buckets → loud error.
func TestFetchEdgesZeroBucketsIsLoudError(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":999}},"aggregations":{"edges":{"buckets":[]}}}`),
	})
	_, _, err := cli.FetchEdges(context.Background(), DefaultFieldMap(), 24*time.Hour, nil, 1000)
	if !errors.Is(err, ErrZeroBuckets) {
		t.Fatalf("expected ErrZeroBuckets, got %v", err)
	}
}

func TestResponderCardinality(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":100}},"aggregations":{"responders":{
			"buckets":[{"key":"10.0.1.10","clients":{"value":42},
				"sample_hosts":{"buckets":[{"key":"10.0.2.30","doc_count":5}]}}]}}}`),
	})
	ev, err := cli.ResponderCardinality(context.Background(), DefaultFieldMap(), []string{"kerberos"}, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev["10.0.1.10"].Clients != 42 || ev["10.0.1.10"].SampleHosts[0] != "10.0.2.30" {
		t.Errorf("bad evidence: %+v", ev)
	}
}

// Evidence classification: protocol beats state beats bytes beats port-only.
func TestFetchEdgesEvidence(t *testing.T) {
	_, cli := newMockES(t, map[string]http.HandlerFunc{
		"/logs-*/_search": jsonHandler(200, `{"hits":{"total":{"value":100}},"aggregations":{"edges":{
			"buckets":[
			{"key":{"src":"10.0.0.1","dst":"10.0.0.2","port":53},"doc_count":10,
				"bytes_out":{"value":100},"bytes_in":{"value":200},
				"first":{"value":1750000000000},"last":{"value":1750086400000},
				"sensors":{"buckets":[]},
				"states":{"buckets":[{"key":"SF","doc_count":10}]},
				"protos":{"buckets":[{"key":"dns","doc_count":10}]}},
			{"key":{"src":"10.0.0.1","dst":"10.0.0.3","port":445},"doc_count":8,
				"bytes_out":{"value":900},"bytes_in":{"value":700},
				"first":{"value":1750000000000},"last":{"value":1750086400000},
				"sensors":{"buckets":[]},
				"states":{"buckets":[{"key":"SF","doc_count":8}]},
				"protos":{"buckets":[]}},
			{"key":{"src":"10.0.0.9","dst":"10.0.0.4","port":3306},"doc_count":40,
				"bytes_out":{"value":2400},"bytes_in":{"value":0},
				"first":{"value":1750000000000},"last":{"value":1750086400000},
				"sensors":{"buckets":[]},
				"states":{"buckets":[{"key":"S0","doc_count":40}]},
				"protos":{"buckets":[]}}
			]}}}`),
	})
	edges, _, err := cli.FetchEdges(context.Background(), DefaultFieldMap(), 24*time.Hour, nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 3 {
		t.Fatalf("want 3 edges, got %d", len(edges))
	}
	want := []graph.EvidenceLevel{
		graph.EvidenceProtocolConfirmed,
		graph.EvidenceResponderConfirmed,
		graph.EvidencePortOnly,
	}
	for i, w := range want {
		if edges[i].Evidence != w {
			t.Errorf("edge %d evidence = %q, want %q", i, edges[i].Evidence, w)
		}
	}
}
