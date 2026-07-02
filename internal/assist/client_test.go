package assist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

func TestAnalyzeSendsCappedSnapshotAndValidatesCitations(t *testing.T) {
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"summary\":\"DNS is key terrain\",\"findings\":[{\"title\":\"DNS dependency\",\"severity\":\"medium\",\"rationale\":\"Many clients depend on it\",\"node_ids\":[\"10.0.0.1\"],\"edge_ids\":[\"10.0.0.2>10.0.0.1:53\"],\"confidence\":0.8}]}"}}]}`)
	}))
	defer server.Close()

	snap := graph.Snapshot{
		Nodes: []graph.Node{
			{IP: "10.0.0.1", Scores: graph.ScoreSet{Rank: 1}},
			{IP: "10.0.0.2", Scores: graph.ScoreSet{Rank: 2}},
			{IP: "10.0.0.3", Scores: graph.ScoreSet{Rank: 3}},
		},
		Edges: []graph.Edge{{Src: "10.0.0.2", Dst: "10.0.0.1", Port: 53, ConnCount: 200}},
	}
	result, err := Analyze(context.Background(), Config{Endpoint: server.URL, Model: "test", MaxNodes: 2, MaxEdges: 1}, snap)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary != "DNS is key terrain" || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	var request struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(requestBody), &request); err != nil {
		t.Fatal(err)
	}
	content := request.Messages[len(request.Messages)-1].Content
	var payload struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []struct {
			ID string `json:"id"`
		} `json:"edges"`
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Nodes) != 2 || len(payload.Edges) != 1 || payload.Edges[0].ID != "10.0.0.2>10.0.0.1:53" {
		t.Fatalf("payload was not capped or edge IDs missing: %s", requestBody)
	}
}

func TestAnalyzeRejectsUnknownCitations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"summary\":\"x\",\"findings\":[{\"title\":\"x\",\"node_ids\":[\"192.0.2.99\"]}]}"}}]}`)
	}))
	defer server.Close()
	_, err := Analyze(context.Background(), Config{Endpoint: server.URL, Model: "test", MaxNodes: 1}, graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.0.1"}}})
	if err == nil || !strings.Contains(err.Error(), "unknown node citation") {
		t.Fatalf("expected citation error, got %v", err)
	}
}

func TestValidateEndpointRequiresExplicitSecureRemoteEgress(t *testing.T) {
	if err := validateEndpoint("http://127.0.0.1:11434/v1/chat/completions", false); err != nil {
		t.Fatalf("loopback endpoint rejected: %v", err)
	}
	if err := validateEndpoint("https://example.com/v1/chat/completions", false); err == nil {
		t.Fatal("remote endpoint accepted without explicit egress permission")
	}
	if err := validateEndpoint("http://example.com/v1/chat/completions", true); err == nil {
		t.Fatal("insecure remote endpoint accepted")
	}
	if err := validateEndpoint("https://example.com/v1/chat/completions", true); err != nil {
		t.Fatalf("explicit secure remote endpoint rejected: %v", err)
	}
}
