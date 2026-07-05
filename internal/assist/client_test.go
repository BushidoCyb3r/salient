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

func TestTagDevicesSupportsProviderAPIs(t *testing.T) {
	tests := []struct {
		name       string
		provider   Provider
		authHeader string
		response   string
		checkBody  func(t *testing.T, body []byte)
	}{
		{
			name: "openai compatible", provider: ProviderOpenAI,
			authHeader: "Authorization",
			response:   `{"choices":[{"message":{"content":"{\"tags\":[{\"node_id\":\"10.0.0.1\",\"tags\":[\"dns\",\"infrastructure\"],\"confidence\":0.9,\"rationale\":\"Answers DNS for many clients\"}]}"}}]}`,
			checkBody: func(t *testing.T, body []byte) {
				var request struct {
					Model    string `json:"model"`
					Messages []any  `json:"messages"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Fatal(err)
				}
				if request.Model != "test-model" || len(request.Messages) != 2 {
					t.Fatalf("unexpected OpenAI-compatible request: %s", body)
				}
			},
		},
		{
			name: "anthropic messages", provider: ProviderAnthropic,
			authHeader: "X-Api-Key",
			response:   `{"content":[{"type":"text","text":"{\"tags\":[{\"node_id\":\"10.0.0.1\",\"tags\":[\"dns\"],\"confidence\":0.9,\"rationale\":\"Answers DNS\"}]}"}]}`,
			checkBody: func(t *testing.T, body []byte) {
				var request struct {
					Model    string `json:"model"`
					System   string `json:"system"`
					Messages []any  `json:"messages"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Fatal(err)
				}
				if request.Model != "test-model" || request.System == "" || len(request.Messages) != 1 {
					t.Fatalf("unexpected Anthropic request: %s", body)
				}
			},
		},
		{
			name: "gemini generate content", provider: ProviderGemini,
			authHeader: "X-Goog-Api-Key",
			response:   `{"candidates":[{"content":{"parts":[{"text":"{\"tags\":[{\"node_id\":\"10.0.0.1\",\"tags\":[\"dns\"],\"confidence\":0.9,\"rationale\":\"Answers DNS\"}]}"}]}}]}`,
			checkBody: func(t *testing.T, body []byte) {
				var request struct {
					Contents         []any `json:"contents"`
					GenerationConfig struct {
						ResponseMimeType string `json:"responseMimeType"`
					} `json:"generationConfig"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Fatal(err)
				}
				if len(request.Contents) != 1 || request.GenerationConfig.ResponseMimeType != "application/json" {
					t.Fatalf("unexpected Gemini request: %s", body)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if got := r.Header.Get(tt.authHeader); got != "secret" && got != "Bearer secret" {
					t.Errorf("unexpected %s header %q", tt.authHeader, got)
				}
				if tt.provider == ProviderAnthropic && r.Header.Get("Anthropic-Version") == "" {
					t.Error("missing Anthropic-Version header")
				}
				tt.checkBody(t, body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tt.response)
			}))
			defer server.Close()

			result, err := TagDevices(context.Background(), Config{
				Provider: tt.provider, Endpoint: server.URL, Model: "test-model", APIKey: "secret",
			}, graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.0.1"}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Tags) != 1 || result.Tags[0].NodeID != "10.0.0.1" || result.Tags[0].Tags[0] != "dns" {
				t.Fatalf("unexpected tags: %+v", result)
			}
		})
	}
}

func TestTagDevicesSendsOperatorFacts(t *testing.T) {
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"tags\":[{\"node_id\":\"10.0.0.1\",\"tags\":[\"router\"],\"confidence\":0.9,\"rationale\":\"operator confirmed\"}]}"}}]}`)
	}))
	defer server.Close()

	facts := map[string]OperatorFacts{
		"10.0.0.1": {Device: "router", DeviceType: "gateway", RoleOverride: "Gateway", Labels: []string{"udm"}},
		"10.9.9.9": {Device: "ghost"}, // not in snapshot — must not be sent
	}
	_, err := TagDevices(context.Background(), Config{
		Provider: ProviderOpenAI, Endpoint: server.URL, Model: "test",
	}, graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.0.1", MAC: "24:5a:4c:11:22:33"}}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	// The graph payload rides inside a JSON-escaped message string, so
	// quotes arrive backslash-escaped — assert on bare tokens.
	body := string(captured)
	for _, want := range []string{"operator", "router", "gateway", "Gateway", "udm", "Ubiquiti"} {
		if !strings.Contains(body, want) {
			t.Errorf("request body missing %s", want)
		}
	}
	if strings.Contains(body, "ghost") {
		t.Error("facts for nodes outside the summary must not be sent")
	}
}

func TestTagDevicesRejectsUnknownNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"tags\":[{\"node_id\":\"192.0.2.99\",\"tags\":[\"server\"],\"confidence\":0.8,\"rationale\":\"x\"}]}"}}]}`)
	}))
	defer server.Close()

	_, err := TagDevices(context.Background(), Config{
		Provider: ProviderOpenAI, Endpoint: server.URL, Model: "test",
	}, graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.0.1"}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown node") {
		t.Fatalf("expected unknown-node error, got %v", err)
	}
}

func TestTagDevicesRejectsCrossHostRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		io.WriteString(w, `{}`)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	_, err := TagDevices(context.Background(), Config{
		Provider: ProviderAnthropic, Endpoint: origin.URL, Model: "test", APIKey: "secret",
	}, graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.0.1"}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect host") {
		t.Fatalf("expected cross-host redirect error, got %v", err)
	}
	if reached {
		t.Fatal("cross-host redirect reached target")
	}
}
