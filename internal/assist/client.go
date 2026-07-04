// Package assist performs optional, explicitly enabled analysis of a stored
// snapshot. It never contacts Elasticsearch and is not used by scan or map.
package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

type Config struct {
	Provider    Provider
	Endpoint    string
	Model       string
	APIKey      string
	AllowRemote bool
	MaxNodes    int
	MaxEdges    int
	Timeout     time.Duration
}

type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGemini    Provider = "gemini"
)

type Finding struct {
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Rationale  string   `json:"rationale"`
	NodeIDs    []string `json:"node_ids"`
	EdgeIDs    []string `json:"edge_ids"`
	Confidence float64  `json:"confidence"`
}

type Result struct {
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings"`
}

type DeviceTag struct {
	NodeID     string   `json:"node_id"`
	Tags       []string `json:"tags"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

type TagResult struct {
	Tags []DeviceTag `json:"tags"`
}

type nodePayload struct {
	ID        string                `json:"id"`
	Hostnames []string              `json:"hostnames,omitempty"`
	Subnet    string                `json:"subnet"`
	Roles     []graph.RoleAssertion `json:"roles,omitempty"`
	Scores    graph.ScoreSet        `json:"scores"`
}

type edgePayload struct {
	ID        string `json:"id"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Port      uint16 `json:"port"`
	Service   string `json:"service"`
	ConnCount int64  `json:"conn_count"`
}

// Analyze sends only capped, summarized snapshot data and rejects any
// response whose citations do not exist in that payload.
func Analyze(ctx context.Context, cfg Config, snap graph.Snapshot) (Result, error) {
	var result Result
	var err error
	cfg, err = prepareConfig(cfg)
	if err != nil {
		return result, err
	}

	nodes, edges := summarize(snap, cfg.MaxNodes, cfg.MaxEdges)
	payload, err := json.Marshal(struct {
		Nodes []nodePayload `json:"nodes"`
		Edges []edgePayload `json:"edges"`
	}{nodes, edges})
	if err != nil {
		return result, err
	}
	content, err := complete(ctx, cfg,
		`Analyze the supplied dependency graph. Identify key terrain, surprising dependencies, blind spots, and hunting hypotheses. Return JSON only: {"summary":"...","findings":[{"title":"...","severity":"low|medium|high","rationale":"...","node_ids":["existing node id"],"edge_ids":["existing edge id"],"confidence":0.0}]}. Every finding must cite at least one supplied node or edge ID. Do not invent topology.`,
		string(payload))
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(cleanJSON(content)), &result); err != nil {
		return result, fmt.Errorf("decoding structured analysis: %w", err)
	}
	if err := validateCitations(result, nodes, edges); err != nil {
		return Result{}, err
	}
	return result, nil
}

// TagDevices asks a configured model to classify only devices present in the
// capped snapshot summary. Returned IDs are validated before the caller can
// display or persist them.
func TagDevices(ctx context.Context, cfg Config, snap graph.Snapshot) (TagResult, error) {
	var result TagResult
	var err error
	cfg, err = prepareConfig(cfg)
	if err != nil {
		return result, err
	}
	nodes, edges := summarize(snap, cfg.MaxNodes, cfg.MaxEdges)
	payload, err := json.Marshal(struct {
		Nodes []nodePayload `json:"nodes"`
		Edges []edgePayload `json:"edges"`
	}{nodes, edges})
	if err != nil {
		return result, err
	}
	content, err := complete(ctx, cfg,
		`Classify devices from their observed network communications. Return JSON only: {"tags":[{"node_id":"existing node id","tags":["short lowercase tag"],"confidence":0.0,"rationale":"brief communication-based reason"}]}. Use only supplied node IDs. Tags are suggestions, not observed facts. Do not invent devices or topology.`,
		string(payload))
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(cleanJSON(content)), &result); err != nil {
		return result, fmt.Errorf("decoding structured device tags: %w", err)
	}
	valid := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		valid[node.ID] = true
	}
	for i := range result.Tags {
		tag := &result.Tags[i]
		tag.NodeID = strings.TrimSpace(tag.NodeID)
		tag.Rationale = strings.TrimSpace(tag.Rationale)
		if !valid[tag.NodeID] {
			return TagResult{}, fmt.Errorf("device tag cites unknown node %q", tag.NodeID)
		}
		if tag.Confidence < 0 || tag.Confidence > 1 {
			return TagResult{}, fmt.Errorf("device tag for %q has confidence outside 0..1", tag.NodeID)
		}
		if tag.Rationale == "" {
			return TagResult{}, fmt.Errorf("device tag for %q has no rationale", tag.NodeID)
		}
		seen := map[string]bool{}
		cleaned := tag.Tags[:0]
		for _, value := range tag.Tags {
			value = strings.ToLower(strings.TrimSpace(value))
			if value != "" && !seen[value] {
				seen[value] = true
				cleaned = append(cleaned, value)
			}
		}
		tag.Tags = cleaned
		if len(tag.Tags) == 0 {
			return TagResult{}, fmt.Errorf("device tag for %q has no tags", tag.NodeID)
		}
	}
	return result, nil
}

func prepareConfig(cfg Config) (Config, error) {
	if err := validateEndpoint(cfg.Endpoint, cfg.AllowRemote); err != nil {
		return cfg, err
	}
	if cfg.Model == "" {
		return cfg, fmt.Errorf("model is required")
	}
	if cfg.Provider == "" {
		cfg.Provider = ProviderOpenAI
	}
	switch cfg.Provider {
	case ProviderOpenAI, ProviderAnthropic, ProviderGemini:
	default:
		return cfg, fmt.Errorf("unsupported model API %q", cfg.Provider)
	}
	if cfg.MaxNodes <= 0 {
		cfg.MaxNodes = config.AssistMaxNodes
	}
	if cfg.MaxEdges <= 0 {
		cfg.MaxEdges = config.AssistMaxEdges
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = config.AssistTimeout
	}
	return cfg, nil
}

func complete(ctx context.Context, cfg Config, system, user string) (string, error) {
	var body any
	switch cfg.Provider {
	case ProviderOpenAI:
		body = map[string]any{
			"model": cfg.Model,
			"messages": []map[string]string{
				{"role": "system", "content": system},
				{"role": "user", "content": user},
			},
			"temperature": 0.1,
		}
	case ProviderAnthropic:
		body = map[string]any{
			"model": cfg.Model, "max_tokens": 4096, "system": system,
			"messages": []map[string]string{{"role": "user", "content": user}},
		}
	case ProviderGemini:
		body = map[string]any{
			"systemInstruction": map[string]any{"parts": []map[string]string{{"text": system}}},
			"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": user}}}},
			"generationConfig":  map[string]any{"responseMimeType": "application/json", "temperature": 0.1},
		}
	}
	requestBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		switch cfg.Provider {
		case ProviderOpenAI:
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		case ProviderAnthropic:
			req.Header.Set("x-api-key", cfg.APIKey)
			req.Header.Set("anthropic-version", "2023-06-01")
		case ProviderGemini:
			req.Header.Set("x-goog-api-key", cfg.APIKey)
		}
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if !strings.EqualFold(r.URL.Host, req.URL.Host) {
				return fmt.Errorf("analysis redirect host %q does not match endpoint host %q", r.URL.Host, req.URL.Host)
			}
			return validateEndpoint(r.URL.String(), cfg.AllowRemote)
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("analysis request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, config.AssistMaxResponseBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("analysis endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return responseContent(cfg.Provider, responseBody)
}

func responseContent(provider Provider, body []byte) (string, error) {
	switch provider {
	case ProviderOpenAI:
		var envelope struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return "", fmt.Errorf("decoding analysis response: %w", err)
		}
		if len(envelope.Choices) == 0 {
			return "", fmt.Errorf("analysis response contained no choices")
		}
		return envelope.Choices[0].Message.Content, nil
	case ProviderAnthropic:
		var envelope struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return "", fmt.Errorf("decoding analysis response: %w", err)
		}
		if len(envelope.Content) == 0 {
			return "", fmt.Errorf("analysis response contained no content")
		}
		return envelope.Content[0].Text, nil
	case ProviderGemini:
		var envelope struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return "", fmt.Errorf("decoding analysis response: %w", err)
		}
		if len(envelope.Candidates) == 0 || len(envelope.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("analysis response contained no candidates")
		}
		return envelope.Candidates[0].Content.Parts[0].Text, nil
	default:
		return "", fmt.Errorf("unsupported model API %q", provider)
	}
}

func cleanJSON(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(content), "```"))
}

func validateEndpoint(raw string, allowRemote bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid analysis endpoint %q", raw)
	}
	host := u.Hostname()
	local := strings.EqualFold(host, "localhost")
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		local = true
	}
	if local {
		return nil
	}
	if !allowRemote {
		return fmt.Errorf("remote analysis endpoint requires --allow-network-data-egress")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("remote analysis endpoint must use https")
	}
	return nil
}

func summarize(snap graph.Snapshot, maxNodes, maxEdges int) ([]nodePayload, []edgePayload) {
	nodes := append([]graph.Node(nil), snap.Nodes...)
	sort.Slice(nodes, func(i, j int) bool {
		ri, rj := nodes[i].Scores.Rank, nodes[j].Scores.Rank
		if ri == 0 {
			ri = int(^uint(0) >> 1)
		}
		if rj == 0 {
			rj = int(^uint(0) >> 1)
		}
		if ri != rj {
			return ri < rj
		}
		return nodes[i].IP < nodes[j].IP
	})
	if len(nodes) > maxNodes {
		nodes = nodes[:maxNodes]
	}
	selected := make(map[string]bool, len(nodes))
	outNodes := make([]nodePayload, 0, len(nodes))
	for _, n := range nodes {
		selected[n.IP] = true
		outNodes = append(outNodes, nodePayload{ID: n.IP, Hostnames: n.Hostnames, Subnet: n.Subnet, Roles: n.Roles, Scores: n.Scores})
	}
	edges := append([]graph.Edge(nil), snap.Edges...)
	// Stable, fully-ordered: equal ConnCount must not select a different edge
	// set run to run (the whole pipeline is deterministic by design).
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ConnCount != edges[j].ConnCount {
			return edges[i].ConnCount > edges[j].ConnCount
		}
		if edges[i].Src != edges[j].Src {
			return edges[i].Src < edges[j].Src
		}
		if edges[i].Dst != edges[j].Dst {
			return edges[i].Dst < edges[j].Dst
		}
		return edges[i].Port < edges[j].Port
	})
	outEdges := make([]edgePayload, 0, min(maxEdges, len(edges)))
	for _, e := range edges {
		if !selected[e.Src] || !selected[e.Dst] {
			continue
		}
		outEdges = append(outEdges, edgePayload{ID: edgeID(e), Src: e.Src, Dst: e.Dst, Port: e.Port, Service: e.Service, ConnCount: e.ConnCount})
		if len(outEdges) == maxEdges {
			break
		}
	}
	return outNodes, outEdges
}

func edgeID(e graph.Edge) string { return fmt.Sprintf("%s>%s:%d", e.Src, e.Dst, e.Port) }

func validateCitations(result Result, nodes []nodePayload, edges []edgePayload) error {
	nodeIDs, edgeIDs := map[string]bool{}, map[string]bool{}
	for _, n := range nodes {
		nodeIDs[n.ID] = true
	}
	for _, e := range edges {
		edgeIDs[e.ID] = true
	}
	for _, f := range result.Findings {
		if len(f.NodeIDs)+len(f.EdgeIDs) == 0 {
			return fmt.Errorf("finding %q has no citations", f.Title)
		}
		for _, id := range f.NodeIDs {
			if !nodeIDs[id] {
				return fmt.Errorf("finding %q cites unknown node citation %q", f.Title, id)
			}
		}
		for _, id := range f.EdgeIDs {
			if !edgeIDs[id] {
				return fmt.Errorf("finding %q cites unknown edge citation %q", f.Title, id)
			}
		}
	}
	return nil
}
