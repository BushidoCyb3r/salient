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
	Endpoint    string
	Model       string
	APIKey      string
	AllowRemote bool
	MaxNodes    int
	MaxEdges    int
	Timeout     time.Duration
}

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
	if err := validateEndpoint(cfg.Endpoint, cfg.AllowRemote); err != nil {
		return result, err
	}
	if cfg.Model == "" {
		return result, fmt.Errorf("model is required")
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

	nodes, edges := summarize(snap, cfg.MaxNodes, cfg.MaxEdges)
	payload, err := json.Marshal(struct {
		Nodes []nodePayload `json:"nodes"`
		Edges []edgePayload `json:"edges"`
	}{nodes, edges})
	if err != nil {
		return result, err
	}
	requestBody, err := json.Marshal(map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": `Analyze the supplied dependency graph. Identify key terrain, surprising dependencies, blind spots, and hunting hypotheses. Return JSON only: {"summary":"...","findings":[{"title":"...","severity":"low|medium|high","rationale":"...","node_ids":["existing node id"],"edge_ids":["existing edge id"],"confidence":0.0}]}. Every finding must cite at least one supplied node or edge ID. Do not invent topology.`},
			{"role": "user", "content": string(payload)},
		},
		"temperature": 0.1,
	})
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	resp, err := (&http.Client{Timeout: cfg.Timeout}).Do(req)
	if err != nil {
		return result, fmt.Errorf("analysis request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, config.AssistMaxResponseBytes))
	if err != nil {
		return result, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("analysis endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return result, fmt.Errorf("decoding analysis response: %w", err)
	}
	if len(envelope.Choices) == 0 {
		return result, fmt.Errorf("analysis response contained no choices")
	}
	content := strings.TrimSpace(envelope.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(strings.TrimSpace(content), "```")
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &result); err != nil {
		return result, fmt.Errorf("decoding structured analysis: %w", err)
	}
	if err := validateCitations(result, nodes, edges); err != nil {
		return Result{}, err
	}
	return result, nil
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
	sort.Slice(edges, func(i, j int) bool { return edges[i].ConnCount > edges[j].ConnCount })
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
