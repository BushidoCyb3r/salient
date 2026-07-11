// Package scan is the shared scan pipeline: aggregate a window from an
// already-connected Elasticsearch client, build and score the dependency
// graph, and write the snapshot, report, and briefing map. Both the CLI
// `scan` command and the desktop GUI drive it through Run, differing only
// in the report callback (the CLI prints, the GUI emits UI events).
package scan

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/escli"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/report"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/score"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// Options are the tunables a caller chooses per scan.
type Options struct {
	Window   time.Duration
	Scope    []string
	MaxEdges int
	TZ       string // IANA timezone for temporal classification; "" means Local
}

// Stage is one progress step. Name is machine-stable for UI switching;
// Detail is a human-readable line. Level marks warnings.
type Stage struct {
	Name   string
	Detail string
	Warn   bool
}

// Result is what a completed scan produced.
type Result struct {
	SnapshotPath string
	ReportPath   string
	MapPath      string
	Snapshot     graph.Snapshot
	Truncated    bool
}

// Run executes the full pipeline against an already-connected client,
// invoking report(Stage) at each step (report may be nil). Artifacts are
// written under dataDir with 0600/0700 modes. The context cancels the
// underlying ES queries, so a caller can abort a long scan.
func Run(ctx context.Context, cli *escli.Client, fm escli.FieldMap, info escli.ClusterInfo, opts Options, dataDir string, report func(Stage)) (Result, error) {
	emit := func(name, detail string, warn bool) {
		if report != nil {
			report(Stage{Name: name, Detail: detail, Warn: warn})
		}
	}

	if opts.MaxEdges == 0 {
		opts.MaxEdges = config.DefaultMaxEdges
	}

	emit("connecting", fmt.Sprintf("scanning %q, window %s, scope %v", info.ClusterName, opts.Window, scopeOrAll(opts.Scope)), false)

	edges, truncated, err := cli.FetchEdges(ctx, fm, opts.Window, opts.Scope, opts.MaxEdges)
	if err != nil {
		return Result{}, err
	}
	if truncated {
		emit("truncated", fmt.Sprintf("edge aggregation hit --max-edges=%d and was truncated; narrow scope or raise the limit — rankings may be incomplete", opts.MaxEdges), true)
	}
	emit("aggregating-edges", fmt.Sprintf("%d edges aggregated", len(edges)), false)
	if len(edges) == 0 {
		return Result{}, fmt.Errorf("no edges observed — check window, scope, and fieldmap (run `salient discover`)")
	}

	var pc, rc, po int
	for _, e := range edges {
		switch e.Evidence {
		case graph.EvidenceProtocolConfirmed:
			pc++
		case graph.EvidenceResponderConfirmed:
			rc++
		case graph.EvidencePortOnly:
			po++
		}
	}
	emit("evidence", fmt.Sprintf(
		"service evidence: %d protocol-confirmed, %d responder-confirmed, %d port-only (attempts only — excluded from scoring)",
		pc, rc, po), pc == 0)

	ev, err := cli.FetchEvidence(ctx, fm, opts.Window, opts.Scope)
	if err != nil {
		return Result{}, err
	}

	m := graph.Build(edges)

	// Per-node responder MAC (gateway MACs excluded) — powers OUI vendor
	// identification. Best-effort: no MAC fields just means no vendors.
	if macs, err := cli.FetchNodeMACs(ctx, fm, opts.Window); err != nil {
		emit("node-mac", fmt.Sprintf("per-node MAC query failed, nodes will have no vendor: %v", err), true)
	} else {
		for ip, mac := range macs {
			if n, ok := m.Nodes[ip]; ok {
				n.MAC = mac
			}
		}
	}

	res := score.Score(m)
	scored := fmt.Sprintf("%d nodes scored", res.NodeCount)
	if res.BetweennessSampled {
		scored += fmt.Sprintf(" (betweenness sampled: >%d nodes)", config.ExactBetweennessMax)
	}
	emit("scoring", scored, false)

	// Second pass: temporal profiles for edges into the top-N ranked nodes.
	tz := opts.TZ
	if tz == "" {
		tz = "Local"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return Result{}, fmt.Errorf("bad timezone %q: %w", tz, err)
	}
	attachTemporal(ctx, cli, fm, opts.Window, loc, m)
	// Inference runs after temporal so DB-role evidence can cite activity class.
	m.InferRoles(ev)

	sensors, _ := cli.Sensors(ctx, fm, opts.Window, config.SensorTermsSize)
	var sensorNames []string
	for _, s := range sensors {
		sensorNames = append(sensorNames, s.Dataset)
	}

	// Primary gateway evidence: MAC convergence, if the grid has L2 fields.
	l2gw, err := cli.FetchGatewayCandidates(ctx, fm, opts.Window)
	if err != nil {
		emit("gateway-fallback", fmt.Sprintf("gateway candidate query failed, maps will use the inferred fallback: %v", err), true)
	}

	snap := m.Snapshot(graph.SnapshotMeta{
		CreatedAt:      time.Now().UTC(),
		Window:         opts.Window.String(),
		Scope:          opts.Scope,
		ClusterName:    info.ClusterName,
		Sensors:        sensorNames,
		ZeroCovCIDRs:   zeroCoverage(opts.Scope, m),
		L2Gateways:     l2gw,
		BetweenSampled: res.BetweennessSampled,
	})

	path, err := snapshot.Save(dataDir, snap)
	if err != nil {
		return Result{}, err
	}
	emit("saving", "snapshot saved: "+path, false)

	reportPath, err := writeReport(dataDir, snap)
	if err != nil {
		return Result{}, err
	}
	emit("report", "report written: "+reportPath, false)

	mapPath, err := writeBriefingMap(dataDir, snap)
	if err != nil {
		return Result{}, err
	}
	emit("map", "map written: "+mapPath, false)

	return Result{
		SnapshotPath: path,
		ReportPath:   reportPath,
		MapPath:      mapPath,
		Snapshot:     snap,
		Truncated:    truncated,
	}, nil
}

func scopeOrAll(scope []string) any {
	if len(scope) == 0 {
		return "all observed"
	}
	return scope
}

// attachTemporal fetches temporal profiles for the top-N ranked responders
// and attaches each to that node's inbound edges. Fetch failures degrade to
// unclassified edges rather than failing the scan.
func attachTemporal(ctx context.Context, cli *escli.Client, fm escli.FieldMap, window time.Duration, loc *time.Location, m *graph.Model) {
	type ranked struct {
		ip   string
		rank int
	}
	var nodes []ranked
	for _, n := range m.SortedNodes() {
		nodes = append(nodes, ranked{n.IP, n.Scores.Rank})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].rank < nodes[j].rank })
	if len(nodes) > config.TopNTemporal {
		nodes = nodes[:config.TopNTemporal]
	}
	for _, r := range nodes {
		p, err := cli.FetchTemporal(ctx, fm, window, r.ip, loc)
		if err != nil || p == nil {
			continue
		}
		for i := range m.Edges {
			if m.Edges[i].Dst == r.ip {
				m.Edges[i].Temporal = p
			}
		}
	}
}

// zeroCoverage flags in-scope CIDRs with no observed nodes — the
// possible-blind-spot finding. Only meaningful when a scope was given.
func zeroCoverage(scope []string, m *graph.Model) []string {
	var out []string
	for _, cidr := range scope {
		seen := false
		for ip := range m.Nodes {
			if cidrContains(cidr, ip) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, cidr)
		}
	}
	return out
}

func writeReport(dataDir string, snap graph.Snapshot) (string, error) {
	dir := filepath.Join(dataDir, "reports")
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ".html"
	path := filepath.Join(dir, name)
	if err := safefile.Write(path, func(w io.Writer) error { return report.HTML(w, snap) }); err != nil {
		return "", err
	}
	return path, nil
}

func writeBriefingMap(dataDir string, snap graph.Snapshot) (string, error) {
	dir := filepath.Join(dataDir, "maps")
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ".html"
	path := filepath.Join(dir, name)
	mm := mapview.Build(snap, mapview.Options{})
	if err := safefile.Write(path, func(w io.Writer) error { return report.HTMLMap(w, mm) }); err != nil {
		return "", err
	}
	return path, nil
}

func cidrContains(cidr, ip string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Contains(a)
}
