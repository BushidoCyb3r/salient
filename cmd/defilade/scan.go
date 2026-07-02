package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/escli"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/report"
	"github.com/BushidoCyb3r/defilade/internal/score"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func newScanCmd(opts *globalOpts) *cobra.Command {
	var (
		window   time.Duration
		scope    []string
		maxEdges int
		dataDir  string
		tz       string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Aggregate the window, build and score the dependency graph, save snapshot + report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, opts, window, scope, maxEdges, dataDir, tz)
		},
	}
	cmd.Flags().DurationVar(&window, "window", config.DefaultWindow, "analysis window (e.g. 336h for 14d)")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDRs to include (default: everything observed)")
	cmd.Flags().IntVar(&maxEdges, "max-edges", config.DefaultMaxEdges, "safety cap on aggregated edges")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DataDirName, "output directory for snapshots and reports")
	cmd.Flags().StringVar(&tz, "tz", "Local", "IANA timezone driving BusinessHours/Nightly classification")
	return cmd
}

func runScan(cmd *cobra.Command, opts *globalOpts, window time.Duration, scope []string, maxEdges int, dataDir string, tz string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	cfg, err := opts.clientConfig(os.Stderr)
	if err != nil {
		return err
	}
	fm, err := opts.fieldMap()
	if err != nil {
		return err
	}
	cli, err := escli.New(cfg)
	if err != nil {
		return err
	}
	if isTerminal(errOut) {
		defer startSpinner(errOut, 100*time.Millisecond)()
	}
	info, err := cli.Info(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Scanning %q, window %s, scope %v\n", info.ClusterName, window, scopeOrAll(scope))

	edges, truncated, err := cli.FetchEdges(ctx, fm, window, scope, maxEdges)
	if err != nil {
		return err
	}
	if truncated {
		fmt.Fprintf(errOut, "%sWARNING: edge aggregation hit --max-edges=%d and was truncated. Narrow --scope or raise the limit; rankings may be incomplete.%s\n", ansiRed, maxEdges, ansiReset)
	}
	fmt.Fprintf(out, "Edges aggregated: %d\n", len(edges))
	if len(edges) == 0 {
		return fmt.Errorf("no edges observed — check window, scope, and fieldmap (run `defilade discover`)")
	}

	ev, err := cli.FetchEvidence(ctx, fm, window, scope)
	if err != nil {
		return err
	}

	m := graph.Build(edges)
	res := score.Score(m)
	fmt.Fprintf(out, "Graph: %d nodes scored", res.NodeCount)
	if res.BetweennessSampled {
		fmt.Fprintf(out, " (betweenness sampled: >%d nodes)", config.ExactBetweennessMax)
	}
	fmt.Fprintln(out)

	// Second pass (§6.1/§9): temporal profiles for edges into top-N nodes.
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return fmt.Errorf("bad --tz: %w", err)
	}
	attachTemporal(ctx, cli, fm, window, loc, m)
	// Inference runs after temporal so DB-role evidence can cite activity class.
	m.InferRoles(ev)

	sensors, _ := cli.Sensors(ctx, fm, window, config.SensorTermsSize)
	var sensorNames []string
	for _, s := range sensors {
		sensorNames = append(sensorNames, s.Dataset)
	}

	// §8.4 primary: MAC-convergence gateway evidence, if the grid has it.
	l2gw, err := cli.FetchGatewayCandidates(ctx, fm, window)
	if err != nil {
		fmt.Fprintf(errOut, "%swarning:%s gateway candidate query failed, maps will use the inferred fallback: %v\n", ansiYellow, ansiReset, err)
	}

	snap := m.Snapshot(graph.SnapshotMeta{
		CreatedAt:      time.Now().UTC(),
		Window:         window.String(),
		Scope:          scope,
		ClusterName:    info.ClusterName,
		Sensors:        sensorNames,
		ZeroCovCIDRs:   zeroCoverage(scope, m),
		L2Gateways:     l2gw,
		BetweenSampled: res.BetweennessSampled,
	})
	path, err := snapshot.Save(dataDir, snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Snapshot: %s\n", path)

	htmlPath, err := writeReport(dataDir, snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Report:   %s\n", htmlPath)

	mapPath, err := writeBriefingMap(dataDir, snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Map:      %s\n", mapPath)
	fmt.Fprintf(out, "\nTop terrain:\n")
	for i, n := range snap.Nodes {
		if i >= 5 {
			break
		}
		fmt.Fprintf(out, "  %d. %-16s %-18s composite %.2f\n", n.Scores.Rank, n.IP, topRoleLabel(n), n.Scores.Composite)
	}
	fmt.Fprintf(errOut, "%sHandling reminder: report, map, and snapshot describe network terrain — protect at the network's classification.%s\n", ansiYellow, ansiReset)
	return nil
}

func topRoleLabel(n graph.Node) string {
	if len(n.Roles) == 0 {
		return string(graph.RoleUnknown)
	}
	return string(n.Roles[0].Role)
}

func scopeOrAll(scope []string) any {
	if len(scope) == 0 {
		return "all observed"
	}
	return scope
}

// attachTemporal fetches §9 profiles for the top-N ranked responders and
// attaches each profile to that node's inbound edges. Fetch failures degrade
// to unclassified edges rather than failing the scan.
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

// zeroCoverage flags in-scope CIDRs with no observed nodes at all — the
// possible-blind-spot finding (§10). Only meaningful when a scope was given.
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
	if err := os.MkdirAll(dir, config.OutputDirMode); err != nil {
		return "", err
	}
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ".html"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := report.HTML(f, snap); err != nil {
		return "", err
	}
	return path, nil
}

func writeBriefingMap(dataDir string, snap graph.Snapshot) (string, error) {
	dir := filepath.Join(dataDir, "maps")
	if err := os.MkdirAll(dir, config.OutputDirMode); err != nil {
		return "", err
	}
	name := snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ".html"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
	if err != nil {
		return "", err
	}
	defer f.Close()
	mm := mapview.Build(snap, mapview.Options{})
	if err := report.HTMLMap(f, mm); err != nil {
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
