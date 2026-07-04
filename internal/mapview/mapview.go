// Package mapview derives briefing-map models from snapshots (§8). It
// depends only on the snapshot data model — never on escli — so any map can
// be re-rendered offline from a stored snapshot.
package mapview

import (
	"fmt"
	"math"
	"net/netip"
	"sort"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/reconcile"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

// Tier drives the top-to-bottom briefing layout (§8.3).
type Tier string

const (
	TierCore    Tier = "core"    // gateways, DCs, DNS
	TierService Tier = "service" // file/db/web/jump
	TierClient  Tier = "client"  // everything else
)

// Options tune map derivation; zero values take config defaults.
type Options struct {
	GroupPrefix int               // subnet grouping prefix (default /24)
	MinConns    int64             // §8.5 noise floor for briefing edges
	Focus       string            // optional CIDR: keep only groups intersecting it
	GroupLabels map[string]string // CIDR → human name (§8.2 asset-doc enrichment)
}

func (o Options) withDefaults() Options {
	if o.GroupPrefix == 0 {
		o.GroupPrefix = config.GroupPrefixV4
	}
	if o.MinConns == 0 {
		o.MinConns = config.MapMinConns
	}
	return o
}

// Group is a subnet container box on the map.
type Group struct {
	ID        string   `json:"id"`
	CIDR      string   `json:"cidr"`
	Label     string   `json:"label"`
	Sensors   []string `json:"sensors,omitempty"`
	BlindSpot bool     `json:"blind_spot"` // hatched: in-scope, zero coverage
	Sparse    bool     `json:"sparse"`
}

// MapNode is a visible node: a real host, a synthesized gateway, or an
// aggregated "N workstations" meta-node.
type MapNode struct {
	ID                   string   `json:"id"`
	Group                string   `json:"group"`
	Label                string   `json:"label"`
	Role                 string   `json:"role"`
	Tier                 Tier     `json:"tier"`
	Composite            float64  `json:"composite"`
	Rank                 int      `json:"rank,omitempty"`
	Gateway              bool     `json:"gateway"`
	Inferred             bool     `json:"inferred"` // gateway synthesized without L2 evidence
	AggCount             int      `json:"agg_count,omitempty"`
	Evidence             []string `json:"evidence,omitempty"`
	Drift                string   `json:"drift,omitempty"` // new, vanished, rank-up, rank-down
	SuggestedTags        []string `json:"suggested_tags,omitempty"`
	SuggestionConfidence float64  `json:"suggestion_confidence,omitempty"`
	SuggestionRationale  string   `json:"suggestion_rationale,omitempty"`
	SuggestionModel      string   `json:"suggestion_model,omitempty"`
}

// MapEdge is a (possibly bundled) visible edge.
type MapEdge struct {
	Src   string  `json:"src"`
	Dst   string  `json:"dst"`
	Class string  `json:"class"` // service-class label for coloring
	Color string  `json:"color"`
	Label string  `json:"label"`
	Hosts int     `json:"hosts"` // distinct client hosts bundled
	Conns int64   `json:"conns"`
	Width float64 `json:"width"`
	Drift string  `json:"drift,omitempty"` // new or vanished
}

// Model is everything a renderer needs.
type Model struct {
	Groups   []Group            `json:"groups"`
	Nodes    []MapNode          `json:"nodes"`
	Edges    []MapEdge          `json:"edges"`
	Findings []string           `json:"findings"`
	Meta     graph.SnapshotMeta `json:"meta"`
	Overview bool               `json:"overview,omitempty"` // condensed briefing overview, not a complete topology
}

// Elements returns the visible-element count checked against §8.5 targets.
func (m *Model) Elements() int { return len(m.Groups) + len(m.Nodes) + len(m.Edges) }

// Build derives the briefing-map model from a snapshot.
func Build(snap graph.Snapshot, opts Options) *Model {
	return build(snap, opts, nil, nil)
}

type rawEdgeKey struct {
	src, dst string
	port     uint16
}

// BuildDrift overlays Phase 2 changes on the normal briefing-map pipeline.
func BuildDrift(current graph.Snapshot, d snapshot.Diff, opts Options) *Model {
	nodeDrift := make(map[string]string)
	for _, n := range d.AppearedNodes {
		nodeDrift[n.IP] = "new"
	}
	for _, n := range d.DisappearedNodes {
		nodeDrift[n.IP] = "vanished"
		current.Nodes = append(current.Nodes, n)
	}
	for _, change := range d.RankChanges {
		state := "rank-down"
		if change.Delta > 0 {
			state = "rank-up"
		}
		nodeDrift[change.IP] = state
	}
	edgeDrift := make(map[rawEdgeKey]string)
	for _, e := range d.NewEdgesToTop {
		edgeDrift[rawEdgeKey{e.Src, e.Dst, e.Port}] = "new"
	}
	for _, e := range d.VanishedCriticalEdges {
		edgeDrift[rawEdgeKey{e.Src, e.Dst, e.Port}] = "vanished"
		current.Edges = append(current.Edges, e)
	}
	return build(current, opts, nodeDrift, edgeDrift)
}

// BuildReconcile overlays Phase 3 doc-vs-reality flags: undocumented hosts
// red-outlined, role contradictions badged, documented-but-silent assets
// ghosted into their subnet group. Asset segment names enrich group labels.
// ponytail: reuses the Drift flag channel for reconcile states — one string
// field drives all map highlight classes; split into a second field if the
// two overlay kinds ever need to coexist on one map.
func BuildReconcile(current graph.Snapshot, r reconcile.Result, assets []reconcile.Asset, opts Options) *Model {
	opts = opts.withDefaults()
	flags := make(map[string]string)
	for _, n := range r.ObservedUndocumented {
		flags[n.IP] = "undocumented"
	}
	for _, c := range r.RoleContradicted {
		flags[c.IP] = "contradicted"
	}
	if opts.GroupLabels == nil {
		opts.GroupLabels = map[string]string{}
	}
	for _, a := range assets {
		cidr := subnetOf(a.IP, opts.GroupPrefix)
		if a.Segment != "" && cidr != "" && opts.GroupLabels[cidr] == "" {
			opts.GroupLabels[cidr] = a.Segment
		}
	}

	m := build(current, opts, flags, nil)

	if m.Overview {
		// Overview groups are coarser than the /24s ghosts key on, and
		// per-asset ghosts would blow the element budget anyway — the
		// findings below carry the counts; --focus recovers ghost detail.
		appendReconcileFindings(m, r, 0)
		return m
	}

	groupSet := make(map[string]bool, len(m.Groups))
	for _, g := range m.Groups {
		groupSet[g.ID] = true
	}
	ghosted := 0
	for _, s := range r.DocumentedSilent {
		gid := groupID(subnetOf(s.IP, opts.GroupPrefix))
		if !groupSet[gid] {
			continue // no observed subnet to place it in; the findings list covers it
		}
		label := s.IP
		if s.Hostname != "" {
			label = s.Hostname + "\n" + s.IP
		}
		note := "documented but silent in the observation window"
		if s.InBlindSpot {
			note += " — inside a possible sensor blind spot; verify coverage before calling it decommissioned"
		}
		m.Nodes = append(m.Nodes, MapNode{
			ID: "asset:" + s.IP, Group: gid, Label: label,
			Role: "Documented", Tier: TierClient, Drift: "silent",
			Evidence: []string{note},
		})
		ghosted++
	}
	if ghosted > 0 {
		sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].ID < m.Nodes[j].ID })
	}

	appendReconcileFindings(m, r, ghosted)
	return m
}

func appendReconcileFindings(m *Model, r reconcile.Result, ghosted int) {
	if n := len(r.DocumentedSilent); n > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d documented assets produced no observed traffic (%d shown ghosted; cross-check blind spots before calling them decommissioned)", n, ghosted))
	}
	if n := len(r.ObservedUndocumented); n > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d observed hosts are not in the asset list", n))
	}
	if n := len(r.RoleContradicted); n > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d hosts contradict their documented role", n))
	}
}

// subnetOf derives the grouping CIDR for a bare IP (IPv4 only, like regroup).
func subnetOf(ip string, prefix int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is6() {
		return ""
	}
	p, err := a.Prefix(prefix)
	if err != nil {
		return ""
	}
	return p.String()
}

func build(snap graph.Snapshot, opts Options, nodeDrift map[string]string, edgeDrift map[rawEdgeKey]string) *Model {
	opts = opts.withDefaults()
	m := &Model{Meta: snap.Meta}

	nodes := filterFocus(snap.Nodes, opts.Focus)
	groups, resolve := groupNodes(nodes, opts.GroupPrefix)
	for i := range groups {
		if lbl := opts.GroupLabels[groups[i].CIDR]; lbl != "" && groups[i].CIDR != "" {
			groups[i].Label = groups[i].CIDR + " — " + lbl
		}
	}
	byIP := make(map[string]*graph.Node, len(nodes))
	for i := range nodes {
		byIP[nodes[i].IP] = &nodes[i]
	}

	// Tier + client aggregation (§8.3, §8.5.1).
	aggCount := map[string]int{} // group id -> collapsed client count
	visible := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		t := tierOf(n)
		drift := nodeDrift[n.IP]
		if drift == "" && t == TierClient && n.TopRole() == graph.RoleUnknown && n.Scores.Composite < config.ClientAggMaxComposite {
			aggCount[resolve(n.Subnet)]++
			continue
		}
		visible[n.IP] = true
		m.Nodes = append(m.Nodes, MapNode{
			ID: n.IP, Group: resolve(n.Subnet), Label: nodeLabel(n),
			Role: string(n.TopRole()), Tier: t,
			Composite: n.Scores.Composite, Rank: n.Scores.Rank,
			Evidence: evidence(n), Drift: drift,
		})
	}
	for gid, count := range aggCount {
		id := gid + ":clients"
		m.Nodes = append(m.Nodes, MapNode{
			ID: id, Group: gid, Label: fmt.Sprintf("%d workstations", count),
			Role: string(graph.RoleUnknown), Tier: TierClient, AggCount: count,
		})
	}

	// Gateways (§8.4): observed (L2 MAC convergence) or inferred fallback.
	m.addGateways(snap, groups, byIP, resolve)

	// Edge bundling + noise floor (§8.5.2/4). Edges from/to aggregated
	// clients reroute to the meta-node; endpoints outside focus drop.
	m.bundleEdges(filterFocusEdges(snap.Edges, byIP), visible, byIP, resolve, opts.MinConns, edgeDrift)

	m.Groups = groups
	m.findings(snap, opts)
	sortModel(m)

	// §8.5: an unfocused map beyond the hard cap is unreadable — rebuild it
	// as a condensed briefing overview. CIDR --focus keeps full detail;
	// keyword focus (private/public) is a scope filter and still condenses.
	if (opts.Focus == "" || FocusKeyword(opts.Focus)) && m.Elements() > config.MapMaxElements {
		return buildOverview(snap, opts, nodeDrift, edgeDrift, m.Elements())
	}
	return m
}

func sortModel(m *Model) {
	sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].ID < m.Nodes[j].ID })
	sort.Slice(m.Edges, func(i, j int) bool {
		a, b := m.Edges[i], m.Edges[j]
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		if a.Dst != b.Dst {
			return a.Dst < b.Dst
		}
		return a.Class < b.Class
	})
}

func groupID(cidr string) string { return "g:" + cidr }

func nodeLabel(n *graph.Node) string {
	if len(n.Hostnames) > 0 {
		return n.Hostnames[0] + "\n" + n.IP
	}
	return n.IP
}

func evidence(n *graph.Node) []string {
	var out []string
	for _, r := range n.Roles {
		out = append(out, r.Evidence...)
	}
	return out
}

func tierOf(n *graph.Node) Tier {
	switch n.TopRole() {
	case graph.RoleDC, graph.RoleDNS:
		return TierCore
	case graph.RoleFileServer, graph.RoleDatabase, graph.RoleWebServer, graph.RoleJumpBox:
		return TierService
	}
	// Score tiebreak: high-composite unknowns still deserve the service band.
	if n.Scores.Composite >= 2*config.ClientAggMaxComposite {
		return TierService
	}
	return TierClient
}

// groupNodes builds subnet groups from observed nodes; groups smaller than
// SparseGroupMinHosts merge into one "sparse hosts" group (§8.2). The
// returned resolver maps any node's stored Subnet to its final group ID —
// the single place regrouping and sparse-collapse are decided.
func groupNodes(nodes []graph.Node, prefix int) ([]Group, func(subnet string) string) {
	counts := map[string][]string{}
	sensors := map[string]map[string]bool{}
	for _, n := range nodes {
		cidr := regroup(n.Subnet, prefix)
		counts[cidr] = append(counts[cidr], n.IP)
		if sensors[cidr] == nil {
			sensors[cidr] = map[string]bool{}
		}
		for _, s := range n.Sensors {
			sensors[cidr][s] = true
		}
	}
	var groups []Group
	sparseCIDRs := map[string]bool{}
	sparse := 0
	for cidr, ips := range counts {
		if len(ips) < config.SparseGroupMinHosts {
			sparse += len(ips)
			sparseCIDRs[cidr] = true
			continue
		}
		groups = append(groups, Group{
			ID: groupID(cidr), CIDR: cidr, Label: cidr, Sensors: setToSlice(sensors[cidr]),
		})
	}
	if sparse > 0 {
		groups = append(groups, Group{ID: "g:sparse", CIDR: "", Label: fmt.Sprintf("sparse hosts (%d)", sparse), Sparse: true})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	resolve := func(subnet string) string {
		cidr := regroup(subnet, prefix)
		if sparseCIDRs[cidr] {
			return "g:sparse"
		}
		return groupID(cidr)
	}
	return groups, resolve
}

// regroup re-derives the grouping CIDR at the requested prefix. Node.Subnet
// is stored at /24; a coarser --group-prefix widens it.
func regroup(subnet string, prefix int) string {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || p.Addr().Is6() || prefix == p.Bits() {
		return subnet
	}
	wide, err := p.Addr().Prefix(prefix)
	if err != nil {
		return subnet
	}
	return wide.String()
}

// addGateways synthesizes gateway nodes (§8.4). With L2 evidence: one
// observed gateway per (MAC, sensor). Without: one inferred gateway per group
// that has cross-group edges, dashed on every renderer — never presented as
// observed fact.
func (m *Model) addGateways(snap graph.Snapshot, groups []Group, byIP map[string]*graph.Node, resolve func(string) string) {
	if len(snap.Meta.L2Gateways) > 0 {
		for _, gw := range snap.Meta.L2Gateways {
			m.Nodes = append(m.Nodes, MapNode{
				ID:    "gw:" + gw.MAC,
				Label: fmt.Sprintf("gateway %s", gw.MAC),
				Role:  "Gateway", Tier: TierCore, Gateway: true,
				Evidence: []string{fmt.Sprintf("MAC answered for %d distinct IPs (sensor %s) — observed L2 convergence", gw.IPCount, gw.Sensor)},
			})
		}
		return
	}
	crossGroup := map[string]bool{}
	for _, e := range snap.Edges {
		s, sOK := byIP[e.Src]
		d, dOK := byIP[e.Dst]
		if !sOK || !dOK {
			continue
		}
		gs, gd := resolve(s.Subnet), resolve(d.Subnet)
		if gs != gd {
			crossGroup[gs], crossGroup[gd] = true, true
		}
	}
	for _, g := range groups {
		if crossGroup[g.ID] && !g.Sparse {
			m.Nodes = append(m.Nodes, MapNode{
				ID: g.ID + ":gw", Group: g.ID, Label: "gateway (inferred)",
				Role: "Gateway", Tier: TierCore, Gateway: true, Inferred: true,
				Evidence: []string{"synthesized from cross-subnet traffic — no L2 evidence on this grid"},
			})
		}
	}
}

// bundleEdges merges edges by (visible-src, visible-dst, service class),
// where an invisible endpoint resolves to its group's client meta-node.
// Bundles whose total conns fall below minConns are dropped (noise floor).
func (m *Model) bundleEdges(edges []graph.Edge, visible map[string]bool, byIP map[string]*graph.Node, resolve func(string) string, minConns int64, edgeDrift map[rawEdgeKey]string) {
	type key struct{ src, dst, class string }
	type acc struct {
		hosts map[string]bool
		conns int64
		cls   config.ServiceClass
		drift string
	}
	bundles := map[key]*acc{}
	endpoint := func(ip string) string {
		if visible[ip] {
			return ip
		}
		if n, ok := byIP[ip]; ok {
			return resolve(n.Subnet) + ":clients"
		}
		return ""
	}
	for _, e := range edges {
		src, dst := endpoint(e.Src), endpoint(e.Dst)
		if src == "" || dst == "" || src == dst {
			continue
		}
		cls := config.ClassForPort(e.Port)
		k := key{src, dst, config.ClassLabel(cls)}
		b, ok := bundles[k]
		if !ok {
			b = &acc{hosts: map[string]bool{}, cls: cls}
			bundles[k] = b
		}
		b.hosts[e.Src] = true
		b.conns += e.ConnCount
		if drift := edgeDrift[rawEdgeKey{e.Src, e.Dst, e.Port}]; drift != "" {
			if b.drift != "" && b.drift != drift {
				b.drift = "changed"
			} else {
				b.drift = drift
			}
		}
	}
	for k, b := range bundles {
		if b.conns < minConns && b.drift == "" {
			continue
		}
		label := k.class
		if len(b.hosts) > 1 {
			label = fmt.Sprintf("%d hosts → %s", len(b.hosts), k.class)
		}
		m.Edges = append(m.Edges, MapEdge{
			Src: k.src, Dst: k.dst, Class: k.class,
			Color: config.MapPalette[b.cls], Label: label,
			Hosts: len(b.hosts), Conns: b.conns,
			Width: 1 + math.Log1p(float64(len(b.hosts))), Drift: b.drift,
		})
	}
}

// findings adds blind-spot groups and readability warnings. Blind spots
// outside a --focus CIDR are omitted — a per-enclave map should only show
// coverage gaps within the enclave it's scoped to.
func (m *Model) findings(snap graph.Snapshot, opts Options) {
	var focus netip.Prefix
	hasFocus := false
	if opts.Focus != "" {
		if p, err := netip.ParsePrefix(opts.Focus); err == nil {
			focus, hasFocus = p, true
		}
	}
	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		if hasFocus && !cidrsOverlap(focus, cidr) {
			continue
		}
		m.Groups = append(m.Groups, Group{
			ID: groupID(cidr), CIDR: cidr,
			Label: cidr + " (no sensor coverage)", BlindSpot: true,
		})
		m.Findings = append(m.Findings, fmt.Sprintf("possible blind spot: %s is in scope but produced zero observed traffic", cidr))
	}
	if n := m.Elements(); n > config.MapMaxElements {
		m.Findings = append(m.Findings, fmt.Sprintf("map has %d elements (target ≤%d) — consider per-enclave maps via --focus CIDR", n, config.MapTargetElements))
	}
}

// cidrsOverlap reports whether two CIDRs intersect.
func cidrsOverlap(a netip.Prefix, bStr string) bool {
	b, err := netip.ParsePrefix(bStr)
	if err != nil {
		return false
	}
	return a.Overlaps(b)
}

// FocusKeyword reports whether a --focus value is an address-space keyword
// rather than a CIDR. Keyword-focused maps are scope filters, so they still
// condense to an overview when oversized; CIDR focus always keeps detail.
func FocusKeyword(focus string) bool {
	switch focus {
	case "private", "internal", "public", "external":
		return true
	}
	return false
}

func filterFocus(nodes []graph.Node, focus string) []graph.Node {
	if focus == "" {
		return nodes
	}
	keep := func(a netip.Addr) bool { return true }
	switch focus {
	case "private", "internal":
		keep = func(a netip.Addr) bool { return a.IsPrivate() }
	case "public", "external":
		keep = func(a netip.Addr) bool { return !a.IsPrivate() }
	default:
		p, err := netip.ParsePrefix(focus)
		if err != nil {
			return nodes
		}
		keep = p.Contains
	}
	var out []graph.Node
	for _, n := range nodes {
		if a, err := netip.ParseAddr(n.IP); err == nil && keep(a) {
			out = append(out, n)
		}
	}
	return out
}

func filterFocusEdges(edges []graph.Edge, byIP map[string]*graph.Node) []graph.Edge {
	var out []graph.Edge
	for _, e := range edges {
		if _, s := byIP[e.Src]; s {
			if _, d := byIP[e.Dst]; d {
				out = append(out, e)
			}
		}
	}
	return out
}

func setToSlice(set map[string]bool) []string {
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
