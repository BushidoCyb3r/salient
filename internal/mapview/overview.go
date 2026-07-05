package mapview

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

// internalCIDR reports whether a grouping CIDR is private address space —
// the terrain the briefing is about. Everything else (internet peers,
// multicast, broadcast) collapses into the single external group.
func internalCIDR(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Addr().IsPrivate()
}

// buildOverview rebuilds an oversized unfocused map as a condensed briefing
// overview (§8.5): coarse groups, the top-ranked terrain kept individually,
// everything else aggregated, and only the strongest bundled edges that fit
// the element budget. The snapshot stays complete — --focus recovers detail.
func buildOverview(snap graph.Snapshot, opts Options, nodeDrift map[string]string, edgeDrift map[rawEdgeKey]string, detailedElements int) *Model {
	m := &Model{Meta: snap.Meta, Overview: true}
	nodes := filterFocus(snap.Nodes, opts.Focus)

	// Retention first, so group selection can prioritize the CIDRs the
	// terrain actually lives in: overlay-marked nodes ahead of everything,
	// then valid positive rank, IP as the tie-breaker. Multicast/broadcast
	// artifacts are never retainable no matter their rank.
	byIP := make(map[string]*graph.Node, len(nodes))
	idx := make([]int, 0, len(nodes))
	for i := range nodes {
		byIP[nodes[i].IP] = &nodes[i]
		idx = append(idx, i)
	}
	rankLess := func(a, b *graph.Node) bool {
		ar, br := a.Scores.Rank, b.Scores.Rank
		if (ar > 0) != (br > 0) {
			return ar > 0
		}
		if ar != br && ar > 0 {
			return ar < br
		}
		return a.IP < b.IP
	}
	sort.Slice(idx, func(i, j int) bool {
		a, b := &nodes[idx[i]], &nodes[idx[j]]
		am, bm := nodeDrift[a.IP] != "", nodeDrift[b.IP] != ""
		if am != bm {
			return am
		}
		return rankLess(a, b)
	})
	retained := map[string]bool{}
	// Operator-pinned hosts are retained additively — always their own node,
	// on top of the rank-based top-N (their explicit choice can push the map
	// past the element target).
	for i := range nodes {
		if opts.Pinned[nodes[i].IP] && graph.TerrainAddr(nodes[i].IP) {
			retained[nodes[i].IP] = true
		}
	}
	// "Show all private": promote every RFC1918 terrain host to its own node,
	// rank-ordered, up to the cap so a huge internal grid can't produce an
	// unrenderable hairball.
	privateTotal, privatePromoted := 0, 0
	if opts.RetainAllPrivate {
		for _, i := range idx {
			n := &nodes[i]
			if !graph.TerrainAddr(n.IP) || !internalCIDR(n.Subnet) {
				continue
			}
			privateTotal++
			if retained[n.IP] {
				continue
			}
			if privatePromoted >= config.MapAllPrivateCap {
				continue
			}
			retained[n.IP] = true
			privatePromoted++
		}
	}
	omittedMarked := 0
	topN := 0
	for _, i := range idx {
		n := &nodes[i]
		if retained[n.IP] {
			continue // already pinned or promoted
		}
		// With show-all-private on, external hosts always stay in the external
		// aggregate — never individually promoted by rank.
		if opts.RetainAllPrivate && !internalCIDR(n.Subnet) {
			continue
		}
		if !graph.TerrainAddr(n.IP) || topN >= config.MapOverviewTopNodes {
			if nodeDrift[n.IP] != "" {
				omittedMarked++
			}
			continue
		}
		retained[n.IP] = true
		topN++
	}

	// Internal (private) address space gets the real groups; every public,
	// multicast, or broadcast peer collapses into one external box so the
	// briefing shows the operator's terrain, not the internet's.
	var internal []graph.Node
	external := false
	for _, n := range nodes {
		if internalCIDR(n.Subnet) {
			internal = append(internal, n)
		} else {
			external = true
		}
	}
	maxPriv := config.MapOverviewMaxGroups
	if external {
		maxPriv--
	}
	// Show-all-private is a full-detail view: every RFC1918 VLAN keeps its own
	// box, no "other internal networks" overflow that would lump a real segment
	// (e.g. a lightly-populated 10.10.60.0/24) in with unrelated networks.
	if opts.RetainAllPrivate {
		maxPriv = 1 << 30
	}
	// Groups always keep the operator's true grouping prefix (/24 default).
	// Coarsening to /20 or /16 blended distinct VLANs into supernet boxes
	// that name no segment anyone actually runs (10.18.61.0/26 hosts read as
	// "10.18.0.0/16"); when the cap overflows, the honest "other internal
	// networks" bucket absorbs the least important groups instead.
	prefix := opts.GroupPrefix
	counts := map[string]int{}
	retainedIn := map[string]int{}
	for _, n := range internal {
		c := regroup(n.Subnet, prefix)
		counts[c]++
		if retained[n.IP] {
			retainedIn[c]++
		}
	}
	cidrs := make([]string, 0, len(counts))
	for c := range counts {
		cidrs = append(cidrs, c)
	}
	sort.Slice(cidrs, func(i, j int) bool {
		if retainedIn[cidrs[i]] != retainedIn[cidrs[j]] {
			return retainedIn[cidrs[i]] > retainedIn[cidrs[j]]
		}
		if counts[cidrs[i]] != counts[cidrs[j]] {
			return counts[cidrs[i]] > counts[cidrs[j]]
		}
		return cidrs[i] < cidrs[j]
	})
	overflow := len(cidrs) > maxPriv
	if overflow {
		cidrs = cidrs[:maxPriv-1]
	}
	kept := make(map[string]bool, len(cidrs))
	for _, c := range cidrs {
		label := c
		if lbl := opts.GroupLabels[c]; lbl != "" {
			label = c + " — " + lbl
		}
		kept[c] = true
		m.Groups = append(m.Groups, Group{ID: groupID(c), CIDR: c, Label: label})
	}
	if overflow {
		m.Groups = append(m.Groups, Group{ID: "g:other", Label: "other internal networks"})
	}
	if external {
		m.Groups = append(m.Groups, Group{ID: "g:external", Label: "external (internet / non-private)"})
	}
	sort.Slice(m.Groups, func(i, j int) bool { return m.Groups[i].ID < m.Groups[j].ID })
	resolve := func(subnet string) string {
		c := regroup(subnet, prefix)
		if internalCIDR(c) {
			if kept[c] {
				return groupID(c)
			}
			return "g:other"
		}
		return "g:external"
	}

	groupHasRetained := map[string]bool{}
	for _, i := range idx {
		n := &nodes[i]
		if !retained[n.IP] {
			continue
		}
		gid := resolve(n.Subnet)
		groupHasRetained[gid] = true
		m.Nodes = append(m.Nodes, MapNode{
			ID: n.IP, Group: gid, Label: nodeLabel(n),
			Role: string(n.TopRole()), Tier: tierOf(n),
			Composite: n.Scores.Composite, Rank: n.Scores.Rank,
			Evidence: evidence(n), Drift: nodeDrift[n.IP],
			MAC: n.MAC, Vendor: config.VendorForMAC(n.MAC),
		})
	}

	// Everything not retained collapses into one aggregate per group. The
	// ":clients" ID suffix is what bundleEdges routes invisible endpoints
	// to, so aggregates reuse it even though the label says "other hosts".
	aggCount := map[string]int{}
	for i := range nodes {
		n := &nodes[i]
		if !retained[n.IP] {
			gid := resolve(n.Subnet)
			aggCount[gid]++
			m.addAggMember(gid+":clients", n)
		}
	}
	aggGroups := make([]string, 0, len(aggCount))
	for gid := range aggCount {
		aggGroups = append(aggGroups, gid)
	}
	sort.Strings(aggGroups)
	for _, gid := range aggGroups {
		m.Nodes = append(m.Nodes, MapNode{
			ID: gid + ":clients", Group: gid,
			Label: fmt.Sprintf("%d other hosts", aggCount[gid]),
			Role:  string(graph.RoleUnknown), Tier: TierClient, AggCount: aggCount[gid],
		})
	}

	// Observed L2 gateways are real evidence — add them before budgeting
	// edges. Inferred gateways are guesses and come last, in leftover space.
	hasObserved := m.addObservedGateways(snap)

	visible := retained
	m.bundleEdges(filterFocusEdges(snap.Edges, byIP), visible, byIP, resolve, opts.MinConns, edgeDrift)

	// Edges are the dependency story — budget them before inferred gateways,
	// and protect cross-group (inter-VLAN) bundles inside the trim so routed
	// dependencies never lose their slot to intra-group filler.
	groupOf := map[string]string{}
	for _, n := range m.Nodes {
		groupOf[n.ID] = n.Group
	}
	edgeBudget := config.MapTargetElements - len(m.Groups) - len(m.Nodes)
	if opts.RetainAllPrivate {
		// Show-all-private is an explicit "show everything" mode: every
		// connection between the now-visible hosts stays, no budget trim.
		edgeBudget = len(m.Edges)
	}
	m.Edges = trimOverviewEdges(m.Edges, edgeBudget, retained, groupOf)

	// Inferred gateways only when the grid has no observed L2 evidence, only
	// for VLANs whose structure isn't already shown by a retained node, and
	// only in whatever element budget remains: a dashed "probably a router"
	// guess must never displace a real dependency edge or clutter a VLAN that
	// already shows its own hosts.
	if !hasObserved {
		m.addInferredGateways(snap, byIP, resolve, groupHasRetained)
	}

	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		// Text only in overview mode — hatched group boxes would spend the
		// element budget; a focused map still draws them.
		m.Findings = append(m.Findings, fmt.Sprintf("possible blind spot: %s is in scope but produced zero observed traffic", cidr))
	}
	if omittedMarked > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d flagged hosts did not fit the overview and appear only in the report or a focused map", omittedMarked))
	}
	if opts.RetainAllPrivate && privateTotal > config.MapAllPrivateCap {
		m.Findings = append(m.Findings, fmt.Sprintf("show-all-private: %d RFC1918 hosts exceed the %d cap — showing the %d highest-ranked, the rest re-aggregated (map would be too dense otherwise)", privateTotal, config.MapAllPrivateCap, privatePromoted))
	}
	if n := m.Elements(); n > config.MapTargetElements {
		m.Findings = append(m.Findings, fmt.Sprintf("overview exceeds the %d-element target (%d) because flagged changes are never dropped", config.MapTargetElements, n))
	}
	m.Findings = append(m.Findings, fmt.Sprintf("condensed overview: %d elements reduced to %d — only top-ranked terrain and the strongest dependencies are shown individually; use --focus CIDR for full detail", detailedElements, m.Elements()))

	sortModel(m)
	return m
}

// addObservedGateways adds gateways backed by L2 MAC convergence, capped at
// one per overview group, best (highest IP count) first. Returns whether any
// observed evidence existed — the caller skips inferred gateways when it did.
func (m *Model) addObservedGateways(snap graph.Snapshot) bool {
	if len(snap.Meta.L2Gateways) == 0 {
		return false
	}
	gws := append([]graph.L2Gateway(nil), snap.Meta.L2Gateways...)
	sort.Slice(gws, func(i, j int) bool {
		if gws[i].IPCount != gws[j].IPCount {
			return gws[i].IPCount > gws[j].IPCount
		}
		if gws[i].MAC != gws[j].MAC {
			return gws[i].MAC < gws[j].MAC
		}
		return gws[i].Sensor < gws[j].Sensor
	})
	if len(gws) > len(m.Groups) {
		gws = gws[:len(m.Groups)]
	}
	for _, gw := range gws {
		m.Nodes = append(m.Nodes, MapNode{
			ID:    "gw:" + gw.MAC,
			Label: fmt.Sprintf("gateway %s", gw.MAC),
			Role:  "Gateway", Tier: TierCore, Gateway: true,
			Evidence: []string{fmt.Sprintf("MAC answered for %d distinct IPs (sensor %s) — observed L2 convergence", gw.IPCount, gw.Sensor)},
		})
	}
	return true
}

// addInferredGateways synthesizes at most one dashed gateway per routed VLAN
// that has no observed L2 evidence — but only for groups whose own hosts are
// all aggregated (a group already showing a retained node needs no phantom)
// and only while element budget remains. Groups are taken in ID order for
// determinism, strongest-terrain groups first would need a rank the
// aggregate doesn't carry, so ID order is the stable, explainable choice.
func (m *Model) addInferredGateways(snap graph.Snapshot, byIP map[string]*graph.Node, resolve func(string) string, groupHasRetained map[string]bool) {
	crossGroup := map[string]bool{}
	for _, e := range snap.Edges {
		s, sOK := byIP[e.Src]
		d, dOK := byIP[e.Dst]
		if !sOK || !dOK {
			continue
		}
		if gs, gd := resolve(s.Subnet), resolve(d.Subnet); gs != gd {
			crossGroup[gs], crossGroup[gd] = true, true
		}
	}
	for _, g := range m.Groups {
		if m.Elements() >= config.MapTargetElements {
			return
		}
		// Only real internal CIDR groups that route, aren't already shown by
		// a retained host, and fit the budget get a dashed inferred gateway.
		if crossGroup[g.ID] && g.CIDR != "" && !groupHasRetained[g.ID] {
			m.Nodes = append(m.Nodes, MapNode{
				ID: g.ID + ":gw", Group: g.ID, Label: "gateway (inferred)",
				Role: "Gateway", Tier: TierCore, Gateway: true, Inferred: true,
				Evidence: []string{"synthesized from cross-subnet traffic — no L2 evidence on this grid"},
			})
		}
	}
}

// trimOverviewEdges keeps every drift/overlay-flagged edge (a drift map
// exists to show them) plus the strongest budget-many others. Priority after
// drift: cross-group (inter-VLAN) bundles — the routed-dependency story an
// operator opens the map for — then edges touching retained terrain, then
// connection count and stable keys. groupOf maps an edge endpoint id (a
// retained IP or a "…:clients" aggregate) to its group; endpoints absent from
// it (or in the same group) are not cross-group.
func trimOverviewEdges(edges []MapEdge, budget int, retained map[string]bool, groupOf map[string]string) []MapEdge {
	crosses := func(e MapEdge) bool {
		gs, gd := groupOf[e.Src], groupOf[e.Dst]
		return gs != "" && gd != "" && gs != gd
	}
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if af, bf := a.Drift != "", b.Drift != ""; af != bf {
			return af
		}
		if ac, bc := crosses(a), crosses(b); ac != bc {
			return ac
		}
		at := retained[a.Src] || retained[a.Dst]
		bt := retained[b.Src] || retained[b.Dst]
		if at != bt {
			return at
		}
		if a.Conns != b.Conns {
			return a.Conns > b.Conns
		}
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		if a.Dst != b.Dst {
			return a.Dst < b.Dst
		}
		return a.Class < b.Class
	})
	var out []MapEdge
	kept := 0
	for _, e := range edges {
		switch {
		case e.Drift != "":
			out = append(out, e)
		case kept < budget:
			out = append(out, e)
			kept++
		}
	}
	return out
}
