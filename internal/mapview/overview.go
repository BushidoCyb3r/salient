package mapview

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/graph"
)

// overviewPrefixes are tried finest-first; the overview picks the first one
// whose group count fits MapOverviewMaxGroups. Coarsening stops at /16: a /12
// or /8 group is labeled with its supernet network address (e.g. 10.16.0.0/12
// holding 10.18.x hosts), which names no segment an operator actually runs and
// reads as a phantom network. Past /16 the overflow "other internal networks"
// bucket absorbs the excess instead of inventing a misleading boundary.
var overviewPrefixes = []int{24, 20, 16}

// overviewPrefix returns the finest grouping prefix, no finer than start,
// that yields at most max groups. If even /16 exceeds the cap the caller
// merges overflow groups into one "other networks" group.
func overviewPrefix(nodes []graph.Node, start, max int) int {
	for _, p := range overviewPrefixes {
		if p > start {
			continue
		}
		distinct := map[string]bool{}
		for _, n := range nodes {
			distinct[regroup(n.Subnet, p)] = true
		}
		if len(distinct) <= max {
			return p
		}
	}
	return overviewPrefixes[len(overviewPrefixes)-1]
}

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
	omittedMarked := 0
	for _, i := range idx {
		n := &nodes[i]
		if !graph.TerrainAddr(n.IP) || len(retained) >= config.MapOverviewTopNodes {
			if nodeDrift[n.IP] != "" {
				omittedMarked++
			}
			continue
		}
		retained[n.IP] = true
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
	prefix := overviewPrefix(internal, opts.GroupPrefix, maxPriv)
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

	for _, i := range idx {
		n := &nodes[i]
		if !retained[n.IP] {
			continue
		}
		m.Nodes = append(m.Nodes, MapNode{
			ID: n.IP, Group: resolve(n.Subnet), Label: nodeLabel(n),
			Role: string(n.TopRole()), Tier: tierOf(n),
			Composite: n.Scores.Composite, Rank: n.Scores.Rank,
			Evidence: evidence(n), Drift: nodeDrift[n.IP],
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

	m.addOverviewGateways(snap, byIP, resolve)

	visible := retained
	m.bundleEdges(filterFocusEdges(snap.Edges, byIP), visible, byIP, resolve, opts.MinConns, edgeDrift)
	edgeBudget := config.MapTargetElements - len(m.Groups) - len(m.Nodes)
	m.Edges = trimOverviewEdges(m.Edges, edgeBudget, retained)

	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		// Text only in overview mode — hatched group boxes would spend the
		// element budget; a focused map still draws them.
		m.Findings = append(m.Findings, fmt.Sprintf("possible blind spot: %s is in scope but produced zero observed traffic", cidr))
	}
	if omittedMarked > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d flagged hosts did not fit the overview and appear only in the report or a focused map", omittedMarked))
	}
	if n := m.Elements(); n > config.MapTargetElements {
		m.Findings = append(m.Findings, fmt.Sprintf("overview exceeds the %d-element target (%d) because flagged changes are never dropped", config.MapTargetElements, n))
	}
	m.Findings = append(m.Findings, fmt.Sprintf("condensed overview: %d elements reduced to %d — only top-ranked terrain and the strongest dependencies are shown individually; use --focus CIDR for full detail", detailedElements, m.Elements()))

	sortModel(m)
	return m
}

// addOverviewGateways caps gateways at one per overview group. Observed L2
// candidates win by descending IP count, then MAC and sensor.
func (m *Model) addOverviewGateways(snap graph.Snapshot, byIP map[string]*graph.Node, resolve func(string) string) {
	if len(snap.Meta.L2Gateways) > 0 {
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
		return
	}
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
		// Only real internal CIDR groups get an inferred gateway — a dashed
		// gateway inside the "external" or "other" box would be noise.
		if crossGroup[g.ID] && g.CIDR != "" {
			m.Nodes = append(m.Nodes, MapNode{
				ID: g.ID + ":gw", Group: g.ID, Label: "gateway (inferred)",
				Role: "Gateway", Tier: TierCore, Gateway: true, Inferred: true,
				Evidence: []string{"synthesized from cross-subnet traffic — no L2 evidence on this grid"},
			})
		}
	}
}

// trimOverviewEdges keeps every drift/overlay-flagged edge (a drift map
// exists to show them) plus the strongest budget-many others: edges touching
// retained terrain first, then by connection count and stable keys.
func trimOverviewEdges(edges []MapEdge, budget int, retained map[string]bool) []MapEdge {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if af, bf := a.Drift != "", b.Drift != ""; af != bf {
			return af
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
