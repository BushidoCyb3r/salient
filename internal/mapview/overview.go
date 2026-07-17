package mapview

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
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
		am := nodeDrift[a.IP] != "" || opts.DeclaredDevices[a.IP].Name != ""
		bm := nodeDrift[b.IP] != "" || opts.DeclaredDevices[b.IP].Name != ""
		if am != bm {
			return am
		}
		return rankLess(a, b)
	})
	// Segment-flow map: every real internal VLAN keeps its own box, ordered by
	// host count. Only a pathological number of VLANs (> MapSegmentMaxGroups)
	// overflows into "other internal networks"; every public/multicast/broadcast
	// peer collapses into one external box so the briefing shows the operator's
	// terrain, not the internet's. Groups keep the operator's true grouping
	// prefix (/24 default) — never coarsened into supernet boxes.
	prefix := opts.GroupPrefix
	segFor, segNames := segmentGrouper(opts.Segments)
	// groupCIDR resolves a host to its grouping CIDR: an operator-declared
	// segment if one contains it, else the auto /prefix.
	groupCIDR := func(ip, subnet string) string {
		if c, ok := segFor(ip); ok {
			return c
		}
		return regroup(subnet, prefix)
	}
	external := false
	segHosts := map[string][]int{} // internal grouping CIDR -> node indices, rank-ordered (idx is rank-sorted)
	for _, i := range idx {
		n := &nodes[i]
		c := groupCIDR(n.IP, n.Subnet)
		if internalCIDR(c) {
			segHosts[c] = append(segHosts[c], i)
		} else {
			external = true
		}
	}
	// A segment containing a drift/overlay-flagged host is always kept — a drift
	// or reconcile map exists to show those segments — so they sort ahead of the
	// overflow cut, then by host count, then CIDR.
	segMarked := map[string]bool{}
	for _, ns := range segHosts {
		for _, i := range ns {
			if nodeDrift[nodes[i].IP] != "" || opts.DeclaredDevices[nodes[i].IP].Name != "" {
				segMarked[groupCIDR(nodes[i].IP, nodes[i].Subnet)] = true
				break
			}
		}
	}
	segCIDRs := make([]string, 0, len(segHosts))
	for c := range segHosts {
		segCIDRs = append(segCIDRs, c)
	}
	sort.Slice(segCIDRs, func(i, j int) bool {
		if segMarked[segCIDRs[i]] != segMarked[segCIDRs[j]] {
			return segMarked[segCIDRs[i]]
		}
		if len(segHosts[segCIDRs[i]]) != len(segHosts[segCIDRs[j]]) {
			return len(segHosts[segCIDRs[i]]) > len(segHosts[segCIDRs[j]])
		}
		return segCIDRs[i] < segCIDRs[j]
	})
	overflow := len(segCIDRs) > config.MapSegmentMaxGroups
	if overflow {
		segCIDRs = segCIDRs[:config.MapSegmentMaxGroups-1]
	}
	kept := make(map[string]bool, len(segCIDRs))
	for _, c := range segCIDRs {
		kept[c] = true
	}
	resolve := func(ip string) string {
		c := groupCIDR(ip, graph.Subnet(ip))
		if internalCIDR(c) {
			if kept[c] {
				return groupID(c)
			}
			return "g:other"
		}
		return "g:external"
	}

	// Retention: the top MapSegmentTopHosts hosts of every kept segment stay
	// individual, so each VLAN shows its own terrain — a busy segment can no
	// longer monopolize a global top-N and starve the quiet ones. segHosts is
	// in drift-first-then-rank order, so drift/overlay-flagged hosts fill a
	// segment's slots ahead of ordinary hosts. Operator pins are retained
	// additively. RetainAllPrivate (escape hatch) promotes every internal host,
	// capped so a huge grid can't hairball.
	retained := map[string]bool{}
	for i := range nodes {
		if (opts.Pinned[nodes[i].IP] || opts.DeclaredDevices[nodes[i].IP].Name != "") && graph.TerrainAddr(nodes[i].IP) {
			retained[nodes[i].IP] = true
		}
	}
	privateTotal, privatePromoted := 0, 0
	for _, c := range segCIDRs {
		k := 0
		for _, i := range segHosts[c] {
			n := &nodes[i]
			if !graph.TerrainAddr(n.IP) {
				continue
			}
			privateTotal++
			if retained[n.IP] {
				continue // pinned
			}
			if opts.RetainAllPrivate {
				if privatePromoted >= config.MapAllPrivateCap {
					continue
				}
				retained[n.IP] = true
				privatePromoted++
				continue
			}
			if k >= config.MapSegmentTopHosts {
				continue
			}
			retained[n.IP] = true
			k++
		}
	}
	// Flagged hosts that didn't fit their segment's top-N appear only in the
	// aggregate / report — say so, as the drift and reconcile maps rely on it.
	omittedMarked := 0
	for i := range nodes {
		if nodeDrift[nodes[i].IP] != "" && !retained[nodes[i].IP] && graph.TerrainAddr(nodes[i].IP) {
			omittedMarked++
		}
	}

	for _, c := range segCIDRs {
		m.Groups = append(m.Groups, Group{ID: groupID(c), CIDR: c, Label: segmentLabel(c, segNames, opts.GroupLabels)})
	}
	if overflow {
		m.Groups = append(m.Groups, Group{ID: "g:other", Label: "other internal networks"})
	}
	if external {
		m.Groups = append(m.Groups, Group{ID: "g:external", Label: "external (internet / non-private)"})
	}
	sort.Slice(m.Groups, func(i, j int) bool { return m.Groups[i].ID < m.Groups[j].ID })

	groupHasRetained := map[string]bool{}
	for _, i := range idx {
		n := &nodes[i]
		if !retained[n.IP] {
			continue
		}
		gid := resolve(n.IP)
		groupHasRetained[gid] = true
		m.Nodes = append(m.Nodes, MapNode{
			ID: n.IP, Group: gid, Label: nodeLabel(n),
			Role: string(n.TopRole()), Tier: tierOf(n),
			Composite: n.Scores.Composite, Rank: n.Scores.Rank,
			Evidence: evidence(n), Drift: nodeDrift[n.IP],
			MAC: n.MAC, Vendor: config.VendorForMAC(n.MAC),
		})
	}

	// The rest of each segment collapses into one "N more hosts" chip — the
	// drill-in target. The ":clients" ID suffix is what bundleEdges routes
	// invisible endpoints to, so aggregates reuse it.
	aggCount := map[string]int{}
	for i := range nodes {
		n := &nodes[i]
		if !retained[n.IP] {
			gid := resolve(n.IP)
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
			Label: fmt.Sprintf("%d more hosts", aggCount[gid]),
			Role:  string(graph.RoleUnknown), Tier: TierClient, AggCount: aggCount[gid],
		})
	}

	// Observed L2 gateways are real evidence — add them before budgeting
	// edges. Inferred gateways are guesses and come last, in leftover space.
	hasObserved := m.addObservedGateways(snap)
	m.addDeclaredDevices(opts.DeclaredDevices)

	// Declared-config gateways are evidence too (a device config named them):
	// badge them before budgeting edges, alongside any observed L2 node, and
	// record which segments they cover so inference is suppressed there.
	declaredSegs := m.addDeclaredGateways(opts.DeclaredGateways, resolve)

	visible := retained
	m.bundleEdges(filterFocusEdges(snap.Edges, byIP), visible, byIP, resolve, opts.MinConns, edgeDrift)
	m.resolve, m.visible, m.byIP = resolve, visible, byIP

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
		m.addInferredGateways(snap, byIP, resolve, groupHasRetained, declaredSegs)
	}

	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		// Text only in overview mode — hatched group boxes would spend the
		// element budget; a focused map still draws them.
		m.Findings = append(m.Findings, fmt.Sprintf("possible blind spot: %s is in scope but produced zero observed traffic", cidr))
	}
	if omittedMarked > 0 {
		m.Findings = append(m.Findings, fmt.Sprintf("%d flagged hosts did not fit their segment and appear only in the report or a focused map", omittedMarked))
	}
	if opts.RetainAllPrivate && privateTotal > config.MapAllPrivateCap {
		m.Findings = append(m.Findings, fmt.Sprintf("show-all-private: %d RFC1918 hosts exceed the %d cap — showing the %d highest-ranked, the rest re-aggregated (map would be too dense otherwise)", privateTotal, config.MapAllPrivateCap, privatePromoted))
	}
	if n := m.Elements(); n > config.MapTargetElements {
		m.Findings = append(m.Findings, fmt.Sprintf("overview exceeds the %d-element target (%d) because flagged changes and imported devices are never dropped", config.MapTargetElements, n))
	}
	m.Findings = append(m.Findings, fmt.Sprintf("segment-flow overview: %d elements reduced to %d — each VLAN shows its top hosts and the strongest dependencies; drill into a segment (or use --focus CIDR) for full detail", detailedElements, m.Elements()))

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
func (m *Model) addInferredGateways(snap graph.Snapshot, byIP map[string]*graph.Node, resolve func(string) string, groupHasRetained, declaredSegs map[string]bool) {
	crossGroup := map[string]bool{}
	for _, e := range snap.Edges {
		s, sOK := byIP[e.Src]
		d, dOK := byIP[e.Dst]
		if !sOK || !dOK {
			continue
		}
		if gs, gd := resolve(s.IP), resolve(d.IP); gs != gd {
			crossGroup[gs], crossGroup[gd] = true, true
		}
	}
	for _, g := range m.Groups {
		if m.Elements() >= config.MapTargetElements {
			return
		}
		// Only real internal CIDR groups that route, aren't already shown by
		// a retained host, and fit the budget get a dashed inferred gateway.
		if crossGroup[g.ID] && g.CIDR != "" && !groupHasRetained[g.ID] && !declaredSegs[g.ID] {
			m.Nodes = append(m.Nodes, MapNode{
				ID: g.ID + ":gw", Group: g.ID, Label: "gateway (inferred)",
				Role: "Gateway", Tier: TierCore, Gateway: true, Inferred: true,
				Evidence: []string{"synthesized from cross-subnet traffic — no L2 evidence on this grid"},
			})
		}
	}
}

// addDeclaredGateways stamps declared-config identity onto the overview's
// gateways. A retained host sitting at a declared gateway IP is badged in
// place; every other declared gateway whose IP resolves into a real segment
// box gets a synthesized "gateway (declared)" node. Returns the set of segment
// group IDs it covered so the caller suppresses inferred gateways there —
// declared config beats a synthesized guess. Observed L2 gateway nodes are
// MAC-keyed and left untouched, so they still appear alongside.
func (m *Model) addDeclaredGateways(declared map[string]string, resolve func(string) string) map[string]bool {
	covered := map[string]bool{}
	if len(declared) == 0 {
		return covered
	}
	// Badge any already-visible host that is a declared gateway IP.
	stamped := map[string]bool{}
	for i := range m.Nodes {
		if host := declared[m.Nodes[i].ID]; host != "" {
			m.Nodes[i].Gateway = true
			m.Nodes[i].Label += " (declared)"
			m.Nodes[i].Evidence = append(m.Nodes[i].Evidence, fmt.Sprintf("gateway declared by %s config", host))
			covered[m.Nodes[i].Group] = true
			stamped[m.Nodes[i].ID] = true
		}
	}
	// Only real segment boxes (with a CIDR) can host a synthesized gateway —
	// the "other"/"external"/"sparse" lumps carry no routed structure.
	segBox := map[string]bool{}
	for _, g := range m.Groups {
		if g.CIDR != "" {
			segBox[g.ID] = true
		}
	}
	ips := make([]string, 0, len(declared))
	for ip := range declared {
		ips = append(ips, ip)
	}
	sort.Strings(ips) // deterministic node order
	for _, ip := range ips {
		gid := resolve(ip)
		if stamped[ip] || covered[gid] || !segBox[gid] {
			continue
		}
		covered[gid] = true
		m.Nodes = append(m.Nodes, MapNode{
			ID: gid + ":gw", Group: gid, Label: "gateway (declared)",
			Role: "Gateway", Tier: TierCore, Gateway: true,
			Evidence: []string{fmt.Sprintf("gateway declared by %s config", declared[ip])},
		})
	}
	return covered
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
		// Inter-segment (cross-group) bundles are the routed-dependency story
		// the map exists to show, and drift/overlay marks must always appear —
		// both are immune to the budget. Only intra-segment filler is trimmed.
		case e.Drift != "" || crosses(e):
			out = append(out, e)
		case kept < budget:
			out = append(out, e)
			kept++
		}
	}
	return out
}
