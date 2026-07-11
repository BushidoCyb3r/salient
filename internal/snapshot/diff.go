package snapshot

import (
	"slices"
	"sort"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// DiffOptions controls which rank and critical-edge changes are reported.
type DiffOptions struct {
	RankDelta int
	TopN      int
}

// RankChange uses a positive Delta when a node moved toward rank 1.
type RankChange struct {
	IP       string `json:"ip"`
	FromRank int    `json:"from_rank"`
	ToRank   int    `json:"to_rank"`
	Delta    int    `json:"delta"`
}

type RoleChange struct {
	IP   string       `json:"ip"`
	From []graph.Role `json:"from"`
	To   []graph.Role `json:"to"`
}

// NewProvider is a responder that began providing a sensitive service
// between the snapshots, regardless of terrain rank — a new low-ranked
// DNS/DHCP/auth/file/DB provider is an investigation lead, not proof of
// malicious intent.
type NewProvider struct {
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
	Service string `json:"service"`
	Clients int    `json:"clients"`
	NewHost bool   `json:"new_host"`
	Rank    int    `json:"rank"`
}

// Diff is the analyst-relevant drift between two snapshots.
type Diff struct {
	FromMeta              graph.SnapshotMeta `json:"from"`
	ToMeta                graph.SnapshotMeta `json:"to"`
	AppearedNodes         []graph.Node       `json:"appeared_nodes"`
	DisappearedNodes      []graph.Node       `json:"disappeared_nodes"`
	RankChanges           []RankChange       `json:"rank_changes"`
	NewEdgesToTop         []graph.Edge       `json:"new_edges_to_top"`
	VanishedCriticalEdges []graph.Edge       `json:"vanished_critical_edges"`
	RoleChanges           []RoleChange       `json:"role_changes"`
	NewProviders          []NewProvider      `json:"new_providers"`
}

// Compare returns deterministic drift signals required by Phase 2.
func Compare(from, to graph.Snapshot, opts DiffOptions) Diff {
	if opts.RankDelta <= 0 {
		opts.RankDelta = config.DriftRankDelta
	}
	if opts.TopN <= 0 {
		opts.TopN = config.DriftTopN
	}
	d := Diff{FromMeta: from.Meta, ToMeta: to.Meta}
	oldNodes, newNodes := nodesByIP(from.Nodes), nodesByIP(to.Nodes)
	for ip, n := range newNodes {
		old, exists := oldNodes[ip]
		if !exists {
			d.AppearedNodes = append(d.AppearedNodes, n)
			continue
		}
		delta := old.Scores.Rank - n.Scores.Rank
		if old.Scores.Rank > 0 && n.Scores.Rank > 0 && abs(delta) >= opts.RankDelta {
			d.RankChanges = append(d.RankChanges, RankChange{IP: ip, FromRank: old.Scores.Rank, ToRank: n.Scores.Rank, Delta: delta})
		}
		fromRoles, toRoles := roles(old), roles(n)
		if !slices.Equal(fromRoles, toRoles) {
			d.RoleChanges = append(d.RoleChanges, RoleChange{IP: ip, From: fromRoles, To: toRoles})
		}
	}
	for ip, n := range oldNodes {
		if _, exists := newNodes[ip]; !exists {
			d.DisappearedNodes = append(d.DisappearedNodes, n)
		}
	}

	oldEdges, newEdges := edgesByKey(from.Edges), edgesByKey(to.Edges)
	for key, e := range newEdges {
		if _, exists := oldEdges[key]; !exists && isTop(newNodes[e.Dst], opts.TopN) {
			d.NewEdgesToTop = append(d.NewEdgesToTop, e)
		}
	}
	for key, e := range oldEdges {
		if _, exists := newEdges[key]; !exists && isTop(oldNodes[e.Dst], opts.TopN) {
			d.VanishedCriticalEdges = append(d.VanishedCriticalEdges, e)
		}
	}

	type provKey struct {
		dst  string
		port uint16
	}
	oldProv := map[provKey]bool{}
	for _, e := range from.Edges {
		if config.IsSensitiveServicePort(e.Port) && e.Confirmed() {
			oldProv[provKey{e.Dst, e.Port}] = true
		}
	}
	provClients := map[provKey]map[string]bool{}
	for _, e := range to.Edges {
		if !config.IsSensitiveServicePort(e.Port) || !e.Confirmed() ||
			!graph.TerrainAddr(e.Dst) || oldProv[provKey{e.Dst, e.Port}] {
			continue
		}
		k := provKey{e.Dst, e.Port}
		if provClients[k] == nil {
			provClients[k] = map[string]bool{}
		}
		provClients[k][e.Src] = true
	}
	for k, clients := range provClients {
		_, existed := oldNodes[k.dst]
		d.NewProviders = append(d.NewProviders, NewProvider{
			IP: k.dst, Port: k.port, Service: config.ServiceName(k.port),
			Clients: len(clients), NewHost: !existed, Rank: newNodes[k.dst].Scores.Rank,
		})
	}
	sort.Slice(d.NewProviders, func(i, j int) bool {
		a, b := d.NewProviders[i], d.NewProviders[j]
		if a.Clients != b.Clients {
			return a.Clients > b.Clients
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Port < b.Port
	})

	sort.Slice(d.AppearedNodes, func(i, j int) bool { return d.AppearedNodes[i].IP < d.AppearedNodes[j].IP })
	sort.Slice(d.DisappearedNodes, func(i, j int) bool { return d.DisappearedNodes[i].IP < d.DisappearedNodes[j].IP })
	sort.Slice(d.RankChanges, func(i, j int) bool { return d.RankChanges[i].IP < d.RankChanges[j].IP })
	sort.Slice(d.RoleChanges, func(i, j int) bool { return d.RoleChanges[i].IP < d.RoleChanges[j].IP })
	sortEdges(d.NewEdgesToTop)
	sortEdges(d.VanishedCriticalEdges)
	return d
}

type edgeKey struct {
	src, dst string
	port     uint16
}

func nodesByIP(nodes []graph.Node) map[string]graph.Node {
	out := make(map[string]graph.Node, len(nodes))
	for _, n := range nodes {
		out[n.IP] = n
	}
	return out
}

func edgesByKey(edges []graph.Edge) map[edgeKey]graph.Edge {
	out := make(map[edgeKey]graph.Edge, len(edges))
	for _, e := range edges {
		out[edgeKey{e.Src, e.Dst, e.Port}] = e
	}
	return out
}

func roles(n graph.Node) []graph.Role {
	out := make([]graph.Role, 0, len(n.Roles))
	seen := make(map[graph.Role]bool, len(n.Roles))
	for _, role := range n.Roles {
		if !seen[role.Role] {
			seen[role.Role] = true
			out = append(out, role.Role)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isTop(n graph.Node, topN int) bool { return n.Scores.Rank > 0 && n.Scores.Rank <= topN }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func sortEdges(edges []graph.Edge) {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Dst != b.Dst {
			return a.Dst < b.Dst
		}
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		return a.Port < b.Port
	})
}
