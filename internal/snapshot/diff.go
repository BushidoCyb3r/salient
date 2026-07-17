package snapshot

import (
	"fmt"
	"slices"
	"sort"
	"strings"

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

type IdentityChange struct {
	IP       string   `json:"ip"`
	Protocol string   `json:"protocol"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
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

// ProviderDisplacement summarizes client movement into one provider from
// other providers of the same service between two snapshots — e.g. "14
// clients that used Y now use X." Purely descriptive: which clients moved
// and from where, never an intent judgment. Only the gaining provider gets
// an entry; a provider that only lost clients isn't tracked here.
type ProviderDisplacement struct {
	IP           string            `json:"ip"`
	Port         uint16            `json:"port"`
	Service      string            `json:"service"`
	ClientsAdded int               `json:"clients_added"` // clients new to this service entirely, not from a tracked prior provider
	MigratedFrom []MigrationSource `json:"migrated_from,omitempty"`
	Rank         int               `json:"rank,omitempty"`
}

// MigrationSource is one prior provider some of a new provider's clients
// came from, and how many.
type MigrationSource struct {
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
	Clients int    `json:"clients"`
}

// Diff is the analyst-relevant drift between two snapshots.
type Diff struct {
	FromMeta              graph.SnapshotMeta     `json:"from"`
	ToMeta                graph.SnapshotMeta     `json:"to"`
	CompatibilityWarnings []string               `json:"compatibility_warnings,omitempty"`
	AppearedNodes         []graph.Node           `json:"appeared_nodes"`
	DisappearedNodes      []graph.Node           `json:"disappeared_nodes"`
	RankChanges           []RankChange           `json:"rank_changes"`
	NewEdgesToTop         []graph.Edge           `json:"new_edges_to_top"`
	VanishedCriticalEdges []graph.Edge           `json:"vanished_critical_edges"`
	RoleChanges           []RoleChange           `json:"role_changes"`
	IdentityChanges       []IdentityChange       `json:"identity_changes,omitempty"`
	NewProviders          []NewProvider          `json:"new_providers"`
	ProviderDisplacements []ProviderDisplacement `json:"provider_displacements"`
}

// Compare returns deterministic drift signals required by Phase 2.
func Compare(from, to graph.Snapshot, opts DiffOptions) Diff {
	if opts.RankDelta <= 0 {
		opts.RankDelta = config.DriftRankDelta
	}
	if opts.TopN <= 0 {
		opts.TopN = config.DriftTopN
	}
	d := Diff{
		FromMeta:              from.Meta,
		ToMeta:                to.Meta,
		CompatibilityWarnings: compatibilityWarnings(from.Meta, to.Meta),
	}
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
		d.IdentityChanges = append(d.IdentityChanges, identityChanges(ip, old, n)...)
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

	// Provider displacement: for each service, track clients that were
	// already a client of some same-service provider in `from` but are now
	// (also) a client of a *different* same-service provider in `to` — a
	// migration. A client with no prior same-service provider counts as
	// organic new demand (ClientsAdded), not a migration.
	oldClientsByProv := map[provKey]map[string]bool{}
	oldProvsByService := map[string][]provKey{}
	for _, e := range from.Edges {
		if !config.IsSensitiveServicePort(e.Port) || !e.Confirmed() || !graph.TerrainAddr(e.Dst) {
			continue
		}
		k := provKey{e.Dst, e.Port}
		if oldClientsByProv[k] == nil {
			oldClientsByProv[k] = map[string]bool{}
			oldProvsByService[config.ServiceName(e.Port)] = append(oldProvsByService[config.ServiceName(e.Port)], k)
		}
		oldClientsByProv[k][e.Src] = true
	}
	newClientsByProv := map[provKey]map[string]bool{}
	for _, e := range to.Edges {
		if !config.IsSensitiveServicePort(e.Port) || !e.Confirmed() || !graph.TerrainAddr(e.Dst) {
			continue
		}
		k := provKey{e.Dst, e.Port}
		if newClientsByProv[k] == nil {
			newClientsByProv[k] = map[string]bool{}
		}
		newClientsByProv[k][e.Src] = true
	}
	for k, clients := range newClientsByProv {
		service := config.ServiceName(k.port)
		wasClientBefore := oldClientsByProv[k]
		fromCount := map[provKey]int{}
		added := 0
		for c := range clients {
			if wasClientBefore[c] {
				continue // already p's client last time — not new, not a migration
			}
			migrated := false
			for _, q := range oldProvsByService[service] {
				if q == k {
					continue
				}
				if oldClientsByProv[q][c] {
					fromCount[q]++
					migrated = true
					break
				}
			}
			if !migrated {
				added++
			}
		}
		if added == 0 && len(fromCount) == 0 {
			continue
		}
		var sources []MigrationSource
		for q, n := range fromCount {
			sources = append(sources, MigrationSource{IP: q.dst, Port: q.port, Clients: n})
		}
		sort.Slice(sources, func(i, j int) bool {
			if sources[i].Clients != sources[j].Clients {
				return sources[i].Clients > sources[j].Clients
			}
			return sources[i].IP < sources[j].IP
		})
		d.ProviderDisplacements = append(d.ProviderDisplacements, ProviderDisplacement{
			IP: k.dst, Port: k.port, Service: service,
			ClientsAdded: added, MigratedFrom: sources, Rank: newNodes[k.dst].Scores.Rank,
		})
	}
	sort.Slice(d.ProviderDisplacements, func(i, j int) bool {
		total := func(p ProviderDisplacement) int {
			n := p.ClientsAdded
			for _, s := range p.MigratedFrom {
				n += s.Clients
			}
			return n
		}
		a, b := d.ProviderDisplacements[i], d.ProviderDisplacements[j]
		if ta, tb := total(a), total(b); ta != tb {
			return ta > tb
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
	sort.Slice(d.IdentityChanges, func(i, j int) bool {
		if d.IdentityChanges[i].IP != d.IdentityChanges[j].IP {
			return d.IdentityChanges[i].IP < d.IdentityChanges[j].IP
		}
		return d.IdentityChanges[i].Protocol < d.IdentityChanges[j].Protocol
	})
	sortEdges(d.NewEdgesToTop)
	sortEdges(d.VanishedCriticalEdges)
	return d
}

func compatibilityWarnings(from, to graph.SnapshotMeta) []string {
	var warnings []string
	if from.ClusterName != "" && to.ClusterName != "" && from.ClusterName != to.ClusterName {
		warnings = append(warnings, fmt.Sprintf("cluster differs: %q vs %q", from.ClusterName, to.ClusterName))
	}
	if from.Window != "" && to.Window != "" && from.Window != to.Window {
		warnings = append(warnings, fmt.Sprintf("window differs: %q vs %q", from.Window, to.Window))
	}
	if !slices.Equal(sortedStrings(from.Scope), sortedStrings(to.Scope)) {
		warnings = append(warnings, fmt.Sprintf("scope differs: %s vs %s", joinOrNone(from.Scope), joinOrNone(to.Scope)))
	}
	if !slices.Equal(sortedStrings(from.Sensors), sortedStrings(to.Sensors)) {
		warnings = append(warnings, fmt.Sprintf("sensors differ: %s vs %s", joinOrNone(from.Sensors), joinOrNone(to.Sensors)))
	}
	return warnings
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

func identityChanges(ip string, from, to graph.Node) []IdentityChange {
	var out []IdentityChange
	if added, removed := stringSetDiff(from.TLSFingerprints, to.TLSFingerprints); len(added) > 0 || len(removed) > 0 {
		out = append(out, IdentityChange{IP: ip, Protocol: "tls", Added: added, Removed: removed})
	}
	if added, removed := stringSetDiff(from.SSHHostKeys, to.SSHHostKeys); len(added) > 0 || len(removed) > 0 {
		out = append(out, IdentityChange{IP: ip, Protocol: "ssh", Added: added, Removed: removed})
	}
	return out
}

func isTop(n graph.Node, topN int) bool { return n.Scores.Rank > 0 && n.Scores.Rank <= topN }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func joinOrNone(in []string) string {
	if len(in) == 0 {
		return "(none)"
	}
	return strings.Join(sortedStrings(in), ", ")
}

func stringSetDiff(from, to []string) ([]string, []string) {
	var added, removed []string
	fromSet, toSet := map[string]bool{}, map[string]bool{}
	for _, v := range from {
		fromSet[v] = true
	}
	for _, v := range to {
		toSet[v] = true
	}
	for v := range toSet {
		if !fromSet[v] {
			added = append(added, v)
		}
	}
	for v := range fromSet {
		if !toSet[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
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
