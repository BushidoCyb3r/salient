package graph

import (
	"math"
	"net/netip"
	"sort"
	"time"

	"gonum.org/v1/gonum/graph/simple"

	"github.com/BushidoCyb3r/salient/internal/config"
)

// Model is the in-memory working graph: the domain edges plus a gonum
// weighted-directed graph for centrality, with a stable IP<->id mapping.
type Model struct {
	Edges []Edge
	Nodes map[string]*Node // keyed by IP
	g     *simple.WeightedDirectedGraph
	ids   map[string]int64
	order []string // node IPs in first-seen insertion order, for determinism
}

// Build assembles a Model from observed edges. Nodes are the union of edge
// endpoints; the gonum edge points client(Src)->server(Dst) so PageRank ranks
// depended-upon servers high (§10). Parallel edges (same src/dst, different
// port) accumulate weight = log(1+conn), ×3 for auth/dns (§10).
func Build(edges []Edge) *Model {
	m := &Model{
		Edges: edges,
		Nodes: map[string]*Node{},
		g:     simple.NewWeightedDirectedGraph(0, 0),
		ids:   map[string]int64{},
	}
	sensors := make(map[string]map[string]struct{})
	for i := range edges {
		e := &edges[i]
		src := m.node(e.Src, e.FirstSeen, e.LastSeen)
		dst := m.node(e.Dst, e.FirstSeen, e.LastSeen)
		for _, ip := range []string{e.Src, e.Dst} {
			if sensors[ip] == nil {
				sensors[ip] = make(map[string]struct{})
			}
			for _, sensor := range e.Sensors {
				sensors[ip][sensor] = struct{}{}
			}
		}
		if !e.Confirmed() {
			continue // observed attempt only — no centrality weight
		}
		w := math.Log1p(float64(e.ConnCount))
		if config.IsAuthEdge(e.Port) {
			w *= config.AuthEdgeWeightMul
		}
		si, di := m.ids[src.IP], m.ids[dst.IP]
		if si == di {
			continue // self-loop; ignore for centrality
		}
		if we := m.g.WeightedEdge(si, di); we != nil {
			// accumulate parallel-edge weight
			m.g.SetWeightedEdge(m.g.NewWeightedEdge(m.g.Node(si), m.g.Node(di), we.Weight()+w))
		} else {
			m.g.SetWeightedEdge(m.g.NewWeightedEdge(simple.Node(si), simple.Node(di), w))
		}
	}
	for ip, set := range sensors {
		for sensor := range set {
			m.Nodes[ip].Sensors = append(m.Nodes[ip].Sensors, sensor)
		}
		sort.Strings(m.Nodes[ip].Sensors)
	}
	return m
}

func (m *Model) node(ip string, first, last time.Time) *Node {
	n, ok := m.Nodes[ip]
	if !ok {
		id := int64(len(m.ids))
		m.ids[ip] = id
		m.order = append(m.order, ip)
		n = &Node{IP: ip, Subnet: Subnet(ip), FirstSeen: first, LastSeen: last}
		m.Nodes[ip] = n
		if m.g.Node(id) == nil {
			m.g.AddNode(simple.Node(id))
		}
	}
	if first.Before(n.FirstSeen) || n.FirstSeen.IsZero() {
		n.FirstSeen = first
	}
	if last.After(n.LastSeen) {
		n.LastSeen = last
	}
	return n
}

// Directed exposes the gonum graph for the score package.
func (m *Model) Directed() *simple.WeightedDirectedGraph { return m.g }

// ID returns the gonum node id for an IP.
func (m *Model) ID(ip string) (int64, bool) { id, ok := m.ids[ip]; return id, ok }

// SortedNodes returns nodes in a deterministic order (by IP).
func (m *Model) SortedNodes() []*Node {
	out := make([]*Node, 0, len(m.Nodes))
	for _, ip := range m.order {
		out = append(out, m.Nodes[ip])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Snapshot assembles the persisted model from the scored graph. Nodes come
// out ranked (rank 1 first) so reports and diffs read top-down.
func (m *Model) Snapshot(meta SnapshotMeta) Snapshot {
	nodes := make([]Node, 0, len(m.Nodes))
	for _, n := range m.SortedNodes() {
		nodes = append(nodes, *n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Scores.Rank != nodes[j].Scores.Rank {
			return nodes[i].Scores.Rank < nodes[j].Scores.Rank
		}
		return nodes[i].IP < nodes[j].IP
	})
	if meta.Tool == "" {
		meta.Tool = "salient"
	}
	return Snapshot{Meta: meta, Nodes: nodes, Edges: m.Edges}
}

// Subnet returns the /24 (IPv4) or /64 (IPv6) grouping key for an IP. Falls
// back to the raw IP if unparseable.
func Subnet(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ip
	}
	return p.String()
}
