package mapview

import (
	"sort"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// ServiceProvider is one responder providing one sensitive service,
// aggregated from confirmed edges in a single snapshot. It is a descriptive
// evidence summary only — never a suspicion or risk score.
type ServiceProvider struct {
	IP        string              `json:"ip"`
	Hostname  string              `json:"hostname,omitempty"`
	Role      graph.Role          `json:"role"`
	Service   string              `json:"service"`
	Port      uint16              `json:"port"`
	Evidence  graph.EvidenceLevel `json:"evidence"`
	Clients   int                 `json:"clients"`
	FirstSeen time.Time           `json:"first_seen"`
	LastSeen  time.Time           `json:"last_seen"`
	Rank      int                 `json:"rank,omitempty"`
}

// evidenceStrength ranks evidence tiers so aggregation can keep the
// strongest one actually observed for a provider/port pair.
func evidenceStrength(e graph.EvidenceLevel) int {
	switch e {
	case graph.EvidenceProtocolConfirmed:
		return 2
	case graph.EvidenceResponderConfirmed:
		return 1
	default:
		return 0
	}
}

// BuildServiceAuthority groups confirmed edges into sensitive-service
// providers for the current snapshot: for each (responder, port) pair, the
// distinct confirmed client count, the strongest evidence tier observed, and
// the responder's role/rank/hostname. Port-only edges, non-sensitive ports,
// and non-terrain destinations (broadcast/multicast) are excluded — the same
// filters snapshot.Compare's new-provider detection already applies.
func BuildServiceAuthority(snap graph.Snapshot) []ServiceProvider {
	type key struct {
		ip   string
		port uint16
	}
	type agg struct {
		clients   map[string]bool
		evidence  graph.EvidenceLevel
		firstSeen time.Time
		lastSeen  time.Time
	}
	byKey := map[key]*agg{}
	for _, e := range snap.Edges {
		if !config.IsSensitiveServicePort(e.Port) || !e.Confirmed() || !graph.TerrainAddr(e.Dst) {
			continue
		}
		k := key{e.Dst, e.Port}
		a, ok := byKey[k]
		if !ok {
			a = &agg{clients: map[string]bool{}}
			byKey[k] = a
		}
		a.clients[e.Src] = true
		if evidenceStrength(e.Evidence) > evidenceStrength(a.evidence) {
			a.evidence = e.Evidence
		}
		if a.firstSeen.IsZero() || e.FirstSeen.Before(a.firstSeen) {
			a.firstSeen = e.FirstSeen
		}
		if e.LastSeen.After(a.lastSeen) {
			a.lastSeen = e.LastSeen
		}
	}

	nodes := make(map[string]graph.Node, len(snap.Nodes))
	for _, n := range snap.Nodes {
		nodes[n.IP] = n
	}

	rows := make([]ServiceProvider, 0, len(byKey))
	for k, a := range byKey {
		n := nodes[k.ip]
		hostname := ""
		if len(n.Hostnames) > 0 {
			hostname = n.Hostnames[0]
		}
		rows = append(rows, ServiceProvider{
			IP: k.ip, Hostname: hostname, Role: n.TopRole(), Service: config.ServiceName(k.port),
			Port: k.port, Evidence: a.evidence, Clients: len(a.clients),
			FirstSeen: a.firstSeen, LastSeen: a.lastSeen, Rank: n.Scores.Rank,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Clients != rows[j].Clients {
			return rows[i].Clients > rows[j].Clients
		}
		if rows[i].IP != rows[j].IP {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].Port < rows[j].Port
	})
	return rows
}
