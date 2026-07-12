// Package mission computes a mission/enclave relevance overlay: given an
// operator-selected scope (a set of IPs), which other hosts support it and
// how closely, via a bounded breadth-first walk over confirmed edges. This
// never touches or replaces a snapshot's canonical global terrain rank —
// mission relevance is an additional lens over already-computed evidence,
// not a re-derivation of it (SALIENT_PLAN.md's "Later" tier: enclave and
// mission lens).
package mission

import "github.com/BushidoCyb3r/salient/internal/graph"

// MaxDepth bounds the walk so an unrelated, densely-connected grid doesn't
// pull the entire network into "mission relevant." Deliberately small and
// fixed rather than configurable — a mission lens with a 10-hop radius
// isn't a lens anymore.
const MaxDepth = 3

// Score is one host's mission-relevance overlay. Never a replacement for
// the snapshot's canonical graph.ScoreSet — read both together.
type Score struct {
	IP           string
	InScope      bool    // directly one of the operator-selected hosts
	Depth        int     // hops from the nearest in-scope host (0 = in scope)
	MissionScore float64 // 1/(1+Depth) — closer to the mission scope scores higher
}

// Compute walks outward from scope over confirmed edges (either direction —
// a mission system's dependencies and its dependents both matter), up to
// MaxDepth hops, and returns one Score per host reached. Hosts never
// connected to scope within MaxDepth are simply absent from the result —
// this is a scoped view, not a padded one.
func Compute(snap graph.Snapshot, scope map[string]bool) []Score {
	if len(scope) == 0 {
		return nil
	}
	knownNodes := make(map[string]bool, len(snap.Nodes))
	for _, n := range snap.Nodes {
		knownNodes[n.IP] = true
	}
	neighbors := map[string]map[string]bool{}
	for _, e := range snap.Edges {
		if !e.Confirmed() || e.Src == e.Dst {
			continue
		}
		if neighbors[e.Src] == nil {
			neighbors[e.Src] = map[string]bool{}
		}
		if neighbors[e.Dst] == nil {
			neighbors[e.Dst] = map[string]bool{}
		}
		neighbors[e.Src][e.Dst] = true
		neighbors[e.Dst][e.Src] = true
	}

	depth := map[string]int{}
	var frontier []string
	for ip := range scope {
		if !knownNodes[ip] {
			continue // operator typo or decommissioned host — not a silent success
		}
		depth[ip] = 0
		frontier = append(frontier, ip)
	}
	for d := 0; d < MaxDepth && len(frontier) > 0; d++ {
		var next []string
		for _, ip := range frontier {
			for n := range neighbors[ip] {
				if _, seen := depth[n]; seen {
					continue
				}
				depth[n] = d + 1
				next = append(next, n)
			}
		}
		frontier = next
	}

	out := make([]Score, 0, len(depth))
	for ip, d := range depth {
		out = append(out, Score{
			IP: ip, InScope: scope[ip], Depth: d,
			MissionScore: 1.0 / float64(1+d),
		})
	}
	return out
}
