// Package stability computes longitudinal terrain-stability statistics
// across already-stored snapshots: which hosts persistently rank as key
// terrain, which are newly emerging, which have gone quiet. Pure
// computation over graph.Snapshot values already loaded by the caller —
// no I/O, no new telemetry, no live grid required (SALIENT_PLAN.md's
// "Later" tier: longitudinal terrain stability).
package stability

import (
	"sort"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// Classification is a simple, deterministic terrain-persistence label —
// never a probability or anomaly score, matching this project's stance on
// evidence-tier and hunt-lead ordering.
type Classification string

const (
	ClassPersistent Classification = "persistent" // present in every snapshot given
	ClassEmerging   Classification = "emerging"   // absent from the earliest, present in the latest
	ClassTransient  Classification = "transient"  // present earlier but absent from the latest
)

// NodeStability summarizes one host's terrain standing across a sequence
// of snapshots, sorted internally by SnapshotMeta.CreatedAt so the caller's
// input order never matters.
type NodeStability struct {
	IP                   string
	Occurrences          int // snapshots in which this IP appeared at all
	TopNOccurrences      int // snapshots in which it was ranked in the top N
	BestRankPercentile   float64
	WorstRankPercentile  float64
	MedianRankPercentile float64
	RoleConsistent       bool // same non-Unknown top role in every snapshot it had one
	Classification       Classification
}

// Compute derives per-host stability statistics from a sequence of
// snapshots (any input order — sorted internally by CreatedAt) and a
// top-N threshold for the TopNOccurrences count. Callers should supply at
// least 3 comparable snapshots for the classification to be meaningful
// (SALIENT_PLAN.md's own guidance) — Compute itself works with any count
// ≥1, it just won't have much to say about "persistent" with only one.
func Compute(snaps []graph.Snapshot, topN int) []NodeStability {
	ordered := make([]graph.Snapshot, len(snaps))
	copy(ordered, snaps)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Meta.CreatedAt.Before(ordered[j].Meta.CreatedAt)
	})

	type perNode struct {
		occurrences     int
		topNOccurrences int
		percentiles     []float64
		roles           map[graph.Role]bool
		inEarliest      bool
		inLatest        bool
	}
	byIP := map[string]*perNode{}
	for i, s := range ordered {
		rankedCount := 0
		for _, n := range s.Nodes {
			if n.Scores.Rank > 0 {
				rankedCount++
			}
		}
		for _, n := range s.Nodes {
			pn, ok := byIP[n.IP]
			if !ok {
				pn = &perNode{roles: map[graph.Role]bool{}}
				byIP[n.IP] = pn
			}
			pn.occurrences++
			if i == 0 {
				pn.inEarliest = true
			}
			if i == len(ordered)-1 {
				pn.inLatest = true
			}
			if n.Scores.Rank > 0 {
				if n.Scores.Rank <= topN {
					pn.topNOccurrences++
				}
				if rankedCount > 1 {
					pn.percentiles = append(pn.percentiles, float64(rankedCount-n.Scores.Rank)/float64(rankedCount-1))
				} else {
					pn.percentiles = append(pn.percentiles, 1.0) // sole ranked node this snapshot
				}
			}
			if role := n.TopRole(); role != graph.RoleUnknown {
				pn.roles[role] = true
			}
		}
	}

	out := make([]NodeStability, 0, len(byIP))
	for ip, pn := range byIP {
		ns := NodeStability{
			IP: ip, Occurrences: pn.occurrences, TopNOccurrences: pn.topNOccurrences,
			RoleConsistent: len(pn.roles) <= 1,
		}
		if len(pn.percentiles) > 0 {
			sort.Float64s(pn.percentiles)
			ns.WorstRankPercentile = pn.percentiles[0]
			ns.BestRankPercentile = pn.percentiles[len(pn.percentiles)-1]
			ns.MedianRankPercentile = median(pn.percentiles)
		}
		switch {
		case pn.inEarliest && pn.inLatest:
			ns.Classification = ClassPersistent
		case !pn.inEarliest && pn.inLatest:
			ns.Classification = ClassEmerging
		case pn.inEarliest && !pn.inLatest:
			ns.Classification = ClassTransient
		default:
			// Appeared only in a middle snapshot, absent from both ends.
			ns.Classification = ClassTransient
		}
		out = append(out, ns)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
