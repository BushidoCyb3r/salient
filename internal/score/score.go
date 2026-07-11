// Package score computes key-terrain rankings (SALIENT_PLAN.md §10). It uses
// gonum for PageRank and betweenness — centrality is never hand-rolled.
package score

import (
	"fmt"
	"math"
	"sort"

	"gonum.org/v1/gonum/graph/network"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
)

// Result reports how scoring ran; BetweennessSampled is true when the graph
// exceeded the exact-computation node limit and betweenness came from the
// Brandes–Pich pivot approximation instead (flagged in the report).
type Result struct {
	BetweennessSampled bool
	NodeCount          int
}

// Score computes centrality and the composite terrain score for every node in
// the model, mutating Node.Scores in place and assigning ranks (1 = highest).
func Score(m *graph.Model) Result {
	g := m.Directed()
	nodes := m.SortedNodes()
	res := Result{NodeCount: len(nodes)}

	pr := network.PageRank(g, config.PageRankDamping, config.PageRankTolerance)

	var bw map[int64]float64
	if len(nodes) <= config.ExactBetweennessMax {
		bw = network.Betweenness(g)
	} else {
		res.BetweennessSampled = true
		bw = sampledBetweenness(g, config.BetweennessSamplePivots)
	}

	critIn := criticalInDegree(m) // distinct critical-service clients per IP
	spread := subnetSpread(m)     // distinct client subnets per IP

	// Broadcast/multicast destinations are not terrain: they take composite
	// 0 and are excluded from normalization so the traffic converging on
	// them can't compress real nodes' component scores.
	var terrain []*graph.Node
	for _, n := range nodes {
		if graph.TerrainAddr(n.IP) {
			terrain = append(terrain, n)
		} else {
			id, _ := m.ID(n.IP)
			n.Scores.PageRank = pr[id]
			n.Scores.Betweenness = bw[id]
			n.Scores.DependencyInDegree = critIn[n.IP]
			n.Scores.Composite = 0
		}
	}

	// Collect raw component values for min-max normalization.
	var prVals, bwVals, critVals, spreadVals []float64
	for _, n := range terrain {
		id, _ := m.ID(n.IP)
		prVals = append(prVals, pr[id])
		bwVals = append(bwVals, bw[id])
		critVals = append(critVals, float64(critIn[n.IP]))
		spreadVals = append(spreadVals, float64(spread[n.IP]))
	}
	normPR := minMax(prVals)
	normBW := minMax(bwVals)
	normCrit := minMax(critVals)
	normSpread := minMax(spreadVals)
	drivers := make(map[string][]terrainDriver, len(terrain))

	for i, n := range terrain {
		id, _ := m.ID(n.IP)
		n.Scores.PageRank = pr[id]
		n.Scores.Betweenness = bw[id]
		n.Scores.DependencyInDegree = critIn[n.IP]
		n.Scores.Composite = config.WeightDependency*normCrit(critVals[i]) +
			config.WeightPageRank*normPR(prVals[i]) +
			config.WeightBetween*normBW(bwVals[i]) +
			config.WeightSubnet*normSpread(spreadVals[i])
		if critIn[n.IP] > 0 {
			drivers[n.IP] = append(drivers[n.IP], terrainDriver{
				config.WeightDependency * normCrit(critVals[i]),
				fmt.Sprintf("%d distinct hosts depend on it for critical services", critIn[n.IP]),
			})
		}
		if bw[id] > 0 {
			drivers[n.IP] = append(drivers[n.IP], terrainDriver{
				config.WeightBetween * normBW(bwVals[i]),
				fmt.Sprintf("chokepoint: betweenness %.2f — observed dependency paths pass through it", bw[id]),
			})
		}
		if spread[n.IP] > 0 {
			drivers[n.IP] = append(drivers[n.IP], terrainDriver{
				config.WeightSubnet * normSpread(spreadVals[i]),
				fmt.Sprintf("blast radius: dependencies reach it from %d subnets", spread[n.IP]),
			})
		}
		if pr[id] > 0 {
			drivers[n.IP] = append(drivers[n.IP], terrainDriver{
				config.WeightPageRank * normPR(prVals[i]),
				fmt.Sprintf("dependency centrality: PageRank %.4f from weighted incoming traffic", pr[id]),
			})
		}
	}

	// Rank by composite, descending; stable by IP for determinism.
	ranked := append([]*graph.Node(nil), nodes...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Scores.Composite != ranked[j].Scores.Composite {
			return ranked[i].Scores.Composite > ranked[j].Scores.Composite
		}
		return ranked[i].IP < ranked[j].IP
	})
	for i, n := range ranked {
		n.Scores.Rank = i + 1
		n.TerrainEvidence = nil
		if n.Scores.Rank > config.TerrainEvidenceTopN || !graph.TerrainAddr(n.IP) {
			continue
		}
		d := drivers[n.IP]
		sort.SliceStable(d, func(i, j int) bool { return d[i].contribution > d[j].contribution })
		for _, driver := range d {
			n.TerrainEvidence = append(n.TerrainEvidence, driver.text)
		}
	}
	return res
}

type terrainDriver struct {
	contribution float64
	text         string
}

// criticalInDegree: distinct client IPs per responder on auth/dns/smb/db (§10).
func criticalInDegree(m *graph.Model) map[string]int {
	return distinctSrcPerDst(m, func(port uint16) bool { return config.IsCriticalDependency(port) })
}

// subnetSpread: distinct client subnets depending on each responder.
func subnetSpread(m *graph.Model) map[string]int {
	subnets := map[string]map[string]bool{}
	for _, e := range m.Edges {
		if !e.Confirmed() {
			continue
		}
		if subnets[e.Dst] == nil {
			subnets[e.Dst] = map[string]bool{}
		}
		subnets[e.Dst][graph.Subnet(e.Src)] = true
	}
	out := map[string]int{}
	for _, n := range m.Nodes {
		out[n.IP] = len(subnets[n.IP])
	}
	return out
}

func distinctSrcPerDst(m *graph.Model, keep func(uint16) bool) map[string]int {
	clients := map[string]map[string]bool{}
	for _, e := range m.Edges {
		if !e.Confirmed() {
			continue
		}
		if !keep(e.Port) {
			continue
		}
		if clients[e.Dst] == nil {
			clients[e.Dst] = map[string]bool{}
		}
		clients[e.Dst][e.Src] = true
	}
	out := map[string]int{}
	for _, n := range m.Nodes {
		out[n.IP] = len(clients[n.IP])
	}
	return out
}

// minMax returns a normalizer mapping the observed range to [0,1]. A constant
// series maps everything to 0 (no node stands out on that dimension).
func minMax(vals []float64) func(float64) float64 {
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, v := range vals {
		lo = math.Min(lo, v)
		hi = math.Max(hi, v)
	}
	span := hi - lo
	if span <= 0 {
		return func(float64) float64 { return 0 }
	}
	return func(v float64) float64 { return (v - lo) / span }
}
