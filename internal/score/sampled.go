package score

import (
	"slices"

	"gonum.org/v1/gonum/graph"
)

// sampledBetweenness estimates betweenness centrality by running Brandes'
// single-source accumulation from K evenly-strided pivots and scaling by
// n/K (Brandes–Pich). gonum has no sampled variant, and exact Brandes is
// O(V·E) — too slow past the §10 exact limit — so this is the one place the
// "never hand-roll centrality" rule yields to the Phase 4 sampled path.
// Pivots are deterministic (every n/K-th node of the gonum node list sorted
// by ID) so identical snapshots score identically.
func sampledBetweenness(g graph.Directed, pivots int) map[int64]float64 {
	var ids []int64
	it := g.Nodes()
	for it.Next() {
		ids = append(ids, it.Node().ID())
	}
	n := len(ids)
	if n == 0 {
		return map[int64]float64{}
	}
	slices.Sort(ids)
	if pivots > n {
		pivots = n
	}
	stride := n / pivots

	bw := make(map[int64]float64, n)
	for i := 0; i < pivots; i++ {
		brandesFrom(g, ids[i*stride], bw)
	}
	scale := float64(n) / float64(pivots)
	for id := range bw {
		bw[id] *= scale
	}
	return bw
}

// brandesFrom runs one unweighted single-source stage of Brandes' algorithm,
// accumulating pair dependencies of s into bw.
func brandesFrom(g graph.Directed, s int64, bw map[int64]float64) {
	sigma := map[int64]float64{s: 1} // shortest-path counts
	dist := map[int64]int{s: 0}
	preds := map[int64][]int64{}
	var stack []int64

	queue := []int64{s}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		stack = append(stack, v)
		to := g.From(v)
		for to.Next() {
			w := to.Node().ID()
			if _, seen := dist[w]; !seen {
				dist[w] = dist[v] + 1
				queue = append(queue, w)
			}
			if dist[w] == dist[v]+1 {
				sigma[w] += sigma[v]
				preds[w] = append(preds[w], v)
			}
		}
	}

	delta := map[int64]float64{}
	for i := len(stack) - 1; i >= 0; i-- {
		w := stack[i]
		for _, v := range preds[w] {
			delta[v] += sigma[v] / sigma[w] * (1 + delta[w])
		}
		if w != s {
			bw[w] += delta[w]
		}
	}
}
