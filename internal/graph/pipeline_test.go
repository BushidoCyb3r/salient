package graph_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/score"
)

// Synthetic toy enterprise (§13): 1 DC, 1 DNS, 1 file server, 1 jump box,
// 20 workstations across two subnets. Known-correct expectation: the DC and
// DNS rank top-3 with correct roles; workstations stay Unknown.
func synthetic() ([]graph.Edge, graph.Evidence) {
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	dc, dns, file, jump := "10.0.1.10", "10.0.1.11", "10.0.2.20", "10.0.1.50"
	var edges []graph.Edge
	add := func(src, dst string, port uint16, conns int64) {
		edges = append(edges, graph.Edge{
			Src: src, Dst: dst, Port: port, ConnCount: conns,
			FirstSeen: t0, LastSeen: t0.Add(24 * time.Hour),
			Sensors: []string{"sensor1"},
		})
	}
	ws := func(i int) string {
		if i < 10 {
			return fmt.Sprintf("10.0.2.%d", 30+i)
		}
		return fmt.Sprintf("10.0.3.%d", 30+i)
	}
	for i := 0; i < 20; i++ {
		w := ws(i)
		add(w, dc, 88, 500)   // kerberos
		add(w, dc, 389, 200)  // ldap
		add(w, dns, 53, 1000) // dns
		add(w, file, 445, 50) // smb
	}
	// Jump box: 1 admin in, 6 out.
	add("10.0.1.5", jump, 3389, 20)
	for i := 0; i < 6; i++ {
		add(jump, ws(i), 3389, 10)
	}
	ev := graph.Evidence{
		Kerberos: map[string]graph.RoleEvidence{dc: {Clients: 20}},
		LDAP:     map[string]graph.RoleEvidence{dc: {Clients: 20}},
		DNS:      map[string]graph.RoleEvidence{dns: {Clients: 20}},
		SMB:      map[string]graph.RoleEvidence{file: {Clients: 20}},
	}
	return edges, ev
}

func hasRole(n graph.Node, r graph.Role) bool {
	for _, a := range n.Roles {
		if a.Role == r {
			return true
		}
	}
	return false
}

func TestPipelineKnownTerrainRanksCorrectly(t *testing.T) {
	edges, ev := synthetic()
	m := graph.Build(edges)
	m.InferRoles(ev)
	res := score.Score(m)
	if res.BetweennessSampled {
		t.Fatal("tiny graph must get exact betweenness")
	}
	snap := m.Snapshot(graph.SnapshotMeta{Window: "24h"})

	byIP := map[string]graph.Node{}
	for _, n := range snap.Nodes {
		byIP[n.IP] = n
	}

	// Roles.
	for ip, want := range map[string]graph.Role{
		"10.0.1.10": graph.RoleDC,
		"10.0.1.11": graph.RoleDNS,
		"10.0.2.20": graph.RoleFileServer,
		"10.0.1.50": graph.RoleJumpBox,
	} {
		if !hasRole(byIP[ip], want) {
			t.Errorf("%s: want role %s, got %+v", ip, want, byIP[ip].Roles)
		}
	}
	// Workstations honest Unknown.
	if !hasRole(byIP["10.0.3.41"], graph.RoleUnknown) {
		t.Errorf("workstation should be Unknown, got %+v", byIP["10.0.3.41"].Roles)
	}
	// Ranking: DC, DNS, file server occupy the top 3 (order among them may vary).
	top := map[string]bool{}
	for _, n := range snap.Nodes[:3] {
		top[n.IP] = true
	}
	for _, ip := range []string{"10.0.1.10", "10.0.1.11", "10.0.2.20"} {
		if !top[ip] {
			t.Errorf("expected %s in top-3, top-3 was %v (ranks: dc=%d dns=%d file=%d)",
				ip, keys(top), byIP["10.0.1.10"].Scores.Rank, byIP["10.0.1.11"].Scores.Rank, byIP["10.0.2.20"].Scores.Rank)
		}
	}
	// Evidence strings attached to every asserted role.
	for _, a := range byIP["10.0.1.10"].Roles {
		if a.Role != graph.RoleUnknown && len(a.Evidence) == 0 {
			t.Errorf("role %s asserted without evidence", a.Role)
		}
	}
	// Snapshot ordering: rank 1 first.
	if snap.Nodes[0].Scores.Rank != 1 {
		t.Errorf("snapshot not rank-ordered, first node rank=%d", snap.Nodes[0].Scores.Rank)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
