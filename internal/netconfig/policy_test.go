package netconfig

import (
	"reflect"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// edgeIOSDevice: owns 10.0.1.0/24, EDGE_IN bound `in`:
//
//	deny  tcp 10.0.1.0/24 any eq 445
//	permit ip  any any
func edgeIOSDevice() DeclaredDevice {
	return DeclaredDevice{
		Source: "edge.cfg", Vendor: "cisco-ios", Hostname: "edge-rtr",
		Interfaces: []Interface{{
			Name: "Gi0/0", Prefixes: []string{"10.0.1.1/24"},
			Bindings: []Binding{{Ruleset: "EDGE_IN", Direction: In}},
		}},
		Rulesets: []Ruleset{{
			Name: "EDGE_IN", Default: Deny,
			Rules: []Rule{
				{Action: Deny, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
					DstPorts: PortRange{445, 445}, Line: 10, Raw: "deny tcp 10.0.1.0/24 any eq 445"},
				{Action: Permit, Proto: "ip", Src: anyCIDR, Dst: anyCIDR, Line: 20, Raw: "permit ip any any"},
			},
		}},
	}
}

func edge(src, dst string, port uint16) graph.Edge {
	return graph.Edge{Src: src, Dst: dst, Port: port}
}

func edgeProto(src, dst string, port uint16, proto string) graph.Edge {
	return graph.Edge{Src: src, Dst: dst, Port: port, Proto: proto}
}

// The edge deny rule is tcp-only. A udp-proto edge must not match it; the same
// flow with empty proto still does (both-protos fallback); a tcp-proto edge
// matches.
func TestDiffPolicy_ProtoScopedMatching(t *testing.T) {
	dev := edgeIOSDevice()

	udp := DiffPolicy(graph.Snapshot{Edges: []graph.Edge{
		edgeProto("10.0.1.5", "10.0.2.9", 445, "udp"),
	}}, []DeclaredDevice{dev})
	if len(udp.Violations) != 0 {
		t.Errorf("udp edge should not hit tcp-only deny, got %+v", udp.Violations)
	}

	empty := DiffPolicy(graph.Snapshot{Edges: []graph.Edge{
		edgeProto("10.0.1.5", "10.0.2.9", 445, ""),
	}}, []DeclaredDevice{dev})
	if len(empty.Violations) != 1 {
		t.Errorf("empty-proto edge should hit deny via fallback, got %+v", empty.Violations)
	}

	tcp := DiffPolicy(graph.Snapshot{Edges: []graph.Edge{
		edgeProto("10.0.1.5", "10.0.2.9", 445, "tcp"),
	}}, []DeclaredDevice{dev})
	if len(tcp.Violations) != 1 {
		t.Errorf("tcp edge should hit tcp deny, got %+v", tcp.Violations)
	}
}

func TestDiffPolicy_DenyHitAndPermitPass(t *testing.T) {
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.1.5", "10.0.2.9", 445), // in scope, hits deny -> Violation
		edge("10.0.1.6", "10.0.2.9", 80),  // permit ip any any -> no violation
		edge("10.0.1.7", "10.0.2.9", 53),  // proto-irrelevant flow -> permit -> no violation
	}}
	res := DiffPolicy(snap, []DeclaredDevice{edgeIOSDevice()})

	if len(res.Violations) != 1 {
		t.Fatalf("want 1 violation, got %d: %+v", len(res.Violations), res.Violations)
	}
	v := res.Violations[0]
	if v.Device != "edge-rtr" || v.Ruleset != "EDGE_IN" || v.Rule.Line != 10 {
		t.Errorf("wrong violation: %+v", v)
	}
	if v.Edge.Port != 445 || v.Edge.Src != "10.0.1.5" {
		t.Errorf("violation edge wrong: %+v", v.Edge)
	}
	if v.Confidence != "full" {
		t.Errorf("confidence = %q, want full", v.Confidence)
	}
	// permit ip any any decided edges 80 and 53, so it is not unused.
	if len(res.UnusedPermits) != 0 {
		t.Errorf("want 0 unused permits, got %+v", res.UnusedPermits)
	}
}

func TestDiffPolicy_OutDirection(t *testing.T) {
	// Same ruleset bound Out: scope is edge.dst in prefix.
	dev := edgeIOSDevice()
	dev.Interfaces[0].Bindings = []Binding{{Ruleset: "EDGE_IN", Direction: Out}}
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.9.9", "10.0.1.5", 445), // dst in prefix, but src 10.0.9.9 not matched by deny src -> permit
		edge("10.0.1.5", "10.0.9.9", 445), // dst NOT in prefix -> out of scope entirely
	}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	// deny rule src is 10.0.1.0/24; first edge src is 10.0.9.9 -> permit; second out of scope.
	if len(res.Violations) != 0 {
		t.Fatalf("want 0 violations for out binding, got %+v", res.Violations)
	}
}

func TestDiffPolicy_ImplicitDeny(t *testing.T) {
	// IOS ruleset with no catch-all: unmatched edge hits the implicit deny.
	dev := DeclaredDevice{
		Vendor: "cisco-ios", Hostname: "lock-rtr",
		Interfaces: []Interface{{
			Name: "Gi0", Prefixes: []string{"10.0.1.1/24"},
			Bindings: []Binding{{Ruleset: "LOCK", Direction: In}},
		}},
		Rulesets: []Ruleset{{
			Name: "LOCK", Default: Deny,
			Rules: []Rule{{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
				DstPorts: PortRange{22, 22}, Line: 5, Raw: "permit tcp 10.0.1.0/24 any eq 22"}},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{edge("10.0.1.5", "10.0.2.9", 445)}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})

	if len(res.Violations) != 1 {
		t.Fatalf("want 1 implicit-deny violation, got %+v", res.Violations)
	}
	if got := res.Violations[0].Rule.Raw; got != "implicit deny (default)" {
		t.Errorf("violation rule = %q, want implicit deny", got)
	}
	// The port-22 permit decided nothing -> unused.
	if len(res.UnusedPermits) != 1 || res.UnusedPermits[0].Rule.Line != 5 {
		t.Errorf("want 1 unused permit (line 5), got %+v", res.UnusedPermits)
	}
}

func TestDiffPolicy_UniFiDefaultPermit(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "unifi", Hostname: "udm",
		VLANs: []VLAN{{ID: 10, Subnet: "10.0.1.0/24", Purpose: "corporate"}},
		Rulesets: []Ruleset{{
			Name: "LAN_IN", Default: Permit, // controller lists only exceptions
			Rules: []Rule{{Action: Deny, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
				DstPorts: PortRange{3389, 3389}, Line: 0, Raw: "unifi LAN_IN: drop"}},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.1.5", "10.0.2.9", 80),   // cross-subnet, no rule match -> default permit -> ok
		edge("10.0.1.5", "10.0.2.9", 3389), // cross-subnet, hits the deny -> violation
		edge("10.0.1.5", "10.0.1.9", 3389), // same-VLAN, switches locally -> not evaluated
	}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	if len(res.Violations) != 1 || res.Violations[0].Edge.Dst != "10.0.2.9" {
		t.Fatalf("want 1 cross-subnet violation on 3389, got %+v", res.Violations)
	}
}

// Intra-subnet flows switch locally and never reach the router's ACL; an
// In-bound deny must not flag them (false-positive regression guard).
func TestDiffPolicy_IntraSubnetNoViolation(t *testing.T) {
	dev := edgeIOSDevice() // EDGE_IN: deny tcp 10.0.1.0/24 any eq 445
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.1.5", "10.0.1.9", 445), // both in 10.0.1.0/24 -> non-traversing
	}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	if len(res.Violations) != 0 {
		t.Fatalf("intra-subnet flow must not violate, got %+v", res.Violations)
	}
}

// GUEST_IN scopes to guest-purpose subnets; LAN_IN to corporate. A guest-src
// flow is judged by GUEST_IN, a corporate-src flow by LAN_IN.
func TestDiffPolicy_UniFiPurposeScoping(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "unifi", Hostname: "udm",
		VLANs: []VLAN{
			{ID: 10, Subnet: "10.0.1.0/24", Purpose: "corporate"},
			{ID: 40, Subnet: "10.0.40.0/24", Purpose: "guest"},
		},
		Rulesets: []Ruleset{
			{Name: "LAN_IN", Default: Permit, Rules: []Rule{
				{Action: Deny, Proto: "tcp", Src: anyCIDR, Dst: anyCIDR, DstPorts: PortRange{22, 22}, Line: 1, Raw: "lan drop 22"}}},
			{Name: "GUEST_IN", Default: Permit, Rules: []Rule{
				{Action: Deny, Proto: "tcp", Src: anyCIDR, Dst: anyCIDR, DstPorts: PortRange{445, 445}, Line: 1, Raw: "guest drop 445"}}},
		},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.1.5", "10.0.2.9", 22),    // corporate src, cross-subnet -> LAN_IN deny 22
		edge("10.0.40.5", "10.0.2.9", 445),  // guest src, cross-subnet -> GUEST_IN deny 445
		edge("10.0.40.5", "10.0.40.9", 445), // same guest VLAN -> not evaluated
		edge("10.0.1.5", "10.0.2.9", 445),   // corporate src on 445 -> LAN_IN permits (no deny 445)
	}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	got := map[string]uint16{}
	for _, v := range res.Violations {
		got[v.Ruleset] = v.Edge.Port
	}
	if len(res.Violations) != 2 || got["LAN_IN"] != 22 || got["GUEST_IN"] != 445 {
		t.Fatalf("want LAN_IN:22 + GUEST_IN:445, got %+v", res.Violations)
	}
}

func TestDiffPolicy_UniFiWANIn(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "unifi", Hostname: "udm",
		VLANs: []VLAN{{ID: 10, Subnet: "10.0.1.0/24"}},
		Rulesets: []Ruleset{{
			Name: "WAN_IN", Default: Permit,
			Rules: []Rule{{Action: Deny, Proto: "ip", Src: anyCIDR, Dst: "10.0.1.0/24",
				DstPorts: PortRange{445, 445}, Line: 0, Raw: "unifi WAN_IN: drop"}},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("203.0.113.7", "10.0.1.9", 445), // external src -> WAN scope -> deny -> violation
		edge("10.0.1.5", "10.0.1.9", 445),    // internal src -> not WAN scope -> ignored
	}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	if len(res.Violations) != 1 || res.Violations[0].Edge.Src != "203.0.113.7" {
		t.Fatalf("want 1 WAN_IN violation from external src, got %+v", res.Violations)
	}
}

// Unknown/empty VLAN purpose defaults to corporate (LAN_IN), never silently
// dropped.
func TestDiffPolicy_UnknownPurposeIsCorporate(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "unifi", Hostname: "udm",
		VLANs: []VLAN{{ID: 20, Subnet: "10.0.5.0/24"}}, // no Purpose
		Rulesets: []Ruleset{{
			Name: "LAN_IN", Default: Permit,
			Rules: []Rule{{Action: Deny, Proto: "ip", Src: anyCIDR, Dst: anyCIDR, DstPorts: PortRange{445, 445}, Line: 0, Raw: "drop"}},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{edge("10.0.5.5", "10.0.1.9", 445)}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	if len(res.Violations) != 1 {
		t.Fatalf("unknown-purpose subnet must be evaluated under LAN_IN, got %+v", res.Violations)
	}
}

func TestDiffPolicy_CaveatPartialConfidence(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "cisco-ios", Hostname: "cav-rtr",
		Interfaces: []Interface{{
			Name: "Gi0", Prefixes: []string{"10.0.1.1/24"},
			Bindings: []Binding{{Ruleset: "MIX", Direction: In}},
		}},
		Rulesets: []Ruleset{{
			Name: "MIX", Default: Deny,
			Rules: []Rule{
				{Action: Deny, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR, Line: 5,
					Caveat: "object-group unresolved", Raw: "deny tcp obj"},
				{Action: Deny, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
					DstPorts: PortRange{445, 445}, Line: 10, Raw: "deny tcp 10.0.1.0/24 any eq 445"},
				{Action: Permit, Proto: "ip", Src: anyCIDR, Dst: anyCIDR, Line: 20, Raw: "permit ip any any"},
			},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{edge("10.0.1.5", "10.0.2.9", 445)}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	if len(res.Violations) != 1 {
		t.Fatalf("want 1 violation, got %+v", res.Violations)
	}
	if res.Violations[0].Confidence != "partial" {
		t.Errorf("confidence = %q, want partial", res.Violations[0].Confidence)
	}
	if res.Violations[0].Rule.Line != 10 {
		t.Errorf("caveated rule must be skipped; decided by line %d", res.Violations[0].Rule.Line)
	}
	if res.SkippedRules != 1 {
		t.Errorf("SkippedRules = %d, want 1", res.SkippedRules)
	}
}

func TestDiffPolicy_UnusedPermit(t *testing.T) {
	dev := DeclaredDevice{
		Vendor: "cisco-ios", Hostname: "up-rtr",
		Interfaces: []Interface{{
			Name: "Gi0", Prefixes: []string{"10.0.1.1/24"},
			Bindings: []Binding{{Ruleset: "P", Direction: In}},
		}},
		Rulesets: []Ruleset{{
			Name: "P", Default: Deny,
			Rules: []Rule{
				{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
					DstPorts: PortRange{80, 80}, Line: 5, Raw: "permit tcp 10.0.1.0/24 any eq 80"},
				{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: anyCIDR,
					DstPorts: PortRange{22, 22}, Line: 10, Raw: "permit tcp 10.0.1.0/24 any eq 22"},
			},
		}},
	}
	snap := graph.Snapshot{Edges: []graph.Edge{edge("10.0.1.5", "10.0.2.9", 80)}}
	res := DiffPolicy(snap, []DeclaredDevice{dev})
	// port 80 permit used; port 22 permit unused.
	if len(res.UnusedPermits) != 1 || res.UnusedPermits[0].Rule.Line != 10 {
		t.Fatalf("want 1 unused permit (line 10), got %+v", res.UnusedPermits)
	}
}

func TestDiffPolicy_Deterministic(t *testing.T) {
	dev := edgeIOSDevice()
	snap := graph.Snapshot{Edges: []graph.Edge{
		edge("10.0.1.9", "10.0.2.9", 445),
		edge("10.0.1.5", "10.0.2.9", 445),
		edge("10.0.1.7", "10.0.2.9", 445),
	}}
	a := DiffPolicy(snap, []DeclaredDevice{dev})
	b := DiffPolicy(snap, []DeclaredDevice{dev})
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("non-deterministic output:\n%+v\n%+v", a, b)
	}
	if len(a.Violations) != 3 {
		t.Fatalf("want 3 violations, got %d", len(a.Violations))
	}
	// Sorted ascending by edge src.
	if a.Violations[0].Edge.Src != "10.0.1.5" || a.Violations[2].Edge.Src != "10.0.1.9" {
		t.Errorf("violations not sorted by src: %+v", a.Violations)
	}
}
