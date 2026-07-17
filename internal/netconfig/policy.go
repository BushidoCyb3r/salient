package netconfig

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// Violation is an observed flow that a declared device's policy denies.
type Violation struct {
	Device     string     `json:"device"`
	Source     string     `json:"source"` // config file the deny rule was parsed from
	Ruleset    string     `json:"ruleset"`
	Rule       Rule       `json:"rule"`       // the deny rule hit (Raw+Line ride along)
	Edge       graph.Edge `json:"edge"`       // the observed flow
	Confidence string     `json:"confidence"` // "full" | "partial" (device had caveated rules)
}

// UnusedPermit is a caveat-free permit rule that decided zero observed edges.
type UnusedPermit struct {
	Device  string `json:"device"`
	Ruleset string `json:"ruleset"`
	Rule    Rule   `json:"rule"`
}

// PolicyResult is the declared-vs-observed policy reconciliation.
type PolicyResult struct {
	Violations    []Violation    `json:"violations"`
	UnusedPermits []UnusedPermit `json:"unused_permits"`
	SkippedRules  int            `json:"skipped_rules"` // caveated rules, never evaluated
	Warnings      []string       `json:"warnings,omitempty"`
}

// defaultDeny is the synthetic rule reported when an IOS ruleset's implicit
// deny (no explicit rule matched) is what denies a flow.
var defaultDeny = Rule{Action: Deny, Proto: "ip", Src: anyCIDR, Dst: anyCIDR, Raw: "implicit deny (default)"}

// DiffPolicy evaluates observed edges against each declared device's bound
// rulesets. Pure and deterministic: every output slice is sorted, so two runs
// on equal input are reflect.DeepEqual.
//
// All scopes are traversal-only: a ruleset judges a flow only when its src and
// dst sit on opposite sides of the enforcement point (same-subnet flows switch
// locally and never reach it).
//
// IOS: a ruleset applies where it is bound. Direction In → src inside the bound
// interface's prefix and dst outside it; Out → dst inside and src outside.
//
// UniFi has no bindings, so its rulesets apply by name: LAN_IN scopes to
// corporate (and unknown-purpose) VLAN subnets, GUEST_IN to guest-purpose
// subnets — src in a scoped subnet, dst in a different subnet. WAN_IN scopes to
// an external src reaching an internal dst.
func DiffPolicy(snap graph.Snapshot, devs []DeclaredDevice) PolicyResult {
	var res PolicyResult

	// Pre-parse edge endpoints once; drop edges with unparseable IPs.
	type pedge struct {
		src, dst netip.Addr
		e        graph.Edge
	}
	var edges []pedge
	for _, e := range snap.Edges {
		s, err1 := netip.ParseAddr(e.Src)
		d, err2 := netip.ParseAddr(e.Dst)
		if err1 != nil || err2 != nil {
			continue
		}
		edges = append(edges, pedge{s, d, e})
	}

	for _, dev := range devs {
		// Device-level caveat flag drives Violation.Confidence; count every
		// caveated rule for SkippedRules regardless of binding.
		devHasCaveat := false
		for _, rs := range dev.Rulesets {
			for _, r := range rs.Rules {
				if r.Caveat != "" {
					devHasCaveat = true
					res.SkippedRules++
				}
			}
		}
		conf := "full"
		if devHasCaveat {
			conf = "partial"
		}

		// An application is one enforcement point: a ruleset plus the scope
		// predicate deciding which edges it governs.
		type application struct {
			name  string
			rs    *Ruleset
			scope func(src, dst netip.Addr) bool
		}
		var apps []application

		if dev.Vendor == "unifi" {
			// Scope by network purpose. Guest is the only purpose the model
			// treats specially; every other value (including empty/unknown)
			// counts as corporate — safer to evaluate a subnet than to ignore
			// its policy. ponytail: split out wan/vpn purposes if they ever
			// need distinct handling.
			var corpNets, guestNets []netip.Prefix
			for _, v := range dev.VLANs {
				p, err := netip.ParsePrefix(v.Subnet)
				if err != nil {
					continue
				}
				p = p.Masked()
				if v.Purpose == "guest" {
					guestNets = append(guestNets, p)
				} else {
					corpNets = append(corpNets, p)
				}
			}
			declared := dev.OwnedPrefixes()
			for i := range dev.Rulesets {
				rs := &dev.Rulesets[i]
				switch rs.Name {
				case "LAN_IN":
					nets := corpNets
					apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
						return traverses(nets, src, dst)
					}})
				case "GUEST_IN":
					nets := guestNets
					apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
						return traverses(nets, src, dst)
					}})
				case "WAN_IN":
					// External src into an internal dst traverses the gateway;
					// external→external never reaches it.
					nets := declared
					apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
						return !containsAny(nets, src) && containsAny(nets, dst)
					}})
				default:
					if strings.HasPrefix(rs.Name, "ZONE:") {
						nets := declared
						apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
							return crossesDeclaredSubnet(nets, src, dst)
						}})
					}
				}
				// Other ruleset names (WAN_OUT, *_LOCAL, ...) are not
				// observed-ingress policy; skip. ponytail: add named scopes if
				// egress/local evaluation is ever needed.
			}
		} else {
			for _, iface := range dev.Interfaces {
				if iface.Shutdown {
					continue // a binding on a down interface enforces nothing
				}
				var prefixes []netip.Prefix
				for _, c := range iface.Prefixes {
					if p, err := netip.ParsePrefix(c); err == nil {
						prefixes = append(prefixes, p.Masked())
					}
				}
				for _, b := range iface.Bindings {
					rs := dev.Ruleset(b.Ruleset)
					if rs == nil {
						continue
					}
					nets := prefixes
					// Traversal only: a flow the ACL never sees can't be denied.
					// In → src enters the segment from outside it; Out → dst is
					// in the segment and src is not. Same-subnet flows switch
					// locally and never reach the router.
					if b.Direction == In {
						apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
							return containsAny(nets, src) && !containsAny(nets, dst)
						}})
					} else {
						apps = append(apps, application{rs.Name, rs, func(src, dst netip.Addr) bool {
							return containsAny(nets, dst) && !containsAny(nets, src)
						}})
					}
				}
			}
		}

		// used[rulesetName][ruleIdx]: did this rule decide any edge? Keyed by
		// name so a ruleset bound at two interfaces shares one usage record.
		used := map[string][]bool{}
		applied := map[string]bool{}
		for _, app := range apps {
			applied[app.name] = true
			if used[app.name] == nil {
				used[app.name] = make([]bool, len(app.rs.Rules))
			}
			u := used[app.name]
			for _, pe := range edges {
				if !app.scope(pe.src, pe.dst) {
					continue
				}
				// When the edge carries a transport, evaluate only that proto.
				// Empty values fall back to both tcp and udp for pre-proto
				// snapshots and grids where network.transport is unmapped. First
				// matching rule per proto decides; a deny on any evaluated proto
				// is one Violation.
				// ponytail: up to two passes over the rule list per edge; fine
				// at config scale, revisit if edge counts get large.
				protos := []string{"tcp", "udp"}
				if pe.e.Proto != "" {
					protos = []string{pe.e.Proto}
				}
				denied := false
				denyRule := defaultDeny
				for _, proto := range protos {
					idx := firstMatch(app.rs.Rules, pe.src, pe.dst, pe.e.Port, proto)
					if idx < 0 {
						if app.rs.Default == Deny && !denied {
							denied = true
							denyRule = defaultDeny
						}
						continue
					}
					if app.rs.Rules[idx].Action == Deny {
						if !denied {
							denied = true
							denyRule = app.rs.Rules[idx]
						}
					} else {
						u[idx] = true // permit decided this edge
					}
				}
				if denied {
					res.Violations = append(res.Violations, Violation{
						Device: dev.Hostname, Source: dev.Source, Ruleset: app.name,
						Rule: denyRule, Edge: pe.e, Confidence: conf,
					})
				}
			}
		}

		// Caveat-free permits in applied rulesets that decided nothing.
		for i := range dev.Rulesets {
			rs := &dev.Rulesets[i]
			if !applied[rs.Name] {
				continue
			}
			u := used[rs.Name]
			for j, r := range rs.Rules {
				if r.Caveat == "" && r.Action == Permit && !u[j] {
					res.UnusedPermits = append(res.UnusedPermits, UnusedPermit{
						Device: dev.Hostname, Ruleset: rs.Name, Rule: r,
					})
				}
			}
		}
	}

	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Ruleset != b.Ruleset {
			return a.Ruleset < b.Ruleset
		}
		if a.Rule.Line != b.Rule.Line {
			return a.Rule.Line < b.Rule.Line
		}
		if a.Edge.Src != b.Edge.Src {
			return a.Edge.Src < b.Edge.Src
		}
		if a.Edge.Dst != b.Edge.Dst {
			return a.Edge.Dst < b.Edge.Dst
		}
		return a.Edge.Port < b.Edge.Port
	})
	sort.SliceStable(res.UnusedPermits, func(i, j int) bool {
		a, b := res.UnusedPermits[i], res.UnusedPermits[j]
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Ruleset != b.Ruleset {
			return a.Ruleset < b.Ruleset
		}
		return a.Rule.Line < b.Rule.Line
	})
	return res
}

// crossesDeclaredSubnet requires the flow to touch the declared controller and
// excludes flows that remain inside one declared L2 subnet. Official UniFi zone
// policies are otherwise scoped by each parsed rule's explicit endpoint CIDRs.
func crossesDeclaredSubnet(nets []netip.Prefix, src, dst netip.Addr) bool {
	if !containsAny(nets, src) && !containsAny(nets, dst) {
		return false
	}
	for _, p := range nets {
		if p.Contains(src) && p.Contains(dst) {
			return false
		}
	}
	return true
}

// traverses reports whether a flow crosses the gateway for one of nets: src is
// inside a scoped subnet and dst is not in that same subnet. Same-subnet flows
// switch locally and never reach the enforcement point; cross-subnet flows
// (including between two scoped subnets) do.
func traverses(nets []netip.Prefix, src, dst netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(src) {
			return !p.Contains(dst)
		}
	}
	return false
}

func containsAny(nets []netip.Prefix, a netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func firstMatch(rules []Rule, src, dst netip.Addr, port uint16, proto string) int {
	for i, r := range rules {
		if r.Matches(src, dst, port, proto) {
			return i
		}
	}
	return -1
}
