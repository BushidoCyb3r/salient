package netconfig

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// Violation is an observed flow that a declared device's policy denies.
type Violation struct {
	Device     string     `json:"device"`
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
// IOS: a ruleset applies where it is bound. Direction In → the edge's src is
// inside the bound interface's prefix; Out → the edge's dst is. UniFi has no
// bindings, so its rulesets apply by name: LAN_IN scopes to any declared VLAN
// subnet, WAN_IN to sources outside every declared subnet. GUEST_IN cannot be
// scoped — the parser records no per-VLAN network purpose, so guest and
// corporate subnets are indistinguishable — and is skipped with a warning.
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
			var vlanNets, declared []netip.Prefix
			for _, v := range dev.VLANs {
				if p, err := netip.ParsePrefix(v.Subnet); err == nil {
					vlanNets = append(vlanNets, p.Masked())
				}
			}
			declared = dev.OwnedPrefixes()
			for i := range dev.Rulesets {
				rs := &dev.Rulesets[i]
				switch rs.Name {
				case "LAN_IN":
					nets := vlanNets
					apps = append(apps, application{rs.Name, rs, func(src, _ netip.Addr) bool {
						return containsAny(nets, src)
					}})
				case "WAN_IN":
					nets := declared
					apps = append(apps, application{rs.Name, rs, func(src, _ netip.Addr) bool {
						return !containsAny(nets, src)
					}})
				case "GUEST_IN":
					res.Warnings = append(res.Warnings, fmt.Sprintf(
						"device %s: GUEST_IN ruleset skipped — VLAN network purpose is not recorded, so guest subnets cannot be distinguished from corporate", dev.Hostname))
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
					if b.Direction == In {
						apps = append(apps, application{rs.Name, rs, func(src, _ netip.Addr) bool {
							return containsAny(nets, src)
						}})
					} else {
						apps = append(apps, application{rs.Name, rs, func(_, dst netip.Addr) bool {
							return containsAny(nets, dst)
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
				// Edge carries no protocol (graph.Edge has Port/Service only),
				// so evaluate it as both tcp and udp. First matching rule per
				// proto decides; a deny on either proto is one Violation.
				// ponytail: two passes over the rule list per edge; fine at
				// config scale, revisit if edge counts get large.
				denied := false
				denyRule := defaultDeny
				for _, proto := range [2]string{"tcp", "udp"} {
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
						Device: dev.Hostname, Ruleset: app.name,
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
