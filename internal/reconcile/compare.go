package reconcile

import (
	"net/netip"
	"sort"
	"strings"
	"unicode"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// SilentAsset is documented but produced no observed traffic. InBlindSpot
// means its IP falls in a zero-coverage in-scope CIDR — cross-reference the
// blind-spot panel before calling it decommissioned.
type SilentAsset struct {
	Asset
	InBlindSpot bool `json:"in_blind_spot"`
}

// Contradiction is a host whose documented role maps to a role Salient
// infers, but observation disagrees. Hosts whose observed role is Unknown
// are never contradicted — an honest Unknown beats a wrong guess.
type Contradiction struct {
	IP         string       `json:"ip"`
	Hostname   string       `json:"hostname,omitempty"`
	Documented string       `json:"documented"`
	Expected   graph.Role   `json:"expected"`
	Observed   []graph.Role `json:"observed"`
}

// Result is the Phase 3 doc-vs-reality report, designed to hand directly to
// the supported unit's staff.
type Result struct {
	Meta                 graph.SnapshotMeta `json:"meta"`
	DocumentedSilent     []SilentAsset      `json:"documented_silent"`
	ObservedUndocumented []graph.Node       `json:"observed_undocumented"`
	RoleContradicted     []Contradiction    `json:"role_contradicted"`
	Warnings             []string           `json:"warnings,omitempty"`
}

// Compare reconciles the asset list against the snapshot.
func Compare(snap graph.Snapshot, assets []Asset) Result {
	res := Result{Meta: snap.Meta}
	observed := make(map[string]graph.Node, len(snap.Nodes))
	for _, n := range snap.Nodes {
		observed[n.IP] = n
	}
	documented := make(map[string]bool, len(assets))

	var blind []netip.Prefix
	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			blind = append(blind, p)
		}
	}

	for _, a := range assets {
		documented[a.IP] = true
		n, seen := observed[a.IP]
		if !seen {
			res.DocumentedSilent = append(res.DocumentedSilent, SilentAsset{Asset: a, InBlindSpot: inAny(a.IP, blind)})
			continue
		}
		expected := NormalizeRole(a.Role)
		if expected == "" || len(n.Roles) == 0 {
			continue
		}
		obs := uniqueRoles(n)
		if !contains(obs, expected) {
			res.RoleContradicted = append(res.RoleContradicted, Contradiction{
				IP: a.IP, Hostname: a.Hostname, Documented: a.Role, Expected: expected, Observed: obs,
			})
		}
	}

	for _, n := range snap.Nodes {
		if !documented[n.IP] {
			res.ObservedUndocumented = append(res.ObservedUndocumented, n)
		}
	}

	sort.Slice(res.DocumentedSilent, func(i, j int) bool { return res.DocumentedSilent[i].IP < res.DocumentedSilent[j].IP })
	sort.Slice(res.ObservedUndocumented, func(i, j int) bool { return res.ObservedUndocumented[i].IP < res.ObservedUndocumented[j].IP })
	sort.Slice(res.RoleContradicted, func(i, j int) bool { return res.RoleContradicted[i].IP < res.RoleContradicted[j].IP })
	return res
}

// NormalizeRole maps documented free-text role descriptions onto Salient's
// inferred roles. Multiword phrases match by substring; short tokens like
// "dc" or "db" match whole words only, so "datacenter" never becomes a DC.
func NormalizeRole(s string) graph.Role {
	l := strings.ToLower(s)
	tokens := strings.FieldsFunc(l, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	has := func(t string) bool {
		for _, tok := range tokens {
			if tok == t {
				return true
			}
		}
		return false
	}
	switch {
	case strings.Contains(l, "domain controller") || strings.Contains(l, "active directory") || has("dc") || has("ad"):
		return graph.RoleDC
	case has("dns"):
		return graph.RoleDNS
	case has("file") || has("nas") || has("smb") || has("fileserver"):
		return graph.RoleFileServer
	case has("db") || has("database") || has("sql") || has("oracle") || has("postgres") || has("mysql"):
		return graph.RoleDatabase
	case has("jump") || has("bastion") || has("jumpbox"):
		return graph.RoleJumpBox
	case has("web") || has("http") || has("https") || has("iis") || has("apache") || has("nginx") || has("webserver"):
		return graph.RoleWebServer
	}
	return ""
}

func uniqueRoles(n graph.Node) []graph.Role {
	var out []graph.Role
	seen := map[graph.Role]bool{}
	for _, r := range n.Roles {
		if !seen[r.Role] {
			seen[r.Role] = true
			out = append(out, r.Role)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func contains(roles []graph.Role, want graph.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func inAny(ip string, prefixes []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
