package netconfig

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func TestPortRangeContains(t *testing.T) {
	cases := []struct {
		name string
		pr   PortRange
		port uint16
		want bool
	}{
		{"any matches all", PortRange{0, 0}, 443, true},
		{"any matches zero", PortRange{0, 0}, 0, true},
		{"lo boundary", PortRange{100, 200}, 100, true},
		{"hi boundary", PortRange{100, 200}, 200, true},
		{"below lo", PortRange{100, 200}, 99, false},
		{"above hi", PortRange{100, 200}, 201, false},
		{"single port hit", PortRange{80, 80}, 80, true},
		{"single port miss", PortRange{80, 80}, 81, false},
	}
	for _, c := range cases {
		if got := c.pr.Contains(c.port); got != c.want {
			t.Errorf("%s: Contains(%d) = %v, want %v", c.name, c.port, got, c.want)
		}
	}
}

func TestPortRangeAny(t *testing.T) {
	if !(PortRange{}).Any() {
		t.Error("zero PortRange should be Any")
	}
	if (PortRange{0, 100}).Any() {
		t.Error("{0,100} should not be Any")
	}
}

func TestRuleMatches(t *testing.T) {
	cases := []struct {
		name     string
		rule     Rule
		src, dst string
		dstPort  uint16
		proto    string
		want     bool
	}{
		{
			name: "any src any dst tcp",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: true,
		},
		{
			name: "cidr containment hit",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: "10.0.2.0/24"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: true,
		},
		{
			name: "src outside cidr",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: "10.0.2.0/24"},
			src:  "10.0.3.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: false,
		},
		{
			name: "dst outside cidr",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "10.0.1.0/24", Dst: "10.0.2.0/24"},
			src:  "10.0.1.5", dst: "10.0.9.9", dstPort: 443, proto: "tcp", want: false,
		},
		{
			name: "dst port in range",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0", DstPorts: PortRange{80, 443}},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 100, proto: "tcp", want: true,
		},
		{
			name: "dst port out of range",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0", DstPorts: PortRange{80, 443}},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 8080, proto: "tcp", want: false,
		},
		{
			name: "any dst port range matches",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 65535, proto: "tcp", want: true,
		},
		{
			name: "proto ip matches tcp",
			rule: Rule{Action: Permit, Proto: "ip", Src: "0.0.0.0/0", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: true,
		},
		{
			name: "proto ip matches udp",
			rule: Rule{Action: Permit, Proto: "ip", Src: "0.0.0.0/0", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 53, proto: "udp", want: true,
		},
		{
			name: "proto mismatch",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 53, proto: "udp", want: false,
		},
		{
			name: "caveated rule never matches",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "0.0.0.0/0", Caveat: "source-port match unavailable from flow data"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: false,
		},
		{
			name: "invalid src cidr never matches",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "not-a-cidr", Dst: "0.0.0.0/0"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: false,
		},
		{
			name: "invalid dst cidr never matches",
			rule: Rule{Action: Permit, Proto: "tcp", Src: "0.0.0.0/0", Dst: "garbage"},
			src:  "10.0.1.5", dst: "10.0.2.9", dstPort: 443, proto: "tcp", want: false,
		},
	}
	for _, c := range cases {
		got := c.rule.Matches(mustAddr(t, c.src), mustAddr(t, c.dst), c.dstPort, c.proto)
		if got != c.want {
			t.Errorf("%s: Matches = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOwnedPrefixes(t *testing.T) {
	d := DeclaredDevice{
		Interfaces: []Interface{
			{Name: "Gi0/0", Prefixes: []string{"10.0.1.1/24"}},
			{Name: "Gi0/1", Prefixes: []string{"10.0.1.1/24", "10.0.2.1/24"}},  // dup + new
			{Name: "Gi0/2", Prefixes: []string{"10.0.3.1/24"}, Shutdown: true}, // excluded
			{Name: "Gi0/3", Prefixes: []string{"not-a-cidr"}},                  // skipped
		},
		VLANs: []VLAN{
			{ID: 10, Subnet: "10.0.4.0/24"},
			{ID: 20, Subnet: ""},            // no subnet, skipped
			{ID: 30, Subnet: "10.0.1.0/24"}, // dup of iface (same masked prefix)
		},
	}
	got := d.OwnedPrefixes()

	want := map[string]bool{
		"10.0.1.0/24": true, // masked from 10.0.1.1/24
		"10.0.2.0/24": true,
		"10.0.4.0/24": true,
	}
	if len(got) != len(want) {
		t.Fatalf("OwnedPrefixes = %v, want %d unique", got, len(want))
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Errorf("unexpected prefix %s in %v", p, got)
		}
	}
}

func TestRulesetLookup(t *testing.T) {
	d := DeclaredDevice{
		Rulesets: []Ruleset{
			{Name: "LAN_IN", Default: Deny},
			{Name: "WAN_IN", Default: Permit},
		},
	}
	if rs := d.Ruleset("WAN_IN"); rs == nil || rs.Default != Permit {
		t.Errorf("Ruleset(WAN_IN) = %+v", rs)
	}
	if rs := d.Ruleset("nope"); rs != nil {
		t.Errorf("Ruleset(nope) = %+v, want nil", rs)
	}
}
