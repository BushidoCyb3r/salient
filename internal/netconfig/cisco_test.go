package netconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T) DeclaredDevice {
	t.Helper()
	f, err := os.Open("../../testdata/netconfig/ios-router.cfg")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	dev, err := ParseCiscoIOS(f, "ios-router.cfg")
	if err != nil {
		t.Fatalf("ParseCiscoIOS: %v", err)
	}
	return dev
}

func TestParseCiscoIOS_Basics(t *testing.T) {
	dev := loadFixture(t)

	if dev.Vendor != "cisco-ios" {
		t.Errorf("Vendor = %q, want cisco-ios", dev.Vendor)
	}
	if dev.Source != "ios-router.cfg" {
		t.Errorf("Source = %q", dev.Source)
	}
	if dev.Hostname != "edge-rtr-01" {
		t.Errorf("Hostname = %q, want edge-rtr-01", dev.Hostname)
	}
	if len(dev.Interfaces) != 3 {
		t.Fatalf("interface count = %d, want 3: %+v", len(dev.Interfaces), dev.Interfaces)
	}
}

func TestParseCiscoIOS_Interfaces(t *testing.T) {
	dev := loadFixture(t)
	byName := map[string]Interface{}
	for _, i := range dev.Interfaces {
		byName[i.Name] = i
	}

	wan, ok := byName["GigabitEthernet0/0"]
	if !ok {
		t.Fatal("missing Gi0/0")
	}
	wantPrefixes := []string{"203.0.113.2/30", "203.0.113.6/30"}
	if strings.Join(wan.Prefixes, ",") != strings.Join(wantPrefixes, ",") {
		t.Errorf("Gi0/0 prefixes = %v, want %v", wan.Prefixes, wantPrefixes)
	}
	if len(wan.Bindings) != 1 || wan.Bindings[0].Ruleset != "EDGE_IN" || wan.Bindings[0].Direction != In {
		t.Errorf("Gi0/0 bindings = %+v", wan.Bindings)
	}

	sh, ok := byName["GigabitEthernet0/1"]
	if !ok || !sh.Shutdown {
		t.Errorf("Gi0/1 shutdown flag = %+v", sh)
	}

	sub, ok := byName["GigabitEthernet0/0.40"]
	if !ok {
		t.Fatal("missing subinterface Gi0/0.40")
	}
	if sub.VLAN != 40 {
		t.Errorf("subinterface VLAN = %d, want 40", sub.VLAN)
	}
	if len(sub.Prefixes) != 1 || sub.Prefixes[0] != "10.0.40.1/24" {
		t.Errorf("subinterface prefixes = %v", sub.Prefixes)
	}
}

func TestParseCiscoIOS_Switchport(t *testing.T) {
	f, err := os.Open("../../testdata/netconfig/ios-switch.cfg")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	dev, err := ParseCiscoIOS(f, "ios-switch.cfg")
	if err != nil {
		t.Fatalf("ParseCiscoIOS: %v", err)
	}
	byName := map[string]Interface{}
	for _, i := range dev.Interfaces {
		byName[i.Name] = i
	}

	access, ok := byName["GigabitEthernet0/1"]
	if !ok {
		t.Fatal("missing access port Gi0/1")
	}
	if access.VLAN != 40 {
		t.Errorf("access port VLAN = %d, want 40", access.VLAN)
	}
	if access.Trunk {
		t.Errorf("access port should not be a trunk: %+v", access)
	}

	trunk, ok := byName["GigabitEthernet0/24"]
	if !ok {
		t.Fatal("missing trunk port Gi0/24")
	}
	if !trunk.Trunk {
		t.Errorf("trunk port Trunk = false, want true: %+v", trunk)
	}
	if trunk.VLAN != 0 {
		t.Errorf("trunk port VLAN = %d, want 0", trunk.VLAN)
	}
}

func TestParseCiscoIOS_RoutesPoolVLAN(t *testing.T) {
	dev := loadFixture(t)

	if len(dev.Routes) != 2 {
		t.Fatalf("routes = %+v", dev.Routes)
	}
	if dev.Routes[0].Prefix != "0.0.0.0/0" || dev.Routes[0].NextHop != "203.0.113.1" {
		t.Errorf("route0 = %+v", dev.Routes[0])
	}
	if dev.Routes[1].Prefix != "10.5.0.0/16" || dev.Routes[1].NextHop != "10.0.1.254" {
		t.Errorf("route1 = %+v", dev.Routes[1])
	}

	if len(dev.DHCPPools) != 1 {
		t.Fatalf("pools = %+v", dev.DHCPPools)
	}
	p := dev.DHCPPools[0]
	if p.Network != "10.0.1.0/24" || p.Router != "10.0.1.1" {
		t.Errorf("pool = %+v", p)
	}
	if len(p.DNS) != 2 || p.DNS[0] != "10.0.1.2" || p.DNS[1] != "1.1.1.1" {
		t.Errorf("pool DNS = %v", p.DNS)
	}

	if len(dev.VLANs) != 1 || dev.VLANs[0].ID != 40 || dev.VLANs[0].Name != "GUEST" {
		t.Errorf("vlans = %+v", dev.VLANs)
	}
}

func ruleset(t *testing.T, dev DeclaredDevice, name string) Ruleset {
	t.Helper()
	rs := dev.Ruleset(name)
	if rs == nil {
		t.Fatalf("ruleset %q not found; have %+v", name, dev.Rulesets)
	}
	return *rs
}

func TestParseCiscoIOS_ExtendedACL(t *testing.T) {
	dev := loadFixture(t)
	rs := ruleset(t, dev, "EDGE_IN")

	if len(rs.Rules) != 9 {
		t.Fatalf("EDGE_IN rule count = %d, want 9: %+v", len(rs.Rules), rs.Rules)
	}

	// rule 0: permit tcp any host 10.0.1.10 eq 443
	r := rs.Rules[0]
	if r.Action != Permit || r.Proto != "tcp" || r.Src != "0.0.0.0/0" || r.Dst != "10.0.1.10/32" {
		t.Errorf("rule0 = %+v", r)
	}
	if r.DstPorts != (PortRange{443, 443}) || r.Caveat != "" {
		t.Errorf("rule0 ports/caveat = %+v", r)
	}
	if r.Line == 0 || !strings.Contains(r.Raw, "10.0.1.10") {
		t.Errorf("rule0 line/raw = %d %q", r.Line, r.Raw)
	}

	// rule 1: permit tcp 10.0.1.0 0.0.0.255 any eq 22
	if r := rs.Rules[1]; r.Src != "10.0.1.0/24" || r.Dst != "0.0.0.0/0" || r.DstPorts != (PortRange{22, 22}) {
		t.Errorf("rule1 = %+v", r)
	}

	// rule 2: deny ip any any
	if r := rs.Rules[2]; r.Action != Deny || r.Proto != "ip" || r.Src != "0.0.0.0/0" || r.Dst != "0.0.0.0/0" || r.Caveat != "" {
		t.Errorf("rule2 = %+v", r)
	}

	// rule 3: permit udp any eq 53 any  -> source port caveat
	if r := rs.Rules[3]; r.SrcPorts != (PortRange{53, 53}) || r.Caveat != "source-port match unavailable from flow data" {
		t.Errorf("rule3 = %+v", r)
	}

	// rule 4: established
	if r := rs.Rules[4]; r.Caveat != "established unsupported" {
		t.Errorf("rule4 caveat = %q", r.Caveat)
	}

	// rule 5: object-group
	if r := rs.Rules[5]; r.Caveat != "object-group unresolved" {
		t.Errorf("rule5 caveat = %q", r.Caveat)
	}

	// rule 6: discontiguous wildcard
	if r := rs.Rules[6]; r.Caveat != "discontiguous wildcard" {
		t.Errorf("rule6 caveat = %q", r.Caveat)
	}

	// rule 7: unsupported protocol
	if r := rs.Rules[7]; r.Caveat != "unsupported protocol" {
		t.Errorf("rule7 caveat = %q", r.Caveat)
	}

	// rule 8: neq
	if r := rs.Rules[8]; r.Caveat != "neq unsupported" {
		t.Errorf("rule8 caveat = %q", r.Caveat)
	}
}

func TestParseCiscoIOS_NumberedACL(t *testing.T) {
	dev := loadFixture(t)
	rs := ruleset(t, dev, "10")
	if len(rs.Rules) != 2 {
		t.Fatalf("acl 10 rules = %+v", rs.Rules)
	}
	if r := rs.Rules[0]; r.Action != Permit || r.Src != "10.0.1.0/24" || r.Dst != "0.0.0.0/0" {
		t.Errorf("acl10 rule0 = %+v", r)
	}
	if r := rs.Rules[1]; r.Action != Deny || r.Src != "0.0.0.0/0" {
		t.Errorf("acl10 rule1 = %+v", r)
	}
}

func TestParseCiscoIOS_Warnings(t *testing.T) {
	dev := loadFixture(t)
	all := strings.Join(dev.Warnings, "\n")
	for _, want := range []string{"caveat", "vrf", "nat", "route-map"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings missing %q: %v", want, dev.Warnings)
		}
	}
}

func TestParseCiscoIOS_NoSecretsLeak(t *testing.T) {
	dev := loadFixture(t)
	dump := fmt.Sprintf("%+v", dev)
	for _, bad := range []string{"secret", "s3cret", "wr1te", "t4cacs", "$1$", "community", "username"} {
		if strings.Contains(dump, bad) {
			t.Errorf("output leaked secret material %q:\n%s", bad, dump)
		}
	}
}

func TestParseCiscoIOS_Errors(t *testing.T) {
	if _, err := ParseCiscoIOS(strings.NewReader("this is\nnot a config\n"), "junk"); err == nil {
		t.Error("expected error on config with zero recognized constructs")
	}
	if _, err := ParseCiscoIOS(strings.NewReader("hostname r1\n"), "min"); err != nil {
		t.Errorf("minimal valid config errored: %v", err)
	}
}

func TestLooksLikeIOS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"hostname foo\n", true},
		{"interface Gi0/0\n", true},
		{"access-list 10 permit any\n", true},
		{"! comment\nversion 15\n", false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeIOS([]byte(c.in)); got != c.want {
			t.Errorf("LooksLikeIOS(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
