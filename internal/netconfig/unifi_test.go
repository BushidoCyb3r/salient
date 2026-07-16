package netconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func loadUniFi(t *testing.T) DeclaredDevice {
	t.Helper()
	files := map[string][]byte{}
	for _, name := range []string{"unifi-networkconf.json", "unifi-firewallrule.json", "unifi-device.json"} {
		b, err := os.ReadFile("../../testdata/netconfig/" + name)
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		files[name] = b
	}
	dev, err := ParseUniFi(files, "unifi-controller")
	if err != nil {
		t.Fatalf("ParseUniFi: %v", err)
	}
	return dev
}

func TestParseUniFi_Basics(t *testing.T) {
	dev := loadUniFi(t)
	if dev.Vendor != "unifi" {
		t.Errorf("Vendor = %q, want unifi", dev.Vendor)
	}
	if dev.Hostname != "unifi-controller" {
		t.Errorf("Hostname = %q, want unifi-controller", dev.Hostname)
	}
}

func TestParseUniFi_VLANsAndPools(t *testing.T) {
	dev := loadUniFi(t)
	if len(dev.VLANs) != 3 {
		t.Fatalf("VLAN count = %d, want 3: %+v", len(dev.VLANs), dev.VLANs)
	}
	byName := map[string]VLAN{}
	for _, v := range dev.VLANs {
		byName[v.Name] = v
	}
	if g := byName["GUEST"]; g.ID != 40 || g.Subnet != "10.0.40.1/24" {
		t.Errorf("GUEST vlan = %+v", g)
	}
	if l := byName["LAN"]; l.Subnet != "10.0.1.1/24" {
		t.Errorf("LAN vlan = %+v", l)
	}

	// LAN + GUEST have dhcpd_enabled; IOT does not.
	if len(dev.DHCPPools) != 2 {
		t.Fatalf("pool count = %d, want 2: %+v", len(dev.DHCPPools), dev.DHCPPools)
	}
	var lanPool *Pool
	for i := range dev.DHCPPools {
		if dev.DHCPPools[i].Network == "10.0.1.1/24" {
			lanPool = &dev.DHCPPools[i]
		}
	}
	if lanPool == nil {
		t.Fatalf("LAN pool missing: %+v", dev.DHCPPools)
	}
	if len(lanPool.DNS) != 2 || lanPool.DNS[0] != "10.0.1.1" || lanPool.DNS[1] != "1.1.1.1" {
		t.Errorf("LAN pool DNS = %v", lanPool.DNS)
	}
}

func TestParseUniFi_Rules(t *testing.T) {
	dev := loadUniFi(t)
	lan := ruleset(t, dev, "LAN_IN")
	if lan.Default != Permit {
		t.Errorf("LAN_IN default = %q, want permit (UniFi default-allow)", lan.Default)
	}
	// r1 tcp, r2 all->ip, r3 tcp_udp -> 2, r6 udp range, r7 tcp srcport = 6.
	// r5 disabled is skipped.
	if len(lan.Rules) != 6 {
		t.Fatalf("LAN_IN rule count = %d, want 6: %+v", len(lan.Rules), lan.Rules)
	}

	r := lan.Rules[0] // r1
	if r.Action != Permit || r.Proto != "tcp" || r.Src != anyCIDR || r.Dst != "10.0.1.10/32" {
		t.Errorf("r1 = %+v", r)
	}
	if r.DstPorts != (PortRange{443, 443}) || r.Caveat != "" {
		t.Errorf("r1 ports/caveat = %+v", r)
	}

	if r := lan.Rules[1]; r.Action != Deny || r.Proto != "ip" || r.Src != "10.0.50.0/24" || r.Dst != "10.0.1.0/24" {
		t.Errorf("r2 = %+v", r)
	}

	// r3 tcp_udp expands to two adjacent rules, tcp then udp, identical otherwise.
	tcp, udp := lan.Rules[2], lan.Rules[3]
	if tcp.Proto != "tcp" || udp.Proto != "udp" {
		t.Errorf("tcp_udp expansion protos = %q,%q", tcp.Proto, udp.Proto)
	}
	if tcp.Dst != "10.0.1.1/32" || tcp.DstPorts != (PortRange{53, 53}) {
		t.Errorf("r3 tcp = %+v", tcp)
	}
	if udp.Dst != "10.0.1.1/32" || udp.DstPorts != (PortRange{53, 53}) {
		t.Errorf("r3 udp = %+v", udp)
	}

	if r := lan.Rules[4]; r.Proto != "udp" || r.DstPorts != (PortRange{8000, 8080}) {
		t.Errorf("r6 range = %+v", r)
	}

	// r7 constrains src_port -> caveat, and its port is recorded.
	if r := lan.Rules[5]; r.SrcPorts != (PortRange{1024, 1024}) || r.Caveat != "source-port match unavailable from flow data" {
		t.Errorf("r7 srcport = %+v", r)
	}
}

func TestParseUniFi_FirewallGroupCaveat(t *testing.T) {
	dev := loadUniFi(t)
	wan := ruleset(t, dev, "WAN_IN")
	if len(wan.Rules) != 1 {
		t.Fatalf("WAN_IN rules = %+v", wan.Rules)
	}
	if wan.Rules[0].Caveat != "firewall group unresolved" {
		t.Errorf("r4 caveat = %q", wan.Rules[0].Caveat)
	}
}

func TestParseUniFi_DisabledWarning(t *testing.T) {
	dev := loadUniFi(t)
	all := strings.Join(dev.Warnings, "\n")
	if !strings.Contains(all, "disabled") {
		t.Errorf("warnings missing disabled-rule note: %v", dev.Warnings)
	}
}

func TestParseUniFi_Devices(t *testing.T) {
	dev := loadUniFi(t)
	if len(dev.Interfaces) != 3 {
		t.Fatalf("interface count = %d, want 3: %+v", len(dev.Interfaces), dev.Interfaces)
	}
	byMAC := map[string]Interface{}
	for _, i := range dev.Interfaces {
		byMAC[i.MAC] = i
	}
	gw, ok := byMAC["aa:bb:cc:dd:ee:01"]
	if !ok {
		t.Fatalf("gateway device missing: %+v", dev.Interfaces)
	}
	if gw.Name != "USG-Gateway" || len(gw.Prefixes) != 1 || gw.Prefixes[0] != "10.0.1.1/32" {
		t.Errorf("gateway iface = %+v", gw)
	}
}

func TestParseUniFi_NoSecretsLeak(t *testing.T) {
	dev := loadUniFi(t)
	dump := fmt.Sprintf("%+v", dev)
	for _, bad := range []string{"passphrase", "should-not-appear", "authkey", "secret-authkey", "x_"} {
		if strings.Contains(dump, bad) {
			t.Errorf("output leaked secret material %q:\n%s", bad, dump)
		}
	}
}

func TestParseUniFi_Errors(t *testing.T) {
	if _, err := ParseUniFi(map[string][]byte{"junk": []byte(`{"hello":"world"}`)}, "junk"); err == nil {
		t.Error("expected error when no recognized UniFi constructs present")
	}
	if _, err := ParseUniFi(map[string][]byte{"bad": []byte(`not json`)}, "bad"); err == nil {
		t.Error("expected error on non-JSON input")
	}
}

func TestLooksLikeUniFi(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`{"meta":{"rc":"ok"},"data":[{"x":1}]}`, true},
		{`[{"mac":"a"}]`, true},
		{`  [1,2,3]`, true},
		{`{"foo":"bar"}`, false},
		{`hostname r1`, false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeUniFi([]byte(c.in)); got != c.want {
			t.Errorf("LooksLikeUniFi(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
