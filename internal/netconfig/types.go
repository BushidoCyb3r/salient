// Package netconfig models declared network devices parsed from router
// configs (Cisco IOS, UniFi). Pure data plus matching helpers; no I/O.
package netconfig

import "net/netip"

type Action string

const (
	Permit Action = "permit"
	Deny   Action = "deny"
)

// PortRange is inclusive; zero value {0,0} means "any port".
type PortRange struct {
	Lo uint16 `json:"lo"`
	Hi uint16 `json:"hi"`
}

func (p PortRange) Any() bool { return p.Lo == 0 && p.Hi == 0 }

func (p PortRange) Contains(port uint16) bool {
	if p.Any() {
		return true
	}
	return port >= p.Lo && port <= p.Hi
}

type Rule struct {
	Action   Action    `json:"action"`
	Proto    string    `json:"proto"` // "ip"|"tcp"|"udp"|"icmp" ("ip" = any proto)
	Src      string    `json:"src"`   // CIDR; "0.0.0.0/0" = any
	Dst      string    `json:"dst"`
	SrcPorts PortRange `json:"src_ports"`
	DstPorts PortRange `json:"dst_ports"`
	Line     int       `json:"line"`
	Raw      string    `json:"raw"`
	Caveat   string    `json:"caveat,omitempty"`
}

// Matches reports whether a flow (src,dst IPs; dst port; proto "tcp"/"udp")
// is matched by this rule. Rules with a Caveat never match (caller counts
// them separately). Invalid rule CIDRs never match.
//
// SrcPorts is intentionally not evaluated here: observed flow edges carry
// only the responder (dst) port, so a source-port match cannot be honestly
// decided. Rules that constrain SrcPorts get a Caveat set at parse time
// ("source-port match unavailable from flow data"), and caveated rules are
// rejected above — so Matches never needs to inspect SrcPorts.
func (r Rule) Matches(src, dst netip.Addr, dstPort uint16, proto string) bool {
	if r.Caveat != "" {
		return false
	}
	if r.Proto != "ip" && r.Proto != proto {
		return false
	}
	srcNet, err := netip.ParsePrefix(r.Src)
	if err != nil || !srcNet.Contains(src) {
		return false
	}
	dstNet, err := netip.ParsePrefix(r.Dst)
	if err != nil || !dstNet.Contains(dst) {
		return false
	}
	return r.DstPorts.Contains(dstPort)
}

type Direction string

const (
	In  Direction = "in"
	Out Direction = "out"
)

type Binding struct {
	Ruleset   string    `json:"ruleset"` // Ruleset.Name it points at
	Direction Direction `json:"direction"`
}

type Interface struct {
	Name     string    `json:"name"`
	Prefixes []string  `json:"prefixes"` // CIDRs (primary + secondaries)
	VLAN     int       `json:"vlan,omitempty"`
	Shutdown bool      `json:"shutdown,omitempty"`
	Bindings []Binding `json:"bindings,omitempty"`
}

type VLAN struct {
	ID     int    `json:"id"`
	Name   string `json:"name,omitempty"`
	Subnet string `json:"subnet,omitempty"` // CIDR, may be ""
}

type Pool struct {
	Network string   `json:"network"` // CIDR
	Router  string   `json:"router,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type Route struct {
	Prefix  string `json:"prefix"` // CIDR
	NextHop string `json:"next_hop"`
}

type Ruleset struct {
	Name    string `json:"name"`
	Default Action `json:"default"` // IOS: Deny (implicit); UniFi: per ruleset
	Rules   []Rule `json:"rules"`
}

type DeclaredDevice struct {
	Source     string      `json:"source"`
	Vendor     string      `json:"vendor"` // "cisco-ios" | "unifi"
	Hostname   string      `json:"hostname"`
	Interfaces []Interface `json:"interfaces,omitempty"`
	VLANs      []VLAN      `json:"vlans,omitempty"`
	DHCPPools  []Pool      `json:"dhcp_pools,omitempty"`
	Routes     []Route     `json:"routes,omitempty"`
	Rulesets   []Ruleset   `json:"rulesets,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
}

// OwnedPrefixes returns parsed prefixes of all non-shutdown interfaces plus
// VLAN subnets, deduplicated. Invalid CIDRs skipped. Prefixes are masked
// (via Prefix.Masked) so host addresses collapse to their network.
func (d DeclaredDevice) OwnedPrefixes() []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	add := func(cidr string) {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return
		}
		p = p.Masked()
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, iface := range d.Interfaces {
		if iface.Shutdown {
			continue
		}
		for _, cidr := range iface.Prefixes {
			add(cidr)
		}
	}
	for _, v := range d.VLANs {
		if v.Subnet != "" {
			add(v.Subnet)
		}
	}
	return out
}

// Ruleset returns the named ruleset, or nil.
func (d DeclaredDevice) Ruleset(name string) *Ruleset {
	for i := range d.Rulesets {
		if d.Rulesets[i].Name == name {
			return &d.Rulesets[i]
		}
	}
	return nil
}
