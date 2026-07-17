package netconfig

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// DeviceMatch links a declared device to the observed nodes it was found at.
type DeviceMatch struct {
	Device string   `json:"device"` // DeclaredDevice.Hostname
	Source string   `json:"source"`
	IPs    []string `json:"ips"`    // observed node IPs that matched
	ByMAC  bool     `json:"by_mac"` // matched only via MAC, not a direct interface IP
}

// AdoptedDevice is a UniFi Network device and the observed node it matched.
// ObservedIP is empty when the controller knows the device but the snapshot
// does not; maps never invent traffic nodes for those devices.
type AdoptedDevice struct {
	Name       string `json:"name"`
	Model      string `json:"model"`
	IP         string `json:"ip,omitempty"`
	ObservedIP string `json:"observed_ip,omitempty"`
}

// SilentSubnet is a declared prefix with no observed member nodes. InBlindSpot
// means it overlaps a zero-coverage in-scope CIDR — check the blind-spot panel
// before calling it decommissioned.
type SilentSubnet struct {
	CIDR        string `json:"cidr"`
	Device      string `json:"device"`
	InBlindSpot bool   `json:"in_blind_spot"`
}

// InventoryResult is the declared-vs-observed reconciliation.
type InventoryResult struct {
	Matches          []DeviceMatch     `json:"matches"`
	AdoptedDevices   []AdoptedDevice   `json:"adopted_devices"`
	DeclaredGateways map[string]string `json:"declared_gateways"` // IP → device hostname
	SilentSubnets    []SilentSubnet    `json:"silent_subnets"`
	UndeclaredCIDRs  []string          `json:"undeclared_cidrs"` // observed subnets no declared prefix covers
	Warnings         []string          `json:"warnings,omitempty"`
}

// DiffInventory reconciles declared devices against an observed snapshot. Pure
// and deterministic: every output slice is sorted, so two runs on equal input
// are reflect.DeepEqual.
func DiffInventory(snap graph.Snapshot, devs []DeclaredDevice) InventoryResult {
	res := InventoryResult{DeclaredGateways: map[string]string{}}

	// Index observed nodes by IP and MAC; keep parsed addrs for containment.
	byIP := make(map[netip.Addr]struct{}, len(snap.Nodes))
	byMAC := make(map[string]graph.Node)
	var nodeAddrs []netip.Addr
	for _, n := range snap.Nodes {
		if a, err := netip.ParseAddr(n.IP); err == nil {
			byIP[a] = struct{}{}
			nodeAddrs = append(nodeAddrs, a)
		}
		if n.MAC != "" {
			byMAC[strings.ToLower(strings.TrimSpace(n.MAC))] = n // ponytail: last-wins on dup MAC; snapshots dedup upstream
		}
	}

	var blind []netip.Prefix
	for _, cidr := range snap.Meta.ZeroCovCIDRs {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			blind = append(blind, p.Masked())
		}
	}

	var declared []netip.Prefix // aggregate across all devices, for UndeclaredCIDRs

	for _, d := range devs {
		var matchedIPs []string
		seenIP := map[string]bool{}
		gotIP, gotMAC := false, false
		add := func(ip string, viaMAC bool) {
			if !seenIP[ip] {
				seenIP[ip] = true
				matchedIPs = append(matchedIPs, ip)
			}
			if viaMAC {
				gotMAC = true
			} else {
				gotIP = true
			}
		}

		for _, iface := range d.Interfaces {
			if iface.Shutdown {
				continue
			}
			adopted := AdoptedDevice{Name: iface.Name, Model: iface.Model}
			// Interface's own IP vs observed nodes; if it routes for others, gateway.
			for _, cidr := range iface.Prefixes {
				p, err := netip.ParsePrefix(cidr)
				if err != nil {
					continue
				}
				own, masked := p.Addr(), p.Masked()
				if adopted.IP == "" {
					adopted.IP = own.String()
				}
				if _, ok := byIP[own]; ok {
					add(own.String(), false) // DeviceMatch needs the IP observed
					adopted.ObservedIP = own.String()
				}
				// Gateway entry does NOT require the router's own IP to be
				// observed: real routers often terminate no tracked flows, but
				// mapview must still stamp declared identity onto the inferred
				// gateway. Enough that the subnet holds an observed node.
				for _, a := range nodeAddrs {
					if a != own && masked.Contains(a) {
						res.DeclaredGateways[own.String()] = d.Hostname
						break
					}
				}
			}
			// MAC match (UniFi inventory): find the node wearing this NIC.
			if iface.MAC != "" {
				if n, ok := byMAC[strings.ToLower(strings.TrimSpace(iface.MAC))]; ok {
					add(n.IP, true)
					adopted.ObservedIP = n.IP // MAC is stronger identity than a possibly stale controller IP.
				}
			}
			if d.Vendor == "unifi" && iface.MAC != "" {
				res.AdoptedDevices = append(res.AdoptedDevices, adopted)
			}
		}

		if len(matchedIPs) > 0 {
			sort.Strings(matchedIPs)
			res.Matches = append(res.Matches, DeviceMatch{
				Device: d.Hostname, Source: d.Source,
				IPs: matchedIPs, ByMAC: gotMAC && !gotIP,
			})
		}

		for _, p := range d.OwnedPrefixes() {
			declared = append(declared, p)
			member := false
			for _, a := range nodeAddrs {
				if p.Contains(a) {
					member = true
					break
				}
			}
			if !member {
				res.SilentSubnets = append(res.SilentSubnets, SilentSubnet{
					CIDR: p.String(), Device: d.Hostname, InBlindSpot: overlapsAny(p, blind),
				})
			}
		}
	}

	seenU := map[string]bool{}
	for _, n := range snap.Nodes {
		s, err := netip.ParsePrefix(n.Subnet)
		if err != nil {
			continue
		}
		s = s.Masked()
		covered := false
		for _, d := range declared {
			if d.Bits() <= s.Bits() && d.Contains(s.Addr()) {
				covered = true
				break
			}
		}
		if !covered && !seenU[s.String()] {
			seenU[s.String()] = true
			res.UndeclaredCIDRs = append(res.UndeclaredCIDRs, s.String())
		}
	}

	sort.Slice(res.Matches, func(i, j int) bool { return res.Matches[i].Device < res.Matches[j].Device })
	sort.Slice(res.AdoptedDevices, func(i, j int) bool {
		if res.AdoptedDevices[i].Name != res.AdoptedDevices[j].Name {
			return res.AdoptedDevices[i].Name < res.AdoptedDevices[j].Name
		}
		return res.AdoptedDevices[i].IP < res.AdoptedDevices[j].IP
	})
	sort.Slice(res.SilentSubnets, func(i, j int) bool {
		if a, b := res.SilentSubnets[i], res.SilentSubnets[j]; a.CIDR != b.CIDR {
			return a.CIDR < b.CIDR
		}
		return res.SilentSubnets[i].Device < res.SilentSubnets[j].Device
	})
	sort.Strings(res.UndeclaredCIDRs)
	return res
}

func overlapsAny(p netip.Prefix, ps []netip.Prefix) bool {
	for _, q := range ps {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}
