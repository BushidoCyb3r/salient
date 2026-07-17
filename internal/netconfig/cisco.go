package netconfig

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const anyCIDR = "0.0.0.0/0"

// ParseCiscoIOS reads a Cisco IOS running-config and returns the recognized,
// whitelisted subset as a DeclaredDevice. Unrecognized lines are skipped
// silently; secret-bearing directives (enable secret, snmp-server community,
// tacacs/radius keys, usernames) are never in the whitelist and so never
// reach the output. It errors only on unreadable input or when no recognized
// construct is found.
func ParseCiscoIOS(r io.Reader, source string) (DeclaredDevice, error) {
	dev := DeclaredDevice{Source: source, Vendor: "cisco-ios"}

	const (
		secNone = iota
		secIface
		secACL
		secPool
		secVLAN
	)
	section := secNone
	var curIface, curPool, curVLAN, curACL int
	standardACL := false

	recognized := 0
	caveated := 0
	var vrfN, natN, rmN int
	lineNum := 0

	rulesetIdx := func(name string) int {
		for i := range dev.Rulesets {
			if dev.Rulesets[i].Name == name {
				return i
			}
		}
		dev.Rulesets = append(dev.Rulesets, Ruleset{Name: name, Default: Deny})
		return len(dev.Rulesets) - 1
	}
	addRule := func(idx int, rule Rule) {
		// ponytail: a well-formed ACL line never contains "secret"; this guard
		// closes the only path that copies a raw line into output, keeping the
		// no-secret invariant true even against mutated (fuzz) input.
		if strings.Contains(strings.ToLower(rule.Raw), "secret") {
			return
		}
		dev.Rulesets[idx].Rules = append(dev.Rulesets[idx].Rules, rule)
		if rule.Caveat != "" {
			caveated++
		}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lineNum++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		fields := strings.Fields(trimmed)

		// Unmodeled constructs: one warning per type, counted anywhere.
		switch {
		case len(fields) > 0 && fields[0] == "vrf",
			len(fields) > 1 && fields[0] == "ip" && fields[1] == "vrf":
			vrfN++
		case strings.HasPrefix(trimmed, "ip nat "):
			natN++
		case strings.HasPrefix(trimmed, "route-map "):
			rmN++
		}

		// Continuation line of an active block.
		if indented && section != secNone && len(fields) > 0 {
			switch section {
			case secIface:
				iface := &dev.Interfaces[curIface]
				switch {
				case fields[0] == "shutdown":
					iface.Shutdown = true
					recognized++
				case len(fields) >= 4 && fields[0] == "ip" && fields[1] == "address":
					if cidr, ok := maskToCIDR(fields[2], fields[3]); ok {
						iface.Prefixes = append(iface.Prefixes, cidr)
						recognized++
					}
				case len(fields) >= 3 && fields[0] == "encapsulation" && strings.EqualFold(fields[1], "dot1Q"):
					if v, err := strconv.Atoi(fields[2]); err == nil {
						iface.VLAN = v
						recognized++
					}
				case len(fields) >= 4 && fields[0] == "ip" && fields[1] == "access-group":
					dir := Direction(fields[3])
					if dir == In || dir == Out {
						iface.Bindings = append(iface.Bindings, Binding{Ruleset: fields[2], Direction: dir})
						recognized++
					}
				case len(fields) >= 4 && fields[0] == "switchport" && fields[1] == "access" && fields[2] == "vlan":
					if v, err := strconv.Atoi(fields[3]); err == nil {
						iface.VLAN = v
						recognized++
					}
				case len(fields) >= 3 && fields[0] == "switchport" && fields[1] == "mode" && fields[2] == "trunk":
					iface.Trunk = true
					recognized++
				}
			case secACL:
				if fields[0] == "permit" || fields[0] == "deny" {
					addRule(curACL, parseACLEntry(Action(fields[0]), fields[1:], standardACL, lineNum, trimmed))
					recognized++
				}
			case secPool:
				switch {
				case len(fields) >= 3 && fields[0] == "network":
					if cidr, ok := maskToCIDR(fields[1], fields[2]); ok {
						dev.DHCPPools[curPool].Network = cidr
						recognized++
					}
				case len(fields) >= 2 && fields[0] == "default-router":
					dev.DHCPPools[curPool].Router = fields[1]
					recognized++
				case len(fields) >= 2 && fields[0] == "dns-server":
					dev.DHCPPools[curPool].DNS = append(dev.DHCPPools[curPool].DNS, fields[1:]...)
					recognized++
				}
			case secVLAN:
				if len(fields) >= 2 && fields[0] == "name" {
					dev.VLANs[curVLAN].Name = fields[1]
					recognized++
				}
			}
			continue
		}

		// Top-level directive: any non-indented line closes the current block.
		section = secNone
		if len(fields) == 0 || strings.HasPrefix(trimmed, "!") {
			continue
		}

		switch {
		case fields[0] == "hostname" && len(fields) >= 2:
			dev.Hostname = fields[1]
			recognized++
		case fields[0] == "interface" && len(fields) >= 2:
			dev.Interfaces = append(dev.Interfaces, Interface{Name: fields[1]})
			curIface = len(dev.Interfaces) - 1
			section = secIface
			recognized++
		case fields[0] == "ip" && len(fields) >= 4 && fields[1] == "access-list" &&
			(fields[2] == "extended" || fields[2] == "standard"):
			standardACL = fields[2] == "standard"
			curACL = rulesetIdx(fields[3])
			section = secACL
			recognized++
		case fields[0] == "access-list" && len(fields) >= 3:
			n, err := strconv.Atoi(fields[1])
			if err == nil && (fields[2] == "permit" || fields[2] == "deny") {
				std := (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999)
				idx := rulesetIdx(fields[1])
				addRule(idx, parseACLEntry(Action(fields[2]), fields[3:], std, lineNum, trimmed))
				recognized++
			}
		case fields[0] == "ip" && len(fields) >= 5 && fields[1] == "route":
			if cidr, ok := maskToCIDR(fields[2], fields[3]); ok {
				dev.Routes = append(dev.Routes, Route{Prefix: cidr, NextHop: fields[4]})
				recognized++
			}
		case fields[0] == "ip" && len(fields) >= 3 && fields[1] == "dhcp" && fields[2] == "pool":
			dev.DHCPPools = append(dev.DHCPPools, Pool{})
			curPool = len(dev.DHCPPools) - 1
			section = secPool
			recognized++
		case fields[0] == "vlan" && len(fields) >= 2:
			if id, err := strconv.Atoi(fields[1]); err == nil {
				dev.VLANs = append(dev.VLANs, VLAN{ID: id})
				curVLAN = len(dev.VLANs) - 1
				section = secVLAN
				recognized++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return dev, err
	}
	if recognized == 0 {
		return dev, errors.New("netconfig: no recognized Cisco IOS constructs")
	}

	if caveated > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("%d ACL rule(s) carry a caveat and are not evaluated", caveated))
	}
	if vrfN > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("vrf configuration seen on %d line(s); not modeled", vrfN))
	}
	if natN > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("ip nat seen on %d line(s); not modeled", natN))
	}
	if rmN > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("route-map seen on %d line(s); not modeled", rmN))
	}
	return dev, nil
}

// parseACLEntry parses one ACL entry (the tokens after ACTION). Unknown or
// unresolvable constructs never produce a verdict: they set a Caveat instead,
// and caveated rules are rejected by Rule.Matches.
func parseACLEntry(action Action, toks []string, standard bool, line int, raw string) Rule {
	r := Rule{Action: action, Proto: "ip", Src: anyCIDR, Dst: anyCIDR, Line: line, Raw: raw}
	setCaveat := func(s string) {
		if r.Caveat == "" {
			r.Caveat = s
		}
	}
	i := 0
	next := func() (string, bool) {
		if i < len(toks) {
			t := toks[i]
			i++
			return t, true
		}
		return "", false
	}
	peek := func() (string, bool) {
		if i < len(toks) {
			return toks[i], true
		}
		return "", false
	}

	if !standard {
		p, ok := next()
		if !ok {
			return r
		}
		r.Proto = p
		switch p {
		case "ip", "tcp", "udp", "icmp":
		default:
			setCaveat("unsupported protocol")
			return r
		}
	}

	// object-group anywhere is unresolvable without the group definition.
	for _, t := range toks {
		if t == "object-group" {
			setCaveat("object-group unresolved")
			return r
		}
	}

	src, ok := parseSpec(next, setCaveat)
	if !ok {
		return r
	}
	r.Src = src

	ported := r.Proto == "tcp" || r.Proto == "udp"
	if ported {
		if pr, matched := parsePorts(next, peek, setCaveat); matched {
			r.SrcPorts = pr
			if !pr.Any() {
				setCaveat("source-port match unavailable from flow data")
			}
		}
	}

	if standard {
		return r // Dst stays any.
	}

	dst, ok := parseSpec(next, setCaveat)
	if !ok {
		return r
	}
	r.Dst = dst

	if ported {
		if pr, matched := parsePorts(next, peek, setCaveat); matched {
			r.DstPorts = pr
		}
	}

	for {
		t, ok := next()
		if !ok {
			break
		}
		if t == "established" {
			setCaveat("established unsupported")
		}
	}
	return r
}

// parseSpec consumes an address spec: "any" | "host A" | "A WILDCARD".
func parseSpec(next func() (string, bool), setCaveat func(string)) (string, bool) {
	t, ok := next()
	if !ok {
		return "", false
	}
	switch t {
	case "any":
		return anyCIDR, true
	case "host":
		a, ok := next()
		if !ok {
			return "", false
		}
		if ip := net.ParseIP(a); ip == nil || ip.To4() == nil {
			return "", false
		}
		return a + "/32", true
	default:
		w, ok := next()
		if !ok {
			return "", false
		}
		cidr, valid := wildcardToCIDR(t, w)
		if !valid {
			setCaveat("discontiguous wildcard")
			return anyCIDR, true
		}
		return cidr, true
	}
}

// parsePorts consumes a port clause if the next token is one. The second
// return value reports whether a clause was present (not whether it was
// resolvable — unresolvable ones set a caveat).
func parsePorts(next func() (string, bool), peek func() (string, bool), setCaveat func(string)) (PortRange, bool) {
	kw, ok := peek()
	if !ok {
		return PortRange{}, false
	}
	switch kw {
	case "eq", "gt", "lt", "neq":
		next()
		t, ok := next()
		if !ok {
			return PortRange{}, true
		}
		p, ok := parsePort(t)
		if !ok {
			setCaveat("named port unresolved")
			return PortRange{}, true
		}
		switch kw {
		case "eq":
			return PortRange{p, p}, true
		case "gt":
			if p == 65535 {
				return PortRange{}, true
			}
			return PortRange{p + 1, 65535}, true
		case "lt":
			if p <= 1 {
				return PortRange{}, true
			}
			return PortRange{1, p - 1}, true
		default: // neq
			setCaveat("neq unsupported")
			return PortRange{}, true
		}
	case "range":
		next()
		a, ok1 := next()
		b, ok2 := next()
		if !ok1 || !ok2 {
			return PortRange{}, true
		}
		lo, okA := parsePort(a)
		hi, okB := parsePort(b)
		if !okA || !okB {
			setCaveat("named port unresolved")
			return PortRange{}, true
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		return PortRange{lo, hi}, true
	}
	return PortRange{}, false
}

func parsePort(t string) (uint16, bool) {
	n, err := strconv.ParseUint(t, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// maskToCIDR turns "A" + dotted netmask into "A/len". Host bits are kept
// (callers rely on DeclaredDevice.OwnedPrefixes to mask). Non-contiguous
// masks are rejected.
func maskToCIDR(addr, mask string) (string, bool) {
	a := net.ParseIP(addr).To4()
	m := net.ParseIP(mask).To4()
	if a == nil || m == nil {
		return "", false
	}
	ones, bits := net.IPMask(m).Size()
	if bits == 0 {
		return "", false
	}
	return fmt.Sprintf("%s/%d", a.String(), ones), true
}

// wildcardToCIDR turns "A" + Cisco wildcard mask into "network/len". A
// wildcard is the bitwise inverse of a netmask; only contiguous ones
// (^0*1*$ in binary) map to a prefix, others are rejected.
func wildcardToCIDR(addr, wild string) (string, bool) {
	a := net.ParseIP(addr).To4()
	w := net.ParseIP(wild).To4()
	if a == nil || w == nil {
		return "", false
	}
	mask := make(net.IPMask, 4)
	for i := 0; i < 4; i++ {
		mask[i] = ^w[i]
	}
	ones, bits := mask.Size()
	if bits == 0 {
		return "", false // discontiguous
	}
	return fmt.Sprintf("%s/%d", a.Mask(mask).String(), ones), true
}

// LooksLikeIOS reports whether head (first bytes of a file) looks like a
// Cisco IOS config. Used by Task 8 vendor detection.
func LooksLikeIOS(head []byte) bool {
	if len(head) > 2048 {
		head = head[:2048]
	}
	sc := bufio.NewScanner(bytes.NewReader(head))
	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " \t")
		if strings.HasPrefix(line, "hostname ") ||
			strings.HasPrefix(line, "interface ") ||
			strings.HasPrefix(line, "access-list ") {
			return true
		}
	}
	return false
}
