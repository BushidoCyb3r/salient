package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseUniFi reads UniFi controller API JSON exports and returns the
// controller as a single DeclaredDevice. files maps basenames to raw bytes;
// items are recognized by content shape, not filename. Only whitelisted
// fields are extracted, so secret-bearing UniFi fields (x_passphrase,
// x_authkey and any other x_* key) never reach the output. Unresolvable
// constructs set a Caveat or bump a warning counter; nothing is silently
// dropped. It errors on unreadable input or when no recognized construct is
// found across all files.
func ParseUniFi(files map[string][]byte, source string) (DeclaredDevice, error) {
	dev := DeclaredDevice{Source: source, Vendor: "unifi", Hostname: source}

	recognized, disabled, caveated, unknownAction, unknownItems := 0, 0, 0, 0, 0

	rulesetIdx := func(name string) int {
		for i := range dev.Rulesets {
			if dev.Rulesets[i].Name == name {
				return i
			}
		}
		// UniFi rulesets are default-allow; the controller only lists exceptions.
		dev.Rulesets = append(dev.Rulesets, Ruleset{Name: name, Default: Permit})
		return len(dev.Rulesets) - 1
	}

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var items []map[string]any
	for _, k := range keys {
		items = append(items, unifiItems(files[k])...)
	}

	// Pass 1: networks first, so rules in any file (or ordered before their
	// networkconf) can resolve src/dst_networkconf_id references.
	netByID := map[string]string{}
	for _, item := range items {
		if has(item, "purpose") && has(item, "ip_subnet") {
			recognized++
			addNetwork(&dev, item)
			if id := ustr(item, "_id"); id != "" {
				netByID[id] = ustr(item, "ip_subnet")
			}
		}
	}

	// Pass 2: rules and devices.
	for _, item := range items {
		switch {
		case has(item, "purpose") && has(item, "ip_subnet"):
			// handled in pass 1
		case has(item, "ruleset") && has(item, "action"):
			recognized++
			switch added, cav := addRules(&dev, item, rulesetIdx, netByID); {
			case added == statusBadAction:
				unknownAction++
			case added == statusDisabled:
				disabled++
			default:
				caveated += cav
			}
		case has(item, "mac") && has(item, "type"):
			recognized++
			addDevice(&dev, item)
		default:
			unknownItems++
		}
	}

	if recognized == 0 {
		return dev, errors.New("netconfig: no recognized UniFi constructs")
	}

	if disabled > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("%d firewall rule(s) disabled and skipped", disabled))
	}
	if caveated > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("%d firewall rule(s) carry a caveat and are not evaluated", caveated))
	}
	if unknownAction > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("%d firewall rule(s) with unrecognized action; skipped", unknownAction))
	}
	if unknownItems > 0 {
		dev.Warnings = append(dev.Warnings, fmt.Sprintf("%d JSON item(s) not recognized as UniFi network/rule/device; skipped", unknownItems))
	}
	return dev, nil
}

// unifiItems decodes one file into its list of objects, accepting either the
// {"meta":..,"data":[..]} controller wrapper or a bare JSON array. Malformed
// or unrecognized shapes yield no items (never a panic).
func unifiItems(b []byte) []map[string]any {
	var wrap struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.Data != nil {
		return wrap.Data
	}
	var arr []map[string]any
	if err := json.Unmarshal(b, &arr); err == nil {
		return arr
	}
	return nil
}

func addNetwork(dev *DeclaredDevice, m map[string]any) {
	subnet := ustr(m, "ip_subnet")
	vlan, _ := unum(m, "vlan")
	dev.VLANs = append(dev.VLANs, VLAN{ID: vlan, Name: ustr(m, "name"), Subnet: subnet, Purpose: ustr(m, "purpose")})

	if ubool(m, "dhcpd_enabled") {
		p := Pool{Network: subnet, Router: ustr(m, "dhcpd_gateway")}
		for _, k := range []string{"dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4"} {
			if s := ustr(m, k); s != "" {
				p.DNS = append(p.DNS, s)
			}
		}
		dev.DHCPPools = append(dev.DHCPPools, p)
	}
}

func addDevice(dev *DeclaredDevice, m map[string]any) {
	name := ustr(m, "name")
	if name == "" {
		name = ustr(m, "mac")
	}
	iface := Interface{Name: name, MAC: ustr(m, "mac")}
	if ip := ustr(m, "ip"); ip != "" {
		iface.Prefixes = []string{unifiAddr(ip)}
	}
	dev.Interfaces = append(dev.Interfaces, iface)
}

const (
	statusBadAction = -1 // unrecognized action, nothing added
	statusDisabled  = -2 // rule disabled, nothing added
)

// addRules maps one firewall-rule object into 1+ Rule entries (tcp_udp
// expands to two). It returns (added, caveated): added is the number of Rule
// entries appended, or a status sentinel; caveated is how many of them carry
// a Caveat.
func addRules(dev *DeclaredDevice, m map[string]any, rulesetIdx func(string) int, netByID map[string]string) (int, int) {
	var act Action
	switch strings.ToLower(ustr(m, "action")) {
	case "accept":
		act = Permit
	case "drop", "reject":
		act = Deny
	default:
		return statusBadAction, 0
	}
	if !ubool(m, "enabled") {
		return statusDisabled, 0
	}

	// Endpoint: explicit address wins; otherwise a *_networkconf_id reference
	// resolves to the network's subnet. An unresolvable id must NOT widen the
	// rule to "any" (that would fabricate policy hits) — the caller caveats it
	// so Rule.Matches rejects it.
	resolve := func(addrKey, idKey string) (cidr string, ok bool) {
		if a := strings.TrimSpace(ustr(m, addrKey)); a != "" {
			return unifiAddr(a), true
		}
		if id := ustr(m, idKey); id != "" {
			if sub, found := netByID[id]; found && sub != "" {
				return sub, true
			}
			return anyCIDR, false
		}
		return anyCIDR, true
	}
	src, srcOK := resolve("src_address", "src_networkconf_id")
	dst, dstOK := resolve("dst_address", "dst_networkconf_id")
	rsName := ustr(m, "ruleset")
	line, _ := unum(m, "rule_index")

	base := Rule{
		Action: act,
		Src:    src,
		Dst:    dst,
		Line:   line,
		// Raw is synthesized from whitelisted fields only; the raw JSON (which
		// may contain x_* secrets) is never copied in.
		Raw: fmt.Sprintf("unifi %s: %s %s->%s", rsName, strings.ToLower(ustr(m, "action")), src, dst),
	}
	setCaveat := func(s string) {
		if base.Caveat == "" {
			base.Caveat = s
		}
	}
	if !srcOK || !dstOK {
		setCaveat("network-scoped rule unresolved")
	}

	var protos []string
	switch strings.ToLower(ustr(m, "protocol")) {
	case "", "all", "any":
		protos = []string{"ip"}
	case "tcp":
		protos = []string{"tcp"}
	case "udp":
		protos = []string{"udp"}
	case "tcp_udp":
		protos = []string{"tcp", "udp"}
	case "icmp", "icmpv6":
		protos = []string{"icmp"}
	default:
		protos = []string{"ip"}
		setCaveat("unsupported protocol")
	}

	if nonEmptyList(m, "src_firewallgroup_ids") || nonEmptyList(m, "dst_firewallgroup_ids") {
		setCaveat("firewall group unresolved")
	}

	if pr, present, ok := unifiPorts(ustr(m, "dst_port")); present {
		if ok {
			base.DstPorts = pr
		} else {
			setCaveat("named port unresolved")
		}
	}
	if pr, present, ok := unifiPorts(ustr(m, "src_port")); present {
		if ok {
			base.SrcPorts = pr
			if !pr.Any() {
				setCaveat("source-port match unavailable from flow data")
			}
		} else {
			setCaveat("named port unresolved")
		}
	}

	idx := rulesetIdx(rsName)
	added := 0
	for _, p := range protos {
		r := base
		r.Proto = p
		dev.Rulesets[idx].Rules = append(dev.Rulesets[idx].Rules, r)
		added++
	}
	caveated := 0
	if base.Caveat != "" {
		caveated = added // caveat applies to every emitted rule (tcp_udp emits two)
	}
	return added, caveated
}

// unifiAddr turns a UniFi address field into a CIDR: "" -> any, bare IP ->
// /32, CIDR -> unchanged.
func unifiAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return anyCIDR
	}
	if strings.Contains(s, "/") {
		return s
	}
	return s + "/32"
}

// unifiPorts parses a UniFi dst_port/src_port string. present reports whether
// a clause existed; ok reports whether it parsed to a numeric port/range.
func unifiPorts(s string) (pr PortRange, present, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortRange{}, false, true
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, e1 := strconv.ParseUint(strings.TrimSpace(s[:i]), 10, 16)
		hi, e2 := strconv.ParseUint(strings.TrimSpace(s[i+1:]), 10, 16)
		if e1 != nil || e2 != nil {
			return PortRange{}, true, false
		}
		l, h := uint16(lo), uint16(hi)
		if l > h {
			l, h = h, l
		}
		return PortRange{l, h}, true, true
	}
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return PortRange{}, true, false
	}
	return PortRange{uint16(p), uint16(p)}, true, true
}

// LooksLikeUniFi reports whether head looks like UniFi controller JSON: the
// first 2KB begin a JSON array, or a JSON object carrying a top-level "data"
// key. Used by vendor detection.
func LooksLikeUniFi(head []byte) bool {
	if len(head) > 2048 {
		head = head[:2048]
	}
	dec := json.NewDecoder(bytes.NewReader(head))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	if d == '[' {
		return true
	}
	if d != '{' {
		return false
	}
	// Scan the top-level object's keys for "data". depth tracks nesting so a
	// nested key of the same name is ignored; truncation just ends the scan.
	depth := 1
	wantKey := true
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		if dl, ok := t.(json.Delim); ok {
			switch dl {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			wantKey = depth == 1
			continue
		}
		if depth == 1 && wantKey {
			if s, ok := t.(string); ok && s == "data" {
				return true
			}
		}
		// At depth 1, tokens alternate key/value; flip after each scalar.
		if depth == 1 {
			wantKey = !wantKey
		}
	}
	return false
}

// --- typed accessors over decoded JSON objects ---

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func ustr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func ubool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func unum(m map[string]any, k string) (int, bool) {
	f, ok := m[k].(float64)
	return int(f), ok
}

func nonEmptyList(m map[string]any, k string) bool {
	a, ok := m[k].([]any)
	return ok && len(a) > 0
}
