// Package devices stores operator-owned device identity: device names,
// types, notes, and member IPs; durable per-IP labels; and dismissed hint
// keys. It is a pure overlay over snapshot data — deleting the registry
// loses only operator annotations, never observations. Persisted as
// devices.json in the data dir via safefile (atomic writes).
package devices

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/defilade/internal/safefile"
)

// Device is one physical device that may own several IPs (e.g. a router
// with an interface per VLAN).
type Device struct {
	Name      string   `json:"name"`
	Type      string   `json:"type,omitempty"` // router/switch/nas/printer/…
	Notes     string   `json:"notes,omitempty"`
	IPs       []string `json:"ips"`
	OwnsCIDRs []string `json:"owns_cidrs,omitempty"` // ranges routed through this device (topology view)
}

// DeviceLayer normalizes a device Type into a topology band: boundary
// (firewall/edge), router (core L3), switch (L2), or "" for a normal host.
// Drives both band placement and edge routing in the topology layout.
func DeviceLayer(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "firewall", "edge", "boundary":
		return "boundary"
	case "router", "l3", "gateway":
		return "router"
	case "switch", "l2":
		return "switch"
	default:
		return ""
	}
}

// SetDeviceOwns replaces the owned-CIDR list of a device (created by name if
// absent, like the label/role overlays). CIDRs are validated and masked; an
// empty list clears them. On any invalid CIDR the device is left unchanged.
func (r *Registry) SetDeviceOwns(name string, cidrs []string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("device name required")
	}
	masked := make([]string, 0, len(cidrs))
	seen := map[string]bool{}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return fmt.Errorf("invalid owned CIDR %q", c)
		}
		m := p.Masked().String()
		if !seen[m] {
			seen[m] = true
			masked = append(masked, m)
		}
	}
	sort.Strings(masked)
	for i := range r.Devices {
		if r.Devices[i].Name == name {
			r.Devices[i].OwnsCIDRs = masked
			return nil
		}
	}
	r.Devices = append(r.Devices, Device{Name: name, IPs: []string{}, OwnsCIDRs: masked})
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].Name < r.Devices[j].Name })
	return nil
}

// Registry is the whole devices.json document.
type Registry struct {
	Devices        []Device            `json:"devices"`
	Labels         map[string][]string `json:"labels,omitempty"`           // ip -> durable labels
	RoleOverrides  map[string]string   `json:"role_overrides,omitempty"`   // ip -> operator-corrected role
	DismissedHints []string            `json:"dismissed_hints,omitempty"`  // hint keys never to re-show
	Pinned         []string            `json:"pinned_ips,omitempty"`       // IPs force-retained as their own map node
	ShowAllPrivate bool                `json:"show_all_private,omitempty"` // promote every RFC1918 host to its own overview node
	Segments       []Segment           `json:"segments,omitempty"`         // operator-declared real subnets overriding auto-/24 grouping
}

// Segment is an operator-declared real subnet with an optional display name.
type Segment struct {
	CIDR string `json:"cidr"`
	Name string `json:"name,omitempty"`
}

// SetSegment adds or updates (by CIDR) an operator segment; an empty name just
// declares the subnet. The CIDR must parse.
func (r *Registry) SetSegment(cidr, name string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid segment CIDR %q", cidr)
	}
	cidr = p.Masked().String()
	for i := range r.Segments {
		if r.Segments[i].CIDR == cidr {
			r.Segments[i].Name = name
			return nil
		}
	}
	r.Segments = append(r.Segments, Segment{CIDR: cidr, Name: name})
	sort.Slice(r.Segments, func(i, j int) bool { return r.Segments[i].CIDR < r.Segments[j].CIDR })
	return nil
}

// RemoveSegment drops an operator segment by CIDR (masked or not).
func (r *Registry) RemoveSegment(cidr string) {
	if p, err := netip.ParsePrefix(cidr); err == nil {
		cidr = p.Masked().String()
	}
	kept := r.Segments[:0]
	for _, s := range r.Segments {
		if s.CIDR != cidr {
			kept = append(kept, s)
		}
	}
	r.Segments = kept
}

// Load reads the registry; a missing file is an empty registry.
func Load(path string) (Registry, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Registry{}, nil
	}
	if err != nil {
		return Registry{}, fmt.Errorf("reading device registry: %w", err)
	}
	var r Registry
	if err := json.Unmarshal(raw, &r); err != nil {
		return Registry{}, fmt.Errorf("decoding device registry: %w", err)
	}
	return r, nil
}

// Save validates and writes the registry atomically.
func (r Registry) Save(path string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, raw)
}

// Validate enforces the registry invariants: unique non-empty device
// names, parseable IPs, and at most one owning device per IP.
func (r Registry) Validate() error {
	names := map[string]bool{}
	owner := map[string]string{}
	for _, d := range r.Devices {
		if d.Name == "" {
			return fmt.Errorf("device with empty name")
		}
		if names[d.Name] {
			return fmt.Errorf("duplicate device name %q", d.Name)
		}
		names[d.Name] = true
		for _, ip := range d.IPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				return fmt.Errorf("device %q: invalid IP %q", d.Name, ip)
			}
			if prev := owner[ip]; prev != "" {
				return fmt.Errorf("IP %s belongs to devices %q and %q", ip, prev, d.Name)
			}
			owner[ip] = d.Name
		}
	}
	for ip := range r.RoleOverrides {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("role override for invalid IP %q", ip)
		}
	}
	return nil
}

// SetRole records an operator role correction for ip; an empty role clears
// it. The inferred role in snapshots is never touched — this is an overlay.
func (r *Registry) SetRole(ip, role string) error {
	if _, err := netip.ParseAddr(ip); err != nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	if role == "" {
		delete(r.RoleOverrides, ip)
		return nil
	}
	if r.RoleOverrides == nil {
		r.RoleOverrides = map[string]string{}
	}
	r.RoleOverrides[ip] = role
	return nil
}

// DeviceForIP returns the device owning ip, or nil.
func (r *Registry) DeviceForIP(ip string) *Device {
	for i := range r.Devices {
		for _, dip := range r.Devices[i].IPs {
			if dip == ip {
				return &r.Devices[i]
			}
		}
	}
	return nil
}

// Assign moves ip into the named device, creating the device if needed and
// removing the ip from any previous owner. moved is the previous owner's
// name ("" if none, or if this was a same-device no-op).
func (r *Registry) Assign(name, ip string) (moved string, err error) {
	if name == "" {
		return "", fmt.Errorf("device name required")
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("invalid IP %q", ip)
	}
	if prev := r.DeviceForIP(ip); prev != nil {
		if prev.Name == name {
			return "", nil
		}
		moved = prev.Name
		r.Unassign(ip)
	}
	for i := range r.Devices {
		if r.Devices[i].Name == name {
			r.Devices[i].IPs = append(r.Devices[i].IPs, ip)
			sort.Strings(r.Devices[i].IPs)
			return moved, nil
		}
	}
	r.Devices = append(r.Devices, Device{Name: name, IPs: []string{ip}})
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].Name < r.Devices[j].Name })
	return moved, nil
}

// Unassign removes ip from whatever device holds it. A device left with no
// IPs survives — it may carry type/notes the operator wants to keep.
func (r *Registry) Unassign(ip string) {
	for i := range r.Devices {
		kept := r.Devices[i].IPs[:0]
		for _, dip := range r.Devices[i].IPs {
			if dip != ip {
				kept = append(kept, dip)
			}
		}
		r.Devices[i].IPs = kept
	}
}

// Upsert creates (originalName == "") or updates/renames the device that
// currently has originalName. On invariant violation the registry is
// unchanged.
func (r *Registry) Upsert(originalName string, d Device) error {
	next := make([]Device, 0, len(r.Devices)+1)
	replaced := false
	for _, ex := range r.Devices {
		if originalName != "" && ex.Name == originalName {
			next = append(next, d)
			replaced = true
			continue
		}
		next = append(next, ex)
	}
	if !replaced {
		if originalName != "" {
			return fmt.Errorf("no device named %q", originalName)
		}
		next = append(next, d)
	}
	trial := Registry{Devices: next, Labels: r.Labels, DismissedHints: r.DismissedHints}
	if err := trial.Validate(); err != nil {
		return err
	}
	sort.Slice(next, func(i, j int) bool { return next[i].Name < next[j].Name })
	r.Devices = next
	return nil
}

// Delete removes the named device; its IPs become unassigned.
func (r *Registry) Delete(name string) {
	kept := r.Devices[:0]
	for _, d := range r.Devices {
		if d.Name != name {
			kept = append(kept, d)
		}
	}
	r.Devices = kept
}

// Dismiss records a hint key so it is never shown again. Idempotent.
func (r *Registry) Dismiss(key string) {
	if !r.Dismissed(key) {
		r.DismissedHints = append(r.DismissedHints, key)
	}
}

// Dismissed reports whether the hint key was dismissed.
func (r *Registry) Dismissed(key string) bool {
	for _, k := range r.DismissedHints {
		if k == key {
			return true
		}
	}
	return false
}

// Pin force-retains an IP as its own map node even when its rank would
// otherwise collapse it into an aggregate. Idempotent.
func (r *Registry) Pin(ip string) {
	if !r.IsPinned(ip) {
		r.Pinned = append(r.Pinned, ip)
	}
}

// Unpin removes an IP from the pin set.
func (r *Registry) Unpin(ip string) {
	for i, p := range r.Pinned {
		if p == ip {
			r.Pinned = append(r.Pinned[:i], r.Pinned[i+1:]...)
			return
		}
	}
}

// IsPinned reports whether an IP is force-retained.
func (r *Registry) IsPinned(ip string) bool {
	for _, p := range r.Pinned {
		if p == ip {
			return true
		}
	}
	return false
}
