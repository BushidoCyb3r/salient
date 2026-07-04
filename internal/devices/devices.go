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

	"github.com/BushidoCyb3r/defilade/internal/safefile"
)

// Device is one physical device that may own several IPs (e.g. a router
// with an interface per VLAN).
type Device struct {
	Name  string   `json:"name"`
	Type  string   `json:"type,omitempty"` // router/switch/nas/printer/…
	Notes string   `json:"notes,omitempty"`
	IPs   []string `json:"ips"`
}

// Registry is the whole devices.json document.
type Registry struct {
	Devices        []Device            `json:"devices"`
	Labels         map[string][]string `json:"labels,omitempty"`          // ip -> durable labels
	RoleOverrides  map[string]string   `json:"role_overrides,omitempty"`  // ip -> operator-corrected role
	DismissedHints []string            `json:"dismissed_hints,omitempty"` // hint keys never to re-show
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
