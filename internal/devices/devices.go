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
	return nil
}
