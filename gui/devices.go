package main

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/BushidoCyb3r/defilade/internal/assist"
	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/devices"
	"github.com/BushidoCyb3r/defilade/internal/graph"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func (a *App) registryPath() string { return filepath.Join(a.DataDir, "devices.json") }

// mutateRegistry serializes load-mutate-save under the App mutex so two
// GUI actions can't interleave writes.
func (a *App) mutateRegistry(fn func(*devices.Registry) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, err := devices.Load(a.registryPath())
	if err != nil {
		return err
	}
	if err := fn(&r); err != nil {
		return err
	}
	return r.Save(a.registryPath())
}

// ListDevices returns the whole registry for the Devices sidebar.
func (a *App) ListDevices() (devices.Registry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return devices.Load(a.registryPath())
}

// SaveDevice creates (originalName == "") or updates/renames a device.
func (a *App) SaveDevice(originalName string, d devices.Device) error {
	return a.mutateRegistry(func(r *devices.Registry) error { return r.Upsert(originalName, d) })
}

// DeleteDevice removes a device; its IPs become unassigned.
func (a *App) DeleteDevice(name string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.Delete(name); return nil })
}

// AssignIP links ip to deviceName (creating it if new) and returns the
// previous owner's name if the IP moved, "" otherwise.
func (a *App) AssignIP(deviceName, ip string) (string, error) {
	var moved string
	err := a.mutateRegistry(func(r *devices.Registry) error {
		var aerr error
		moved, aerr = r.Assign(deviceName, ip)
		return aerr
	})
	return moved, err
}

// UnassignIP removes ip from whatever device owns it.
func (a *App) UnassignIP(ip string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.Unassign(ip); return nil })
}

// SetLabels writes durable operator labels for an IP (used directly and by
// AI-tag promotion). Empty labels deletes the entry.
func (a *App) SetLabels(ip string, labels []string) error {
	return a.mutateRegistry(func(r *devices.Registry) error {
		if len(labels) == 0 {
			delete(r.Labels, ip)
			return nil
		}
		if r.Labels == nil {
			r.Labels = map[string][]string{}
		}
		sort.Strings(labels)
		r.Labels[ip] = labels
		return nil
	})
}

// DismissHint permanently hides a hint ("hostname:<name>", "ai:<ip>").
func (a *App) DismissHint(key string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.Dismiss(key); return nil })
}

// SetRole records an operator role correction; empty role clears it.
func (a *App) SetRole(ip, role string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { return r.SetRole(ip, role) })
}

// PinToMap force-retains an IP as its own overview node; UnpinFromMap undoes
// it. Both are idempotent; the caller reloads the map to see the change.
func (a *App) PinToMap(ip string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.Pin(ip); return nil })
}

// UnpinFromMap removes an IP from the pin set.
func (a *App) UnpinFromMap(ip string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.Unpin(ip); return nil })
}

// SetShowAllPrivate toggles promoting every RFC1918 host to its own overview
// node. Persisted so the choice survives reloads; the caller reloads the map.
func (a *App) SetShowAllPrivate(on bool) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.ShowAllPrivate = on; return nil })
}

// overrideTiers maps known override roles (lowercased) to their map tier.
// Free-text overrides not listed here keep the node's inferred tier.
var overrideTiers = map[string]mapview.Tier{
	"domaincontroller": mapview.TierCore, "dnsserver": mapview.TierCore,
	"fileserver": mapview.TierService, "database": mapview.TierService,
	"webserver": mapview.TierService, "jumpbox": mapview.TierService,
	"mailserver": mapview.TierService,
	"printer":    mapview.TierClient, "camera": mapview.TierClient,
	"workstation": mapview.TierClient,
}

// Hint is a suggested same-device link: one hostname observed on 2+ IPs.
// Nothing links automatically — the operator accepts or dismisses it.
type Hint struct {
	Key      string   `json:"key"`
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips"`
}

// hostnameHints derives link suggestions from hostname evidence. A hint is
// suppressed when dismissed or when all its IPs already share one device.
func hostnameHints(nodes []graph.Node, reg *devices.Registry) []Hint {
	byHost := map[string][]string{}
	for _, n := range nodes {
		for _, h := range n.Hostnames {
			byHost[h] = append(byHost[h], n.IP)
		}
	}
	var hints []Hint
	for host, ips := range byHost {
		if len(ips) < 2 {
			continue
		}
		key := "hostname:" + host
		if reg.Dismissed(key) {
			continue
		}
		owner, allLinked := "", true
		for _, ip := range ips {
			d := reg.DeviceForIP(ip)
			if d == nil || (owner != "" && d.Name != owner) {
				allLinked = false
				break
			}
			owner = d.Name
		}
		if allLinked {
			continue
		}
		sort.Strings(ips)
		hints = append(hints, Hint{Key: key, Hostname: host, IPs: ips})
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].Key < hints[j].Key })
	return hints
}

// macHints derives same-device suggestions from a shared responder MAC
// (gateway MACs are already excluded from node data). The Hostname field
// carries the OUI vendor for display. Suppressed when dismissed or when all
// IPs already share one device.
func macHints(nodes []graph.Node, reg *devices.Registry) []Hint {
	byMAC := map[string][]string{}
	for _, n := range nodes {
		if n.MAC != "" {
			byMAC[n.MAC] = append(byMAC[n.MAC], n.IP)
		}
	}
	var hints []Hint
	for mac, ips := range byMAC {
		if len(ips) < 2 {
			continue
		}
		key := "mac:" + mac
		if reg.Dismissed(key) {
			continue
		}
		owner, allLinked := "", true
		for _, ip := range ips {
			d := reg.DeviceForIP(ip)
			if d == nil || (owner != "" && d.Name != owner) {
				allLinked = false
				break
			}
			owner = d.Name
		}
		if allLinked {
			continue
		}
		sort.Strings(ips)
		hints = append(hints, Hint{Key: key, Hostname: config.VendorForMAC(mac), IPs: ips})
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].Key < hints[j].Key })
	return hints
}

// DeviceHints returns pending same-device link suggestions for a snapshot:
// hostname-based first, then MAC-based.
func (a *App) DeviceHints(path string) ([]Hint, error) {
	snap, err := snapshot.Load(a.resolveSnapshotPath(path))
	if err != nil {
		return nil, err
	}
	reg, err := devices.Load(a.registryPath())
	if err != nil {
		return nil, err
	}
	return append(hostnameHints(snap.Nodes, &reg), macHints(snap.Nodes, &reg)...), nil
}

// overlayNodes stamps operator device identity and labels onto map nodes.
func overlayNodes(nodes []mapview.MapNode, reg *devices.Registry) {
	for i := range nodes {
		if d := reg.DeviceForIP(nodes[i].ID); d != nil {
			nodes[i].Device, nodes[i].DeviceType = d.Name, d.Type
		}
		if lbls := reg.Labels[nodes[i].ID]; len(lbls) > 0 {
			nodes[i].Labels = lbls
		}
		if role := reg.RoleOverrides[nodes[i].ID]; role != "" {
			nodes[i].RoleOverride = role
			if t, ok := overrideTiers[strings.ToLower(role)]; ok {
				nodes[i].Tier = t
			}
		}
		nodes[i].Pinned = reg.IsPinned(nodes[i].ID)
	}
}

// operatorFacts flattens the registry into per-IP ground truth for the AI
// tagging prompt: device name/type, role overrides, durable labels. Notes
// never leave the host. A corrupt registry yields nil — tagging proceeds
// without grounding rather than failing.
func (a *App) operatorFacts() map[string]assist.OperatorFacts {
	reg, err := devices.Load(a.registryPath())
	if err != nil {
		a.emit("device:warning", "device registry unreadable — AI tagging runs without operator facts: "+err.Error())
		return nil
	}
	facts := map[string]assist.OperatorFacts{}
	for _, d := range reg.Devices {
		for _, ip := range d.IPs {
			f := facts[ip]
			f.Device, f.DeviceType = d.Name, d.Type
			facts[ip] = f
		}
	}
	for ip, role := range reg.RoleOverrides {
		f := facts[ip]
		f.RoleOverride = role
		facts[ip] = f
	}
	for ip, labels := range reg.Labels {
		f := facts[ip]
		f.Labels = labels
		facts[ip] = f
	}
	return facts
}

// applyDeviceOverlay loads the registry and overlays it; a corrupt
// registry never blocks map loading — the overlay is skipped and the
// operator warned in the task log.
func (a *App) applyDeviceOverlay(nodes []mapview.MapNode) {
	reg, err := devices.Load(a.registryPath())
	if err != nil {
		a.emit("device:warning", "device registry unreadable — overlay skipped: "+err.Error())
		return
	}
	overlayNodes(nodes, &reg)
}
