package main

import (
	"path/filepath"
	"sort"

	"github.com/BushidoCyb3r/defilade/internal/devices"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
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

// overlayNodes stamps operator device identity and labels onto map nodes.
func overlayNodes(nodes []mapview.MapNode, reg *devices.Registry) {
	for i := range nodes {
		if d := reg.DeviceForIP(nodes[i].ID); d != nil {
			nodes[i].Device, nodes[i].DeviceType = d.Name, d.Type
		}
		if lbls := reg.Labels[nodes[i].ID]; len(lbls) > 0 {
			nodes[i].Labels = lbls
		}
	}
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
