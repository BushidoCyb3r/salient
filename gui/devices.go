package main

import (
	"fmt"
	"net/netip"
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

// SetSegment declares (or renames) a real subnet that overrides auto-/24
// grouping; RemoveSegment drops it. The caller reloads the map to apply.
func (a *App) SetSegment(cidr, name string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { return r.SetSegment(cidr, name) })
}

// RemoveSegment drops an operator-declared subnet.
func (a *App) RemoveSegment(cidr string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { r.RemoveSegment(cidr); return nil })
}

// SetDeviceOwns replaces the CIDR ranges routed through a device (topology
// view). The caller reloads the map to apply.
func (a *App) SetDeviceOwns(name string, cidrs []string) error {
	return a.mutateRegistry(func(r *devices.Registry) error { return r.SetDeviceOwns(name, cidrs) })
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

func overlayModel(model *mapview.Model, reg *devices.Registry) {
	overlayNodes(model.Nodes, reg)
	for id, members := range model.AggMembers {
		overlayNodes(members, reg)
		model.AggMembers[id] = members
	}
	collapseDeviceRoleNodes(model)
}

func collapseDeviceRoleNodes(model *mapview.Model) {
	groups := map[string][]int{}
	for i, n := range model.Nodes {
		name, ok := collapseName(n)
		if !ok || n.AggCount > 0 || n.Gateway {
			continue
		}
		if _, err := netip.ParseAddr(n.ID); err != nil {
			continue
		}
		groups[name] = append(groups[name], i)
	}

	rewrite := map[string]string{}
	remove := map[int]bool{}
	devGroups := map[string]string{}
	for name, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		sort.Slice(idxs, func(i, j int) bool { return mapNodeLess(model.Nodes[idxs[i]], model.Nodes[idxs[j]]) })
		aggID := "dev:" + fmt.Sprintf("%x", name)
		groupID := "devg:" + fmt.Sprintf("%x", name)
		devGroups[groupID] = name
		members := make([]mapview.MapNode, 0, len(idxs))
		agg := model.Nodes[idxs[0]]
		agg.ID = aggID
		agg.Group = groupID
		agg.Label = fmt.Sprintf("%d IPs", len(idxs))
		agg.Device = name
		agg.AggCount = len(idxs)
		agg.Composite = 0
		agg.Rank = 0
		agg.RoleOverride = sharedOverride(model.Nodes, idxs)
		agg.MAC, agg.Vendor = "", ""
		agg.Pinned = false
		agg.Services = nil
		agg.Labels = nil
		for _, idx := range idxs {
			n := model.Nodes[idx]
			members = append(members, n)
			rewrite[n.ID] = aggID
			remove[idx] = true
			if n.Composite > agg.Composite {
				agg.Composite = n.Composite
			}
			if n.Rank > 0 && (agg.Rank == 0 || n.Rank < agg.Rank) {
				agg.Rank = n.Rank
			}
			agg.Services = appendUnique(agg.Services, n.Services...)
			agg.Labels = appendUnique(agg.Labels, n.Labels...)
		}
		if model.AggMembers == nil {
			model.AggMembers = map[string][]mapview.MapNode{}
		}
		model.AggMembers[aggID] = members
		model.Nodes = append(model.Nodes, agg)
	}
	if len(rewrite) == 0 {
		return
	}

	for id, label := range devGroups {
		model.Groups = append(model.Groups, mapview.Group{ID: id, Label: label})
	}
	kept := model.Nodes[:0]
	for i, n := range model.Nodes {
		if !remove[i] {
			kept = append(kept, n)
		}
	}
	model.Nodes = kept
	model.Edges = rewriteDeviceEdges(model.Edges, rewrite)
	sort.Slice(model.Groups, func(i, j int) bool { return model.Groups[i].ID < model.Groups[j].ID })
	sort.Slice(model.Nodes, func(i, j int) bool { return model.Nodes[i].ID < model.Nodes[j].ID })
}

func collapseName(n mapview.MapNode) (string, bool) {
	if n.Device != "" {
		return n.Device, true
	}
	if customDeviceLabel(n.RoleOverride) {
		return n.RoleOverride, true
	}
	return "", false
}

func customDeviceLabel(role string) bool {
	if role == "" {
		return false
	}
	switch strings.ToLower(role) {
	case "gateway", "networkgear", "unknown":
		return false
	}
	_, generic := overrideTiers[strings.ToLower(role)]
	return !generic
}

func sharedOverride(nodes []mapview.MapNode, idxs []int) string {
	role := nodes[idxs[0]].RoleOverride
	for _, idx := range idxs[1:] {
		if nodes[idx].RoleOverride != role {
			return ""
		}
	}
	return role
}

func mapNodeLess(a, b mapview.MapNode) bool {
	if (a.Rank > 0) != (b.Rank > 0) {
		return a.Rank > 0
	}
	if a.Rank != b.Rank && a.Rank > 0 {
		return a.Rank < b.Rank
	}
	return a.ID < b.ID
}

func appendUnique(out []string, vals ...string) []string {
	seen := map[string]bool{}
	for _, v := range out {
		seen[v] = true
	}
	for _, v := range vals {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func rewriteDeviceEdges(edges []mapview.MapEdge, rewrite map[string]string) []mapview.MapEdge {
	type key struct{ src, dst, class string }
	merged := map[key]mapview.MapEdge{}
	for _, e := range edges {
		if dst := rewrite[e.Src]; dst != "" {
			e.Src = dst
		}
		if dst := rewrite[e.Dst]; dst != "" {
			e.Dst = dst
		}
		if e.Src == e.Dst {
			continue
		}
		k := key{e.Src, e.Dst, e.Class}
		if prev, ok := merged[k]; ok {
			prev.Hosts += e.Hosts
			prev.Conns += e.Conns
			if e.Width > prev.Width {
				prev.Width = e.Width
			}
			if e.Drift != "" && prev.Drift != "" && e.Drift != prev.Drift {
				prev.Drift = "changed"
			} else if prev.Drift == "" {
				prev.Drift = e.Drift
			}
			if prev.Hosts > 1 {
				prev.Label = fmt.Sprintf("%d hosts → %s", prev.Hosts, prev.Class)
			}
			merged[k] = prev
			continue
		}
		merged[k] = e
	}
	out := make([]mapview.MapEdge, 0, len(merged))
	for _, e := range merged {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src < out[j].Src
		}
		if out[i].Dst != out[j].Dst {
			return out[i].Dst < out[j].Dst
		}
		return out[i].Class < out[j].Class
	})
	return out
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
func (a *App) applyDeviceOverlay(model *mapview.Model) {
	reg, err := devices.Load(a.registryPath())
	if err != nil {
		a.emit("device:warning", "device registry unreadable — overlay skipped: "+err.Error())
		return
	}
	overlayModel(model, &reg)
}
