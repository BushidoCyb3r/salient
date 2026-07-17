package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/netconfig"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// declaredArtifact is the sanitized persistence for ingested device configs.
// It holds only parsed DeclaredDevices — secrets are already stripped by the
// parsers — plus the last diff results. Raw config text is never written.
type declaredArtifact struct {
	Devices   []netconfig.DeclaredDevice `json:"devices"`
	Inventory netconfig.InventoryResult  `json:"inventory"`
	Policy    netconfig.PolicyResult     `json:"policy"`
	UpdatedAt time.Time                  `json:"updated_at"`
}

func (a *App) declaredPath() string { return filepath.Join(a.DataDir, "declared.json") }

// loadDeclaredArtifact reads persisted device configs; nil (no error) when none
// have been ingested yet. A corrupt file surfaces as an error to the caller.
func (a *App) loadDeclaredArtifact() (*declaredArtifact, error) {
	raw, err := os.ReadFile(a.declaredPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading declared configs: %w", err)
	}
	var art declaredArtifact
	if err := json.Unmarshal(raw, &art); err != nil {
		return nil, fmt.Errorf("decoding declared configs: %w", err)
	}
	return &art, nil
}

// declaredGateways re-derives the declared gateway map for a snapshot from the
// persisted device configs, if any. Re-diffing (rather than reusing the stored
// gateway map) keeps the overlay correct for whichever snapshot is loaded — the
// gateways depend on which subnets hold observed nodes.
func (a *App) declaredGateways(snap graph.Snapshot) map[string]string {
	art, err := a.loadDeclaredArtifact()
	if err != nil || art == nil {
		return nil
	}
	return netconfig.DiffInventory(snap, art.Devices).DeclaredGateways
}

// declaredPolicy re-derives the policy diff for a snapshot from persisted
// configs, for hunt-lead enrichment. nil when nothing is ingested.
func (a *App) declaredPolicy(snap graph.Snapshot) *netconfig.PolicyResult {
	art, err := a.loadDeclaredArtifact()
	if err != nil || art == nil {
		return nil
	}
	p := netconfig.DiffPolicy(snap, art.Devices)
	return &p
}

// PickDeviceConfigs opens the native multi-select Open dialog for device config
// exports (Cisco IOS text, UniFi controller JSON). Returns nil (no error) when
// the dialog is cancelled.
func (a *App) PickDeviceConfigs() ([]string, error) {
	open := a.openMultiFn
	if open == nil {
		open = func(opts runtime.OpenDialogOptions) ([]string, error) {
			return runtime.OpenMultipleFilesDialog(a.ctx, opts)
		}
	}
	return open(runtime.OpenDialogOptions{
		Title: "Device configs (Cisco IOS / UniFi JSON)",
		Filters: []runtime.FileFilter{
			{DisplayName: "Device configs", Pattern: "*.txt;*.cfg;*.conf;*.json"},
		},
	})
}

// LoadDeclared reads the given config files, autodetects and parses each, diffs
// them against the snapshot, persists the sanitized devices + results to
// salient-data/declared.json, and returns the map model with declared-gateway
// identity and findings applied.
func (a *App) LoadDeclared(snapshotPath string, configPaths []string) (*mapview.Model, error) {
	resolved := a.resolveSnapshotPath(snapshotPath)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, p := range configPaths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		files[p] = raw
	}
	if len(files) == 0 {
		return nil, errors.New("no device config files selected")
	}

	devs, warnings := netconfig.ParseConfigs(files)
	inv := netconfig.DiffInventory(snap, devs)
	pol := netconfig.DiffPolicy(snap, devs)

	raw, err := json.MarshalIndent(declaredArtifact{
		Devices: devs, Inventory: inv, Policy: pol, UpdatedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := safefile.WriteFile(a.declaredPath(), raw); err != nil {
		return nil, err
	}

	opts := a.mapOptions()
	opts.DeclaredGateways = inv.DeclaredGateways
	model := mapview.Build(snap, opts)
	model.Findings = append(model.Findings, declaredFindings(devs, inv, pol, warnings)...)
	return a.finishModel(resolved, model)
}

// ClearDeclared removes persisted device configs so the map reverts to plain
// observed terrain. No-op (no error) when nothing is stored.
func (a *App) ClearDeclared() error {
	if err := os.Remove(a.declaredPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// declaredFindings summarizes the diffs into task-log lines, mirroring the
// reconcile findings style so the frontend renders them the same way.
func declaredFindings(devs []netconfig.DeclaredDevice, inv netconfig.InventoryResult, pol netconfig.PolicyResult, warnings []string) []string {
	var out []string
	for _, w := range warnings {
		out = append(out, "device configs: "+w)
	}
	for _, d := range devs {
		for _, w := range d.Warnings {
			out = append(out, "device configs ("+d.Hostname+"): "+w)
		}
	}
	out = append(out, fmt.Sprintf("device configs: %d device(s) declared, %d gateway(s) identified, %d silent subnet(s), %d undeclared CIDR(s)",
		len(devs), len(inv.DeclaredGateways), len(inv.SilentSubnets), len(inv.UndeclaredCIDRs)))
	out = append(out, fmt.Sprintf("declared policy: %d denied-but-observed violation(s), %d unused permit(s), %d rule(s) skipped (caveated)",
		len(pol.Violations), len(pol.UnusedPermits), pol.SkippedRules))
	for _, w := range inv.Warnings {
		out = append(out, "device configs: "+w)
	}
	for _, w := range pol.Warnings {
		out = append(out, "declared policy: "+w)
	}
	return out
}
