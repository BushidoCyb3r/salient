package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/salient/internal/assist"
	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/devices"
	"github.com/BushidoCyb3r/salient/internal/escli"
	"github.com/BushidoCyb3r/salient/internal/hunt"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
	"github.com/BushidoCyb3r/salient/internal/report"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/scan"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// App struct
type App struct {
	ctx     context.Context
	DataDir string

	// emitFn, when set, replaces the Wails runtime event emitter — the
	// scan progress path is then unit-testable without the Wails runtime.
	emitFn func(event string, data ...interface{})
	// saveFileFn, when set, replaces runtime.SaveFileDialog — ExportMap's
	// render logic is then unit-testable without the Wails runtime.
	saveFileFn func(opts runtime.SaveDialogOptions) (string, error)
	// openFileFn, when set, replaces runtime.OpenFileDialog — PickAssetCSV
	// is then unit-testable without the Wails runtime.
	openFileFn func(opts runtime.OpenDialogOptions) (string, error)

	mu     sync.Mutex
	cli    *escli.Client      // set by Connect; nil until connected
	info   escli.ClusterInfo  // connected cluster identity
	fm     escli.FieldMap     // field map resolved at connect time
	cancel context.CancelFunc // non-nil while a scan is running
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{DataDir: defaultDataDir()}
}

// defaultDataDir anchors DataDir to the user's home directory. Unlike the
// CLI — always run from a terminal in a directory the operator chose —
// a double-clicked (or `open`ed) .app has no reliable working directory;
// on macOS it's often "/", which isn't writable. A relative "salient-data"
// would then fail every scan with a read-only-filesystem error.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return config.DataDirName
	}
	return filepath.Join(home, config.DataDirName)
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) emit(event string, data ...interface{}) {
	if a.emitFn != nil {
		a.emitFn(event, data...)
		return
	}
	runtime.EventsEmit(a.ctx, event, data...)
}

func (a *App) ListSnapshots() ([]snapshot.ArtifactEntry, error) {
	return snapshot.ScanArtifacts(a.DataDir)
}

// resolveSnapshotPath accepts either an absolute path (native Open dialog)
// or a DataDir-relative path (ArtifactEntry.Snapshot from ListSnapshots).
func (a *App) resolveSnapshotPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(a.DataDir, path)
}

// finishModel applies the per-snapshot overlays every map view needs:
// model-assisted tag suggestions (sidecar keyed on the resolved snapshot
// path) and the operator device registry. Extracted so plain, drift, and
// reconcile views cannot drift apart in post-processing.
func (a *App) finishModel(resolved string, model *mapview.Model) (*mapview.Model, error) {
	artifact, err := loadTagArtifact(resolved)
	if err != nil {
		return nil, err
	}
	if artifact != nil {
		byID := make(map[string]assist.DeviceTag, len(artifact.Tags))
		for _, tag := range artifact.Tags {
			byID[tag.NodeID] = tag
		}
		for i := range model.Nodes {
			if tag, ok := byID[model.Nodes[i].ID]; ok {
				model.Nodes[i].SuggestedTags = tag.Tags
				model.Nodes[i].SuggestionConfidence = tag.Confidence
				model.Nodes[i].SuggestionRationale = tag.Rationale
				model.Nodes[i].SuggestionModel = artifact.Model
			}
		}
	}
	a.applyDeviceOverlay(model)
	return model, nil
}

// mapOptions builds the map Options from the operator registry — currently
// the pin set that force-retains hosts as their own overview node. A corrupt
// registry yields empty options rather than failing the map.
func (a *App) mapOptions() mapview.Options {
	reg, err := devices.Load(a.registryPath())
	if err != nil {
		return mapview.Options{}
	}
	opts := mapview.Options{RetainAllPrivate: reg.ShowAllPrivate}
	if len(reg.Pinned) > 0 {
		opts.Pinned = make(map[string]bool, len(reg.Pinned))
		for _, ip := range reg.Pinned {
			opts.Pinned[ip] = true
		}
	}
	for _, d := range reg.Devices {
		for _, ip := range d.IPs {
			if opts.Pinned == nil {
				opts.Pinned = map[string]bool{}
			}
			opts.Pinned[ip] = true
		}
	}
	for ip, role := range reg.RoleOverrides {
		if customDeviceLabel(role) {
			if opts.Pinned == nil {
				opts.Pinned = map[string]bool{}
			}
			opts.Pinned[ip] = true
		}
	}
	for _, s := range reg.Segments {
		opts.Segments = append(opts.Segments, mapview.Segment{CIDR: s.CIDR, Name: s.Name})
	}
	return opts
}

// LoadModel loads a snapshot and re-derives its briefing-map model fresh.
func (a *App) LoadModel(path string) (*mapview.Model, error) {
	resolved := a.resolveSnapshotPath(path)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	return a.finishModel(resolved, mapview.Build(snap, a.mapOptions()))
}

// LoadFocusedModel is the segment drill-down: it re-derives the map focused on
// one CIDR, so the caller can render every host and intra-segment flow of a
// single VLAN and offer a "back to overview" return.
func (a *App) LoadFocusedModel(path, cidr string) (*mapview.Model, error) {
	resolved := a.resolveSnapshotPath(path)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	opts := a.mapOptions()
	opts.Focus = cidr
	// Drilling in means "show me everything in this VLAN": no client
	// aggregation, every host individual — that is the point of the drill.
	opts.RetainAllPrivate = true
	return a.finishModel(resolved, mapview.Build(snap, opts))
}

// LoadDriftModel builds a drift-overlaid map: fromPath is the baseline,
// toPath the snapshot under review. Drift counts ride Model.Findings.
func (a *App) LoadDriftModel(fromPath, toPath string) (*mapview.Model, error) {
	from, err := snapshot.Load(a.resolveSnapshotPath(fromPath))
	if err != nil {
		return nil, fmt.Errorf("baseline snapshot: %w", err)
	}
	resolved := a.resolveSnapshotPath(toPath)
	to, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	d := snapshot.Compare(from, to, snapshot.DiffOptions{})
	model := mapview.BuildDrift(to, d, a.mapOptions())
	for _, warning := range d.CompatibilityWarnings {
		model.Findings = append(model.Findings, "comparison warning: "+warning)
	}
	model.Findings = append(model.Findings, fmt.Sprintf(
		"drift vs %s: %d appeared, %d vanished, %d rank changes, %d new edges to top terrain, %d vanished critical edges, %d identity changes, %d new sensitive-service providers, %d provider displacements",
		from.Meta.CreatedAt.UTC().Format("20060102T150405Z"),
		len(d.AppearedNodes), len(d.DisappearedNodes), len(d.RankChanges),
		len(d.NewEdgesToTop), len(d.VanishedCriticalEdges), len(d.IdentityChanges), len(d.NewProviders), len(d.ProviderDisplacements)))
	for _, change := range d.IdentityChanges {
		model.Findings = append(model.Findings, fmt.Sprintf(
			"%s identity changed on %s: added %v removed %v",
			strings.ToUpper(change.Protocol), change.IP, change.Added, change.Removed))
	}
	for _, p := range d.NewProviders {
		hostNote := ""
		if p.NewHost {
			hostNote = ", host first seen this window"
		}
		model.Findings = append(model.Findings, fmt.Sprintf(
			"new provider: %s began serving %s (port %d) to %d client(s)%s — investigate if unexpected",
			p.IP, p.Service, p.Port, p.Clients, hostNote))
	}
	for _, p := range d.ProviderDisplacements {
		for _, src := range p.MigratedFrom {
			model.Findings = append(model.Findings, fmt.Sprintf(
				"%d client(s) moved from %s:%d to %s:%d for %s",
				src.Clients, src.IP, src.Port, p.IP, p.Port, p.Service))
		}
	}
	return a.finishModel(resolved, model)
}

// AggregateHosts lists the hosts collapsed into an aggregate map node
// ("N workstations" / "N other hosts"), identified by its node ID
// ("g:<cidr>:clients"). Ranked hosts come first (best rank leading),
// unranked hosts follow ordered by IP string, matching the map's own sort.
func (a *App) AggregateHosts(path string, nodeID string) ([]mapview.MapNode, error) {
	resolved := a.resolveSnapshotPath(path)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	model, err := a.finishModel(resolved, mapview.Build(snap, a.mapOptions()))
	if err != nil {
		return nil, err
	}
	hosts := model.AggMembers[nodeID]
	sort.Slice(hosts, func(i, j int) bool {
		x, y := hosts[i], hosts[j]
		if (x.Rank > 0) != (y.Rank > 0) {
			return x.Rank > 0
		}
		if x.Rank != y.Rank {
			return x.Rank < y.Rank
		}
		return x.ID < y.ID
	})
	return hosts, nil
}

// FlowEndpointIPs returns the real IPs behind a bundled flow arrow's
// aggregated endpoint (srcID or dstID, whichever is a group node like
// "g:external:clients"), identified as shown on the map plus the arrow's
// service class label. Empty when neither end is aggregated.
func (a *App) FlowEndpointIPs(path, srcID, dstID, class string) ([]string, error) {
	resolved := a.resolveSnapshotPath(path)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	model := mapview.Build(snap, a.mapOptions())
	return model.EdgeMemberIPs(snap, srcID, dstID, class), nil
}

// LoadServiceAuthority derives the Service Authority view from a snapshot:
// one row per sensitive-service provider, sorted by client count. Pure
// aggregation over the stored snapshot — no live ES query.
func (a *App) LoadServiceAuthority(path string) ([]mapview.ServiceProvider, error) {
	snap, err := snapshot.Load(a.resolveSnapshotPath(path))
	if err != nil {
		return nil, err
	}
	return mapview.BuildServiceAuthority(snap), nil
}

// LoadHuntLeads derives prioritized investigation leads from a snapshot,
// optionally enriched with drift (basePath) and reconciliation (assetsPath)
// context. Both are optional — an empty basePath skips drift-derived leads
// (new-provider/new-service), an empty assetsPath skips reconciliation-
// derived leads (undocumented/contradicted). Pure composition over
// already-loaded snapshots — no live ES query.
func (a *App) LoadHuntLeads(path, basePath, assetsPath string) ([]hunt.Lead, error) {
	snap, err := snapshot.Load(a.resolveSnapshotPath(path))
	if err != nil {
		return nil, err
	}

	var diff *snapshot.Diff
	if basePath != "" {
		base, err := snapshot.Load(a.resolveSnapshotPath(basePath))
		if err != nil {
			return nil, fmt.Errorf("baseline snapshot: %w", err)
		}
		d := snapshot.Compare(base, snap, snapshot.DiffOptions{})
		diff = &d
	}

	var rec *reconcile.Result
	if assetsPath != "" {
		f, err := os.Open(assetsPath)
		if err != nil {
			return nil, fmt.Errorf("asset CSV: %w", err)
		}
		defer f.Close()
		assets, _, err := reconcile.ParseCSV(f)
		if err != nil {
			return nil, fmt.Errorf("asset CSV: %w", err)
		}
		r := reconcile.Compare(snap, assets)
		rec = &r
	}

	reg, err := devices.Load(a.registryPath())
	if err != nil {
		a.emit("device:warning", "device registry unreadable — approved-provider suppression skipped: "+err.Error())
		return hunt.BuildLeads(snap, diff, rec, nil), nil
	}
	approved := make(map[string]bool, len(reg.ApprovedProviders))
	for _, k := range reg.ApprovedProviders {
		approved[k] = true
	}
	return hunt.BuildLeads(snap, diff, rec, approved), nil
}

// PickAssetCSV opens the native Open dialog for an asset inventory CSV.
// Returns "" (no error) when the dialog is cancelled.
func (a *App) PickAssetCSV() (string, error) {
	open := a.openFileFn
	if open == nil {
		open = func(opts runtime.OpenDialogOptions) (string, error) {
			return runtime.OpenFileDialog(a.ctx, opts)
		}
	}
	return open(runtime.OpenDialogOptions{
		Title:   "Asset inventory CSV",
		Filters: []runtime.FileFilter{{DisplayName: "CSV", Pattern: "*.csv"}},
	})
}

// LoadReconcileModel reconciles a snapshot against an asset CSV file and
// returns the flagged map model. ParseCSV warnings and reconcile counts ride
// Model.Findings.
func (a *App) LoadReconcileModel(snapshotPath, assetsPath string) (*mapview.Model, error) {
	f, err := os.Open(assetsPath)
	if err != nil {
		return nil, fmt.Errorf("asset CSV: %w", err)
	}
	defer f.Close()
	return a.reconcileFrom(snapshotPath, f)
}

// LoadReconcileModelCSV reconciles a snapshot against asset rows the operator
// typed into the in-app grid, serialized as CSV text (header ip,hostname,
// role,segment). Same parse + reconcile path as the file loader — the only
// difference is where the CSV comes from.
func (a *App) LoadReconcileModelCSV(snapshotPath, csvText string) (*mapview.Model, error) {
	return a.reconcileFrom(snapshotPath, strings.NewReader(csvText))
}

func (a *App) reconcileFrom(snapshotPath string, assets io.Reader) (*mapview.Model, error) {
	resolved := a.resolveSnapshotPath(snapshotPath)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	parsed, warnings, err := reconcile.ParseCSV(assets)
	if err != nil {
		return nil, fmt.Errorf("asset list: %w", err)
	}
	res := reconcile.Compare(snap, parsed)
	model := mapview.BuildReconcile(snap, res, parsed, a.mapOptions())
	for _, w := range warnings {
		model.Findings = append(model.Findings, "asset list: "+w)
	}
	return a.finishModel(resolved, model)
}

type TagRequest struct {
	SnapshotPath string
	Provider     string
	Endpoint     string
	Model        string
	APIKey       string
	AllowRemote  bool
}

type TagArtifact struct {
	GeneratedAt  time.Time          `json:"generated_at"`
	Provider     string             `json:"provider"`
	EndpointHost string             `json:"endpoint_host"`
	Model        string             `json:"model"`
	Tags         []assist.DeviceTag `json:"tags"`
}

// SuggestTags stores generated labels separately from observed snapshot data.
// The API key is used only for this request and is never persisted.
func (a *App) SuggestTags(req TagRequest) (*assist.TagResult, error) {
	resolved := a.resolveSnapshotPath(req.SnapshotPath)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := assist.TagDevices(ctx, assist.Config{
		Provider:    assist.Provider(req.Provider),
		Endpoint:    req.Endpoint,
		Model:       req.Model,
		APIKey:      req.APIKey,
		AllowRemote: req.AllowRemote,
	}, snap, a.operatorFacts())
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(req.Endpoint)
	if err != nil {
		return nil, err
	}
	artifact := TagArtifact{
		GeneratedAt: time.Now().UTC(), Provider: req.Provider,
		EndpointHost: u.Host, Model: req.Model, Tags: result.Tags,
	}
	if err := writeTagArtifact(resolved, artifact); err != nil {
		return nil, err
	}
	return &result, nil
}

// SuggestTagsForHosts tags only the given IPs — the on-demand path for
// aggregated "other hosts". Results merge into the existing sidecar: tags for
// the listed IPs are replaced, all others kept, so repeated targeted runs
// accumulate rather than clobber.
func (a *App) SuggestTagsForHosts(req TagRequest, ips []string) (*assist.TagResult, error) {
	resolved := a.resolveSnapshotPath(req.SnapshotPath)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return nil, err
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := assist.TagDevicesForIPs(ctx, assist.Config{
		Provider:    assist.Provider(req.Provider),
		Endpoint:    req.Endpoint,
		Model:       req.Model,
		APIKey:      req.APIKey,
		AllowRemote: req.AllowRemote,
	}, snap, a.operatorFacts(), ips)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(req.Endpoint)
	if err != nil {
		return nil, err
	}
	targeted := make(map[string]bool, len(ips))
	for _, ip := range ips {
		targeted[ip] = true
	}
	merged := result.Tags
	if prev, err := loadTagArtifact(resolved); err == nil && prev != nil {
		for _, t := range prev.Tags {
			if !targeted[t.NodeID] {
				merged = append(merged, t)
			}
		}
	}
	if err := writeTagArtifact(resolved, TagArtifact{
		GeneratedAt: time.Now().UTC(), Provider: req.Provider,
		EndpointHost: u.Host, Model: req.Model, Tags: merged,
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

func writeTagArtifact(snapshotPath string, artifact TagArtifact) error {
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(tagArtifactPath(snapshotPath), raw)
}

func tagArtifactPath(snapshotPath string) string { return snapshotPath + ".tags.json" }

func loadTagArtifact(snapshotPath string) (*TagArtifact, error) {
	raw, err := os.ReadFile(tagArtifactPath(snapshotPath))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading device tags: %w", err)
	}
	var artifact TagArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return nil, fmt.Errorf("decoding device tags: %w", err)
	}
	return &artifact, nil
}

// ExportMap re-renders the snapshot currently on screen as html or graphml —
// the same renderers the CLI's `map --format` uses — and saves it wherever
// the operator picks via the native Save dialog. Returns "" (no error) if
// the dialog was cancelled.
//
// "svg" is deliberately not offered here: report.SVGMap lays nodes out with
// its own static grid algorithm, independent of whatever fcose/dagre layout
// is currently on screen in the console, so the export would never match
// what the operator is looking at — exactly the complaint that led to
// ExportImage below, which rasterizes the live Cytoscape canvas instead.
func (a *App) ExportMap(path string, format string) (string, error) {
	resolved := a.resolveSnapshotPath(path)
	snap, err := snapshot.Load(resolved)
	if err != nil {
		return "", err
	}
	mm, err := a.finishModel(resolved, mapview.Build(snap, a.mapOptions()))
	if err != nil {
		return "", err
	}

	var ext, filterName string
	var render func(io.Writer, *mapview.Model) error
	switch format {
	case "graphml":
		ext, filterName, render = ".graphml", "GraphML", report.GraphMLMap
	case "html":
		ext, filterName, render = ".html", "HTML", report.HTMLMap
	default:
		return "", fmt.Errorf("unknown export format %q (want html or graphml)", format)
	}

	saveDialog := a.saveFileFn
	if saveDialog == nil {
		saveDialog = func(opts runtime.SaveDialogOptions) (string, error) {
			return runtime.SaveFileDialog(a.ctx, opts)
		}
	}
	out, err := saveDialog(runtime.SaveDialogOptions{
		DefaultFilename: snap.Meta.CreatedAt.UTC().Format("20060102T150405Z") + ext,
		Filters:         []runtime.FileFilter{{DisplayName: filterName, Pattern: "*" + ext}},
	})
	if err != nil || out == "" {
		return "", err
	}

	if err := safefile.Write(out, func(w io.Writer) error { return render(w, mm) }); err != nil {
		return "", err
	}
	return out, nil
}

// ExportImage saves a PNG the frontend captured from the live Cytoscape
// canvas via cy.png() — i.e. exactly the layout, positions, and colors
// currently on screen, whichever of fcose/dagre is active. dataURL is the
// "data:image/png;base64,..." string cy.png() returns. Returns "" (no
// error) if the Save dialog was cancelled.
func (a *App) ExportImage(dataURL string) (string, error) {
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(dataURL, prefix) {
		return "", errors.New("expected a data:image/png;base64 URL")
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dataURL, prefix))
	if err != nil {
		return "", fmt.Errorf("decoding image data: %w", err)
	}

	saveDialog := a.saveFileFn
	if saveDialog == nil {
		saveDialog = func(opts runtime.SaveDialogOptions) (string, error) {
			return runtime.SaveFileDialog(a.ctx, opts)
		}
	}
	out, err := saveDialog(runtime.SaveDialogOptions{
		DefaultFilename: time.Now().UTC().Format("20060102T150405Z") + ".png",
		Filters:         []runtime.FileFilter{{DisplayName: "PNG image", Pattern: "*.png"}},
	})
	if err != nil || out == "" {
		return "", err
	}
	if err := safefile.WriteFile(out, png); err != nil {
		return "", err
	}
	return out, nil
}

// ConnectRequest is the connection form the launch screen submits. The API
// key lives only in this request and the resulting in-memory client — it is
// never written to disk or included in any emitted event.
type ConnectRequest struct {
	ESURL              string
	APIKey             string
	CACertPath         string
	FieldmapPath       string
	InsecureSkipVerify bool
}

// Connect validates the grid connection (authenticated GET /), resolves the
// field map, and stores a live client in memory for RunScan to reuse. It
// returns the cluster identity so the console can show what it's attached to.
// connectProbeTimeout bounds the initial GET / auth check so an
// unreachable or silently-dropping host fails fast with a visible error
// instead of leaving the Connect button spinning indefinitely — the
// connect screen has no cancel affordance, unlike a running scan.
const connectProbeTimeout = 20 * time.Second

func (a *App) Connect(req ConnectRequest) (escli.ClusterInfo, error) {
	cli, err := escli.New(escli.Config{
		ESURL:              req.ESURL,
		APIKey:             req.APIKey,
		CACertPath:         req.CACertPath,
		InsecureSkipVerify: req.InsecureSkipVerify,
		Timeout:            config.HTTPTimeout,
	})
	if err != nil {
		return escli.ClusterInfo{}, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, connectProbeTimeout)
	defer cancel()
	info, err := cli.Info(ctx)
	if err != nil {
		return escli.ClusterInfo{}, err
	}
	fm, err := escli.LoadFieldMap(req.FieldmapPath)
	if err != nil {
		return escli.ClusterInfo{}, err
	}
	a.mu.Lock()
	a.cli, a.info, a.fm = cli, info, fm
	a.mu.Unlock()

	// Surface the same trust warnings the CLI prints — a GUI-only operator
	// otherwise never sees that TLS verification is off or that the key can
	// write (SALIENT_PLAN.md §14). Best-effort: the connection itself
	// already succeeded, so a failed privilege probe is not fatal.
	if req.InsecureSkipVerify {
		a.emit("connect:warning", "TLS certificate verification is DISABLED — the connection to the grid is open to interception. Use a CA cert instead.")
	}
	if priv, perr := cli.CheckWritePrivileges(ctx, fm.IndexPattern); perr != nil {
		a.emit("connect:warning", "could not verify that this API key is read-only: "+perr.Error())
	} else if priv.Indeterminate {
		a.emit("connect:warning", "could not verify that this API key is read-only: "+priv.Detail)
	} else if priv.CanWrite {
		a.emit("connect:warning", "this API key can WRITE to "+fm.IndexPattern+" ("+priv.Detail+"). Salient never writes, but the key violates least privilege — create a read-only key.")
	}
	return info, nil
}

// ScanRequest is the scan form the console submits.
type ScanRequest struct {
	Window   string // Go duration, e.g. "336h"
	Scope    []string
	MaxEdges int
	TZ       string
}

// RunScan runs the shared pipeline against the connected client, emitting a
// "scan:progress" event per stage, then "scan:done" (snapshot path) or
// "scan:error". It blocks until the scan finishes; the frontend awaits the
// returned Result while listening for the progress events. Only one scan may
// run at a time.
func (a *App) RunScan(req ScanRequest) (*scan.Result, error) {
	window, err := time.ParseDuration(req.Window)
	if err != nil {
		return nil, fmt.Errorf("invalid window %q: %w", req.Window, err)
	}

	a.mu.Lock()
	cli, info, fm := a.cli, a.info, a.fm
	if cli == nil {
		a.mu.Unlock()
		return nil, errors.New("not connected — connect to a grid first")
	}
	if a.cancel != nil {
		a.mu.Unlock()
		return nil, errors.New("a scan is already running")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.cancel = nil
		a.mu.Unlock()
		cancel()
	}()

	res, err := scan.Run(ctx, cli, fm, info, scan.Options{
		Window:   window,
		Scope:    req.Scope,
		MaxEdges: req.MaxEdges,
		TZ:       req.TZ,
	}, a.DataDir, func(s scan.Stage) {
		a.emit("scan:progress", s)
	})
	if err != nil {
		a.emit("scan:error", err.Error())
		return nil, err
	}
	a.emit("scan:done", res.SnapshotPath)
	return &res, nil
}

// CancelScan aborts a running scan, if any.
func (a *App) CancelScan() {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

type LegendItem struct {
	Label string
	Color string
}

func (a *App) Legend() []LegendItem {
	classes := []config.ServiceClass{
		config.ClassAuth,
		config.ClassName,
		config.ClassFile,
		config.ClassDB,
		config.ClassWeb,
		config.ClassAdmin,
		config.ClassOther,
	}
	items := make([]LegendItem, len(classes))
	for i, class := range classes {
		items[i] = LegendItem{Label: config.ClassLabel(class), Color: config.MapPalette[class]}
	}
	return items
}
