package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/escli"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/scan"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

// App struct
type App struct {
	ctx     context.Context
	DataDir string

	// emitFn, when set, replaces the Wails runtime event emitter — the
	// scan progress path is then unit-testable without the Wails runtime.
	emitFn func(event string, data ...interface{})

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
// on macOS it's often "/", which isn't writable. A relative "defilade-data"
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

// LoadModel accepts either an absolute path (native Open dialog) or a
// DataDir-relative path (ArtifactEntry.Snapshot from ListSnapshots).
func (a *App) LoadModel(path string) (*mapview.Model, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.DataDir, path)
	}
	snap, err := snapshot.Load(path)
	if err != nil {
		return nil, err
	}
	return mapview.Build(snap, mapview.Options{}), nil
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
