package main

import (
	"context"
	"fmt"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

// App struct
type App struct {
	ctx     context.Context
	DataDir string
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{DataDir: config.DataDirName}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) ListSnapshots() ([]snapshot.ArtifactEntry, error) {
	return snapshot.ScanArtifacts(a.DataDir)
}

func (a *App) LoadModel(path string) (*mapview.Model, error) {
	snap, err := snapshot.Load(path)
	if err != nil {
		return nil, err
	}
	return mapview.Build(snap, mapview.Options{}), nil
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
