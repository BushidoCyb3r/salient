package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Create an instance of the app structure
	app := NewApp()

	appMenu := menu.NewMenu()
	// Without an Edit menu, macOS has no menu item bound to Cmd+C/Cmd+V/etc,
	// so keyboard paste into the connect form's inputs silently does
	// nothing. EditMenu() wires the standard Cut/Copy/Paste/Select All/
	// Undo/Redo roles to the OS's native handlers.
	appMenu.Append(menu.EditMenu())
	fileMenu := appMenu.AddSubmenu("File")
	fileMenu.AddText("Open Snapshot...", keys.CmdOrCtrl("o"), func(_ *menu.CallbackData) {
		path, err := runtime.OpenFileDialog(app.ctx, runtime.OpenDialogOptions{
			DefaultDirectory: app.DataDir + "/snapshots",
			Filters: []runtime.FileFilter{
				{DisplayName: "Defilade snapshots (*.json.gz)", Pattern: "*.json.gz"},
			},
		})
		if err != nil || path == "" {
			return
		}
		runtime.EventsEmit(app.ctx, "snapshot:open", path)
	})
	fileMenu.AddText("Refresh", keys.CmdOrCtrl("r"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "snapshots:refresh")
	})

	// Create application with options
	err := wails.Run(&options.App{
		Title:  "Defilade Briefing Map",
		Width:  1440,
		Height: 900,
		Menu:   appMenu,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
