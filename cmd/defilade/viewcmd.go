package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	defilade "github.com/BushidoCyb3r/defilade"
	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
	"github.com/spf13/cobra"
)

const browserIndexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Defilade reports</title><style>
:root{color-scheme:dark}body{margin:0;background:#111820;color:#e8edf2;font:16px system-ui,sans-serif}main{max-width:900px;margin:auto;padding:32px}header{display:flex;align-items:center;gap:20px;border-bottom:1px solid #34414d;padding-bottom:20px}.logo{width:96px;height:96px;object-fit:contain}h1{margin:0}.note{color:#aeb9c3}.scan{display:flex;align-items:center;justify-content:space-between;gap:20px;background:#1b2630;border:1px solid #34414d;border-radius:8px;margin:16px 0;padding:18px}.links{display:flex;gap:10px}a{background:#b58a43;color:#111820;text-decoration:none;font-weight:700;padding:9px 14px;border-radius:5px}a:hover{background:#d1a65d}@media(max-width:600px){.scan{align-items:flex-start;flex-direction:column}}</style></head>
<body><main><header><img class="logo" alt="Defilade logo" src="data:image/png;base64,{{.Logo}}"><div><h1>Defilade reports</h1><p class="note">Local terrain artifacts · newest first</p></div></header>
{{range .Entries}}<section class="scan"><time>{{.Timestamp}}</time><div class="links">{{if .Report}}<a href="{{.Report}}">Report</a>{{end}}{{if .Map}}<a href="{{.Map}}">Map</a>{{end}}</div></section>{{end}}
<p class="note">Protect these artifacts at the network's classification.</p></main></body></html>`

func newViewCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "view",
		Short: "Open a browser index of saved reports and maps",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := writeBrowserIndex(dataDir, defilade.LogoPNG)
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			target := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
			name, browserArgs, err := browserCommand(runtime.GOOS, os.Getenv("BROWSER"), target, exec.LookPath)
			if err != nil {
				return fmt.Errorf("%w; index written to %s", err, path)
			}
			process := exec.Command(name, browserArgs...)
			if err := process.Start(); err != nil {
				return fmt.Errorf("opening browser: %w; index written to %s", err, path)
			}
			_ = process.Process.Release()
			fmt.Fprintf(cmd.OutOrStdout(), "Index: %s\n", path)
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: these reports describe network terrain — protect them at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DataDirName, "data directory")
	return cmd
}

func writeBrowserIndex(dataDir string, logo []byte) (string, error) {
	entries, err := snapshot.ScanArtifacts(dataDir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errors.New("no HTML reports or maps found — run `defilade scan` first")
	}

	if err := os.MkdirAll(dataDir, config.OutputDirMode); err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, "index.html")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Chmod(config.OutputFileMode); err != nil {
		return "", err
	}
	data := struct {
		Logo    string
		Entries []snapshot.ArtifactEntry
	}{base64.StdEncoding.EncodeToString(logo), entries}
	if err := template.Must(template.New("index").Parse(browserIndexHTML)).Execute(io.Writer(f), data); err != nil {
		return "", err
	}
	return path, nil
}

func browserCommand(goos, browser, target string, lookPath func(string) (string, error)) (string, []string, error) {
	if browser != "" {
		parts := strings.Fields(browser)
		if name, err := lookPath(parts[0]); err == nil {
			return name, append(parts[1:], target), nil
		}
	}
	type candidate struct {
		name string
		args []string
	}
	var candidates []candidate
	switch goos {
	case "darwin":
		candidates = []candidate{{"open", []string{target}}}
	case "windows":
		candidates = []candidate{{"rundll32", []string{"url.dll,FileProtocolHandler", target}}}
	default:
		candidates = []candidate{{"gio", []string{"open", target}}, {"xdg-open", []string{target}}, {"sensible-browser", []string{target}}}
	}
	for _, candidate := range candidates {
		if name, err := lookPath(candidate.name); err == nil {
			return name, candidate.args, nil
		}
	}
	return "", nil, errors.New("no default browser launcher found")
}
