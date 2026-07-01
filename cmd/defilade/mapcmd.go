package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/report"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func newMapCmd() *cobra.Command {
	var (
		path        string
		format      string
		focus       string
		groupPrefix int
		minConns    int64
	)
	cmd := &cobra.Command{
		Use:   "map --snapshot FILE",
		Short: "Render a briefing map from a stored snapshot (html|svg|graphml)",
		Long: `Derives a subnet-grouped, tiered briefing map from a snapshot — a pure
function of the snapshot, so it re-renders offline without touching the grid.
See docs/MAPS.md for what these maps do and don't show.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				return fmt.Errorf("--snapshot is required")
			}
			snap, err := snapshot.Load(path)
			if err != nil {
				return err
			}
			mm := mapview.Build(snap, mapview.Options{
				GroupPrefix: groupPrefix, MinConns: minConns, Focus: focus,
			})
			for _, f := range mm.Findings {
				fmt.Fprintf(os.Stderr, "%sfinding:%s %s\n", ansiYellow, ansiReset, f)
			}
			w := cmd.OutOrStdout()
			switch format {
			case "svg":
				return report.SVGMap(w, mm)
			case "graphml":
				return report.GraphMLMap(w, mm)
			case "html":
				out := path + ".map.html"
				f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := report.HTMLMap(f, mm); err != nil {
					return err
				}
				fmt.Fprintln(w, out)
				return nil
			default:
				return fmt.Errorf("unknown --format %q (html|svg|graphml)", format)
			}
		},
	}
	cmd.Flags().StringVar(&path, "snapshot", "", "snapshot .json.gz to render")
	cmd.Flags().StringVar(&format, "format", "html", "html|svg|graphml")
	cmd.Flags().StringVar(&focus, "focus", "", "restrict the map to one CIDR")
	cmd.Flags().IntVar(&groupPrefix, "group-prefix", config.GroupPrefixV4, "subnet grouping prefix")
	cmd.Flags().Int64Var(&minConns, "min-conns", config.MapMinConns, "hide bundled edges below this connection count")
	return cmd
}
