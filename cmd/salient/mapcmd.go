package main

import (
	"fmt"
	"io"
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/report"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
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
			if focus != "" && !mapview.FocusKeyword(focus) {
				if _, err := netip.ParsePrefix(focus); err != nil {
					return fmt.Errorf("invalid --focus %q (CIDR, private, or public): %w", focus, err)
				}
			}
			if groupPrefix < 1 || groupPrefix > 32 {
				return fmt.Errorf("--group-prefix must be between 1 and 32")
			}
			if minConns < 0 {
				return fmt.Errorf("--min-conns must not be negative")
			}
			snap, err := snapshot.Load(path)
			if err != nil {
				return err
			}
			mm := mapview.Build(snap, mapview.Options{
				GroupPrefix: groupPrefix, MinConns: minConns, Focus: focus,
			})
			for _, f := range mm.Findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "%sfinding:%s %s\n", ansiYellow, ansiReset, f)
			}
			w := cmd.OutOrStdout()
			switch format {
			case "svg":
				if err := report.SVGMap(w, mm); err != nil {
					return err
				}
			case "graphml":
				if err := report.GraphMLMap(w, mm); err != nil {
					return err
				}
			case "html":
				out := path + ".map.html"
				if err := safefile.Write(out, func(w io.Writer) error { return report.HTMLMap(w, mm) }); err != nil {
					return err
				}
				fmt.Fprintln(w, out)
			default:
				return fmt.Errorf("unknown --format %q (html|svg|graphml)", format)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this map describes network terrain — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "snapshot", "", "snapshot .json.gz to render")
	cmd.Flags().StringVar(&format, "format", "html", "html|svg|graphml")
	cmd.Flags().StringVar(&focus, "focus", "", "restrict the map to one CIDR, or 'private'/'public' address space")
	cmd.Flags().IntVar(&groupPrefix, "group-prefix", config.GroupPrefixV4, "subnet grouping prefix")
	cmd.Flags().Int64Var(&minConns, "min-conns", config.MapMinConns, "hide bundled edges below this connection count")
	return cmd
}
