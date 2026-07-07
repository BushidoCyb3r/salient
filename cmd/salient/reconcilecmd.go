package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/mapview"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
	"github.com/BushidoCyb3r/salient/internal/report"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func newReconcileCmd() *cobra.Command {
	var snapPath, assetsPath, format string
	var withMap bool
	cmd := &cobra.Command{
		Use:   "reconcile --snapshot SNAP --assets assets.csv",
		Short: "Diff the supported unit's asset list against observed reality",
		Long: `Reconcile compares a documented asset list (CSV) against a stored snapshot
and reports three lists: documented-but-silent, observed-but-undocumented,
and role-contradicted. --map renders a briefing map with the same flags.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapPath == "" || assetsPath == "" {
				return fmt.Errorf("--snapshot and --assets are required")
			}
			if withMap && format != "html" {
				return fmt.Errorf("--map requires --format html")
			}
			snap, err := snapshot.Load(snapPath)
			if err != nil {
				return fmt.Errorf("loading snapshot: %w", err)
			}
			f, err := os.Open(assetsPath)
			if err != nil {
				return err
			}
			defer f.Close()
			assets, warnings, err := reconcile.ParseCSV(f)
			if err != nil {
				return fmt.Errorf("parsing asset list: %w", err)
			}
			for _, w := range warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "%swarning:%s %s\n", ansiYellow, ansiReset, w)
			}
			res := reconcile.Compare(snap, assets)
			res.Warnings = warnings

			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
			case "html":
				out := snapPath + ".reconcile.html"
				if err := safefile.Write(out, func(w io.Writer) error { return report.ReconcileHTML(w, res) }); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), out)
			default:
				return fmt.Errorf("unknown --format %q (html|json)", format)
			}
			if withMap {
				out := snapPath + ".reconcile.map.html"
				if err := safefile.Write(out, func(w io.Writer) error {
					return report.HTMLMap(w, mapview.BuildReconcile(snap, res, assets, mapview.Options{}))
				}); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), out)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this reconciliation report describes network terrain — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "snapshot .json.gz to reconcile against")
	cmd.Flags().StringVar(&assetsPath, "assets", "", "documented asset list (CSV)")
	cmd.Flags().StringVar(&format, "format", "html", "html|json")
	cmd.Flags().BoolVar(&withMap, "map", false, "also write a reconciliation-flagged briefing map (HTML only)")
	return cmd
}
