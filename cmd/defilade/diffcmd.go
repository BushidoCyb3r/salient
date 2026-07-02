package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/internal/report"
	"github.com/BushidoCyb3r/defilade/internal/snapshot"
)

func newDiffCmd() *cobra.Command {
	var fromPath, toPath, format string
	var rankDelta, topN int
	var withMap bool
	cmd := &cobra.Command{
		Use:   "diff --from SNAP1 --to SNAP2",
		Short: "Report security-relevant drift between two snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromPath == "" || toPath == "" {
				return fmt.Errorf("--from and --to are required")
			}
			if rankDelta < 1 || topN < 1 {
				return fmt.Errorf("--rank-delta and --top must be positive")
			}
			if withMap && format != "html" {
				return fmt.Errorf("--map requires --format html")
			}
			from, err := snapshot.Load(fromPath)
			if err != nil {
				return fmt.Errorf("loading --from snapshot: %w", err)
			}
			to, err := snapshot.Load(toPath)
			if err != nil {
				return fmt.Errorf("loading --to snapshot: %w", err)
			}
			d := snapshot.Compare(from, to, snapshot.DiffOptions{RankDelta: rankDelta, TopN: topN})
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(d); err != nil {
					return err
				}
			case "html":
				out := toPath + ".diff.html"
				f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := report.DriftHTML(f, d); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), out)
			default:
				return fmt.Errorf("unknown --format %q (html|json)", format)
			}
			if withMap {
				out := toPath + ".diff.map.html"
				f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, config.OutputFileMode)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := report.HTMLMap(f, mapview.BuildDrift(to, d, mapview.Options{})); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), out)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this drift report describes network terrain — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&fromPath, "from", "", "older snapshot .json.gz")
	cmd.Flags().StringVar(&toPath, "to", "", "newer snapshot .json.gz")
	cmd.Flags().StringVar(&format, "format", "html", "html|json")
	cmd.Flags().IntVar(&rankDelta, "rank-delta", config.DriftRankDelta, "minimum absolute rank change to report")
	cmd.Flags().IntVar(&topN, "top", config.DriftTopN, "critical rank cutoff for edge drift")
	cmd.Flags().BoolVar(&withMap, "map", false, "also write a drift-highlighted briefing map (HTML only)")
	return cmd
}
