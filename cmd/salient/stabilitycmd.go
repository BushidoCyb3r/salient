package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
	"github.com/BushidoCyb3r/salient/internal/stability"
)

func newStabilityCmd() *cobra.Command {
	var dataDir, format string
	var topN int
	cmd := &cobra.Command{
		Use:   "stability",
		Short: "Longitudinal terrain stability across stored snapshots",
		Long: "Reports which hosts persistently rank as key terrain, which are\n" +
			"newly emerging, and which have gone quiet, across every stored\n" +
			"snapshot in --data-dir. At least 3 comparable snapshots are needed\n" +
			"for the classification to mean much.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if topN < 1 {
				return fmt.Errorf("--top must be positive")
			}
			entries, err := snapshot.ScanArtifacts(dataDir)
			if err != nil {
				return fmt.Errorf("scanning %s: %w", dataDir, err)
			}
			var snaps []graph.Snapshot
			for _, e := range entries {
				if e.Snapshot == "" {
					continue
				}
				path := e.Snapshot
				if !filepath.IsAbs(path) {
					path = filepath.Join(dataDir, path)
				}
				s, err := snapshot.Load(path)
				if err != nil {
					return fmt.Errorf("loading %s: %w", path, err)
				}
				snaps = append(snaps, s)
			}
			if len(snaps) == 0 {
				return fmt.Errorf("no stored snapshots found in %s", dataDir)
			}
			if len(snaps) < 3 {
				fmt.Fprintf(cmd.ErrOrStderr(), "%swarning: only %d stored snapshot(s) found — the classification (persistent/emerging/transient) is most meaningful across ≥3 comparable snapshots%s\n",
					ansiYellow, len(snaps), ansiReset)
			}
			stats := stability.Compute(snaps, topN)

			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(stats)
			case "text":
				fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-6s %-8s %-8s %-8s %-14s %s\n",
					"IP", "SEEN", "TOP-N", "BEST%", "MEDIAN%", "CLASS", "ROLE STABLE")
				for _, s := range stats {
					fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-6d %-8d %-8.2f %-8.2f %-14s %v\n",
						s.IP, s.Occurrences, s.TopNOccurrences, s.BestRankPercentile, s.MedianRankPercentile,
						s.Classification, s.RoleConsistent)
				}
				return nil
			default:
				return fmt.Errorf("unknown --format %q (text|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DataDirName, "directory holding stored snapshots")
	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	cmd.Flags().IntVar(&topN, "top", config.DriftTopN, "rank cutoff counted as top-N terrain")
	return cmd
}
