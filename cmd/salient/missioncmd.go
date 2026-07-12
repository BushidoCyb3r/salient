package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/mission"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func newMissionCmd() *cobra.Command {
	var snapPath, scopeIPs, format string
	cmd := &cobra.Command{
		Use:   "mission --snapshot FILE --scope IP1,IP2,...",
		Short: "Mission relevance overlay from a set of operator-selected hosts",
		Long: "Walks outward from --scope over confirmed edges (either direction,\n" +
			"up to 3 hops) and reports which other hosts support those mission\n" +
			"systems and how closely. This is an overlay, not a replacement for\n" +
			"the snapshot's canonical terrain rank — both are worth reading\n" +
			"together.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapPath == "" {
				return fmt.Errorf("--snapshot is required")
			}
			if strings.TrimSpace(scopeIPs) == "" {
				return fmt.Errorf("--scope is required (comma-separated IPs)")
			}
			scope := map[string]bool{}
			for _, ip := range strings.Split(scopeIPs, ",") {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					scope[ip] = true
				}
			}
			snap, err := snapshot.Load(snapPath)
			if err != nil {
				return fmt.Errorf("loading %s: %w", snapPath, err)
			}
			scores := mission.Compute(snap, scope)
			if len(scores) == 0 {
				return fmt.Errorf("no hosts in --scope were found in this snapshot")
			}
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(scores)
			case "text":
				fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-9s %-6s %s\n", "IP", "IN-SCOPE", "DEPTH", "MISSION-SCORE")
				for _, s := range scores {
					fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-9v %-6d %.2f\n", s.IP, s.InScope, s.Depth, s.MissionScore)
				}
				return nil
			default:
				return fmt.Errorf("unknown --format %q (text|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "snapshot .json.gz to score")
	cmd.Flags().StringVar(&scopeIPs, "scope", "", "comma-separated mission-system IPs")
	cmd.Flags().StringVar(&format, "format", "text", "text|json")
	return cmd
}
