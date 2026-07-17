package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/netconfig"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// declaredResult is the CLI's JSON contract: the two declared-vs-observed
// diffs over a snapshot. Field names are the stable public API.
type declaredResult struct {
	Inventory netconfig.InventoryResult `json:"inventory"`
	Policy    netconfig.PolicyResult    `json:"policy"`
}

func newDeclaredCmd() *cobra.Command {
	var snapPath, configs string
	cmd := &cobra.Command{
		Use:   "declared --snapshot SNAP --configs f1,f2,...",
		Short: "Diff declared device configs (Cisco IOS / UniFi) against observed reality",
		Long: `Declared parses exported router/firewall configs — Cisco IOS running-config
text and UniFi controller JSON — and diffs them against a stored snapshot.
It reports an inventory reconciliation (declared gateways, silent subnets,
undeclared CIDRs) and a policy reconciliation (denied-but-observed flows,
unused permits). Vendor is autodetected per file; UniFi JSON exports are
grouped into one controller. Raw configs are read, diffed, and discarded —
nothing is written.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapPath == "" || strings.TrimSpace(configs) == "" {
				return fmt.Errorf("--snapshot and --configs are required")
			}
			snap, err := snapshot.Load(snapPath)
			if err != nil {
				return fmt.Errorf("loading snapshot: %w", err)
			}
			files := map[string][]byte{}
			for _, p := range strings.Split(configs, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				raw, err := os.ReadFile(p)
				if err != nil {
					return fmt.Errorf("reading %s: %w", p, err)
				}
				files[p] = raw
			}
			if len(files) == 0 {
				return fmt.Errorf("--configs listed no readable files")
			}
			devs, warnings := netconfig.ParseConfigs(files)
			for _, w := range warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "%swarning:%s %s\n", ansiYellow, ansiReset, w)
			}
			res := declaredResult{
				Inventory: netconfig.DiffInventory(snap, devs),
				Policy:    netconfig.DiffPolicy(snap, devs),
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this describes network terrain and enforcement policy — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapPath, "snapshot", "", "snapshot .json.gz to diff against")
	cmd.Flags().StringVar(&configs, "configs", "", "comma-separated device config files (Cisco IOS text / UniFi JSON)")
	return cmd
}
