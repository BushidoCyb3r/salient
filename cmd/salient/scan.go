package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/escli"
	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/scan"
)

func newScanCmd(opts *globalOpts) *cobra.Command {
	var (
		window   time.Duration
		scope    []string
		maxEdges int
		dataDir  string
		tz       string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Aggregate the window, build and score the dependency graph, save snapshot + report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, opts, window, scope, maxEdges, dataDir, tz)
		},
	}
	cmd.Flags().DurationVar(&window, "window", config.DefaultWindow, "analysis window (e.g. 336h for 14d)")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDRs to include (default: everything observed)")
	cmd.Flags().IntVar(&maxEdges, "max-edges", config.DefaultMaxEdges, "safety cap on aggregated edges")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DataDirName, "output directory for snapshots and reports")
	cmd.Flags().StringVar(&tz, "tz", "Local", "IANA timezone driving BusinessHours/Nightly classification")
	return cmd
}

func runScan(cmd *cobra.Command, opts *globalOpts, window time.Duration, scope []string, maxEdges int, dataDir string, tz string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	cfg := opts.clientConfig(cmd.ErrOrStderr())
	fm, err := opts.fieldMap()
	if err != nil {
		return err
	}
	cli, err := escli.New(cfg)
	if err != nil {
		return err
	}
	if isTerminal(errOut) {
		defer startSpinner(errOut, 100*time.Millisecond)()
	}
	info, err := cli.Info(ctx)
	if err != nil {
		return err
	}

	// Each pipeline stage prints its own human line; warnings go to stderr.
	report := func(s scan.Stage) {
		if s.Warn {
			fmt.Fprintf(errOut, "%swarning:%s %s\n", ansiYellow, ansiReset, s.Detail)
			return
		}
		fmt.Fprintln(out, s.Detail)
	}

	res, err := scan.Run(ctx, cli, fm, info, scan.Options{
		Window:   window,
		Scope:    scope,
		MaxEdges: maxEdges,
		TZ:       tz,
	}, dataDir, report)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\nTop terrain:\n")
	for i, n := range res.Snapshot.Nodes {
		if i >= 5 {
			break
		}
		fmt.Fprintf(out, "  %d. %-16s %-18s composite %.2f\n", n.Scores.Rank, n.IP, topRoleLabel(n), n.Scores.Composite)
	}
	fmt.Fprintf(errOut, "%sHandling reminder: report, map, and snapshot describe network terrain — protect at the network's classification.%s\n", ansiYellow, ansiReset)
	return nil
}

func topRoleLabel(n graph.Node) string {
	if len(n.Roles) == 0 {
		return string(graph.RoleUnknown)
	}
	return string(n.Roles[0].Role)
}
