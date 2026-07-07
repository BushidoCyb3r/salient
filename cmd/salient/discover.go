package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/escli"
)

func newDiscoverCmd(opts *globalOpts) *cobra.Command {
	var window time.Duration
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Enumerate datasets, sensors, and L2 field presence on the grid",
		Long: `Ground-truth probe for Phase 0. Reports which Zeek datasets actually
exist on this grid and their document counts, which sensors are reporting,
and whether MAC fields survive the ECS mapping (this decides whether
gateway inference can use MAC convergence or must fall back to heuristics).
Record the output in docs/FIELDMAP.md and pin deviations via --fieldmap.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiscover(cmd, opts, window)
		},
	}
	cmd.Flags().DurationVar(&window, "window", config.DiscoverWindow, "lookback window for counts (e.g. 24h, 168h)")
	return cmd
}

func runDiscover(cmd *cobra.Command, opts *globalOpts, window time.Duration) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	cfg, err := opts.clientConfig(cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	fm, err := opts.fieldMap()
	if err != nil {
		return err
	}
	cli, err := escli.New(cfg)
	if err != nil {
		return err
	}

	info, err := cli.Info(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Cluster %q, Elasticsearch %s — window: last %s, pattern: %q\n\n",
		info.ClusterName, info.Version.Number, window, fm.IndexPattern)

	// Datasets. ErrZeroBuckets here is fatal by design: it is the
	// wrong-fieldmap signature and must never look like "empty grid".
	datasets, err := cli.DatasetCounts(ctx, fm, window, config.DatasetTermsSize)
	if err != nil {
		if errors.Is(err, escli.ErrZeroBuckets) {
			return fmt.Errorf("%s%v%s", ansiRed, err, ansiReset)
		}
		return err
	}
	if len(datasets) == 0 {
		fmt.Fprintf(out, "No documents in %q within the window. Widen --window or check the index pattern.\n", fm.IndexPattern)
		return nil
	}
	fmt.Fprintf(out, "Datasets observed (%s):\n", fm.DatasetField)
	for _, d := range datasets {
		fmt.Fprintf(out, "  %-30s %12d docs\n", d.Dataset, d.Docs)
	}

	// Which datasets do Salient's role-evidence queries need, and which
	// candidates actually exist here?
	fmt.Fprintln(out, "\nRole-evidence dataset resolution:")
	present := map[string]bool{}
	for _, d := range datasets {
		present[d.Dataset] = true
	}
	for _, need := range []struct {
		name       string
		candidates []string
	}{
		{"conn (edges — REQUIRED)", fm.Datasets.Conn},
		{"dns", fm.Datasets.DNS},
		{"kerberos", fm.Datasets.Kerberos},
		{"smb", fm.Datasets.SMB},
		{"ssl", fm.Datasets.SSL},
		{"http", fm.Datasets.HTTP},
		{"dhcp", fm.Datasets.DHCP},
		{"ldap", fm.Datasets.LDAP},
	} {
		found := []string{}
		for _, c := range need.candidates {
			if present[c] {
				found = append(found, c)
			}
		}
		if len(found) > 0 {
			fmt.Fprintf(out, "  %-28s -> %v\n", need.name, found)
		} else {
			fmt.Fprintf(out, "  %-28s -> NOT FOUND (candidates tried: %v)\n", need.name, need.candidates)
		}
	}
	if !slices.ContainsFunc(fm.Datasets.Conn, func(c string) bool { return present[c] }) {
		fmt.Fprintf(os.Stderr, "%sWARNING: no conn dataset found — Salient cannot build a dependency graph on this grid without it.%s\n", ansiRed, ansiReset)
	}

	// Sensors.
	sensors, err := cli.Sensors(ctx, fm, window, config.SensorTermsSize)
	if err != nil {
		return err
	}
	if len(sensors) == 0 {
		fmt.Fprintf(out, "\nSensors: none found via %q — sensor attribution and coverage findings will be unavailable\n", fm.ObserverName)
	} else {
		fmt.Fprintf(out, "\nSensors (%s):\n", fm.ObserverName)
		for _, s := range sensors {
			fmt.Fprintf(out, "  %-30s %12d docs\n", s.Dataset, s.Docs)
		}
	}

	// L2/MAC presence — decides §8.4 primary vs fallback.
	cov, err := cli.MACCoverage(ctx, fm, window)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "\nL2/MAC field presence in conn logs:")
	if cov.ConnDocs == 0 {
		fmt.Fprintln(out, "  no conn documents in window — undetermined")
		return nil
	}
	srcPct := 100 * float64(cov.SrcMACDocs) / float64(cov.ConnDocs)
	dstPct := 100 * float64(cov.DstMACDocs) / float64(cov.ConnDocs)
	fmt.Fprintf(out, "  %-20s %12d / %d docs (%.1f%%)\n", fm.SourceMAC, cov.SrcMACDocs, cov.ConnDocs, srcPct)
	fmt.Fprintf(out, "  %-20s %12d / %d docs (%.1f%%)\n", fm.DestinationMAC, cov.DstMACDocs, cov.ConnDocs, dstPct)
	if cov.DstMACDocs > 0 {
		fmt.Fprintln(out, "  => MAC evidence PRESENT: gateway inference can use MAC convergence (primary method)")
	} else {
		fmt.Fprintln(out, "  => MAC evidence ABSENT: gateway inference will use the cross-subnet heuristic fallback; maps will label gateways \"inferred\"")
	}
	return nil
}
