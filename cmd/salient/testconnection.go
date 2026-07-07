package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/escli"
)

func newTestConnectionCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-connection",
		Short: "Authenticate to the grid, discover indices, and sanity-probe the field map",
		Long: `Connects read-only to the manager's Elasticsearch API and reports:
cluster identity, whether the API key is genuinely read-only, which
indices/data streams match the field map's index pattern, and whether the
core conn fields the field map assumes are actually mapped on this grid.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestConnection(cmd, opts)
		},
	}
	return cmd
}

func runTestConnection(cmd *cobra.Command, opts *globalOpts) error {
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

	// 1. Authentication + cluster identity.
	info, err := cli.Info(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Connected: cluster %q, Elasticsearch %s — authentication OK\n",
		info.ClusterName, info.Version.Number)

	// 2. Key must be read-only (§14).
	priv, err := cli.CheckWritePrivileges(ctx, fm.IndexPattern)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "%swarning:%s could not check key privileges: %v\n", ansiYellow, ansiReset, err)
	case priv.CanWrite:
		fmt.Fprintf(os.Stderr, "%sWARNING: this API key can WRITE to %s (%s). Salient never writes, but the key violates least privilege — create a read-only key per docs/DEPLOYMENT.md.%s\n",
			ansiRed, fm.IndexPattern, priv.Detail, ansiReset)
	case priv.Indeterminate:
		fmt.Fprintf(out, "Key privileges: could not verify (%s) — confirm the key is read-only manually\n", priv.Detail)
	default:
		fmt.Fprintf(out, "Key privileges: read-only against %s — good\n", fm.IndexPattern)
	}

	// 3. Index discovery.
	indices, err := cli.ResolveIndices(ctx, fm.IndexPattern)
	if err != nil {
		return err
	}
	streams := 0
	for _, ix := range indices {
		if ix.DataStream {
			streams++
		}
	}
	fmt.Fprintf(out, "Index pattern %q: %d indices/data streams (%d data streams)\n",
		fm.IndexPattern, len(indices), streams)
	if len(indices) == 0 {
		fmt.Fprintf(os.Stderr, "%sWARNING: nothing matches %q. The index pattern in the field map is wrong for this grid — run `salient discover` after adjusting --fieldmap.%s\n",
			ansiRed, fm.IndexPattern, ansiReset)
		return nil
	}

	// 4. Field sanity probe: are the assumed field names actually mapped?
	probe := append(fm.CoreConnFields(), fm.DatasetField, fm.Timestamp)
	presence, err := cli.FieldPresence(ctx, fm.IndexPattern, probe)
	if err != nil {
		return err
	}
	missing := []string{}
	fmt.Fprintln(out, "Field sanity probe:")
	for _, f := range probe {
		mark := "ok     "
		if !presence[f] {
			mark = "MISSING"
			missing = append(missing, f)
		}
		fmt.Fprintf(out, "  %s  %s\n", mark, f)
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "%sWARNING: %d assumed field(s) are not mapped on this grid. Queries would silently return empty results. Fix with --fieldmap (see docs/FIELDMAP.md) before any scan.%s\n",
			ansiRed, len(missing), ansiReset)
	} else {
		fmt.Fprintln(out, "All core fields mapped — field map looks valid for this grid.")
	}
	return nil
}
