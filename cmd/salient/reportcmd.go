package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/report"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

func newReportCmd() *cobra.Command {
	var format, output string
	cmd := &cobra.Command{
		Use:   "report --snapshot FILE",
		Short: "Re-render a stored snapshot as html, json, or graphml",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("snapshot")
			if path == "" {
				return fmt.Errorf("--snapshot is required")
			}
			snap, err := snapshot.Load(path)
			if err != nil {
				return err
			}
			var render func(io.Writer) error
			ext := format
			switch format {
			case "json":
				render = func(w io.Writer) error { return report.JSON(w, snap) }
			case "graphml":
				render = func(w io.Writer) error { return report.GraphML(w, snap) }
			case "html":
				ext = "html"
				render = func(w io.Writer) error { return report.HTML(w, snap) }
			default:
				return fmt.Errorf("unknown --format %q (html|json|graphml)", format)
			}
			if output == "" {
				output = path + "." + ext
			}
			if output == "-" {
				if err := render(cmd.OutOrStdout()); err != nil {
					return err
				}
			} else {
				if err := safefile.Write(output, render); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), output)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this report describes network terrain — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().String("snapshot", "", "snapshot .json.gz to render")
	cmd.Flags().StringVar(&format, "format", "html", "html|json|graphml")
	cmd.Flags().StringVarP(&output, "output", "o", "", "protected output file; use - for stdout")
	return cmd
}

func newListCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := snapshot.List(dataDir)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no snapshots — run `salient scan`")
				return nil
			}
			for _, e := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  window %-8s  %5d nodes %6d edges  %s\n",
					e.File, e.CreatedAt.Format("2006-01-02 15:04"), e.Window, e.Nodes, e.Edges, e.Cluster)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DataDirName, "data directory")
	return cmd
}
