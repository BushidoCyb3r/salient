package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/assist"
	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/safefile"
	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

type analysisArtifact struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Model       string        `json:"model"`
	Endpoint    string        `json:"endpoint_host"`
	Result      assist.Result `json:"result"`
}

func newAnalyzeCmd() *cobra.Command {
	var snapshotPath, endpoint, model, output string
	var allowRemote bool
	var maxNodes, maxEdges int
	cmd := &cobra.Command{
		Use:   "analyze --snapshot FILE --endpoint URL --model NAME",
		Short: "Optionally analyze a stored snapshot with an external or local model",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotPath == "" || endpoint == "" || model == "" {
				return fmt.Errorf("--snapshot, --endpoint, and --model are required")
			}
			if maxNodes < 1 || maxEdges < 1 {
				return fmt.Errorf("--max-nodes and --max-edges must be positive")
			}
			snap, err := snapshot.Load(snapshotPath)
			if err != nil {
				return err
			}
			if allowRemote {
				fmt.Fprintf(cmd.ErrOrStderr(), "%sWARNING: summarized network topology may leave this host for the configured analysis endpoint.%s\n", ansiRed, ansiReset)
			}
			result, err := assist.Analyze(cmd.Context(), assist.Config{
				Endpoint: endpoint, Model: model, APIKey: os.Getenv(config.EnvAssistAPIKey),
				AllowRemote: allowRemote, MaxNodes: maxNodes, MaxEdges: maxEdges,
			}, snap)
			if err != nil {
				return err
			}
			if output == "" {
				output = snapshotPath + ".analysis.json"
			}
			u, _ := url.Parse(endpoint)
			artifact := analysisArtifact{GeneratedAt: time.Now().UTC(), Model: model, Endpoint: u.Host, Result: result}
			raw, err := json.MarshalIndent(artifact, "", "  ")
			if err != nil {
				return err
			}
			raw = append(raw, '\n')
			if err := safefile.WriteFile(output, raw); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), output)
			fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: this analysis describes network terrain — protect it at the network's classification.%s\n", ansiYellow, ansiReset)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "snapshot .json.gz to analyze")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "chat-completions-compatible endpoint URL")
	cmd.Flags().StringVar(&model, "model", "", "model name understood by the endpoint")
	cmd.Flags().StringVar(&output, "output", "", "analysis JSON path (default: SNAPSHOT.analysis.json)")
	cmd.Flags().BoolVar(&allowRemote, "allow-network-data-egress", false, "explicitly allow summarized topology to reach a remote HTTPS endpoint")
	cmd.Flags().IntVar(&maxNodes, "max-nodes", config.AssistMaxNodes, "maximum top-ranked nodes sent")
	cmd.Flags().IntVar(&maxEdges, "max-edges", config.AssistMaxEdges, "maximum highest-volume edges sent")
	return cmd
}
