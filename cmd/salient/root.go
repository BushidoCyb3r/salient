package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/escli"
)

const ansiRed = "\x1b[31;1m"
const ansiYellow = "\x1b[33;1m"
const ansiReset = "\x1b[0m"

// globalOpts holds flags shared by every subcommand. Precedence:
// flags > environment (SALIENT_ES_URL, SALIENT_API_KEY) > nothing.
type globalOpts struct {
	esURL              string
	apiKey             string
	caCert             string
	insecureSkipVerify bool
	fieldmapPath       string
}

func newRootCmd() *cobra.Command {
	opts := &globalOpts{}
	root := &cobra.Command{
		Use:   "salient",
		Short: "Passive terrain-dependency analyzer for Security Onion grids",
		Long: `Salient queries the Zeek logs already aggregated on a Security Onion
manager and produces dependency graphs, key-terrain rankings, and briefing
maps. It is strictly read-only against Elasticsearch: the only writes are
to the local filesystem. No agents, no scans, no changes to the SO stack.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&opts.esURL, "es", "", "Elasticsearch URL (env "+config.EnvESURL+")")
	root.PersistentFlags().StringVar(&opts.apiKey, "api-key", "", "ES API key; prefer env "+config.EnvAPIKey+" to keep it out of shell history")
	root.PersistentFlags().StringVar(&opts.caCert, "ca-cert", "", "path to the grid CA certificate (PEM)")
	root.PersistentFlags().BoolVar(&opts.insecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification (NOT recommended)")
	root.PersistentFlags().StringVar(&opts.fieldmapPath, "fieldmap", "", "YAML field-map override for the target SO version")

	root.AddCommand(newTestConnectionCmd(opts))
	root.AddCommand(newDiscoverCmd(opts))
	root.AddCommand(newScanCmd(opts))
	root.AddCommand(newReportCmd())
	root.AddCommand(newMapCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newStabilityCmd())
	root.AddCommand(newReconcileCmd())
	root.AddCommand(newAnalyzeCmd())
	root.AddCommand(newListCmd())
	root.AddCommand(newViewCmd())
	return root
}

// clientConfig resolves flags and environment into an escli.Config,
// printing the mandatory warnings to out as it goes.
func (o *globalOpts) clientConfig(out io.Writer) (escli.Config, error) {
	esURL := o.esURL
	if esURL == "" {
		esURL = os.Getenv(config.EnvESURL)
	}
	apiKey := o.apiKey
	if apiKey != "" {
		fmt.Fprintf(out, "%swarning:%s API key passed as a flag; it is now in your shell history. Prefer the %s environment variable.\n",
			ansiYellow, ansiReset, config.EnvAPIKey)
	} else {
		apiKey = os.Getenv(config.EnvAPIKey)
	}
	if o.insecureSkipVerify {
		fmt.Fprintf(out, "%sWARNING: TLS certificate verification is DISABLED (--insecure-skip-verify). The connection to the grid is open to interception. Use --ca-cert with the grid CA instead.%s\n",
			ansiRed, ansiReset)
	}
	return escli.Config{
		ESURL:              esURL,
		APIKey:             apiKey,
		CACertPath:         o.caCert,
		InsecureSkipVerify: o.insecureSkipVerify,
		Timeout:            config.HTTPTimeout,
	}, nil
}

func (o *globalOpts) fieldMap() (escli.FieldMap, error) {
	return escli.LoadFieldMap(o.fieldmapPath)
}
