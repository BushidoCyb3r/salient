package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/safefile"
)

const (
	uniFiIntegrationPath = "/proxy/network/integration/v1"
	uniFiPageSize        = 200
	uniFiMaxResponse     = 32 << 20
)

type uniFiExportOptions struct {
	controller         string
	site               string
	outDir             string
	apiKey             string
	caCert             string
	insecureSkipVerify bool
}

type uniFiSite struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

type uniFiClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newUniFiExportCmd() *cobra.Command {
	var opts uniFiExportOptions
	cmd := &cobra.Command{
		Use:   "unifi-export",
		Short: "Export UniFi Network configuration with a local Integration API key",
		Long: `Export reads the official local UniFi Network Integration API and writes
import-ready JSON collections for Salient's declared-config importer. It
uses GET requests only and never changes the console. Generate the key in the
local Network application under Settings > Control Plane > Integrations, then
provide it through SALIENT_UNIFI_API_KEY whenever possible.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUniFiExport(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.controller, "controller", "", "local UniFi console URL, e.g. https://192.168.1.1")
	cmd.Flags().StringVar(&opts.site, "site", "", "site ID, internal reference, or display name (automatic when only one exists)")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", filepath.Join(config.DataDirName, "unifi-export"), "directory for protected JSON exports")
	cmd.Flags().StringVar(&opts.apiKey, "unifi-api-key", "", "Network Integration API key; prefer env "+config.EnvUniFiAPIKey)
	cmd.Flags().StringVar(&opts.caCert, "unifi-ca-cert", "", "path to the UniFi console CA certificate (PEM)")
	cmd.Flags().BoolVar(&opts.insecureSkipVerify, "unifi-insecure-skip-verify", false, "disable UniFi TLS certificate verification (NOT recommended)")
	return cmd
}

func runUniFiExport(cmd *cobra.Command, opts uniFiExportOptions) error {
	if strings.TrimSpace(opts.controller) == "" {
		return errors.New("--controller is required")
	}
	key := opts.apiKey
	if key != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "%swarning:%s UniFi API key passed as a flag; it is now in your shell history. Prefer %s.\n",
			ansiYellow, ansiReset, config.EnvUniFiAPIKey)
	} else {
		key = os.Getenv(config.EnvUniFiAPIKey)
	}
	if key == "" {
		return fmt.Errorf("no UniFi API key provided; set %s or use --unifi-api-key", config.EnvUniFiAPIKey)
	}
	if opts.insecureSkipVerify {
		fmt.Fprintf(cmd.ErrOrStderr(), "%sWARNING: UniFi TLS certificate verification is DISABLED. The API key and configuration are open to interception. Use --unifi-ca-cert when possible.%s\n",
			ansiRed, ansiReset)
	}

	client, err := newUniFiClient(opts.controller, key, opts.caCert, opts.insecureSkipVerify, config.HTTPTimeout)
	if err != nil {
		return err
	}
	sitesRaw, err := client.list(cmd.Context(), "/sites")
	if err != nil {
		return fmt.Errorf("listing UniFi sites: %w", err)
	}
	site, err := selectUniFiSite(sitesRaw, opts.site)
	if err != nil {
		return err
	}

	prefix := "/sites/" + url.PathEscape(site.ID)
	networks, err := client.list(cmd.Context(), prefix+"/networks")
	if err != nil {
		return fmt.Errorf("listing UniFi networks: %w", err)
	}
	details := make([]json.RawMessage, 0, len(networks))
	for _, raw := range networks {
		var overview struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &overview); err != nil || overview.ID == "" {
			return errors.New("UniFi networks response contained an item without an id")
		}
		detail, err := client.get(cmd.Context(), prefix+"/networks/"+url.PathEscape(overview.ID))
		if err != nil {
			return fmt.Errorf("reading UniFi network %s: %w", overview.ID, err)
		}
		details = append(details, detail)
	}

	collections := []struct {
		name string
		path string
		data []json.RawMessage
	}{
		{name: "unifi-integration-networks.json", data: details},
		{name: "unifi-integration-devices.json", path: prefix + "/devices"},
		{name: "unifi-integration-firewall-zones.json", path: prefix + "/firewall/zones"},
		{name: "unifi-integration-firewall-policies.json", path: prefix + "/firewall/policies"},
	}
	for i := range collections {
		if collections[i].data != nil {
			continue
		}
		collections[i].data, err = client.list(cmd.Context(), collections[i].path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", strings.TrimSuffix(collections[i].name, ".json"), err)
		}
	}

	for _, collection := range collections {
		raw, err := json.MarshalIndent(collection.data, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding %s: %w", collection.name, err)
		}
		raw = append(raw, '\n')
		if err := safefile.WriteFile(filepath.Join(opts.outDir, collection.name), raw); err != nil {
			return fmt.Errorf("writing %s: %w", collection.name, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %d records\n", filepath.Join(opts.outDir, collection.name), len(collection.data))
	}
	name := site.Name
	if name == "" {
		name = site.InternalReference
	}
	if name == "" {
		name = site.ID
	}
	fmt.Fprintf(cmd.OutOrStdout(), "exported read-only UniFi configuration for site %q\n", name)
	fmt.Fprintf(cmd.ErrOrStderr(), "%sHandling reminder: these files describe network layout and enforcement policy — protect them at the network's classification.%s\n", ansiYellow, ansiReset)
	return nil
}

func newUniFiClient(controller, apiKey, caCert string, insecure bool, timeout time.Duration) (*uniFiClient, error) {
	base, err := normalizeUniFiBaseURL(controller)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // explicit CLI opt-in with a red warning
	if caCert != "" {
		pem, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("reading UniFi CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", caCert)
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ResponseHeaderTimeout: timeout,
	}
	return &uniFiClient{
		baseURL: base,
		apiKey:  apiKey,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("refusing redirect from UniFi API")
			},
		},
	}, nil
}

func normalizeUniFiBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parsing UniFi controller URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("UniFi controller URL must use https://")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("UniFi controller URL must contain only scheme, host, optional port, and API base path")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && !net.ParseIP(host).IsLoopback() {
			return "", errors.New("refusing plaintext UniFi URL: the API key would travel in cleartext")
		}
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	switch path {
	case "":
		u.Path = uniFiIntegrationPath
	case uniFiIntegrationPath:
		u.Path = uniFiIntegrationPath
	default:
		return "", fmt.Errorf("unexpected UniFi API path %q; provide the console URL or a URL ending in %s", u.Path, uniFiIntegrationPath)
	}
	u.RawPath = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func (c *uniFiClient) get(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, uniFiMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > uniFiMaxResponse {
		return nil, fmt.Errorf("response exceeds %d MiB limit", uniFiMaxResponse>>20)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("UniFi API returned %s", res.Status)
	}
	if !json.Valid(body) {
		return nil, errors.New("UniFi API returned non-JSON content")
	}
	return body, nil
}

func (c *uniFiClient) list(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for offset := 0; ; {
		q := url.Values{}
		q.Set("offset", fmt.Sprint(offset))
		q.Set("limit", fmt.Sprint(uniFiPageSize))
		raw, err := c.get(ctx, path+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var page struct {
			Data       []json.RawMessage `json:"data"`
			TotalCount int               `json:"totalCount"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("decoding paginated response: %w", err)
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || (page.TotalCount > 0 && len(all) >= page.TotalCount) {
			return all, nil
		}
		offset += len(page.Data)
		if page.TotalCount == 0 && len(page.Data) < uniFiPageSize {
			return all, nil
		}
	}
}

func selectUniFiSite(raw []json.RawMessage, selector string) (uniFiSite, error) {
	sites := make([]uniFiSite, 0, len(raw))
	for _, item := range raw {
		var site uniFiSite
		if err := json.Unmarshal(item, &site); err != nil || site.ID == "" {
			return uniFiSite{}, errors.New("UniFi sites response contained an item without an id")
		}
		sites = append(sites, site)
	}
	if len(sites) == 0 {
		return uniFiSite{}, errors.New("UniFi Network returned no sites")
	}
	if selector == "" {
		if len(sites) == 1 {
			return sites[0], nil
		}
		return uniFiSite{}, fmt.Errorf("multiple UniFi sites found; choose one with --site (%s)", uniFiSiteChoices(sites))
	}
	var matches []uniFiSite
	for _, site := range sites {
		if selector == site.ID || strings.EqualFold(selector, site.InternalReference) || strings.EqualFold(selector, site.Name) {
			matches = append(matches, site)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return uniFiSite{}, fmt.Errorf("--site %q is ambiguous; use the site ID", selector)
	}
	return uniFiSite{}, fmt.Errorf("UniFi site %q not found; available sites: %s", selector, uniFiSiteChoices(sites))
}

func uniFiSiteChoices(sites []uniFiSite) string {
	choices := make([]string, 0, len(sites))
	for _, site := range sites {
		label := site.Name
		if label == "" {
			label = site.InternalReference
		}
		choices = append(choices, fmt.Sprintf("%s (%s)", label, site.ID))
	}
	sort.Strings(choices)
	return strings.Join(choices, ", ")
}
