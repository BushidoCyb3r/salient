package escli

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
	"strings"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	elasticsearch "github.com/elastic/go-elasticsearch/v8"
)

// Config carries connection settings for the read-only ES client.
type Config struct {
	ESURL              string
	APIKey             string
	CACertPath         string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Client wraps the low-level go-elasticsearch client. Salient only ever
// issues reads: GET/POST search, field_caps, resolve, and privilege checks.
type Client struct {
	es      *elasticsearch.Client
	timeout time.Duration
}

// ErrZeroBuckets is the wrong-fieldmap signature: the index holds documents
// but an aggregation on a mapped field returned no buckets. This must be
// loud, never silent (SALIENT_PLAN.md §13).
var ErrZeroBuckets = errors.New(
	"aggregation returned zero buckets from a non-empty index — this is the signature of a wrong field map; " +
		"run `salient discover` and pin correct names with --fieldmap")

// New builds a client. TLS: prefer a grid CA via CACertPath;
// InsecureSkipVerify is honored but the caller is responsible for the
// mandatory red warning.
func New(cfg Config) (*Client, error) {
	if cfg.ESURL == "" {
		return nil, errors.New("no Elasticsearch URL provided")
	}
	if err := checkScheme(cfg.ESURL); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // operator opt-in, warned loudly at CLI layer
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{cfg.ESURL},
		APIKey:    cfg.APIKey,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			// DialContext bounds the TCP handshake itself. Without it, an
			// unreachable-but-silent host (firewall drop, dead route) hangs
			// on the OS's own retransmit timeout — which can run past two
			// minutes — because ResponseHeaderTimeout below only starts
			// once a connection already exists.
			DialContext:           (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
			ResponseHeaderTimeout: cfg.Timeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building ES client: %w", err)
	}
	return &Client{es: es, timeout: cfg.Timeout}, nil
}

func (c *Client) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

// checkScheme rejects plaintext HTTP URLs except against loopback, so the
// API key never travels the network in the clear.
func checkScheme(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing Elasticsearch URL: %w", err)
	}
	if u.Scheme != "http" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" || net.ParseIP(host).IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing http:// Elasticsearch URL %q: the API key would travel in plaintext; use https:// or a loopback host", rawURL)
}

// ClusterInfo is the subset of GET / that test-connection reports.
type ClusterInfo struct {
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
}

// Info authenticates and returns cluster identity.
func (c *Client) Info(ctx context.Context) (ClusterInfo, error) {
	var info ClusterInfo
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	res, err := c.es.Info(c.es.Info.WithContext(ctx))
	if err != nil {
		return info, fmt.Errorf("connecting to Elasticsearch: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		return info, apiError("info", res.StatusCode, res.Body)
	}
	if err := decodeJSONLimited(res.Body, &info); err != nil {
		return info, fmt.Errorf("decoding cluster info: %w", err)
	}
	return info, nil
}

// IndexInfo is one concrete index or data stream behind the index pattern.
type IndexInfo struct {
	Name       string
	DataStream bool
}

// ResolveIndices expands the index pattern into concrete indices and data
// streams via GET _resolve/index.
func (c *Client) ResolveIndices(ctx context.Context, pattern string) ([]IndexInfo, error) {
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	res, err := c.es.Indices.ResolveIndex(
		[]string{pattern},
		c.es.Indices.ResolveIndex.WithContext(ctx),
		c.es.Indices.ResolveIndex.WithExpandWildcards("open"),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving indices %q: %w", pattern, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		return nil, apiError("resolve index", res.StatusCode, res.Body)
	}
	var body struct {
		Indices []struct {
			Name string `json:"name"`
		} `json:"indices"`
		DataStreams []struct {
			Name string `json:"name"`
		} `json:"data_streams"`
	}
	if err := decodeJSONLimited(res.Body, &body); err != nil {
		return nil, fmt.Errorf("decoding resolve response: %w", err)
	}
	out := make([]IndexInfo, 0, len(body.Indices)+len(body.DataStreams))
	for _, ds := range body.DataStreams {
		out = append(out, IndexInfo{Name: ds.Name, DataStream: true})
	}
	for _, ix := range body.Indices {
		out = append(out, IndexInfo{Name: ix.Name})
	}
	return out, nil
}

// search runs a request body against the pattern and returns the raw
// decoded response. All Salient searches are size:0 aggregations.
func (c *Client) search(ctx context.Context, pattern, body string) (map[string]json.RawMessage, error) {
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(pattern),
		c.es.Search.WithBody(strings.NewReader(body)),
		c.es.Search.WithExpandWildcards("open"),
	)
	if err != nil {
		return nil, fmt.Errorf("search against %q: %w", pattern, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		return nil, apiError("search", res.StatusCode, res.Body)
	}
	var decoded map[string]json.RawMessage
	if err := decodeJSONLimited(res.Body, &decoded); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}
	return decoded, nil
}

// searchSources runs a one-page search and returns each hit's _source blob.
// ponytail: single page by design; add search_after only if a real grid
// exceeds this cap for the raw-doc features that use it.
func (c *Client) searchSources(ctx context.Context, pattern, body string) ([]json.RawMessage, error) {
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex(pattern),
		c.es.Search.WithBody(strings.NewReader(body)),
		c.es.Search.WithExpandWildcards("open"),
	)
	if err != nil {
		return nil, fmt.Errorf("search against %q: %w", pattern, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		return nil, apiError("search", res.StatusCode, res.Body)
	}
	var decoded struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := decodeJSONLimited(res.Body, &decoded); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}
	out := make([]json.RawMessage, 0, len(decoded.Hits.Hits))
	for _, hit := range decoded.Hits.Hits {
		if len(hit.Source) > 0 {
			out = append(out, hit.Source)
		}
	}
	return out, nil
}

// FieldPresence reports, via _field_caps, whether each requested field is
// mapped anywhere under the pattern.
func (c *Client) FieldPresence(ctx context.Context, pattern string, fields []string) (map[string]bool, error) {
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	res, err := c.es.FieldCaps(
		c.es.FieldCaps.WithContext(ctx),
		c.es.FieldCaps.WithIndex(pattern),
		c.es.FieldCaps.WithFields(strings.Join(fields, ",")),
	)
	if err != nil {
		return nil, fmt.Errorf("field_caps against %q: %w", pattern, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		return nil, apiError("field_caps", res.StatusCode, res.Body)
	}
	var body struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := decodeJSONLimited(res.Body, &body); err != nil {
		return nil, fmt.Errorf("decoding field_caps response: %w", err)
	}
	out := make(map[string]bool, len(fields))
	for _, f := range fields {
		_, ok := body.Fields[f]
		out[f] = ok
	}
	return out, nil
}

// WritePrivilegeCheck is the result of asking ES whether the current key
// can write to the Zeek indices. Indeterminate is true when the security
// API itself was unavailable to this key.
type WritePrivilegeCheck struct {
	CanWrite      bool
	Indeterminate bool
	Detail        string
}

// CheckWritePrivileges verifies the API key is genuinely read-only against
// the index pattern (SALIENT_PLAN.md §14).
func (c *Client) CheckWritePrivileges(ctx context.Context, pattern string) (WritePrivilegeCheck, error) {
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	body, err := HasWritePrivilegesQuery(pattern)
	if err != nil {
		return WritePrivilegeCheck{}, err
	}
	res, err := c.es.Security.HasPrivileges(
		strings.NewReader(body),
		c.es.Security.HasPrivileges.WithContext(ctx),
	)
	if err != nil {
		return WritePrivilegeCheck{}, fmt.Errorf("privilege check: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.IsError() {
		// A key without permission to even ask is fine — just report
		// that the check could not be performed.
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return WritePrivilegeCheck{
			Indeterminate: true,
			Detail:        fmt.Sprintf("security API returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(msg))),
		}, nil
	}
	var decoded struct {
		HasAllRequested bool                       `json:"has_all_requested"`
		Index           map[string]map[string]bool `json:"index"`
	}
	if err := decodeJSONLimited(res.Body, &decoded); err != nil {
		return WritePrivilegeCheck{}, fmt.Errorf("decoding privilege response: %w", err)
	}
	check := WritePrivilegeCheck{}
	var granted []string
	for _, privs := range decoded.Index {
		for name, has := range privs {
			if has {
				check.CanWrite = true
				granted = append(granted, name)
			}
		}
	}
	if check.CanWrite {
		check.Detail = "granted write-class privileges: " + strings.Join(granted, ", ")
	}
	return check, nil
}

func decodeJSONLimited(body io.Reader, dst any) error {
	return decodeJSONWithLimit(body, dst, config.ESMaxResponseBytes)
}

func decodeJSONWithLimit(body io.Reader, dst any, limit int64) error {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	return json.Unmarshal(raw, dst)
}

func apiError(op string, status int, body io.Reader) error {
	msg, _ := io.ReadAll(io.LimitReader(body, 2048))
	trimmed := strings.TrimSpace(string(msg))
	if status == http.StatusUnauthorized {
		return fmt.Errorf("%s: authentication failed (HTTP 401) — check SALIENT_API_KEY: %s", op, trimmed)
	}
	if status == http.StatusForbidden {
		return fmt.Errorf("%s: authorization failed (HTTP 403) — API key lacks read access: %s", op, trimmed)
	}
	return fmt.Errorf("%s: Elasticsearch returned HTTP %d: %s", op, status, trimmed)
}
