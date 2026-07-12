package escli

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
)

type x509Cert struct {
	Fingerprint string
	Subject     string
	SANs        []string
}

func TLSServerNamesQuery(fm FieldMap, window time.Duration, afterKey map[string]any) (string, error) {
	composite := map[string]any{
		"size": config.CompositePageSize,
		"sources": []any{
			source("dst", fm.DestinationIP),
			source("name", fm.SSLServerName),
		},
	}
	if afterKey != nil {
		composite["after"] = afterKey
	}
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.SSL}},
					map[string]any{"exists": map[string]any{"field": fm.DestinationIP}},
					map[string]any{"exists": map[string]any{"field": fm.SSLServerName}},
				},
			},
		},
		"aggs": map[string]any{
			"pairs": map[string]any{"composite": composite},
		},
	}
	return marshal(q)
}

func (c *Client) FetchTLSServerNames(ctx context.Context, fm FieldMap, window time.Duration) (map[string][]string, error) {
	if len(fm.Datasets.SSL) == 0 || fm.SSLServerName == "" {
		return map[string][]string{}, nil
	}
	type aggPage struct {
		AfterKey map[string]any `json:"after_key"`
		Buckets  []struct {
			Key struct {
				Dst  string `json:"dst"`
				Name string `json:"name"`
			} `json:"key"`
		} `json:"buckets"`
	}
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	var after map[string]any
	for {
		body, err := TLSServerNamesQuery(fm, window, after)
		if err != nil {
			return nil, err
		}
		res, err := c.search(ctx, fm.IndexPattern, body)
		if err != nil {
			return nil, err
		}
		aggs, err := aggregations(res)
		if err != nil {
			return nil, err
		}
		raw, ok := aggs["pairs"]
		if !ok {
			break
		}
		var page aggPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("decoding TLS server-name pairs: %w", err)
		}
		for _, b := range page.Buckets {
			if b.Key.Dst == "" || b.Key.Name == "" {
				continue
			}
			if seen[b.Key.Dst] == nil {
				seen[b.Key.Dst] = map[string]bool{}
			}
			if !seen[b.Key.Dst][b.Key.Name] {
				seen[b.Key.Dst][b.Key.Name] = true
				out[b.Key.Dst] = append(out[b.Key.Dst], b.Key.Name)
			}
		}
		if len(page.Buckets) == 0 || page.AfterKey == nil {
			break
		}
		after = page.AfterKey
	}
	for ip := range out {
		sort.Strings(out[ip])
	}
	return out, nil
}

func X509DocsQuery(fm FieldMap, window time.Duration) (string, error) {
	q := map[string]any{
		"size": 5000,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.X509}},
				},
			},
		},
	}
	return marshal(q)
}

func (c *Client) FetchX509Certs(ctx context.Context, fm FieldMap, window time.Duration) ([]x509Cert, error) {
	if len(fm.Datasets.X509) == 0 || fm.MessageField == "" {
		return nil, nil
	}
	body, err := X509DocsQuery(fm, window)
	if err != nil {
		return nil, err
	}
	srcs, err := c.searchSources(ctx, fm.IndexPattern, body)
	if err != nil {
		return nil, err
	}
	type doc struct {
		X509 struct {
			SANDNS      []string `json:"san_dns"`
			Certificate struct {
				Subject string `json:"subject"`
			} `json:"certificate"`
		} `json:"x509"`
	}
	var out []x509Cert
	seen := map[string]bool{}
	for _, src := range srcs {
		var raw map[string]any
		if err := json.Unmarshal(src, &raw); err != nil {
			return nil, fmt.Errorf("decoding x509 source: %w", err)
		}
		var d doc
		if err := json.Unmarshal(src, &d); err != nil {
			return nil, fmt.Errorf("decoding x509 source: %w", err)
		}
		fp := x509Fingerprint(stringValue(raw, fm.MessageField))
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, x509Cert{
			Fingerprint: fp,
			Subject:     d.X509.Certificate.Subject,
			SANs:        sortedUniqueNames(d.X509.SANDNS, d.X509.Certificate.Subject),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

func SSHDocsQuery(fm FieldMap, window time.Duration) (string, error) {
	q := map[string]any{
		"size": 5000,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					rangeFilter(fm.Timestamp, window),
					map[string]any{"terms": map[string]any{fm.DatasetField: fm.Datasets.SSH}},
					map[string]any{"exists": map[string]any{"field": fm.DestinationIP}},
					map[string]any{"exists": map[string]any{"field": fm.SSHHostKey}},
				},
			},
		},
	}
	return marshal(q)
}

func (c *Client) FetchSSHHostKeys(ctx context.Context, fm FieldMap, window time.Duration) (map[string][]string, error) {
	if len(fm.Datasets.SSH) == 0 || fm.SSHHostKey == "" {
		return map[string][]string{}, nil
	}
	body, err := SSHDocsQuery(fm, window)
	if err != nil {
		return nil, err
	}
	srcs, err := c.searchSources(ctx, fm.IndexPattern, body)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	for _, src := range srcs {
		var raw map[string]any
		if err := json.Unmarshal(src, &raw); err != nil {
			return nil, fmt.Errorf("decoding ssh source: %w", err)
		}
		ip := stringValue(raw, fm.DestinationIP)
		hostKey := stringValue(raw, fm.SSHHostKey)
		if ip == "" || hostKey == "" {
			continue
		}
		if seen[ip] == nil {
			seen[ip] = map[string]bool{}
		}
		if !seen[ip][hostKey] {
			seen[ip][hostKey] = true
			out[ip] = append(out[ip], hostKey)
		}
	}
	for ip := range out {
		sort.Strings(out[ip])
	}
	return out, nil
}

// FetchTLSFingerprints correlates observed TLS server names to x509 certs by
// SAN/CN match. ponytail: best-effort SNI→cert matching, not per-connection
// uid correlation; add stricter joins only if this heuristic proves too weak.
func (c *Client) FetchTLSFingerprints(ctx context.Context, fm FieldMap, window time.Duration) (map[string][]string, error) {
	namesByIP, err := c.FetchTLSServerNames(ctx, fm, window)
	if err != nil {
		return nil, err
	}
	certs, err := c.FetchX509Certs(ctx, fm, window)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	for ip, names := range namesByIP {
		for _, name := range names {
			for _, cert := range certs {
				if !certMatchesName(cert, name) {
					continue
				}
				if seen[ip] == nil {
					seen[ip] = map[string]bool{}
				}
				if !seen[ip][cert.Fingerprint] {
					seen[ip][cert.Fingerprint] = true
					out[ip] = append(out[ip], cert.Fingerprint)
				}
			}
		}
		sort.Strings(out[ip])
	}
	return out, nil
}

func x509Fingerprint(message string) string {
	var raw struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(message), &raw); err != nil {
		return ""
	}
	return raw.Fingerprint
}

func sortedUniqueNames(sans []string, subject string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range sans {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if cn := subjectCN(subject); cn != "" && !seen[cn] {
		out = append(out, cn)
	}
	sort.Strings(out)
	return out
}

func subjectCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.ToLower(strings.TrimSpace(after))
		}
	}
	return ""
}

func certMatchesName(cert x509Cert, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, pat := range cert.SANs {
		if pat == name {
			return true
		}
		if strings.Contains(pat, "*") {
			if ok, _ := path.Match(pat, name); ok {
				return true
			}
		}
	}
	return false
}

func stringValue(m map[string]any, dotted string) string {
	if dotted == "" {
		return ""
	}
	var cur any = m
	for _, part := range strings.Split(dotted, ".") {
		next, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = next[part]
		if !ok {
			return ""
		}
	}
	s, _ := cur.(string)
	return s
}
