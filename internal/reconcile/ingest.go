// Package reconcile diffs a supported unit's documented asset list against
// observed reality (DEFILADE_PLAN.md Phase 3). It depends only on the
// snapshot data model — never on escli — so reconciliation is a pure
// function of a snapshot plus a CSV.
package reconcile

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Asset is one documented host from the unit's asset list.
type Asset struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Role     string `json:"role,omitempty"`    // raw documented role text
	Segment  string `json:"segment,omitempty"` // VLAN/segment/site name
	Row      int    `json:"row"`               // 1-based source row
}

// ParseCSV ingests a real-world asset spreadsheet export: header names are
// autodetected, quoting is lazy, rows without a parseable IP are skipped
// with a warning rather than failing the run.
func ParseCSV(r io.Reader) ([]Asset, []string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("reading asset CSV: %w", err)
	}
	if len(rows) > 0 && len(rows[0]) > 0 {
		rows[0][0] = strings.TrimPrefix(rows[0][0], "\ufeff")
	}
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("asset CSV is empty")
	}

	var warnings []string
	cols, headered := detectHeader(rows[0])
	data := rows
	firstRow := 1
	if headered {
		data = rows[1:]
		firstRow = 2
	} else {
		cols = detectByContent(rows)
		warnings = append(warnings, "no recognizable header row — detected the IP column by content; hostname/role/segment columns unavailable")
	}
	if cols.ip < 0 {
		return nil, nil, fmt.Errorf("no IP column found in asset CSV (looked for an ip/address header, then for a column of parseable IPs)")
	}

	var assets []Asset
	seen := map[string]bool{}
	for i, row := range data {
		rowNum := firstRow + i
		ip := field(row, cols.ip)
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			if strings.TrimSpace(strings.Join(row, "")) != "" {
				warnings = append(warnings, fmt.Sprintf("row %d: no parseable IP (%q) — skipped", rowNum, ip))
			}
			continue
		}
		ipStr := addr.String()
		if seen[ipStr] {
			warnings = append(warnings, fmt.Sprintf("row %d: duplicate IP %s — first occurrence kept", rowNum, ipStr))
			continue
		}
		seen[ipStr] = true
		assets = append(assets, Asset{
			IP:       ipStr,
			Hostname: strings.TrimSpace(field(row, cols.hostname)),
			Role:     strings.TrimSpace(field(row, cols.role)),
			Segment:  strings.TrimSpace(field(row, cols.segment)),
			Row:      rowNum,
		})
	}
	if len(assets) == 0 {
		return nil, warnings, fmt.Errorf("asset CSV yielded zero usable rows")
	}
	return assets, warnings, nil
}

type columns struct{ ip, hostname, role, segment int }

// detectHeader classifies header cells by keyword. Segment keywords are
// checked before hostname ones so "VLAN Name" lands on segment, not hostname.
func detectHeader(header []string) (columns, bool) {
	cols := columns{ip: -1, hostname: -1, role: -1, segment: -1}
	for i, cell := range header {
		l := strings.ToLower(strings.TrimSpace(cell))
		switch {
		case cols.segment < 0 && containsAny(l, "vlan", "segment", "subnet", "site", "enclave", "zone", "network"):
			cols.segment = i
		case cols.ip < 0 && containsAny(l, "ip", "address", "addr"):
			cols.ip = i
		case cols.hostname < 0 && containsAny(l, "host", "name", "fqdn", "asset", "system", "device"):
			cols.hostname = i
		case cols.role < 0 && containsAny(l, "role", "function", "type", "purpose", "service", "description"):
			cols.role = i
		}
	}
	return cols, cols.ip >= 0
}

// detectByContent finds the column with the most parseable IPs across all
// rows, for headerless exports.
func detectByContent(rows [][]string) columns {
	counts := map[int]int{}
	for _, row := range rows {
		for i, cell := range row {
			if _, err := netip.ParseAddr(strings.TrimSpace(cell)); err == nil {
				counts[i]++
			}
		}
	}
	best, bestN := -1, 0
	for i, n := range counts {
		if n > bestN {
			best, bestN = i, n
		}
	}
	return columns{ip: best, hostname: -1, role: -1, segment: -1}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func field(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}
