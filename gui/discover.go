package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/BushidoCyb3r/salient/internal/config"
	"github.com/BushidoCyb3r/salient/internal/escli"
)

// discoverLines formats grid discovery results for the task log, mirroring
// the CLI's discover wording so operators see one vocabulary.
// ponytail: gui-local formatter; share with cmd/salient/discover.go if a
// third consumer appears.
func discoverLines(counts, sensors []escli.DatasetCount, fm escli.FieldMap, cov escli.MACCoverage) []string {
	var lines []string
	present := map[string]bool{}
	var parts []string
	for _, c := range counts {
		present[c.Dataset] = true
		parts = append(parts, fmt.Sprintf("%s %d", c.Dataset, c.Docs))
	}
	lines = append(lines, "datasets observed: "+strings.Join(parts, " · "))
	has := func(candidates []string) bool {
		return slices.ContainsFunc(candidates, func(c string) bool { return present[c] })
	}
	if !has(fm.Datasets.Conn) {
		lines = append(lines, "WARNING: REQUIRED conn dataset missing — no edges, Salient cannot scan this grid")
	}
	optional := []struct {
		name, blind string
		candidates  []string
	}{
		{"dns", "DNS server inference blind", fm.Datasets.DNS},
		{"kerberos", "DC inference blind", fm.Datasets.Kerberos},
		{"smb", "file-server inference blind", fm.Datasets.SMB},
		{"ssl", "TLS service evidence blind", fm.Datasets.SSL},
		{"http", "web service evidence blind", fm.Datasets.HTTP},
		{"dhcp", "L2 gateway evidence blind", fm.Datasets.DHCP},
		{"ldap", "DC corroboration blind", fm.Datasets.LDAP},
	}
	var missing []string
	for _, o := range optional {
		if !has(o.candidates) {
			missing = append(missing, o.name+" ("+o.blind+")")
		}
	}
	if len(missing) > 0 {
		lines = append(lines, "WARNING: missing datasets: "+strings.Join(missing, ", "))
	}
	// L2/MAC coverage decides gateway detection: FetchGatewayCandidates keys
	// on the destination (responder) MAC, so its presence is what tells the
	// operator whether they get observed gateways or inferred guesses.
	if cov.ConnDocs > 0 {
		pct := cov.DstMACDocs * 100 / cov.ConnDocs
		if pct == 0 {
			lines = append(lines, fmt.Sprintf(
				"WARNING: L2/MAC: %s present in 0%% of conn docs — gateways will be inferred; verify the field map's destination_mac and that sensors capture L2 addresses",
				fm.DestinationMAC))
		} else {
			lines = append(lines, fmt.Sprintf(
				"L2/MAC: %s in %d%% of conn docs — observed gateway detection available",
				fm.DestinationMAC, pct))
		}
	}
	parts = parts[:0]
	for _, s := range sensors {
		parts = append(parts, fmt.Sprintf("%s (%d)", s.Dataset, s.Docs))
	}
	if len(parts) > 0 {
		lines = append(lines, "sensors: "+strings.Join(parts, ", "))
	}
	return lines
}

// DiscoverGrid summarizes datasets and sensors on the connected grid for
// the task log. Runs right after Connect; failures warn, never block.
func (a *App) DiscoverGrid(window string) ([]string, error) {
	a.mu.Lock()
	cli, fm := a.cli, a.fm
	a.mu.Unlock()
	if cli == nil {
		return nil, errors.New("not connected")
	}
	w, err := time.ParseDuration(window)
	if err != nil || w <= 0 {
		w = config.DefaultWindow
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	counts, err := cli.DatasetCounts(ctx, fm, w, config.DatasetTermsSize)
	if err != nil {
		return nil, err
	}
	sensors, err := cli.Sensors(ctx, fm, w, config.SensorTermsSize)
	if err != nil {
		return nil, err
	}
	// MAC coverage is best-effort: a probe failure must not blank out the
	// dataset/sensor discovery the operator connected to see.
	cov, err := cli.MACCoverage(ctx, fm, w)
	if err != nil {
		cov = escli.MACCoverage{}
	}
	return discoverLines(counts, sensors, fm, cov), nil
}
