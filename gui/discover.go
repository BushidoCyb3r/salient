package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/escli"
)

// discoverLines formats grid discovery results for the task log, mirroring
// the CLI's discover wording so operators see one vocabulary.
// ponytail: gui-local formatter; share with cmd/defilade/discover.go if a
// third consumer appears.
func discoverLines(counts, sensors []escli.DatasetCount, fm escli.FieldMap) []string {
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
		lines = append(lines, "WARNING: REQUIRED conn dataset missing — no edges, Defilade cannot scan this grid")
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
	return discoverLines(counts, sensors, fm), nil
}
