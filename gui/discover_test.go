package main

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/defilade/internal/escli"
)

func TestDiscoverLines(t *testing.T) {
	fm := escli.DefaultFieldMap()
	counts := []escli.DatasetCount{{Dataset: "conn", Docs: 2100000}, {Dataset: "dns", Docs: 890000}}
	sensors := []escli.DatasetCount{{Dataset: "so-sensor-01", Docs: 2900000}}
	// Good L2 coverage: destination MAC present in most conn docs.
	cov := escli.MACCoverage{ConnDocs: 2100000, SrcMACDocs: 1900000, DstMACDocs: 1980000}
	lines := discoverLines(counts, sensors, fm, cov)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"conn", "2100000", "dns", "so-sensor-01", "L2/MAC", "94%", "observed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lines missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "REQUIRED conn dataset missing") {
		t.Error("conn present but flagged missing")
	}
	// Zero L2 coverage warns that gateways will be inferred and names the field.
	lines = discoverLines(counts, sensors, fm, escli.MACCoverage{ConnDocs: 2100000})
	joined = strings.Join(lines, "\n")
	if !strings.Contains(joined, "gateways will be inferred") || !strings.Contains(joined, fm.DestinationMAC) {
		t.Errorf("zero-MAC warning missing field/inferred note:\n%s", joined)
	}
	// Without conn the required warning must appear; missing optional
	// datasets are named with what goes blind.
	lines = discoverLines([]escli.DatasetCount{{Dataset: "dns", Docs: 1}}, nil, fm, escli.MACCoverage{})
	joined = strings.Join(lines, "\n")
	if !strings.Contains(joined, "REQUIRED conn dataset missing") {
		t.Errorf("missing-conn warning absent:\n%s", joined)
	}
	if !strings.Contains(joined, "kerberos") {
		t.Errorf("missing kerberos not reported:\n%s", joined)
	}
}

func TestDiscoverGridRequiresConnection(t *testing.T) {
	if _, err := (&App{}).DiscoverGrid("336h"); err == nil {
		t.Fatal("expected not-connected error")
	}
}
