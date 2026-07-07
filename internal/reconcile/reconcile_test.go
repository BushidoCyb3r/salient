package reconcile

import (
	"strings"
	"testing"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

func TestParseCSVForgivingHeaders(t *testing.T) {
	csv := "\ufeffIP Address,Host Name,Role/Function,VLAN Name\n" +
		"10.0.1.5,dc01,Domain Controller,Server VLAN\n" +
		"not-an-ip,junk,junk,junk\n" +
		"10.0.1.5,dup,dup,dup\n" +
		" 10.0.2.9 ,ws-1,,User LAN\n" +
		",,,\n"
	assets, warnings, err := ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets = %+v, want 2", assets)
	}
	a := assets[0]
	if a.IP != "10.0.1.5" || a.Hostname != "dc01" || a.Role != "Domain Controller" || a.Segment != "Server VLAN" || a.Row != 2 {
		t.Errorf("asset[0] = %+v", a)
	}
	if assets[1].IP != "10.0.2.9" {
		t.Errorf("asset[1] = %+v", assets[1])
	}
	if len(warnings) != 2 {
		t.Errorf("warnings = %v, want bad-row + duplicate", warnings)
	}
}

// A "Description" column contains the substring "ip" and used to hijack the
// IP column, dropping every row. The IP column must match "ip" as a token.
func TestParseCSVDescriptionDoesNotHijackIP(t *testing.T) {
	csv := "Hostname,Description,IP Address\n" +
		"web01,front-end web server,10.0.0.5\n"
	assets, _, err := ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].IP != "10.0.0.5" {
		t.Fatalf("assets = %+v, want IP 10.0.0.5", assets)
	}
	if assets[0].Role != "front-end web server" {
		t.Errorf("role = %q, want the Description column", assets[0].Role)
	}
}

// An explicit "IP" column wins over a generic address column ("MAC Address").
func TestParseCSVExplicitIPBeatsMAC(t *testing.T) {
	csv := "MAC Address,IP,Hostname\naa:bb:cc:dd:ee:ff,10.0.0.7,host1\n"
	assets, _, err := ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].IP != "10.0.0.7" {
		t.Fatalf("assets = %+v, want IP 10.0.0.7", assets)
	}
}

func TestParseCSVHeaderless(t *testing.T) {
	csv := "dc01,10.0.1.5\nws-1,10.0.2.9\n"
	assets, warnings, err := ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[0].IP != "10.0.1.5" {
		t.Fatalf("assets = %+v", assets)
	}
	if len(warnings) == 0 {
		t.Error("expected a no-header warning")
	}
}

func TestParseCSVNoIPColumn(t *testing.T) {
	if _, _, err := ParseCSV(strings.NewReader("a,b\nx,y\n")); err == nil {
		t.Fatal("expected error for CSV without IPs")
	}
}

func TestNormalizeRole(t *testing.T) {
	cases := map[string]graph.Role{
		"Domain Controller": graph.RoleDC,
		"DC":                graph.RoleDC,
		"datacenter switch": "", // "dc" must not match inside a word
		"Primary DNS":       graph.RoleDNS,
		"File Server (NAS)": graph.RoleFileServer,
		"SQL DB":            graph.RoleDatabase,
		"jump box":          graph.RoleJumpBox,
		"IIS web frontend":  graph.RoleWebServer,
		"printer":           "",
		"":                  "",
	}
	for in, want := range cases {
		if got := NormalizeRole(in); got != want {
			t.Errorf("NormalizeRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareThreeLists(t *testing.T) {
	snap := graph.Snapshot{
		Meta: graph.SnapshotMeta{ZeroCovCIDRs: []string{"10.0.9.0/24"}},
		Nodes: []graph.Node{
			{IP: "10.0.1.5", Subnet: "10.0.1.0/24", Roles: []graph.RoleAssertion{{Role: graph.RoleDC}}},
			{IP: "10.0.2.9", Subnet: "10.0.2.0/24"}, // observed, undocumented below
		},
	}
	assets := []Asset{
		{IP: "10.0.1.5", Hostname: "dc01", Role: "File Server"},    // contradicted: observed DC
		{IP: "10.0.9.7", Hostname: "scada1", Role: "database"},     // silent, in blind spot
		{IP: "10.0.3.1", Hostname: "old-nas", Role: "file server"}, // silent, not blind
	}
	res := Compare(snap, assets)

	if len(res.DocumentedSilent) != 2 {
		t.Fatalf("silent = %+v", res.DocumentedSilent)
	}
	if !res.DocumentedSilent[1].InBlindSpot || res.DocumentedSilent[1].IP != "10.0.9.7" {
		t.Errorf("blind-spot flag wrong: %+v", res.DocumentedSilent)
	}
	if res.DocumentedSilent[0].InBlindSpot {
		t.Errorf("10.0.3.1 wrongly flagged blind: %+v", res.DocumentedSilent[0])
	}

	if len(res.ObservedUndocumented) != 1 || res.ObservedUndocumented[0].IP != "10.0.2.9" {
		t.Fatalf("undocumented = %+v", res.ObservedUndocumented)
	}

	if len(res.RoleContradicted) != 1 {
		t.Fatalf("contradicted = %+v", res.RoleContradicted)
	}
	c := res.RoleContradicted[0]
	if c.IP != "10.0.1.5" || c.Expected != graph.RoleFileServer || len(c.Observed) != 1 || c.Observed[0] != graph.RoleDC {
		t.Errorf("contradiction = %+v", c)
	}
}

func TestCompareUnknownObservedNeverContradicted(t *testing.T) {
	snap := graph.Snapshot{Nodes: []graph.Node{{IP: "10.0.1.5", Subnet: "10.0.1.0/24"}}}
	res := Compare(snap, []Asset{{IP: "10.0.1.5", Role: "Domain Controller"}})
	if len(res.RoleContradicted) != 0 {
		t.Fatalf("host with no inferred roles must not be contradicted: %+v", res.RoleContradicted)
	}
	if len(res.DocumentedSilent) != 0 || len(res.ObservedUndocumented) != 0 {
		t.Fatalf("unexpected lists: %+v", res)
	}
}
