package devices

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingFileIsEmptyRegistry(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 0 || len(r.Labels) != 0 || len(r.DismissedHints) != 0 {
		t.Fatalf("expected empty registry, got %#v", r)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	r := Registry{
		Devices: []Device{{Name: "router", Type: "gateway", Notes: "UDM — VLAN trunk",
			IPs: []string{"10.10.40.1", "10.18.61.1", "192.168.20.1"}}},
		Labels:         map[string][]string{"10.10.40.5": {"nas", "synology"}},
		DismissedHints: []string{"hostname:unifi"},
	}
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0].Name != "router" ||
		len(got.Devices[0].IPs) != 3 || got.Labels["10.10.40.5"][0] != "nas" ||
		got.DismissedHints[0] != "hostname:unifi" {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestLoadCorruptFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestValidateRejectsBadRegistries(t *testing.T) {
	cases := []struct {
		name string
		r    Registry
		want string
	}{
		{"empty name", Registry{Devices: []Device{{Name: ""}}}, "empty name"},
		{"dup name", Registry{Devices: []Device{{Name: "a"}, {Name: "a"}}}, "duplicate"},
		{"bad ip", Registry{Devices: []Device{{Name: "a", IPs: []string{"not-an-ip"}}}}, "invalid IP"},
		{"ip in two devices", Registry{Devices: []Device{
			{Name: "a", IPs: []string{"10.0.0.1"}},
			{Name: "b", IPs: []string{"10.0.0.1"}},
		}}, "10.0.0.1"},
	}
	for _, tc := range cases {
		err := tc.r.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate() = %v, want containing %q", tc.name, err, tc.want)
		}
	}
}

func TestAssignCreatesMovesAndDeduplicates(t *testing.T) {
	var r Registry
	if _, err := r.Assign("router", "192.168.20.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Assign("router", "10.10.40.1"); err != nil {
		t.Fatal(err)
	}
	d := r.DeviceForIP("10.10.40.1")
	if d == nil || d.Name != "router" || len(d.IPs) != 2 {
		t.Fatalf("DeviceForIP = %#v", d)
	}
	// Re-assigning to the same device is a no-op, not a duplicate.
	if _, err := r.Assign("router", "10.10.40.1"); err != nil {
		t.Fatal(err)
	}
	if len(r.DeviceForIP("10.10.40.1").IPs) != 2 {
		t.Fatal("re-assign duplicated the IP")
	}
	// Assigning to another device moves it and reports the old owner.
	moved, err := r.Assign("switch", "10.10.40.1")
	if err != nil || moved != "router" {
		t.Fatalf("Assign move = (%q, %v), want (router, nil)", moved, err)
	}
	if got := r.DeviceForIP("10.10.40.1"); got == nil || got.Name != "switch" {
		t.Fatalf("after move DeviceForIP = %#v", got)
	}
	if len(r.DeviceForIP("192.168.20.1").IPs) != 1 {
		t.Fatal("router should have exactly one IP left")
	}
	// Bad inputs.
	if _, err := r.Assign("", "10.0.0.1"); err == nil {
		t.Fatal("empty device name must error")
	}
	if _, err := r.Assign("x", "nope"); err == nil {
		t.Fatal("bad IP must error")
	}
}

func TestUnassignRemovesIPKeepsDevice(t *testing.T) {
	var r Registry
	_, _ = r.Assign("router", "10.0.0.1")
	r.Unassign("10.0.0.1")
	if r.DeviceForIP("10.0.0.1") != nil {
		t.Fatal("IP still owned after Unassign")
	}
	if len(r.Devices) != 1 {
		t.Fatal("empty device must survive (may carry type/notes)")
	}
}

func TestUpsertCreateRenameAndInvariants(t *testing.T) {
	var r Registry
	if err := r.Upsert("", Device{Name: "router", Type: "gateway", IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	// Rename keyed by original name.
	if err := r.Upsert("router", Device{Name: "core-router", Type: "gateway", IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if r.DeviceForIP("10.0.0.1").Name != "core-router" {
		t.Fatal("rename did not stick")
	}
	// Unknown original name.
	if err := r.Upsert("ghost", Device{Name: "x"}); err == nil {
		t.Fatal("unknown original name must error")
	}
	// Invariant violation must not mutate.
	if err := r.Upsert("", Device{Name: "core-router"}); err == nil {
		t.Fatal("duplicate name must error")
	}
	if len(r.Devices) != 1 {
		t.Fatal("failed Upsert mutated the registry")
	}
}

func TestDeleteAndDismiss(t *testing.T) {
	var r Registry
	_, _ = r.Assign("router", "10.0.0.1")
	r.Delete("router")
	if len(r.Devices) != 0 || r.DeviceForIP("10.0.0.1") != nil {
		t.Fatal("Delete left the device behind")
	}
	if r.Dismissed("hostname:unifi") {
		t.Fatal("nothing dismissed yet")
	}
	r.Dismiss("hostname:unifi")
	r.Dismiss("hostname:unifi") // idempotent
	if !r.Dismissed("hostname:unifi") || len(r.DismissedHints) != 1 {
		t.Fatalf("Dismiss bookkeeping wrong: %#v", r.DismissedHints)
	}
}

func TestPinUnpin(t *testing.T) {
	var r Registry
	if r.IsPinned("10.0.0.9") {
		t.Fatal("nothing pinned yet")
	}
	r.Pin("10.0.0.9")
	r.Pin("10.0.0.9") // idempotent
	if !r.IsPinned("10.0.0.9") || len(r.Pinned) != 1 {
		t.Fatalf("Pin bookkeeping wrong: %#v", r.Pinned)
	}
	r.Unpin("10.0.0.9")
	if r.IsPinned("10.0.0.9") || len(r.Pinned) != 0 {
		t.Fatalf("Unpin left state: %#v", r.Pinned)
	}
}

func TestApproveUnapproveProvider(t *testing.T) {
	var r Registry
	key := "10.0.0.99:53"
	if r.IsApprovedProvider(key) {
		t.Fatal("nothing approved yet")
	}
	r.ApproveProvider(key)
	r.ApproveProvider(key) // idempotent
	if !r.IsApprovedProvider(key) || len(r.ApprovedProviders) != 1 {
		t.Fatalf("ApproveProvider bookkeeping wrong: %#v", r.ApprovedProviders)
	}
	r.UnapproveProvider(key)
	if r.IsApprovedProvider(key) || len(r.ApprovedProviders) != 0 {
		t.Fatalf("UnapproveProvider left state: %#v", r.ApprovedProviders)
	}
}

func TestSetRoleSetClearValidate(t *testing.T) {
	var r Registry
	if err := r.SetRole("10.0.0.1", "Camera"); err != nil {
		t.Fatal(err)
	}
	if r.RoleOverrides["10.0.0.1"] != "Camera" {
		t.Fatalf("RoleOverrides = %#v", r.RoleOverrides)
	}
	if err := r.SetRole("nope", "Camera"); err == nil {
		t.Fatal("bad IP must error")
	}
	if err := r.SetRole("10.0.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.RoleOverrides["10.0.0.1"]; ok {
		t.Fatal("empty role must clear the override")
	}
	// Validate rejects a hand-edited registry with a bad override key.
	bad := Registry{RoleOverrides: map[string]string{"not-an-ip": "Camera"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate must reject invalid override IP")
	}
}

func TestSaveRejectsInvalidRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	r := Registry{Devices: []Device{{Name: ""}}}
	if err := r.Save(path); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid registry must not be written")
	}
}
