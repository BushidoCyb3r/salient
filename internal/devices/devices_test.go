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
