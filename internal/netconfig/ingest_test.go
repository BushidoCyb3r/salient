package netconfig

import (
	"os"
	"testing"
)

func TestParseConfigs_DetectsAndGroups(t *testing.T) {
	files := map[string][]byte{}
	for _, name := range []string{
		"ios-router.cfg", "unifi-networkconf.json",
		"unifi-firewallrule.json", "unifi-device.json",
	} {
		b, err := os.ReadFile("../../testdata/netconfig/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		files["/some/dir/"+name] = b
	}
	files["notes.txt"] = []byte("just some prose, not a config\n")

	devs, warnings := ParseConfigs(files)

	// One IOS device + one folded UniFi controller.
	if len(devs) != 2 {
		t.Fatalf("device count = %d, want 2: %+v", len(devs), devs)
	}
	var gotIOS, gotUniFi bool
	for _, d := range devs {
		switch d.Vendor {
		case "cisco-ios":
			gotIOS = true
			if d.Source != "ios-router.cfg" { // base name, not full path
				t.Errorf("IOS source = %q, want ios-router.cfg", d.Source)
			}
		case "unifi":
			gotUniFi = true
		}
	}
	if !gotIOS || !gotUniFi {
		t.Errorf("missing a vendor: ios=%v unifi=%v", gotIOS, gotUniFi)
	}
	if len(warnings) != 1 { // the prose file
		t.Errorf("warnings = %v, want 1 (unrecognized notes.txt)", warnings)
	}
}
