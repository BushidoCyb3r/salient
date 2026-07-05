package config

import "testing"

func TestVendorForMAC(t *testing.T) {
	cases := map[string]string{
		"24:5a:4c:11:22:33": "Ubiquiti",
		"F0-9F-C2-aa-bb-cc": "Ubiquiti",
		"00:1b:0c:00:00:01": "Cisco",
		"e0:55:3d:00:00:01": "Cisco Meraki",
		"00:0b:86:00:00:01": "Aruba/HPE",
		"00:05:85:00:00:01": "Juniper",
		"00:50:56:00:00:01": "VMware",
		"b8:27:eb:00:00:01": "Raspberry Pi",
		"":                  "",
		"not-a-mac":         "",
		"aa:bb:cc:dd:ee:ff": "", // unknown OUI
	}
	for mac, want := range cases {
		if got := VendorForMAC(mac); got != want {
			t.Errorf("VendorForMAC(%q) = %q, want %q", mac, got, want)
		}
	}
}
