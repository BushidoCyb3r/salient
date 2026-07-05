package config

import "strings"

// ouiVendor maps a normalized 6-hex-digit OUI (first three octets, lower
// case, no separators) to a vendor name. Curated subset of well-known
// prefixes — not the full IEEE registry.
// ponytail: extend only if coverage gaps bite; swapping in the full IEEE
// OUI file is the upgrade path.
var ouiVendor = map[string]string{
	// Ubiquiti
	"245a4c": "Ubiquiti", "f09fc2": "Ubiquiti", "fcecda": "Ubiquiti",
	"788a20": "Ubiquiti", "b4fbe4": "Ubiquiti", "0418d6": "Ubiquiti",
	"e063da": "Ubiquiti", "68d79a": "Ubiquiti", "802aa8": "Ubiquiti",
	"74acb9": "Ubiquiti", "dc9fdb": "Ubiquiti", "44d9e7": "Ubiquiti",
	// Cisco
	"001b0c": "Cisco", "0018b9": "Cisco", "00000c": "Cisco",
	"e8b7a3": "Cisco", "00256b": "Cisco", "0025b4": "Cisco",
	// Cisco Meraki
	"e0553d": "Cisco Meraki", "88153f": "Cisco Meraki", "0c8ddb": "Cisco Meraki",
	"ac17c8": "Cisco Meraki", "e8264b": "Cisco Meraki",
	// Aruba / HPE
	"000b86": "Aruba/HPE", "6cf37f": "Aruba/HPE", "9c1c12": "Aruba/HPE",
	"204c03": "Aruba/HPE", "d8c7c8": "Aruba/HPE",
	// Juniper
	"000585": "Juniper", "3c8ab0": "Juniper", "2c6bf5": "Juniper",
	"84b59c": "Juniper", "f4b52f": "Juniper",
	// Common non-network
	"005056": "VMware", "000c29": "VMware", "001c14": "VMware",
	"b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
	"001451": "Apple", "3c0754": "Apple", "a45e60": "Apple",
	"001320": "Intel", "00aa00": "Intel", "0015f2": "Intel",
	"000d3a": "Microsoft", "001dd8": "Microsoft",
	"00188b": "Dell", "d067e5": "Dell", "18a99b": "Dell",
}

// VendorForMAC returns the vendor for a MAC's OUI, or "" if unknown or the
// MAC is unparseable.
func VendorForMAC(mac string) string {
	var hex []rune
	for _, r := range strings.ToLower(mac) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			hex = append(hex, r)
		}
		if len(hex) == 6 {
			break
		}
	}
	if len(hex) < 6 {
		return ""
	}
	return ouiVendor[string(hex)]
}
