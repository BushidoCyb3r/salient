package netconfig

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
)

// ParseConfigs autodetects and parses raw device-config files into declared
// devices. Each IOS-looking file yields one device (source = its base name);
// all UniFi-looking JSON files are grouped and parsed together as a single
// controller. Files matching neither format, and per-file parse failures, are
// reported as warnings rather than failing the whole batch — one bad export
// should not sink the others. Shared by the CLI `declared` command and the
// GUI's LoadDeclared so both group and detect identically.
//
// ponytail: all UniFi files fold into one controller device; splitting by
// controller would need a grouping key filenames alone don't carry.
func ParseConfigs(files map[string][]byte) (devs []DeclaredDevice, warnings []string) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	unifi := map[string][]byte{}
	for _, name := range names {
		raw := files[name]
		base := filepath.Base(name)
		switch {
		case LooksLikeIOS(raw):
			dev, err := ParseCiscoIOS(bytes.NewReader(raw), base)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", base, err))
				continue
			}
			devs = append(devs, dev)
		case LooksLikeUniFi(raw):
			unifi[base] = raw
		default:
			warnings = append(warnings, fmt.Sprintf("%s: unrecognized format (not Cisco IOS text or UniFi JSON)", base))
		}
	}
	if len(unifi) > 0 {
		dev, err := ParseUniFi(unifi, "unifi-controller")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("unifi: %v", err))
		} else {
			devs = append(devs, dev)
		}
	}
	return devs, warnings
}
