package netconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// FuzzParseCiscoIOS asserts the parser never panics and never leaks secret
// material into its output, regardless of input.
func FuzzParseCiscoIOS(f *testing.F) {
	if b, err := os.ReadFile("../../testdata/netconfig/ios-router.cfg"); err == nil {
		f.Add(b)
	}
	f.Add([]byte("hostname r1\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		dev, err := ParseCiscoIOS(strings.NewReader(string(data)), "fuzz")
		if err != nil {
			return
		}
		if strings.Contains(fmt.Sprintf("%+v", dev), "secret") {
			t.Fatalf("output contains \"secret\": %+v", dev)
		}
	})
}

// FuzzParseUniFi asserts the UniFi parser never panics on arbitrary bytes and
// never lets an x_* (secret) field value survive into its output. The seed
// corpus carries the real fixtures, whose x_passphrase/x_authkey sentinels
// must not appear in the parsed model.
func FuzzParseUniFi(f *testing.F) {
	for _, name := range []string{"unifi-networkconf.json", "unifi-firewallrule.json", "unifi-device.json"} {
		if b, err := os.ReadFile("../../testdata/netconfig/" + name); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"data":[{"purpose":"x","ip_subnet":"10.0.0.1/24","x_passphrase":"should-not-appear"}]}`))
	f.Add([]byte(`[{"mac":"a","type":"ugw","x_authkey":"secret-authkey"}]`))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		dev, err := ParseUniFi(map[string][]byte{"fuzz.json": data}, "fuzz")
		if err != nil {
			return
		}
		dump := fmt.Sprintf("%+v", dev)

		// Collect string values from the input, split by whether they sit under
		// an x_* (secret) key. A distinctive x_* value that is NOT also a
		// legitimate non-x_ value must never surface in the output. (The same
		// string appearing under both an x_ key and, say, ip_subnet is not a
		// leak — it reached output via the whitelisted field.)
		xVals := map[string]bool{}
		var safe []string
		var walk func(v any, underX bool)
		walk = func(v any, underX bool) {
			switch t := v.(type) {
			case map[string]any:
				for k, vv := range t {
					walk(vv, underX || strings.HasPrefix(k, "x_"))
				}
			case []any:
				for _, vv := range t {
					walk(vv, underX)
				}
			case string:
				if underX {
					xVals[t] = true
				} else {
					safe = append(safe, t)
				}
			}
		}
		var root any
		if json.Unmarshal(data, &root) == nil {
			walk(root, false)
		}
		safeBlob := strings.Join(safe, "\x00")
		for xv := range xVals {
			if len(xv) < 6 || strings.Contains(safeBlob, xv) {
				continue // too short to be a distinctive secret, or legit elsewhere
			}
			if strings.Contains(dump, xv) {
				t.Fatalf("output leaked x_* secret %q: %s", xv, dump)
			}
		}
	})
}
