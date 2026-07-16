package netconfig

import (
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
