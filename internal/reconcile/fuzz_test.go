package reconcile

import (
	"strings"
	"testing"
)

// FuzzParseCSV: the ingester's contract is "any bytes in, never panic;
// either assets or an error out". Asset lists come from arbitrary
// real-world spreadsheet exports — a trust boundary.
func FuzzParseCSV(f *testing.F) {
	f.Add("ip,host\n10.0.0.1,a\n")
	f.Add("\ufeffIP Address,Host Name,Role/Function,VLAN Name\n10.0.1.5,dc01,DC,Srv\n")
	f.Add("a,b\n\"unclosed,10.0.0.1\n")
	f.Add(",,,\n,,,\n")
	f.Add("dc01,10.0.1.5\nws,10.0.2.9\n")
	f.Fuzz(func(t *testing.T, in string) {
		assets, _, err := ParseCSV(strings.NewReader(in))
		if err == nil && len(assets) == 0 {
			t.Fatal("nil error with zero assets")
		}
	})
}
