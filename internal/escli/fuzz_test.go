package escli

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadFieldMap: operator-supplied YAML must never panic the loader, and
// every returned map must keep non-empty defaults for unset fields.
func FuzzLoadFieldMap(f *testing.F) {
	f.Add("source_ip: my.src\n")
	f.Add("index_pattern: \"zeek-*\"\ntimestamp: ts\n")
	f.Add(":\n:\n")
	f.Add("source_ip: [not, a, string]\n")
	f.Fuzz(func(t *testing.T, in string) {
		p := filepath.Join(t.TempDir(), "fm.yaml")
		if err := os.WriteFile(p, []byte(in), 0o600); err != nil {
			t.Fatal(err)
		}
		fm, err := LoadFieldMap(p)
		if err != nil {
			return
		}
		if fm.SourceIP == "" || fm.IndexPattern == "" || fm.Timestamp == "" {
			t.Fatalf("merged fieldmap lost a default: %+v", fm)
		}
	})
}
