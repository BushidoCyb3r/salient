// Defilade — passive terrain-dependency analyzer for Security Onion grids.
//
// Read-only Elasticsearch client; the only writes are to the local
// filesystem. Phase 0 ships `test-connection` and `discover` only: no graph
// code is built until the field map is verified against a real grid.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
