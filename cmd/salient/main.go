// Salient — passive terrain-dependency analyzer for Security Onion grids.
//
// Read-only Elasticsearch client; the only writes are to the local
// filesystem. Subcommands: test-connection, discover, scan, report, map,
// diff, reconcile, analyze, list, view (see internal/scan for the shared
// scan pipeline, also driven by the desktop GUI).
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
