// Package report renders a Snapshot to analyst-facing formats: JSON,
// GraphML, and a self-contained HTML terrain report. Every format is a pure
// function of the Snapshot.
package report

import (
	"encoding/json"
	"io"

	"github.com/BushidoCyb3r/defilade/internal/graph"
)

// JSON writes the snapshot as indented JSON.
func JSON(w io.Writer, snap graph.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}
