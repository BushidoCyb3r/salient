package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/BushidoCyb3r/salient/internal/mapview"
)

// GraphMLMap writes the briefing map as GraphML with subnet groups as nested
// subgraphs — the structure yEd and draw.io import as group nodes. Node data
// carries role/tier/criticality so imported diagrams can be styled there.
//
// ponytail: no yFiles geometry extensions — importers re-layout anyway
// (that's the point of the draw.io/yEd path: orthogonal "Visio-style"
// routing). Add <y:...> geometry only if a real yEd round-trip demands it.
func GraphMLMap(w io.Writer, m *mapview.Model) error {
	var writeErr error
	write := func(s string) {
		if writeErr == nil {
			_, writeErr = io.WriteString(w, s)
		}
	}
	writef := func(format string, args ...any) {
		if writeErr == nil {
			_, writeErr = fmt.Fprintf(w, format, args...)
		}
	}
	write(xml.Header)
	const head = `<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="d_label" for="node" attr.name="label" attr.type="string"/>
  <key id="d_role" for="node" attr.name="role" attr.type="string"/>
  <key id="d_tier" for="node" attr.name="tier" attr.type="string"/>
  <key id="d_comp" for="node" attr.name="composite" attr.type="double"/>
  <key id="d_gw" for="node" attr.name="gateway" attr.type="string"/>
  <key id="d_blind" for="node" attr.name="blind_spot" attr.type="string"/>
  <key id="e_class" for="edge" attr.name="service_class" attr.type="string"/>
  <key id="e_label" for="edge" attr.name="label" attr.type="string"/>
  <key id="e_conns" for="edge" attr.name="conn_count" attr.type="long"/>
  <graph id="map" edgedefault="directed">
`
	write(head)
	byGroup := map[string][]mapview.MapNode{}
	var floating []mapview.MapNode
	for _, n := range m.Nodes {
		if n.Group == "" {
			floating = append(floating, n)
			continue
		}
		byGroup[n.Group] = append(byGroup[n.Group], n)
	}
	writeNode := func(indent string, n mapview.MapNode) {
		writef("%s<node id=%q>\n", indent, esc(n.ID))
		gw := ""
		if n.Gateway {
			gw = "observed"
			if n.Inferred {
				gw = "inferred"
			}
		}
		writef("%s  <data key=\"d_label\">%s</data>\n", indent, esc(n.Label))
		writef("%s  <data key=\"d_role\">%s</data>\n", indent, esc(n.Role))
		writef("%s  <data key=\"d_tier\">%s</data>\n", indent, esc(string(n.Tier)))
		writef("%s  <data key=\"d_comp\">%.4f</data>\n", indent, n.Composite)
		if gw != "" {
			writef("%s  <data key=\"d_gw\">%s</data>\n", indent, gw)
		}
		writef("%s</node>\n", indent)
	}
	for _, g := range m.Groups {
		writef("    <node id=%q>\n      <data key=\"d_label\">%s</data>\n", esc(g.ID), esc(g.Label))
		if g.BlindSpot {
			write("      <data key=\"d_blind\">true</data>\n")
		}
		writef("      <graph id=\"%s:\" edgedefault=\"directed\">\n", esc(g.ID))
		for _, n := range byGroup[g.ID] {
			writeNode("        ", n)
		}
		write("      </graph>\n    </node>\n")
	}
	for _, n := range floating {
		writeNode("    ", n)
	}
	for i, e := range m.Edges {
		writef("    <edge id=\"e%d\" source=%q target=%q>\n", i, esc(e.Src), esc(e.Dst))
		writef("      <data key=\"e_class\">%s</data>\n", esc(e.Class))
		writef("      <data key=\"e_label\">%s</data>\n", esc(e.Label))
		writef("      <data key=\"e_conns\">%d</data>\n", e.Conns)
		write("    </edge>\n")
	}
	write("  </graph>\n</graphml>\n")
	return writeErr
}
