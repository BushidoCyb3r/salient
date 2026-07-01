package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/BushidoCyb3r/defilade/internal/mapview"
)

// GraphMLMap writes the briefing map as GraphML with subnet groups as nested
// subgraphs — the structure yEd and draw.io import as group nodes. Node data
// carries role/tier/criticality so imported diagrams can be styled there.
//
// ponytail: no yFiles geometry extensions — importers re-layout anyway
// (that's the point of the draw.io/yEd path: orthogonal "Visio-style"
// routing). Add <y:...> geometry only if a real yEd round-trip demands it.
func GraphMLMap(w io.Writer, m *mapview.Model) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
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
	if _, err := io.WriteString(w, head); err != nil {
		return err
	}
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
		fmt.Fprintf(w, "%s<node id=%q>\n", indent, esc(n.ID))
		gw := ""
		if n.Gateway {
			gw = "observed"
			if n.Inferred {
				gw = "inferred"
			}
		}
		fmt.Fprintf(w, "%s  <data key=\"d_label\">%s</data>\n", indent, esc(n.Label))
		fmt.Fprintf(w, "%s  <data key=\"d_role\">%s</data>\n", indent, esc(n.Role))
		fmt.Fprintf(w, "%s  <data key=\"d_tier\">%s</data>\n", indent, esc(string(n.Tier)))
		fmt.Fprintf(w, "%s  <data key=\"d_comp\">%.4f</data>\n", indent, n.Composite)
		if gw != "" {
			fmt.Fprintf(w, "%s  <data key=\"d_gw\">%s</data>\n", indent, gw)
		}
		fmt.Fprintf(w, "%s</node>\n", indent)
	}
	for _, g := range m.Groups {
		fmt.Fprintf(w, "    <node id=%q>\n      <data key=\"d_label\">%s</data>\n", esc(g.ID), esc(g.Label))
		if g.BlindSpot {
			io.WriteString(w, "      <data key=\"d_blind\">true</data>\n")
		}
		fmt.Fprintf(w, "      <graph id=\"%s:\" edgedefault=\"directed\">\n", esc(g.ID))
		for _, n := range byGroup[g.ID] {
			writeNode("        ", n)
		}
		io.WriteString(w, "      </graph>\n    </node>\n")
	}
	for _, n := range floating {
		writeNode("    ", n)
	}
	for i, e := range m.Edges {
		fmt.Fprintf(w, "    <edge id=\"e%d\" source=%q target=%q>\n", i, esc(e.Src), esc(e.Dst))
		fmt.Fprintf(w, "      <data key=\"e_class\">%s</data>\n", esc(e.Class))
		fmt.Fprintf(w, "      <data key=\"e_label\">%s</data>\n", esc(e.Label))
		fmt.Fprintf(w, "      <data key=\"e_conns\">%d</data>\n", e.Conns)
		io.WriteString(w, "    </edge>\n")
	}
	_, err := io.WriteString(w, "  </graph>\n</graphml>\n")
	return err
}
