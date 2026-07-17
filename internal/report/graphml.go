package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// GraphML writes a minimal GraphML document: nodes carry ip/role/composite/
// subnet attributes, edges carry service/conn_count. yEd/draw.io group
// geometry extensions come in Phase 1.5; this is the analyst-report baseline.
func GraphML(w io.Writer, snap graph.Snapshot) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	const head = `<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="d_ip" for="node" attr.name="ip" attr.type="string"/>
  <key id="d_role" for="node" attr.name="role" attr.type="string"/>
  <key id="d_subnet" for="node" attr.name="subnet" attr.type="string"/>
  <key id="d_comp" for="node" attr.name="composite" attr.type="double"/>
  <key id="d_rank" for="node" attr.name="rank" attr.type="int"/>
  <key id="e_svc" for="edge" attr.name="service" attr.type="string"/>
  <key id="e_conn" for="edge" attr.name="conn_count" attr.type="long"/>
  <graph edgedefault="directed">
`
	if _, err := io.WriteString(w, head); err != nil {
		return err
	}
	for _, n := range snap.Nodes {
		if _, err := fmt.Fprintf(w, "    <node id=%q>\n", esc(n.IP)); err != nil {
			return err
		}
		for _, data := range [][2]string{
			{"d_ip", n.IP}, {"d_role", string(n.TopRole())}, {"d_subnet", n.Subnet},
			{"d_comp", fmt.Sprintf("%.4f", n.Scores.Composite)}, {"d_rank", fmt.Sprintf("%d", n.Scores.Rank)},
		} {
			if err := writeData(w, data[0], data[1]); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "    </node>\n"); err != nil {
			return err
		}
	}
	for i, e := range snap.Edges {
		if _, err := fmt.Fprintf(w, "    <edge id=\"e%d\" source=%q target=%q>\n", i, esc(e.Src), esc(e.Dst)); err != nil {
			return err
		}
		if err := writeData(w, "e_svc", e.Service); err != nil {
			return err
		}
		if err := writeData(w, "e_conn", fmt.Sprintf("%d", e.ConnCount)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "    </edge>\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "  </graph>\n</graphml>\n")
	return err
}

func writeData(w io.Writer, key, val string) error {
	_, err := fmt.Fprintf(w, "      <data key=%q>%s</data>\n", key, esc(val))
	return err
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
