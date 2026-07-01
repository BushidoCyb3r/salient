package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/BushidoCyb3r/defilade/internal/graph"
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
		fmt.Fprintf(w, "    <node id=%q>\n", esc(n.IP))
		writeData(w, "d_ip", n.IP)
		writeData(w, "d_role", string(topRole(n)))
		writeData(w, "d_subnet", n.Subnet)
		writeData(w, "d_comp", fmt.Sprintf("%.4f", n.Scores.Composite))
		writeData(w, "d_rank", fmt.Sprintf("%d", n.Scores.Rank))
		io.WriteString(w, "    </node>\n")
	}
	for i, e := range snap.Edges {
		fmt.Fprintf(w, "    <edge id=\"e%d\" source=%q target=%q>\n", i, esc(e.Src), esc(e.Dst))
		writeData(w, "e_svc", e.Service)
		writeData(w, "e_conn", fmt.Sprintf("%d", e.ConnCount))
		io.WriteString(w, "    </edge>\n")
	}
	_, err := io.WriteString(w, "  </graph>\n</graphml>\n")
	return err
}

func writeData(w io.Writer, key, val string) {
	fmt.Fprintf(w, "      <data key=%q>%s</data>\n", key, esc(val))
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
