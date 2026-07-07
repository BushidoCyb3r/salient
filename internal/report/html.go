package report

import (
	"html/template"
	"io"
	"sort"
	"strconv"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// HTML writes a self-contained analyst terrain report: a ranked table with
// per-node expandable evidence, plus a sensor-coverage / blind-spot panel.
// No external assets — everything inlined so it opens offline (§1 constraint).
func HTML(w io.Writer, snap graph.Snapshot) error {
	return htmlTmpl.Execute(w, snap)
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(f float64) string {
		return strconv.Itoa(int(f*100 + 0.5))
	},
	"topRole": graph.Node.TopRole,
	"topTerrain": func(nodes []graph.Node) []graph.Node {
		out := make([]graph.Node, 0, len(nodes))
		for _, n := range nodes {
			if n.Scores.Rank > 0 && graph.TerrainAddr(n.IP) {
				out = append(out, n)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Scores.Rank < out[j].Scores.Rank })
		if len(out) > 10 {
			out = out[:10]
		}
		return out
	},
	"why": func(n graph.Node) string {
		if len(n.TerrainEvidence) > 0 {
			return n.TerrainEvidence[0]
		}
		for _, role := range n.Roles {
			if len(role.Evidence) > 0 {
				return role.Evidence[0]
			}
		}
		return "No score-driver evidence recorded"
	},
}).Parse(reportHTML))

const reportHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Salient Terrain Report — {{.Meta.ClusterName}}</title>
<style>
 :root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8a90a0;--card:#181b22;--acc:#e2734a;--line:#262a33}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
 header{padding:20px 28px;border-bottom:1px solid var(--line)}
 h1{margin:0 0 4px;font-size:20px}
 .meta{color:var(--mut);font-size:12px}
 .handle{background:#3a1d15;color:#f0b8a2;padding:8px 28px;font-size:12px;border-bottom:1px solid var(--line)}
 main{padding:20px 28px;max-width:1100px}
 .panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 18px;margin-bottom:20px}
 .panel h2{margin:0 0 10px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
 table{width:100%;border-collapse:collapse}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-weight:600;font-size:12px}
 tr.node{cursor:pointer}
 tr.node:hover{background:#1e222b}
 .rank{color:var(--acc);font-weight:700}
 .role{display:inline-block;background:#242a36;border-radius:4px;padding:1px 7px;font-size:12px;margin:1px}
 .bar{height:6px;background:#242a36;border-radius:3px;overflow:hidden;min-width:80px}
 .bar>span{display:block;height:100%;background:var(--acc)}
 .ev{display:none;background:#12151b}
 .ev.open{display:table-row}
 .ev td{color:var(--mut);font-size:13px}
 .ev li{margin:2px 0}
 code{color:#a8c7ff}
 .warn{color:#f0b8a2}
 footer{padding:16px 28px;color:var(--mut);font-size:12px;border-top:1px solid var(--line)}
</style></head><body>
<header>
 <h1>Salient — Key Cyber Terrain</h1>
 <div class="meta">Cluster <code>{{.Meta.ClusterName}}</code> · window {{.Meta.Window}} · generated {{.Meta.CreatedAt.Format "2006-01-02 15:04 MST"}} · {{len .Nodes}} hosts, {{len .Edges}} edges</div>
</header>
<div class="handle">⚠ This report describes network topology and dependencies. Handle at the classification of the network it describes. Do not distribute uncontrolled.</div>
<main>

<div class="panel">
 <h2>Sensor coverage</h2>
 {{if .Meta.Sensors}}<div>Observing sensors: {{range .Meta.Sensors}}<span class="role">{{.}}</span>{{end}}</div>{{else}}<div class="warn">No sensor attribution available on this grid.</div>{{end}}
 {{if .Meta.ZeroCovCIDRs}}<div class="warn" style="margin-top:8px">Possible blind spots (in-scope, zero observed traffic): {{range .Meta.ZeroCovCIDRs}}<code>{{.}}</code> {{end}}</div>{{end}}
 {{if .Meta.BetweenSampled}}<div class="warn" style="margin-top:8px">Betweenness was sampled (graph exceeded the exact-computation limit); choke-point scores are approximate.</div>{{end}}
</div>

<div class="panel">
 <h2>Top 10 key terrain</h2>
 <table>
  <thead><tr><th>#</th><th>Host</th><th>Role</th><th>Why</th></tr></thead>
  <tbody>{{range topTerrain .Nodes}}<tr>
   <td class="rank">{{.Scores.Rank}}</td>
   <td><code>{{.IP}}</code>{{range .Hostnames}}<br><span class="meta">{{.}}</span>{{end}}</td>
   <td><span class="role">{{topRole .}}</span></td>
   <td>{{why .}}</td>
  </tr>{{end}}</tbody>
 </table>
</div>

<div class="panel">
 <h2>Ranked terrain</h2>
 <table>
  <thead><tr><th>#</th><th>Host</th><th>Roles</th><th>Clients</th><th>Composite</th></tr></thead>
  <tbody>
  {{range .Nodes}}
   <tr class="node" onclick="this.nextElementSibling.classList.toggle('open')">
    <td class="rank">{{.Scores.Rank}}</td>
    <td><code>{{.IP}}</code>{{range .Hostnames}}<br><span class="meta">{{.}}</span>{{end}}</td>
    <td>{{range .Roles}}<span class="role">{{.Role}}</span>{{end}}</td>
    <td>{{.Scores.DependencyInDegree}}</td>
    <td><div class="bar"><span style="width:{{pct .Scores.Composite}}%"></span></div></td>
   </tr>
   <tr class="ev"><td colspan="5">
     <strong>Subnet:</strong> <code>{{.Subnet}}</code> ·
     <strong>PageRank:</strong> {{printf "%.4f" .Scores.PageRank}} ·
     <strong>Betweenness:</strong> {{printf "%.2f" .Scores.Betweenness}}
     {{if .TerrainEvidence}}<div style="margin-top:6px"><strong>Why this is key terrain</strong>
      <ul>{{range .TerrainEvidence}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
     {{range .Roles}}{{if .Evidence}}
     <div style="margin-top:6px"><strong>{{.Role}}</strong> (confidence {{pct .Confidence}}%)
      <ul>{{range .Evidence}}<li>{{.}}</li>{{end}}</ul></div>
     {{end}}{{end}}
   </td></tr>
  {{end}}
  </tbody>
 </table>
</div>

</main>
<footer>Salient · passive, read-only · L3 logical dependency view, not physical topology. Absence of evidence is not evidence of absence — see LIMITATIONS.</footer>
</body></html>`
