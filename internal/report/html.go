package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"

	"github.com/BushidoCyb3r/salient/internal/graph"
)

// HTML writes a self-contained analyst terrain report in the "app shell"
// layout: sticky sidebar (grid stats, top-10 nav, handling warnings), main
// pane with evidence-rich detail sections for the top 10 and a full ranked
// table with per-node expandable evidence. No external assets — everything
// inlined so it opens offline (§1 constraint).
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
	"abbr": func(v float64) string {
		switch {
		case v >= 1e6:
			return fmt.Sprintf("%.1fM", v/1e6)
		case v >= 1e3:
			return fmt.Sprintf("%.0fk", v/1e3)
		default:
			return fmt.Sprintf("%.0f", v)
		}
	},
	"rankedCount": func(nodes []graph.Node) int {
		c := 0
		for _, n := range nodes {
			if n.Scores.Rank > 0 {
				c++
			}
		}
		return c
	},
	"permille": func(f float64) string {
		return fmt.Sprintf("%.2f", f*1000)
	},
}).Parse(reportHTML))

const reportHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Salient Terrain Report — {{.Meta.ClusterName}}</title>
<style>
 :root{color-scheme:dark;--bg:#0e0f12;--panel:#14161a;--fg:#e8e9ec;--mut:#969ba6;--acc:#e05252;--line:#212429}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
 .shell{display:grid;grid-template-columns:290px 1fr;min-height:100vh}
 aside{border-right:1px solid var(--line);padding:26px 20px;position:sticky;top:0;height:100vh;overflow-y:auto;background:#0c0d10}
 .logo{font:800 1rem/1 system-ui,sans-serif;letter-spacing:-0.01em}
 .logo i{color:var(--acc);font-style:normal}
 .cl{color:var(--mut);font:.72rem ui-monospace,monospace;margin-top:4px;overflow-wrap:anywhere}
 .sb{margin:22px 0 0}
 .sb h3{font:600 .68rem/1 ui-monospace,monospace;letter-spacing:.1em;color:var(--mut);text-transform:uppercase;margin:0 0 10px}
 .ks{display:grid;grid-template-columns:1fr 1fr;gap:10px}
 .ks div b{display:block;font-size:1.05rem;font-variant-numeric:tabular-nums}
 .ks div span{color:var(--mut);font-size:.68rem}
 .sens{font:.75rem ui-monospace,monospace;color:#c9cdd4;overflow-wrap:anywhere}
 nav{margin-top:6px;display:flex;flex-direction:column}
 nav a{display:flex;gap:8px;align-items:baseline;color:inherit;text-decoration:none;padding:7px 8px;border-radius:5px;font-size:.8rem}
 nav a:hover{background:var(--panel)}
 nav b{color:var(--acc);font:650 .8rem ui-monospace,monospace;width:2ch;text-align:right;flex:none}
 nav .nip{font-family:ui-monospace,monospace}
 nav em{color:var(--mut);font-style:normal;font-size:.7rem;margin-left:auto;padding-left:8px}
 .warnbox{margin-top:18px;font-size:.72rem;color:#d9a54a;border-top:1px solid var(--line);padding-top:12px}
 .warnbox code{color:#d9a54a}
 main{padding:30px 36px;max-width:900px;min-width:0}
 h1{margin:0 0 2px;font-size:1.3rem;font-weight:750;letter-spacing:-0.015em}
 .gen{color:var(--mut);font-size:.78rem;margin-bottom:26px}
 h2{font-size:.95rem;font-weight:700;margin:34px 0 12px}
 .det{border:1px solid var(--line);border-radius:8px;background:var(--panel);padding:18px 22px;margin-bottom:16px}
 .det header{display:flex;gap:12px;align-items:baseline;margin-bottom:10px;flex-wrap:wrap}
 .dr{font:750 1.1rem ui-monospace,monospace;color:var(--acc)}
 .dip{font:650 1.1rem ui-monospace,monospace;overflow-wrap:anywhere}
 .dhost{color:var(--mut);font-size:.8rem}
 .dsub{color:var(--mut);font:.75rem ui-monospace,monospace;margin-left:auto}
 .dnums{display:flex;gap:28px;margin:4px 0 10px;font-variant-numeric:tabular-nums;flex-wrap:wrap}
 .dnums b{display:block;font-size:1rem}
 .dnums span{color:var(--mut);font-size:.68rem}
 .evl{color:#c9cdd4;font-size:.85rem;margin:4px 0}
 .rl{border-top:1px solid var(--line);margin-top:10px;padding-top:8px;font-size:.85rem}
 .rl b{font-weight:650}
 .rl span{color:var(--mut);font-size:.75rem;margin-left:6px}
 .rl p{margin:3px 0;color:var(--mut)}
 table{width:100%;border-collapse:collapse;font-size:.85rem}
 th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-weight:600;font-size:.7rem}
 tr.node{cursor:pointer}
 tr.node:hover{background:var(--panel)}
 td.r{color:var(--acc);font:650 .8rem ui-monospace,monospace}
 td.ipc{font-family:ui-monospace,monospace}
 td.num{font-variant-numeric:tabular-nums;font-family:ui-monospace,monospace}
 .hostn{color:var(--mut);font-size:.75rem}
 .rolet{color:#c9cdd4;font-size:.8rem;margin-right:8px}
 .meter{height:3px;background:#22252b;min-width:70px;margin-top:6px}
 .meter i{display:block;height:100%;background:var(--acc)}
 .ev{display:none;background:#101216}
 .ev.open{display:table-row}
 .ev td{color:var(--mut);font-size:.82rem}
 .ev li{margin:2px 0}
 code{font-family:ui-monospace,monospace;color:#c9cdd4}
 .foot{margin:30px 0 10px;color:#6d727c;font-size:.75rem}
 @media(max-width:900px){.shell{grid-template-columns:1fr}aside{position:static;height:auto}}
</style></head><body><div class="shell">
<aside>
 <div class="logo">▲ SALIENT<i>.</i></div>
 <div class="cl">{{.Meta.ClusterName}} · {{.Meta.Window}}</div>
 <div class="sb"><h3>Grid</h3><div class="ks">
  <div><b>{{len .Nodes}}</b><span>hosts</span></div>
  <div><b>{{len .Edges}}</b><span>edges</span></div>
  <div><b>{{rankedCount .Nodes}}</b><span>ranked</span></div>
  <div><b>{{len .Meta.Sensors}}</b><span>sensors</span></div>
 </div></div>
 <div class="sb"><h3>Sensor coverage</h3>
  {{if .Meta.Sensors}}<div class="sens">{{range $i, $s := .Meta.Sensors}}{{if $i}} · {{end}}{{$s}}{{end}}</div>
  {{else}}<div class="sens">No sensor attribution available on this grid.</div>{{end}}
 </div>
 <div class="sb"><h3>Key terrain</h3><nav>
  {{range topTerrain .Nodes}}<a href="#r{{.Scores.Rank}}"><b>{{.Scores.Rank}}</b> <span class="nip">{{.IP}}</span><em>{{topRole .}}</em></a>{{end}}
 </nav></div>
 <div class="warnbox">⚠ This report describes network topology and dependencies. Handle at the classification of the network it describes. Do not distribute uncontrolled.
  {{if .Meta.ZeroCovCIDRs}}<div style="margin-top:8px">Possible blind spots (in-scope, zero observed traffic): {{range .Meta.ZeroCovCIDRs}}<code>{{.}}</code> {{end}}</div>{{end}}
  {{if .Meta.BetweenSampled}}<div style="margin-top:8px">Betweenness was sampled (graph exceeded the exact-computation limit); choke-point scores are approximate.</div>{{end}}
 </div>
</aside>
<main>
 <h1>Key cyber terrain — {{.Meta.ClusterName}}</h1>
 <div class="gen">generated {{.Meta.CreatedAt.Format "2006-01-02 15:04 MST"}} · window {{.Meta.Window}}{{if .Meta.Scope}} · scope {{range $i, $s := .Meta.Scope}}{{if $i}}, {{end}}<code>{{$s}}</code>{{end}}{{end}}</div>

 <h2>Top 10 key terrain</h2>
 {{range topTerrain .Nodes}}<section id="r{{.Scores.Rank}}" class="det">
  <header><span class="dr">{{.Scores.Rank}}</span><span class="dip">{{.IP}}</span>{{range .Hostnames}}<span class="dhost">{{.}}</span>{{end}}<span class="dsub">{{.Subnet}}</span></header>
  <div class="dnums">
   <div><b>{{pct .Scores.Composite}}</b><span>composite</span></div>
   <div><b>{{.Scores.DependencyInDegree}}</b><span>clients</span></div>
   <div><b>{{abbr .Scores.Betweenness}}</b><span>betweenness</span></div>
   <div><b>{{permille .Scores.PageRank}}‰</b><span>pagerank</span></div>
  </div>
  {{range .TerrainEvidence}}<p class="evl">▸ {{.}}</p>{{end}}
  {{range .Roles}}<div class="rl"><b>{{.Role}}</b><span>{{pct .Confidence}}%</span>{{range .Evidence}}<p>{{.}}</p>{{end}}</div>{{end}}
 </section>{{end}}

 <h2>Ranked terrain</h2>
 <table>
  <thead><tr><th>#</th><th>Host</th><th>Roles</th><th>Clients</th><th>Composite</th></tr></thead>
  <tbody>
  {{range .Nodes}}
   <tr class="node" onclick="this.nextElementSibling.classList.toggle('open')">
    <td class="r">{{.Scores.Rank}}</td>
    <td class="ipc">{{.IP}}{{range .Hostnames}}<br><span class="hostn">{{.}}</span>{{end}}</td>
    <td>{{range .Roles}}<span class="rolet">{{.Role}}</span>{{end}}</td>
    <td class="num">{{.Scores.DependencyInDegree}}</td>
    <td><div class="meter"><i style="width:{{pct .Scores.Composite}}%"></i></div></td>
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

 <div class="foot">Salient · passive, read-only · L3 logical dependency view, not physical topology. Absence of evidence is not evidence of absence — see LIMITATIONS.</div>
</main>
</div></body></html>`
