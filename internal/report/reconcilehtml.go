package report

import (
	"html/template"
	"io"
	"strings"

	"github.com/BushidoCyb3r/salient/internal/graph"
	"github.com/BushidoCyb3r/salient/internal/reconcile"
)

// ReconcileHTML writes the self-contained Phase 3 doc-vs-reality report,
// worded to hand directly to the supported unit's staff.
func ReconcileHTML(w io.Writer, r reconcile.Result) error { return reconcileTmpl.Execute(w, r) }

var reconcileTmpl = template.Must(template.New("reconcile").Funcs(template.FuncMap{
	"roles": func(n graph.Node) string {
		if len(n.Roles) == 0 {
			return string(graph.RoleUnknown)
		}
		var out []string
		for _, r := range n.Roles {
			out = append(out, string(r.Role))
		}
		return strings.Join(out, ", ")
	},
	"hostname": func(n graph.Node) string {
		if len(n.Hostnames) == 0 {
			return ""
		}
		return n.Hostnames[0]
	},
	"joinRoles": func(rs []graph.Role) string {
		var out []string
		for _, r := range rs {
			out = append(out, string(r))
		}
		return strings.Join(out, ", ")
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Salient reconciliation report</title>
<style>body{font:14px/1.45 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 18px;color:#1c2330}h1{margin-bottom:4px}h2{margin-top:28px}table{border-collapse:collapse;width:100%}th,td{padding:6px 8px;border-bottom:1px solid #d7dbe2;text-align:left}.meta{color:#6a7180}.handle{background:#fdf3ef;color:#a04a26;padding:8px 10px;border:1px solid #e8c4b2}.empty{color:#6a7180}.blind{color:#a04a26}.warn{background:#fbf6e9;border:1px solid #e3d3a1;padding:6px 8px;margin:4px 0;font-size:13px}</style></head><body>
<h1>Salient reconciliation report</h1><p class="meta">snapshot {{.Meta.CreatedAt}} · window {{.Meta.Window}}</p>
<p class="handle">Handle at the classification of the network described. This artifact compares documentation against observed terrain — protect it accordingly.</p>
{{if .Warnings}}<h2>Asset-list parsing warnings</h2>{{range .Warnings}}<div class="warn">{{.}}</div>{{end}}{{end}}
<h2>Documented but silent</h2>
<p class="meta">In the asset list, but produced no observed traffic in the window. A silent host may be decommissioned, dormant, or simply outside sensor coverage — entries marked <span class="blind">blind spot?</span> sit in an in-scope CIDR with zero coverage and must be verified before any decommissioning call.</p>
{{if .DocumentedSilent}}<table><tr><th>IP</th><th>Hostname</th><th>Documented role</th><th>Segment</th><th></th></tr>{{range .DocumentedSilent}}<tr><td>{{.IP}}</td><td>{{.Hostname}}</td><td>{{.Role}}</td><td>{{.Segment}}</td><td>{{if .InBlindSpot}}<span class="blind">blind spot?</span>{{end}}</td></tr>{{end}}</table>{{else}}<p class="empty">None — every documented asset was observed.</p>{{end}}
<h2>Observed but undocumented</h2>
<p class="meta">On the wire but not in the asset list. Each is a documentation gap at best and an unauthorized system at worst.</p>
{{if .ObservedUndocumented}}<table><tr><th>IP</th><th>Hostname</th><th>Inferred role</th><th>Terrain rank</th></tr>{{range .ObservedUndocumented}}<tr><td>{{.IP}}</td><td>{{hostname .}}</td><td>{{roles .}}</td><td>{{if .Scores.Rank}}#{{.Scores.Rank}}{{end}}</td></tr>{{end}}</table>{{else}}<p class="empty">None — every observed host is documented.</p>{{end}}
<h2>Role contradicted</h2>
<p class="meta">The documented role maps to a function Salient can observe, and observation disagrees. Hosts whose observed role is Unknown are never listed here.</p>
{{if .RoleContradicted}}<table><tr><th>IP</th><th>Hostname</th><th>Documented</th><th>Expected</th><th>Observed</th></tr>{{range .RoleContradicted}}<tr><td>{{.IP}}</td><td>{{.Hostname}}</td><td>{{.Documented}}</td><td>{{.Expected}}</td><td>{{joinRoles .Observed}}</td></tr>{{end}}</table>{{else}}<p class="empty">None — no observable role disagrees with the documentation.</p>{{end}}
</body></html>`))
