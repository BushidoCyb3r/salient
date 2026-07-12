package report

import (
	"html/template"
	"io"

	"github.com/BushidoCyb3r/salient/internal/snapshot"
)

// DriftHTML writes a self-contained Phase 2 drift report.
func DriftHTML(w io.Writer, d snapshot.Diff) error { return driftTmpl.Execute(w, d) }

var driftTmpl = template.Must(template.New("drift").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Salient drift report</title>
<style>body{font:14px/1.45 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 18px;color:#1c2330}h1{margin-bottom:4px}h2{margin-top:28px}table{border-collapse:collapse;width:100%}th,td{padding:6px 8px;border-bottom:1px solid #d7dbe2;text-align:left}.meta{color:#6a7180}.handle{background:#fdf3ef;color:#a04a26;padding:8px 10px;border:1px solid #e8c4b2}.empty{color:#6a7180}</style></head><body>
<h1>Salient drift report</h1><p class="meta">{{.FromMeta.CreatedAt}} → {{.ToMeta.CreatedAt}}</p>
<p class="handle">Handle at the classification of the network described. This artifact maps terrain changes — protect it accordingly.</p>
{{if .CompatibilityWarnings}}<div class="handle"><strong>Comparison warnings:</strong> {{range .CompatibilityWarnings}}{{.}}; {{end}}</div>{{end}}
<h2>Appeared nodes</h2>{{if .AppearedNodes}}<table><tr><th>IP</th><th>Rank</th></tr>{{range .AppearedNodes}}<tr><td>{{.IP}}</td><td>{{.Scores.Rank}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Disappeared nodes</h2>{{if .DisappearedNodes}}<table><tr><th>IP</th><th>Previous rank</th></tr>{{range .DisappearedNodes}}<tr><td>{{.IP}}</td><td>{{.Scores.Rank}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Rank changes</h2>{{if .RankChanges}}<table><tr><th>IP</th><th>From</th><th>To</th><th>Delta</th></tr>{{range .RankChanges}}<tr><td>{{.IP}}</td><td>{{.FromRank}}</td><td>{{.ToRank}}</td><td>{{.Delta}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>New sensitive-service providers</h2><p class="meta">Hosts that began providing DNS/DHCP/auth/file/database service since the baseline, at any terrain rank. Investigation leads — analyst validation determines intent.</p>{{if .NewProviders}}<table><tr><th>Provider</th><th>Service</th><th>Port</th><th>Clients</th><th>Rank</th><th>New host</th></tr>{{range .NewProviders}}<tr><td>{{.IP}}</td><td>{{.Service}}</td><td>{{.Port}}</td><td>{{.Clients}}</td><td>{{.Rank}}</td><td>{{if .NewHost}}yes{{end}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Provider displacement</h2><p class="meta">Clients that moved to a different provider of the same service since the baseline. Only the gaining provider is listed.</p>{{if .ProviderDisplacements}}<table><tr><th>Provider</th><th>Service</th><th>Port</th><th>New clients (organic)</th><th>Migrated from</th><th>Rank</th></tr>{{range .ProviderDisplacements}}<tr><td>{{.IP}}</td><td>{{.Service}}</td><td>{{.Port}}</td><td>{{.ClientsAdded}}</td><td>{{range .MigratedFrom}}{{.Clients}} from {{.IP}}:{{.Port}}; {{end}}</td><td>{{.Rank}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>New edges to critical nodes</h2>{{if .NewEdgesToTop}}<table><tr><th>Source</th><th>Destination</th><th>Port</th><th>Evidence</th></tr>{{range .NewEdgesToTop}}<tr><td>{{.Src}}</td><td>{{.Dst}}</td><td>{{.Port}}</td><td>{{.Evidence}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Vanished critical edges</h2>{{if .VanishedCriticalEdges}}<table><tr><th>Source</th><th>Destination</th><th>Port</th><th>Evidence</th></tr>{{range .VanishedCriticalEdges}}<tr><td>{{.Src}}</td><td>{{.Dst}}</td><td>{{.Port}}</td><td>{{.Evidence}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Role changes</h2>{{if .RoleChanges}}<table><tr><th>IP</th><th>From</th><th>To</th></tr>{{range .RoleChanges}}<tr><td>{{.IP}}</td><td>{{.From}}</td><td>{{.To}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
<h2>Identity changes</h2>{{if .IdentityChanges}}<table><tr><th>IP</th><th>Protocol</th><th>Added</th><th>Removed</th></tr>{{range .IdentityChanges}}<tr><td>{{.IP}}</td><td>{{.Protocol}}</td><td>{{.Added}}</td><td>{{.Removed}}</td></tr>{{end}}</table>{{else}}<p class="empty">None</p>{{end}}
</body></html>`))
