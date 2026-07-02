package report

import (
	"encoding/json"
	"html/template"
	"io"

	"github.com/BushidoCyb3r/defilade/internal/config"
	"github.com/BushidoCyb3r/defilade/internal/mapview"
	"github.com/BushidoCyb3r/defilade/web"
)

// HTMLMap writes the self-contained interactive briefing map (§8.1):
// Cytoscape compound nodes (subnet boxes), fcose/dagre layout toggle, layer
// toggles, click-for-evidence panel, embedded legend. All JS embedded.
func HTMLMap(w io.Writer, m *mapview.Model) error {
	model, err := json.Marshal(m)
	if err != nil {
		return err
	}
	palette, _ := json.Marshal(paletteJSON())
	return mapTmpl.Execute(w, map[string]any{
		"Meta":     m.Meta,
		"Findings": m.Findings,
		"Model":    template.JS(model),
		"Palette":  template.JS(palette),
		"JS": []template.JS{
			template.JS(web.Cytoscape), template.JS(web.LayoutBase), template.JS(web.CoseBase),
			template.JS(web.Fcose), template.JS(web.Dagre), template.JS(web.CytoscapeDagre),
		},
		"Legend": legendItems(),
	})
}

func paletteJSON() map[string]string {
	out := map[string]string{}
	for c, color := range config.MapPalette {
		out[config.ClassLabel(c)] = color
	}
	return out
}

var mapTmpl = template.Must(template.New("map").Parse(mapHTML))

const mapHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Defilade Briefing Map — {{.Meta.ClusterName}}</title>
<style>
 :root{--bg:#fcfcfd;--fg:#1c2330;--mut:#6a7180;--line:#d7dbe2}
 *{box-sizing:border-box} body{margin:0;font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg);display:flex;flex-direction:column;height:100vh}
 header{padding:10px 18px;border-bottom:1px solid var(--line);display:flex;gap:18px;align-items:baseline;flex-wrap:wrap}
 h1{margin:0;font-size:16px} .meta{color:var(--mut);font-size:12px}
 .handle{background:#fdf3ef;color:#a04a26;padding:4px 18px;font-size:11px;border-bottom:1px solid var(--line)}
 #wrap{flex:1;display:flex;min-height:0}
 #cy{flex:1;min-width:0}
 aside{width:300px;border-left:1px solid var(--line);padding:12px;overflow:auto;font-size:13px}
 aside h2{font-size:12px;text-transform:uppercase;color:var(--mut);margin:12px 0 6px}
 .ctl label{display:block;margin:2px 0;cursor:pointer}
 button{margin:2px 4px 2px 0;padding:4px 10px;border:1px solid var(--line);background:#fff;border-radius:5px;cursor:pointer}
 button.on{background:#e8eefb;border-color:#3d7edb}
 .lg{display:flex;align-items:center;gap:6px;margin:2px 0}
 .lg i{width:22px;height:4px;display:inline-block}
 #ev{white-space:pre-wrap;color:var(--mut)}
 .finding{background:#fdf3ef;border:1px solid #e8c4b2;border-radius:5px;padding:6px;margin:4px 0;font-size:12px}
</style></head><body>
<header><h1>Defilade briefing map — {{.Meta.ClusterName}}</h1>
<span class="meta">window {{.Meta.Window}} · {{.Meta.CreatedAt.Format "2006-01-02 15:04Z"}} · L3 logical dependency map — not physical topology</span></header>
<div class="handle">Handle at the classification of the network described. This artifact maps key terrain — protect it accordingly.</div>
<div id="wrap"><div id="cy"></div>
<aside>
 <h2>Layout</h2>
 <button id="b-fcose" class="on">organic (fcose)</button><button id="b-dagre">tiered (dagre)</button>
 <h2>Layers</h2>
 <div class="ctl">
  <label><input type="checkbox" id="l-heat"> criticality heat</label>
  <label><input type="checkbox" id="l-cov"> sensor coverage</label>
  <label><input type="checkbox" id="l-lbl" checked> edge labels</label>
  <label><input type="checkbox" id="l-drift" checked> drift highlights</label>
 </div>
 <h2>Legend</h2>
 {{range .Legend}}<div class="lg"><i style="background:{{.Color}}"></i>{{.Label}}</div>{{end}}
 <div class="lg" style="margin-top:6px"><i style="background:none;border-top:2px dashed #888"></i>inferred gateway</div>
 <div class="lg"><i style="background:repeating-linear-gradient(45deg,#f6e8e8,#f6e8e8 3px,#c96a6a 3px,#c96a6a 5px)"></i>blind spot (no coverage)</div>
 <div class="lg"><i style="background:#39a85b"></i>new</div>
 <div class="lg"><i style="background:#a8adb5"></i>vanished (ghosted)</div>
 <div class="lg"><i style="background:#d8a02e"></i>rank jump</div>
 {{if .Findings}}<h2>Findings</h2>{{range .Findings}}<div class="finding">{{.}}</div>{{end}}{{end}}
 <h2>Evidence</h2><div id="ev">click a node</div>
</aside></div>
{{range .JS}}<script>{{.}}</script>
{{end}}
<script>
const model = {{.Model}};
const els = [];
for (const g of model.groups) els.push({data:{id:g.id, label:g.label, blind:g.blind_spot?1:0, covered:(g.sensors&&g.sensors.length)?1:0}, classes:'grp'+(g.blind_spot?' blind':'')});
for (const n of model.nodes) els.push({data:{id:n.id, parent:n.group||undefined, label:n.label.split('\n')[0], role:n.role, tier:n.tier,
  comp:n.composite||0, rank:n.rank||0, gw:n.gateway?1:0, inf:n.inferred?1:0, agg:n.agg_count||0, drift:n.drift||'', ev:(n.evidence||[]).join('\n')},
  classes:n.drift?'drift-'+n.drift:''});
for (let i=0;i<model.edges.length;i++){const e=model.edges[i];
  els.push({data:{id:'e'+i, source:e.src, target:e.dst, color:e.color, width:e.width, label:e.label, drift:e.drift||''},
    classes:e.drift?'drift-'+e.drift:''});}

const tierColor = {core:'#fdeee6', service:'#eaf1fb', client:'#ffffff'};
const tierBorder = {core:'#d95f30', service:'#3d7edb', client:'#8f97a5'};
const cy = cytoscape({container: document.getElementById('cy'), elements: els, wheelSensitivity:0.2,
 style: [
  {selector:'node.grp', style:{'background-color':'#f2f4f8','background-opacity':0.55,'border-color':'#b9c0cc','border-width':1,
    shape:'round-rectangle',label:'data(label)','text-valign':'top','font-size':12,'font-weight':600,color:'#39414f',padding:18}},
  {selector:'node.grp.blind', style:{'border-color':'#c96a6a','border-style':'dashed','background-color':'#f6e8e8'}},
  {selector:'node:childless', style:{shape:'round-rectangle',width:120,height:34,label:'data(label)','text-valign':'center',
    'font-size':10,'background-color':ele=>tierColor[ele.data('tier')]||'#fff','border-width':1.6,
    'border-color':ele=>tierBorder[ele.data('tier')]||'#8f97a5'}},
  {selector:'node[gw=1]', style:{shape:'diamond',height:40}},
  {selector:'node[inf=1]', style:{'border-style':'dashed'}},
  {selector:'node[agg>0]', style:{shape:'round-rectangle','border-style':'double','border-width':3}},
  {selector:'node.drift-new', style:{'border-color':'#238b45','border-width':4}},
  {selector:'node.drift-vanished', style:{opacity:0.3,'border-style':'dashed','border-color':'#737983'}},
  {selector:'node.drift-rank-up,node.drift-rank-down', style:{'border-color':'#d8a02e','border-width':4}},
  {selector:'edge', style:{'curve-style':'bezier','line-color':'data(color)','target-arrow-color':'data(color)',
    'target-arrow-shape':'triangle',width:'data(width)',label:'data(label)','font-size':9,color:'#555c68',
    'text-rotation':'autorotate','text-background-color':'#fcfcfd','text-background-opacity':0.85,opacity:0.8}},
  {selector:'edge.drift-new', style:{'line-color':'#238b45','target-arrow-color':'#238b45','line-style':'solid',opacity:1}},
  {selector:'edge.drift-vanished', style:{'line-color':'#737983','target-arrow-color':'#737983','line-style':'dashed',opacity:0.3}},
  {selector:'node.drift-off', style:{opacity:1,'border-width':1.6,'border-style':'solid','border-color':ele=>tierBorder[ele.data('tier')]||'#8f97a5'}},
  {selector:'edge.drift-off', style:{opacity:0.8,'line-style':'solid','line-color':'data(color)','target-arrow-color':'data(color)'}},
 ]});

const layouts = {
 fcose: {name:'fcose', animate:false, nodeSeparation:120, idealEdgeLength:()=>140},
 dagre: {name:'dagre', animate:false, rankDir:'TB', ranker:'tight-tree',
         rankSep:90, nodeSep:30, transform:(n,p)=>p}
};
let cur='fcose';
function run(name){cur=name; cy.layout(layouts[name]).run();
 document.getElementById('b-fcose').classList.toggle('on',name==='fcose');
 document.getElementById('b-dagre').classList.toggle('on',name==='dagre');}
document.getElementById('b-fcose').onclick=()=>run('fcose');
document.getElementById('b-dagre').onclick=()=>run('dagre');
run('fcose');

document.getElementById('l-heat').onchange=function(){
 if(this.checked) cy.nodes(':childless').forEach(n=>{const c=n.data('comp');
   n.style('background-color','rgb('+Math.round(255-90*c)+','+Math.round(240-170*c)+','+Math.round(235-180*c)+')');});
 else cy.nodes(':childless').forEach(n=>n.removeStyle('background-color'));};
document.getElementById('l-cov').onchange=function(){
 cy.nodes('.grp').forEach(g=>g.style('border-width', this.checked && !g.data('covered') ? 3 : 1));
 cy.nodes('.grp').forEach(g=>g.style('border-color', this.checked && !g.data('covered') ? '#c96a6a' : (g.hasClass('blind')?'#c96a6a':'#b9c0cc')));};
document.getElementById('l-lbl').onchange=function(){
 cy.edges().style('text-opacity', this.checked?1:0);};
document.getElementById('l-drift').onchange=function(){
 cy.elements('.drift-new,.drift-vanished,.drift-rank-up,.drift-rank-down,.drift-changed').toggleClass('drift-off',!this.checked);};

cy.on('tap','node:childless',e=>{const n=e.target;
 document.getElementById('ev').textContent =
  n.data('label')+'\nrole: '+n.data('role')+(n.data('rank')?'\nrank: #'+n.data('rank'):'')+
  '\ncomposite: '+(n.data('comp')||0).toFixed(2)+(n.data('drift')?'\ndrift: '+n.data('drift'):'')+
  (n.data('ev')?'\n\n'+n.data('ev'):'\n\n(no role evidence)');});
</script>
</body></html>`
