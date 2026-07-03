import { ListSnapshots, LoadModel, Legend } from '../wailsjs/go/main/App.js';
import { EventsOn } from '../wailsjs/runtime/runtime.js';

const snaplist = document.getElementById('snaplist');
const snaplistEmpty = document.getElementById('snaplist-empty');
const title = document.getElementById('title');
const submeta = document.getElementById('submeta');
const errbanner = document.getElementById('errbanner');
const errtext = document.getElementById('errtext');

function showError(msg) {
  errtext.textContent = msg;
  errbanner.style.display = 'block';
}
document.getElementById('errdismiss').onclick = () => { errbanner.style.display = 'none'; };

async function refreshList() {
  let entries;
  try {
    entries = await ListSnapshots();
  } catch (err) {
    showError('Could not list snapshots: ' + err);
    return;
  }
  entries = entries || [];
  snaplist.innerHTML = '';
  snaplistEmpty.style.display = entries.length === 0 ? 'block' : 'none';
  for (const e of entries) {
    const li = document.createElement('li');
    li.textContent = e.Timestamp;
    if (e.Snapshot) {
      li.onclick = () => {
        openSnapshot(e.Snapshot);
        snaplist.querySelectorAll('li').forEach(x => x.classList.toggle('sel', x === li));
      };
    } else {
      li.style.opacity = '0.4';
      li.style.cursor = 'default';
      li.title = 'snapshot file missing — map cannot be rebuilt';
    }
    snaplist.appendChild(li);
  }
}

async function renderLegend() {
  let items;
  try {
    items = await Legend();
  } catch (err) {
    showError('Could not load legend: ' + err);
    return;
  }
  const legend = document.getElementById('legend');
  legend.innerHTML = '';
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'lg';
    const swatch = document.createElement('i');
    swatch.style.background = item.Color;
    row.appendChild(swatch);
    row.appendChild(document.createTextNode(item.Label));
    legend.appendChild(row);
  }
}

let cy = null;
let curLayout = 'fcose';
const tierColor = { core: '#fdeee6', service: '#eaf1fb', client: '#ffffff' };
const tierBorder = { core: '#d95f30', service: '#3d7edb', client: '#8f97a5' };
const layouts = {
  fcose: { name: 'fcose', animate: false, nodeSeparation: 120, idealEdgeLength: () => 140 },
  dagre: { name: 'dagre', animate: false, rankDir: 'TB', ranker: 'tight-tree', rankSep: 90, nodeSep: 30, transform: (n, p) => p },
};

function runLayout(name) {
  curLayout = name;
  cy.layout(layouts[name]).run();
  document.getElementById('b-fcose').classList.toggle('on', name === 'fcose');
  document.getElementById('b-dagre').classList.toggle('on', name === 'dagre');
}
document.getElementById('b-fcose').onclick = () => { if (cy) runLayout('fcose'); };
document.getElementById('b-dagre').onclick = () => { if (cy) runLayout('dagre'); };

function renderModel(model) {
  title.textContent = 'Defilade briefing map — ' + (model.meta.cluster_name || '');
  submeta.textContent = 'window ' + model.meta.window;

  const els = [];
  for (const g of model.groups || []) {
    els.push({ data: { id: g.id, label: g.label }, classes: 'grp' + (g.blind_spot ? ' blind' : '') });
  }
  for (const n of model.nodes || []) {
    els.push({
      data: {
        id: n.id, parent: n.group || undefined, label: n.label.split('\n')[0], role: n.role, tier: n.tier,
        comp: n.composite || 0, rank: n.rank || 0, gw: n.gateway ? 1 : 0, inf: n.inferred ? 1 : 0,
        agg: n.agg_count || 0, drift: n.drift || '', ev: (n.evidence || []).join('\n'),
      },
      classes: n.drift ? 'drift-' + n.drift : '',
    });
  }
  const edges = model.edges || [];
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    els.push({
      data: { id: 'e' + i, source: e.src, target: e.dst, color: e.color, width: e.width, label: e.label, drift: e.drift || '' },
      classes: e.drift ? 'drift-' + e.drift : '',
    });
  }

  if (cy) cy.destroy();
  cy = cytoscape({
    container: document.getElementById('cy'), elements: els, wheelSensitivity: 0.2,
    style: [
      { selector: 'node.grp', style: { 'background-color': '#f2f4f8', 'background-opacity': 0.55, 'border-color': '#b9c0cc', 'border-width': 1, shape: 'round-rectangle', label: 'data(label)', 'text-valign': 'top', 'font-size': 12, 'font-weight': 600, color: '#39414f', padding: 18 } },
      { selector: 'node.grp.blind', style: { 'border-color': '#c96a6a', 'border-style': 'dashed', 'background-color': '#f6e8e8' } },
      { selector: 'node:childless', style: { shape: 'round-rectangle', width: 120, height: 34, label: 'data(label)', 'text-valign': 'center', 'font-size': 10, 'background-color': ele => tierColor[ele.data('tier')] || '#fff', 'border-width': 1.6, 'border-color': ele => tierBorder[ele.data('tier')] || '#8f97a5' } },
      { selector: 'node[gw=1]', style: { shape: 'diamond', height: 40 } },
      { selector: 'node[inf=1]', style: { 'border-style': 'dashed' } },
      { selector: 'node[agg>0]', style: { shape: 'round-rectangle', 'border-style': 'double', 'border-width': 3 } },
      { selector: 'node.drift-new', style: { 'border-color': '#238b45', 'border-width': 4 } },
      { selector: 'node.drift-vanished', style: { opacity: 0.3, 'border-style': 'dashed', 'border-color': '#737983' } },
      { selector: 'node.drift-rank-up,node.drift-rank-down', style: { 'border-color': '#d8a02e', 'border-width': 4 } },
      { selector: 'node.drift-undocumented', style: { 'border-color': '#c0392b', 'border-width': 4 } },
      { selector: 'node.drift-silent', style: { opacity: 0.35, 'border-style': 'dashed', 'border-color': '#737983' } },
      { selector: 'node.drift-contradicted', style: { 'border-color': '#d8a02e', 'border-width': 4, 'border-style': 'double' } },
      { selector: 'edge', style: { 'curve-style': 'bezier', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle', width: 'data(width)', label: 'data(label)', 'font-size': 9, color: '#555c68', 'text-rotation': 'autorotate', 'text-background-color': '#fcfcfd', 'text-background-opacity': 0.85, opacity: 0.8 } },
      { selector: 'edge.drift-new', style: { 'line-color': '#238b45', 'target-arrow-color': '#238b45', 'line-style': 'solid', opacity: 1 } },
      { selector: 'edge.drift-vanished', style: { 'line-color': '#737983', 'target-arrow-color': '#737983', 'line-style': 'dashed', opacity: 0.3 } },
      { selector: 'node.drift-off', style: { opacity: 1, 'border-width': 1.6, 'border-style': 'solid', 'border-color': ele => tierBorder[ele.data('tier')] || '#8f97a5' } },
      { selector: 'edge.drift-off', style: { opacity: 0.8, 'line-style': 'solid', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)' } },
      { selector: '.dim', style: { opacity: 0.12 } },
    ],
  });
  runLayout(curLayout);
  bindContextMenu();

  document.getElementById('l-heat').onchange = function () {
    if (this.checked) {
      cy.nodes(':childless').forEach(n => {
        const c = n.data('comp');
        n.style('background-color', 'rgb(' + Math.round(255 - 90 * c) + ',' + Math.round(240 - 170 * c) + ',' + Math.round(235 - 180 * c) + ')');
      });
    } else {
      cy.nodes(':childless').forEach(n => n.removeStyle('background-color'));
    }
  };
  document.getElementById('l-lbl').onchange = function () {
    cy.edges().style('text-opacity', this.checked ? 1 : 0);
  };
  document.getElementById('l-drift').onchange = function () {
    cy.elements('.drift-new,.drift-vanished,.drift-rank-up,.drift-rank-down,.drift-changed,.drift-undocumented,.drift-silent,.drift-contradicted')
      .toggleClass('drift-off', !this.checked);
  };

  cy.on('tap', 'node:childless', e => {
    const n = e.target;
    document.getElementById('ev').textContent =
      n.data('label') + '\nrole: ' + n.data('role') + (n.data('rank') ? '\nrank: #' + n.data('rank') : '') +
      '\ncomposite: ' + (n.data('comp') || 0).toFixed(2) + (n.data('drift') ? '\ndrift: ' + n.data('drift') : '') +
      (n.data('ev') ? '\n\n' + n.data('ev') : '\n\n(no role evidence)');
  });
}

function openSnapshot(path) {
  LoadModel(path)
    .then(renderModel)
    .catch(err => showError('Could not load snapshot: ' + err));
}

document.getElementById('search').addEventListener('input', e => {
  if (!cy) return;
  const q = e.target.value.trim().toLowerCase();
  if (!q) { cy.nodes(':childless').removeClass('dim'); return; }
  cy.nodes(':childless').forEach(n => {
    const hay = (n.data('label') + ' ' + n.data('role') + ' ' + n.data('ev')).toLowerCase();
    n.toggleClass('dim', !hay.includes(q));
  });
});

const ctxmenu = document.getElementById('ctxmenu');
document.addEventListener('click', () => { ctxmenu.style.display = 'none'; });

function bindContextMenu() {
  cy.on('cxttap', 'node:childless', e => {
    const n = e.target;
    const pos = e.renderedPosition || e.position;
    ctxmenu.innerHTML = '';
    const addItem = (label, fn) => {
      const d = document.createElement('div');
      d.textContent = label;
      d.onclick = fn;
      ctxmenu.appendChild(d);
    };
    addItem('Copy IP', () => navigator.clipboard.writeText(n.data('id')));
    addItem('Show evidence', () => cy.emit('tap', [n]));
    addItem('Focus this group', () => {
      const group = n.data('parent');
      cy.nodes(':childless').forEach(m => m.toggleClass('dim', m.data('parent') !== group));
    });
    addItem('Clear focus', () => cy.nodes(':childless').removeClass('dim'));
    ctxmenu.style.left = pos.x + 'px';
    ctxmenu.style.top = pos.y + 'px';
    ctxmenu.style.display = 'block';
  });
}

EventsOn('snapshot:open', openSnapshot);
EventsOn('snapshots:refresh', refreshList);

refreshList();
renderLegend();
