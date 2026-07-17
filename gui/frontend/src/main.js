import { Connect, RunScan, CancelScan, ListSnapshots, LoadModel, LoadFocusedModel, LoadDriftModel, LoadReconcileModel, LoadReconcileModelCSV, PickAssetCSV, PickDeviceConfigs, LoadDeclared, ClearDeclared, ExportMap, ExportImage, Legend, SuggestTags, SuggestTagsForHosts, AggregateHosts, FlowEndpointIPs, ListDevices, SaveDevice, DeleteDevice, AssignIP, UnassignIP, SetLabels, SetRole, PinToMap, UnpinFromMap, SetShowAllPrivate, SetSegment, RemoveSegment, DismissHint, DeviceHints, DiscoverGrid, LoadServiceAuthority, LoadHuntLeads, ApproveProvider, UnapproveProvider } from '../wailsjs/go/main/App.js';
import { EventsOn } from '../wailsjs/runtime/runtime.js';

const $ = (id) => document.getElementById(id);

/* ---------------- connect ---------------- */

$('connform').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('connbtn');
  $('connerr').textContent = '';
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  try {
    const info = await Connect({
      ESURL: $('c-url').value.trim(),
      APIKey: $('c-key').value,
      CACertPath: $('c-ca').value.trim(),
      FieldmapPath: $('c-fm').value.trim(),
      InsecureSkipVerify: $('c-insecure').checked,
    });
    // carry the launch-screen scan defaults into the console popover
    $('s-window').value = $('c-window').value.trim() || '336h';
    $('s-scope').value = $('c-scope').value.trim();
    $('s-tz').value = $('c-tz').value.trim() || 'Local';
    // ClusterName comes from the grid's own response — textContent, never
    // innerHTML: a hostile ES endpoint must not inject markup into a webview
    // that has bound Go methods.
    const cn = $('clustername');
    cn.textContent = '';
    const dot = document.createElement('span');
    dot.className = 'dot';
    cn.appendChild(dot);
    cn.appendChild(document.createTextNode(info.ClusterName || 'connected'));
    document.body.classList.add('connected');
    await renderLegend();
    await refreshDevices();
    await refreshList(true);
    logLine('connected to ' + (info.ClusterName || 'grid'), 'ok');
    DiscoverGrid($('c-window').value.trim() || '336h').then((lines) => {
      for (const ln of lines || []) logLine(ln, ln.startsWith('WARNING') ? 'warn' : '');
    }).catch((err) => logLine('grid discovery failed: ' + err, 'warn'));
  } catch (err) {
    $('connerr').textContent = 'Connect failed: ' + err;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Connect';
  }
});

/* ---------------- snapshot list ---------------- */

let snapshotEntries = [];

async function refreshList(loadNewest) {
  let entries;
  try {
    entries = await ListSnapshots();
  } catch (err) {
    logLine('could not list snapshots: ' + err, 'err');
    return;
  }
  entries = entries || [];
  snapshotEntries = entries;
  renderSnapshotButton();
  if (loadNewest && entries.length && entries[0].Snapshot) {
    openSnapshot(entries[0].Snapshot);
  }
  refreshDriftBaseline();
}

function renderSnapshotButton() {
  const btn = $('snapshotbtn');
  btn.disabled = snapshotEntries.length === 0;
  const active = snapshotEntries.find((en) => en.Snapshot === currentSnapshotPath);
  btn.textContent = active ? 'Snapshot: ' + active.Timestamp : (snapshotEntries.length ? 'Open snapshots (' + snapshotEntries.length + ')' : 'No snapshots');
}

function openSnapshotList() {
  hlMode = 'snapshots';
  aggListNode = '';
  $('hl-title').textContent = 'Snapshots';
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'none';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

$('snapshotbtn').onclick = openSnapshotList;

/* ---------------- drift ---------------- */

/* ---------------- reconcile ---------------- */

let sessionAssetPath = '';

function clearReconcile(reload) {
  sessionAssetPath = '';
  $('rec-chip').style.display = 'none';
  if (reload && currentSnapshotPath) openSnapshot(currentSnapshotPath);
}

// showReconcile renders a reconciled model and updates the chip. Shared by the
// CSV-file and manual-grid paths — only the source of the asset rows differs.
function showReconcile(model, label) {
  renderModel(model);
  refreshDevices();
  logFindings(model);
  const findings = (model.findings || []).filter((f) => /silent|asset list|contradict/.test(f));
  $('rec-label').textContent = label + ' — ' +
    (findings.length ? findings.length + ' finding group' + (findings.length === 1 ? '' : 's') : 'no findings');
  $('rec-chip').style.display = 'flex';
}

async function applyReconcile() {
  if (!sessionAssetPath || !currentSnapshotPath) return;
  try {
    const model = await LoadReconcileModel(currentSnapshotPath, sessionAssetPath);
    showReconcile(model, sessionAssetPath.split(/[\\/]/).pop());
  } catch (err) {
    logLine('reconcile failed: ' + err, 'err');
    clearReconcile(true);
  }
}

$('rec-load').onclick = async () => {
  try {
    const path = await PickAssetCSV();
    if (!path) return;
    sessionAssetPath = path;
    await applyReconcile();
  } catch (err) { logLine('asset CSV pick failed: ' + err, 'err'); }
};
$('rec-clear').onclick = () => clearReconcile(true);

/* ---- device configs (Cisco IOS / UniFi JSON) ---- */

function clearDeviceConfigs(reload) {
  $('cfg-chip').style.display = 'none';
  ClearDeclared().catch((err) => logLine('clear device configs failed: ' + err, 'err'));
  if (reload && currentSnapshotPath) openSnapshot(currentSnapshotPath);
}

$('cfg-load').onclick = async () => {
  if (!currentSnapshotPath) { logLine('open a snapshot before loading device configs', 'warn'); return; }
  try {
    const paths = await PickDeviceConfigs();
    if (!paths || !paths.length) return;
    const model = await LoadDeclared(currentSnapshotPath, paths);
    renderModel(model);
    refreshDevices();
    logFindings(model);
    const findings = (model.findings || []).filter((f) => /device configs|declared policy/.test(f));
    $('cfg-label').textContent = paths.length + ' file' + (paths.length === 1 ? '' : 's') + ' — ' +
      (findings.length ? findings.length + ' finding' + (findings.length === 1 ? '' : 's') : 'no findings');
    $('cfg-chip').style.display = 'flex';
  } catch (err) { logLine('device configs failed: ' + err, 'err'); }
};
$('cfg-clear').onclick = () => clearDeviceConfigs(true);

/* ---- manual asset entry grid (native CSV columns, no file needed) ---- */

function rgAddRow(vals) {
  const tr = document.createElement('tr');
  for (let c = 0; c < 4; c++) { // ip, hostname, role, segment
    const td = document.createElement('td');
    const inp = document.createElement('input');
    inp.value = (vals && vals[c]) || '';
    if (c === 0) inp.placeholder = '10.10.40.5';
    td.appendChild(inp);
    tr.appendChild(td);
  }
  const del = document.createElement('td');
  del.className = 'rg-del';
  const x = document.createElement('button');
  x.className = 'rg-x';
  x.textContent = '×';
  x.title = 'remove row';
  x.onclick = () => tr.remove();
  del.appendChild(x);
  tr.appendChild(del);
  $('rg-rows').appendChild(tr);
  return tr;
}

// csvCell quotes a value only when it holds a comma, quote, or newline (RFC 4180).
function csvCell(s) {
  s = (s || '').trim();
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

$('rec-manual').onclick = () => {
  if (!currentSnapshotPath) { logLine('open a snapshot before reconciling', 'warn'); return; }
  $('rg-rows').innerHTML = '';
  for (let i = 0; i < 6; i++) rgAddRow();
  $('rg-msg').textContent = '';
  $('recgrid').style.display = 'flex';
};
$('rg-add').onclick = () => rgAddRow();
$('rg-cancel').onclick = () => { $('recgrid').style.display = 'none'; };
$('rg-apply').onclick = async () => {
  const rows = [...$('rg-rows').querySelectorAll('tr')].map((tr) => [...tr.querySelectorAll('input')].map((i) => i.value));
  const filled = rows.filter((r) => r.some((v) => v.trim() !== ''));
  if (!filled.length) { $('rg-msg').textContent = 'enter at least one row'; return; }
  const csv = ['ip,hostname,role,segment', ...filled.map((r) => r.map(csvCell).join(','))].join('\n');
  try {
    const model = await LoadReconcileModelCSV(currentSnapshotPath, csv);
    sessionAssetPath = ''; // manual entry is not a file
    $('recgrid').style.display = 'none';
    showReconcile(model, 'manual entry (' + filled.length + ' host' + (filled.length === 1 ? '' : 's') + ')');
  } catch (err) {
    $('rg-msg').textContent = 'reconcile failed: ' + err;
  }
};

function refreshDriftBaseline() {
  const sel = $('drift-base');
  sel.innerHTML = '';
  const options = snapshotEntries.filter((en) => en.Snapshot && en.Snapshot !== currentSnapshotPath);
  for (const en of options) {
    const opt = document.createElement('option');
    opt.value = en.Snapshot;
    opt.textContent = en.Timestamp;
    sel.appendChild(opt);
  }
  const ready = options.length > 0 && !!currentSnapshotPath;
  sel.disabled = !ready;
  $('drift-go').disabled = !ready;
}

function logFindings(model) {
  for (const f of model.findings || []) {
    logLine(f, f.includes('blind spot') || f.startsWith('drift vs') ? 'warn' : '');
  }
}

$('drift-go').onclick = async () => {
  const base = $('drift-base').value;
  if (!base || !currentSnapshotPath) return;
  try {
    const model = await LoadDriftModel(base, currentSnapshotPath);
    clearReconcile(false);
    renderModel(model);
    refreshDevices();
    logFindings(model);
  } catch (err) { logLine('drift compare failed: ' + err, 'err'); }
};
$('drift-clear').onclick = () => { if (currentSnapshotPath) openSnapshot(currentSnapshotPath); };

async function renderLegend() {
  let items;
  try {
    items = await Legend();
  } catch (err) {
    logLine('could not load legend: ' + err, 'err');
    return;
  }
  const legend = $('legend');
  legend.innerHTML = '';
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'lg';
    const sw = document.createElement('i');
    sw.style.background = item.Color;
    row.appendChild(sw);
    row.appendChild(document.createTextNode(item.Label));
    legend.appendChild(row);
  }
}

/* ---------------- scan ---------------- */

let scanning = false;

$('scanbtn').onclick = () => {
  const cfg = $('scancfg');
  cfg.style.display = cfg.style.display === 'block' ? 'none' : 'block';
};

// sidebar tabs: show/hide .tabpane, persist active tab in localStorage
function activateTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tabpane').forEach((p) => p.classList.toggle('active', p.dataset.pane === name));
  try { localStorage.setItem('salient.paneltab', name); } catch (e) { /* private mode */ }
}
document.querySelectorAll('.tab').forEach((t) => { t.onclick = () => activateTab(t.dataset.tab); });
let savedTab = 'investigate';
try { savedTab = localStorage.getItem('salient.paneltab') || 'investigate'; } catch (e) { /* private mode */ }
activateTab(savedTab);

$('gearbtn').onclick = () => {
  const p = $('aicfg');
  p.style.display = p.style.display === 'block' ? 'none' : 'block';
};

$('scango').onclick = async () => {
  if (scanning) return;
  $('scancfg').style.display = 'none';
  const scope = $('s-scope').value.split(',').map((s) => s.trim()).filter(Boolean);
  setScanning(true);
  $('tasklog').innerHTML = '';
  logLine('scan requested (window ' + $('s-window').value + (scope.length ? ', scope ' + scope.join(' ') : '') + ')');
  try {
    await RunScan({ Window: $('s-window').value.trim(), Scope: scope, TZ: $('s-tz').value.trim(), MaxEdges: 0 });
  } catch (err) {
    logLine('scan failed: ' + err, 'err');
    setScanning(false);
  }
};

$('cancelbtn').onclick = () => {
  if (scanning) {
    CancelScan();
    logLine('cancel requested…', 'warn');
  }
};

function setScanning(on) {
  scanning = on;
  $('scanbtn').disabled = on;
  $('cancelbtn').disabled = !on;
  $('taskstate').textContent = on ? 'scanning…' : 'idle';
  $('pulse').classList.toggle('idle', !on);
}

EventsOn('scan:progress', (s) => logLine(s.Detail || s.Name, s.Warn ? 'warn' : ''));
EventsOn('scan:done', (snapshotPath) => {
  logLine('done — snapshot ' + snapshotPath, 'ok');
  logLine('handling reminder: report, map, and snapshot describe network terrain — protect at the network\'s classification.', 'warn');
  setScanning(false);
  refreshList(true);
});
EventsOn('scan:error', (msg) => {
  logLine('scan error: ' + msg, 'err');
  setScanning(false);
});

function logLine(text, cls) {
  const log = $('tasklog');
  const div = document.createElement('div');
  div.className = 'ln' + (cls ? ' ' + cls : '');
  const ts = new Date().toTimeString().slice(0, 8);
  div.innerHTML = '<span class="ts">[' + ts + ']</span> ';
  div.appendChild(document.createTextNode(text));
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

/* ---------------- map (dark) ---------------- */

let cy = null;
let curLayout = 'fcose';
let overviewMode = false; // segment overview vs focused single-VLAN view
let currentModel = null;
const tierColor = { core: '#241a15', service: '#141d2b', client: '#1c232d' };
const topoBandColor = { boundary: '#3a2417', router: '#12243f', switch: '#12331f' };
const topoBorder = { boundary: '#e3a008', router: '#5a86ff', switch: '#3fb950' };
const tierBorder = { core: '#d9773f', service: '#4d8fe0', client: '#586274' };
const TERRAIN_TOP_N = 15;
const layouts = {
  // Tight, tiled fcose: pack each segment's hosts into a compact grid inside its
  // box (so boxes come out small and uniform, not ballooned by wide separation),
  // and pack the boxes rather than letting the physics scatter them.
  fcose: {
    name: 'fcose', animate: false, quality: 'proof', randomize: true,
    nodeSeparation: 18, idealEdgeLength: () => 60, nodeRepulsion: () => 3500,
    gravity: 0.9, gravityCompound: 1.2, tile: true,
    tilingPaddingVertical: 6, tilingPaddingHorizontal: 6,
    packComponents: true, nodeDimensionsIncludeLabels: true,
  },
};

// tieredLayout is a deterministic "realistic network map": the external/internet
// box spans the top, VLAN boxes sit in a row below it, and inside every box the
// router (gateway) is pinned to the top with the rest of the hosts stacked under
// it (core → service → client, then rank). Holds in the focused VLAN view too —
// one box, router on top. ponytail: single VLAN row scrolls horizontally on wide
// grids; fine, the canvas pans.
function tieredLayout() {
  const tierRank = { core: 0, service: 1, client: 2 };
  const childOrder = (a, b) => {
    const ga = a.data('gw') ? 0 : 1, gb = b.data('gw') ? 0 : 1;
    if (ga !== gb) return ga - gb; // router/gateway first
    const ta = tierRank[a.data('tier')] ?? 3, tb = tierRank[b.data('tier')] ?? 3;
    if (ta !== tb) return ta - tb; // core → service → client
    return (a.data('rank') || 1e9) - (b.data('rank') || 1e9);
  };
  const parents = cy.nodes('.grp');
  const ext = parents.filter((p) => p.id() === 'g:external');
  const vlans = parents.filter((p) => p.id() !== 'g:external')
    .sort((a, b) => (a.data('label') || '').localeCompare(b.data('label') || ''));
  const NODEW = 150, NODEH = 42, VGAP = 8, PADX = 40, PADY = 44;
  const CELLW = 480;    // wide cells → lots of horizontal space between VLAN boxes
  const BANDGAP = 190;  // vertical gap between VLAN rows
  const EXTGAP = 260;   // external band sits far above the internal VLAN rows
  const pos = {};

  // Per-host activity = total traffic volume on the edges touching a host.
  const hact = {};
  cy.edges('.host-edge').forEach((e) => {
    const w = e.data('width') || 1;
    hact[e.source().id()] = (hact[e.source().id()] || 0) + w;
    hact[e.target().id()] = (hact[e.target().id()] || 0) + w;
  });
  const H = (k) => hact[k.id()] || 0;

  // Focused single-VLAN view: same treatment as the overview, one level down.
  // Router on top, then hosts banded by activity — busy in the upper rows,
  // barely-any traffic in a lower band, zero-connection hosts off in a side
  // column so they don't clutter the box.
  if (!overviewMode && vlans.length) {
    const box = vlans[0];
    const kids = box.children();
    const gw = kids.filter((k) => k.data('gw')).sort(childOrder);
    const rest = kids.filter((k) => !k.data('gw')).sort(childOrder);
    const maxH = rest.reduce((m, k) => Math.max(m, H(k)), 0);
    const cut = maxH * 0.1; // <10% of peak = "barely any"
    const busy = rest.filter((k) => H(k) > cut);
    const quiet = rest.filter((k) => H(k) > 0 && H(k) <= cut);
    const dead = rest.filter((k) => H(k) <= 0);

    const COLW = NODEW + 20, ROWH = NODEH + VGAP;
    const cols = Math.min(8, Math.max(4, Math.ceil(Math.sqrt(busy.length || 1))));
    const rowW = cols * COLW;
    const placeGrid = (arr, y0) => {
      arr.forEach((k, i) => { pos[k.id()] = { x: PADX + (i % cols) * COLW, y: y0 + Math.floor(i / cols) * ROWH }; });
      return y0 + Math.ceil(arr.length / cols) * ROWH;
    };

    // External band centered over the box row, far above it.
    ext.forEach((p) => {
      const eks = p.children();
      const w = eks.length * (NODEW + 16);
      const sx = rowW / 2 - w / 2;
      eks.forEach((k, j) => { pos[k.id()] = { x: sx + j * (NODEW + 16), y: PADY }; });
    });
    const topH = ext.length ? PADY + NODEH + EXTGAP : PADY;

    // Router(s) centered over the busy grid, on top.
    gw.forEach((k, i) => { pos[k.id()] = { x: rowW / 2 - (gw.length * COLW) / 2 + i * COLW + PADX, y: topH }; });
    let y = topH + ROWH + 28;
    y = placeGrid(busy, y);
    if (quiet.length) y = placeGrid(quiet, y + BANDGAP);
    // Zero-connection hosts: a column off to the right of the box.
    const deadX = rowW + COLW * 1.2;
    dead.forEach((k, i) => { pos[k.id()] = { x: PADX + deadX, y: topH + i * ROWH }; });

    cy.layout({ name: 'preset', positions: (n) => pos[n.id()] || n.position(), fit: true, padding: 40 }).run();
    return;
  }

  // Per-VLAN activity = total traffic volume on its hosts' edges. Three bands:
  // real traffic (upper row), barely-any traffic (bottom row), and zero
  // connections (a column off to the side so they don't clutter the map).
  const act = {};
  cy.edges('.host-edge').forEach((e) => {
    const w = e.data('width') || 1;
    const sp = e.source().parent().id();
    const dp = e.target().parent().id();
    if (sp) act[sp] = (act[sp] || 0) + w;
    if (dp && dp !== sp) act[dp] = (act[dp] || 0) + w;
  });
  const A = (p) => act[p.id()] || 0;
  const maxAct = vlans.reduce((m, p) => Math.max(m, A(p)), 0);
  const barelyCut = maxAct * 0.1; // ponytail: <10% of peak = "barely any"; tune to taste
  const zero = vlans.filter((p) => A(p) <= 0);
  const barely = vlans.filter((p) => A(p) > 0 && A(p) <= barelyCut).sort((a, b) => A(a) - A(b));
  const real = vlans.filter((p) => A(p) > barelyCut).sort((a, b) => A(b) - A(a)); // busiest first

  // placeBand lays one activity band as a horizontal row of vertical stacks
  // (router on top of each box) and returns the Y for the next band.
  const placeBand = (band, y) => {
    let maxK = 0;
    band.forEach((p, i) => {
      const kids = p.children().sort(childOrder);
      maxK = Math.max(maxK, kids.length);
      kids.forEach((k, j) => { pos[k.id()] = { x: i * CELLW + PADX, y: y + PADY + j * (NODEH + VGAP) }; });
    });
    return y + PADY + maxK * (NODEH + VGAP) + BANDGAP;
  };

  // External/internet band centered over the real-traffic row, far above it.
  const realW = Math.max(real.length, 1) * CELLW;
  ext.forEach((p) => {
    const kids = p.children();
    const w = kids.length * (NODEW + 16);
    const startX = realW / 2 - w / 2;
    kids.forEach((k, j) => { pos[k.id()] = { x: startX + j * (NODEW + 16), y: PADY }; });
  });
  const extH = ext.length ? PADY + NODEH + EXTGAP : 0;

  // Declared device bands: boundary → router → switch, between external and the
  // VLAN rows. A tagged device (network layer from its Type) is pulled OUT of
  // its VLAN box into its own focus box in the band — one box per device, all
  // its on-map IPs inside it, regardless of how many VLANs it spans. No routing
  // arrows: the band placement carries the hierarchy; click a box for its IPs.
  const bandDevs = { boundary: [], router: [], switch: [] };
  (registry.devices || []).forEach((d) => {
    const layer = deviceLayer(d.type);
    if (!layer) return;
    const members = (d.ips || []).map((ip) => cy.getElementById(ip)).filter((n) => n.nonempty() && n.isChildless());
    if (!members.length) return;
    cy.add({ group: 'nodes', data: { id: 'topo:' + d.name, label: d.name, device: d.name, topoLayer: layer }, classes: 'grp topo-box topo-added' });
    members.forEach((n) => {
      if (n.data('origParent') === undefined) n.data('origParent', n.parent().nonempty() ? n.parent().id() : '');
      n.move({ parent: 'topo:' + d.name });
    });
    bandDevs[layer].push({ members });
  });
  const BOXW = NODEW + 40, ROWH = NODEH + VGAP;
  let devY = extH ? extH - EXTGAP / 2 : PADY;
  let vlanTop = extH;
  ['boundary', 'router', 'switch'].forEach((layer) => {
    const boxes = bandDevs[layer];
    if (!boxes.length) return;
    const totalW = boxes.length * (BOXW + 60);
    let startX = realW / 2 - totalW / 2;
    let maxH = 1;
    boxes.forEach((b) => {
      b.members.forEach((n, j) => { pos[n.id()] = { x: startX + PADX, y: devY + PADY + j * ROWH }; });
      maxH = Math.max(maxH, b.members.length);
      startX += BOXW + 60;
    });
    devY += PADY + maxH * ROWH + 96;
    vlanTop = devY + BANDGAP * 0.3;
  });

  let y = placeBand(real, vlanTop);   // real traffic (upper)
  placeBand(barely, y);               // barely any (bottom)

  // Zero-connection VLANs: a spaced column far off to the right, isolated so
  // they add no visual noise to the live map.
  const zeroX = Math.max(realW, barely.length * CELLW) + CELLW * 1.5;
  zero.forEach((p, i) => {
    p.children().sort(childOrder).forEach((k, j) => {
      pos[k.id()] = { x: zeroX + PADX, y: vlanTop + i * 360 + PADY + j * (NODEH + VGAP) };
    });
  });
  cy.layout({ name: 'preset', positions: (n) => pos[n.id()] || n.position(), fit: true, padding: 40 }).run();
}

// gridLayout is a deterministic uniform layout for the segment overview: every
// VLAN box is one cell of a grid, and each box's hosts sit in a fixed 2-column
// mini-grid inside it. Boxes come out the same size and orderly, instead of the
// force sim ballooning and scattering compound boxes.
function gridLayout() {
  const parents = cy.nodes('.grp').sort((a, b) => {
    const ac = a.data('cidr') ? 0 : 1, bc = b.data('cidr') ? 0 : 1;
    if (ac !== bc) return ac - bc; // real VLANs first, then other/external
    return (a.data('label') || '').localeCompare(b.data('label') || '');
  });
  const cols = Math.max(1, Math.ceil(Math.sqrt(parents.length)));
  const CELLW = 380, CELLH = 240, NODEW = 132, NODEH = 40, GAP = 8, PAD = 34;
  const pos = {};
  parents.forEach((p, i) => {
    const gx = (i % cols) * CELLW;
    const gy = Math.floor(i / cols) * CELLH;
    p.children().forEach((k, j) => {
      pos[k.id()] = { x: gx + PAD + (j % 2) * (NODEW + GAP), y: gy + PAD + Math.floor(j / 2) * (NODEH + GAP) };
    });
  });
  cy.layout({ name: 'preset', positions: (n) => pos[n.id()], fit: true, padding: 40 }).run();
}

// deviceLayer: a device Type → topology band.
function deviceLayer(typ) {
  switch ((typ || '').trim().toLowerCase()) {
    case 'firewall': case 'edge': case 'boundary': return 'boundary';
    case 'router': case 'l3': case 'gateway': return 'router';
    case 'switch': case 'l2': return 'switch';
    default: return '';
  }
}

// Minimal IPv4 CIDR helpers for topology routing (v6 ranges are ignored in v1).
function parseCidr(s) {
  const [ip, bitsStr] = (s || '').split('/');
  const n = ipToInt(ip);
  const bits = parseInt(bitsStr, 10);
  if (n === null || !(bits >= 0 && bits <= 32)) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (n & mask) >>> 0, mask, bits };
}
function ipToInt(ip) {
  const p = (ip || '').trim().split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) { const v = Number(o); if (!(v >= 0 && v <= 255)) return null; n = (n * 256) + v; }
  return n >>> 0;
}
// cidrContains: does prefix p contain the network named by cidrStr (e.g. a VLAN box)?
function cidrContains(p, cidrStr) {
  const c = parseCidr(cidrStr);
  if (!c || c.bits < p.bits) return false;
  return ((c.base & p.mask) >>> 0) === p.base;
}

// clearTopo undoes topology reparenting: move every pulled-out device node back
// to its original VLAN box, THEN remove the now-empty band boxes (removing a
// compound parent deletes its children, so restore must come first).
function clearTopo() {
  if (!cy) return;
  cy.nodes('[origParent]').forEach((n) => {
    const p = n.data('origParent');
    n.move({ parent: p ? p : null });
    n.removeData('origParent');
  });
  cy.remove('node.topo-box');
  cy.remove('.topo-added');
}

function runLayout(name) {
  curLayout = name;
  clearTopo();
  if (name === 'grid') gridLayout();
  else if (name === 'dagre') tieredLayout();
  else cy.layout(layouts[name]).run();
  $('b-grid').classList.toggle('on', name === 'grid');
  $('b-fcose').classList.toggle('on', name === 'fcose');
  $('b-dagre').classList.toggle('on', name === 'dagre');
}
// layoutPref remembers an explicit operator choice so it survives re-renders
// (e.g. drilling into a VLAN keeps the tiered/topology layout).
let layoutPref = null;
$('b-grid').onclick = () => { if (cy) { layoutPref = 'grid'; runLayout('grid'); } };
$('b-fcose').onclick = () => { if (cy) { layoutPref = 'fcose'; runLayout('fcose'); } };
$('b-dagre').onclick = () => { if (cy) { layoutPref = 'dagre'; runLayout('dagre'); } };

let currentSnapshotPath = '';

function openSnapshot(path) {
  LoadModel(path).then((model) => {
    currentSnapshotPath = path;
    drilledCIDR = '';
    $('backbtn').style.display = 'none';
    closeHostList();
    renderSnapshotButton();
    $('exportbtn').disabled = false;
    $('ai-tagbtn').disabled = false;
    $('ai-status').textContent = 'ready';
    renderModel(model);
    refreshDevices();
    refreshDriftBaseline();
    if (sessionAssetPath) applyReconcile();
  }).catch((err) => logLine('could not load snapshot: ' + err, 'err'));
}

$('exportbtn').onclick = async () => {
  if (!currentSnapshotPath) return;
  const fmt = $('exportfmt').value;
  const btn = $('exportbtn');
  btn.disabled = true;
  try {
    let saved;
    if (fmt === 'png') {
      // Rasterize the canvas exactly as currently laid out (fcose/dagre,
      // whichever is active) — this is what matches the on-screen view,
      // unlike the server-side SVG renderer which lays nodes out itself.
      if (!cy) throw new Error('no map loaded');
      const dataURL = cy.png({ full: true, scale: 2, bg: '#0d1117' });
      saved = await ExportImage(dataURL);
    } else {
      saved = await ExportMap(currentSnapshotPath, fmt);
    }
    if (saved) logLine('exported ' + fmt.toUpperCase() + ' to ' + saved, 'ok');
  } catch (err) {
    logLine('export failed: ' + err, 'err');
  } finally {
    btn.disabled = false;
  }
};

const providerDefaults = {
  openai: { endpoint: 'https://api.openai.com/v1/chat/completions', model: 'gpt-4.1-mini' },
  anthropic: { endpoint: 'https://api.anthropic.com/v1/messages', model: 'claude-sonnet-4-5' },
  gemini: { endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent', model: 'gemini-2.5-flash' },
};

$('ai-provider').onchange = (e) => {
  const defaults = providerDefaults[e.target.value];
  $('ai-endpoint').value = defaults.endpoint;
  $('ai-model').value = defaults.model;
};

// tagRequest builds the shared AI-tag request from the AI panel fields, or
// returns null after setting a status message when required fields are unset.
function tagRequest() {
  if (!currentSnapshotPath) return null;
  const model = $('ai-model').value.trim();
  let endpoint = $('ai-endpoint').value.trim();
  if (!model || !endpoint) {
    $('ai-status').textContent = 'endpoint and model are required';
    return null;
  }
  endpoint = endpoint.replace('{model}', encodeURIComponent(model));
  return {
    SnapshotPath: currentSnapshotPath,
    Provider: $('ai-provider').value,
    Endpoint: endpoint,
    Model: model,
    APIKey: $('ai-key').value,
    AllowRemote: $('ai-egress').checked,
  };
}

$('ai-tagbtn').onclick = async () => {
  const req = tagRequest();
  if (!req) return;
  const button = $('ai-tagbtn');
  button.disabled = true;
  $('ai-status').textContent = 'requesting suggestions…';
  try {
    const result = await SuggestTags(req);
    const count = (result.tags || []).length;
    $('ai-status').textContent = count + ' device suggestion' + (count === 1 ? '' : 's') + ' saved';
    logLine('saved ' + count + ' model-assisted device tag suggestion' + (count === 1 ? '' : 's'), 'ok');
    openSnapshot(currentSnapshotPath);
  } catch (err) {
    $('ai-status').textContent = 'tagging failed: ' + err;
    logLine('device tagging failed: ' + err, 'err');
  } finally {
    button.disabled = false;
  }
};

function renderModel(model) {
  currentModel = model;
  // Each view gets its best-fit default layout unless the operator picked one
  // explicitly (layoutPref) — that choice persists across re-renders, so a
  // tiered/realistic layout holds when drilling into a VLAN. Default: grid for
  // the segment overview, tiered/banded for the focused VLAN view (hosts banded
  // by activity, the same treatment the overview gives VLANs).
  overviewMode = !!model.overview;
  curLayout = layoutPref || (overviewMode ? 'grid' : 'dagre');
  const els = [];
  for (const g of model.groups || []) {
    els.push({ data: { id: g.id, label: g.label, cidr: g.cidr || '' }, classes: 'grp' + (g.blind_spot ? ' blind' : '') + (g.cidr ? ' drillable' : '') });
  }
  for (const n of model.nodes || []) {
    els.push({
      data: {
        id: n.id, parent: n.group || undefined, label: n.label.split('\n')[0], role: n.role, tier: n.tier,
        comp: n.composite || 0, rank: n.rank || 0, gw: n.gateway ? 1 : 0, inf: n.inferred ? 1 : 0,
        agg: n.agg_count || 0, drift: n.drift || '', ev: (n.evidence || []).join('\n'),
        device: n.device || '', deviceType: n.device_type || '', labels: (n.labels || []).join(', '),
        services: (n.services || []).join(', '), roleOverride: n.role_override || '',
        mac: n.mac || '', vendor: n.vendor || '', pinned: n.pinned ? 1 : 0,
        aiTags: (n.suggested_tags || []).join(', '), aiConfidence: n.suggestion_confidence || 0,
        aiRationale: n.suggestion_rationale || '', aiModel: n.suggestion_model || '',
        // Precomputed search haystack — the input handler only reads this.
        // ponytail: built once at render; device reassignments without a full
        // reload won't refresh it, which is fine (reloads rebuild the map).
        hay: (n.label.split('\n')[0] + ' ' + (n.role || '') + ' ' + (n.evidence || []).join('\n') + ' ' +
          (n.suggested_tags || []).join(', ') + ' ' + (n.device || '') + ' ' + (n.labels || []).join(', ') + ' ' +
          (n.services || []).join(', ') + ' ' + (n.role_override || '')).toLowerCase(),
      },
      classes: (n.drift ? 'drift-' + n.drift + ' ' : '') + (n.device ? 'dev-linked ' : '') + (n.pinned ? 'pinned ' : '') + (n.suggested_tags?.length ? 'ai-tagged' : ''),
    });
  }
  const edges = model.edges || [];
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    els.push({
      data: { id: 'e' + i, source: e.src, target: e.dst, color: e.color, width: e.width, label: e.label, drift: e.drift || '', cls: e.class || '' },
      classes: 'host-edge' + (e.drift ? ' drift-' + e.drift : ''),
    });
  }
  // High-level backbone: collapse the host-level edges into one aggregated
  // segment→segment line per VLAN pair (colored by the dominant service class,
  // thickness by volume). This is the default "logical flow" view; host-level
  // edges stay hidden until a host or segment is selected.
  const ipGroup = {};
  for (const n of model.nodes || []) ipGroup[n.id] = n.group || '';
  const seg = {};
  for (const e of edges) {
    const gs = ipGroup[e.src], gd = ipGroup[e.dst];
    if (!gs || !gd || gs === gd) continue; // inter-segment only
    const k = gs + '' + gd;
    const s = seg[k] || (seg[k] = { src: gs, dst: gd, w: 0, best: 0, color: e.color });
    s.w += e.width || 1;
    if ((e.width || 0) > s.best) { s.best = e.width || 0; s.color = e.color; }
  }
  const segArr = Object.values(seg).sort((a, b) => b.w - a.w).slice(0, 120);
  for (let i = 0; i < segArr.length; i++) {
    const s = segArr[i];
    els.push({
      data: { id: 'seg' + i, source: s.src, target: s.dst, color: s.color, segw: Math.min(8, 1 + Math.log1p(s.w)) },
      classes: 'seg-edge',
    });
  }

  // Preserve the camera + selection across the full rebuild when the operator
  // is looking at the same view (same snapshot, same overview/drill target).
  // A genuinely different view (other snapshot, drill in/out) still fits fresh.
  const viewKey = currentSnapshotPath + '|' + (model.overview ? 'ov' : 'fx') + '|' + drilledCIDR;
  let restore = null;
  if (cy) {
    restore = {
      key: cy.scratch('_viewKey'),
      zoom: cy.zoom(),
      pan: { ...cy.pan() },
      selected: cy.$(':selected').map((e) => e.id()),
    };
    cy.destroy();
  }
  cy = cytoscape({
    container: $('cy'), elements: els, wheelSensitivity: 0.2,
    style: [
      { selector: 'node.grp', style: { 'background-color': '#161b22', 'background-opacity': 0.6, 'border-color': '#30363d', 'border-width': 1, shape: 'round-rectangle', label: 'data(label)', 'text-valign': 'top', 'font-size': 12, 'font-weight': 600, color: '#8b949e', padding: 12, 'min-width': 300, 'min-height': 180 } },
      { selector: 'node.grp.blind', style: { 'border-color': '#a0424a', 'border-style': 'dashed', 'background-color': '#2a1416' } },
      { selector: 'node.grp.drillable', style: { label: (ele) => '▸ ' + ele.data('label'), 'border-color': '#3d4450' } },
      { selector: 'node.topo-box', style: { 'background-color': (ele) => topoBandColor[ele.data('topoLayer')] || '#161b22', 'background-opacity': 0.7, 'border-color': (ele) => topoBorder[ele.data('topoLayer')] || '#5a86ff', 'border-width': 2, 'min-width': 150, 'min-height': 60, padding: 12, color: '#eaf1ff' } },
      { selector: 'node:childless', style: { shape: 'round-rectangle', width: 'mapData(comp, 0, 1, 92, 156)', height: 'mapData(comp, 0, 1, 30, 46)', label: (ele) => (ele.data('device') && !ele.data('agg')) ? ele.data('device') + ' · ' + ele.data('label') : ele.data('label'), 'text-valign': 'center', 'font-size': 10, color: '#c9d1d9', 'background-color': (ele) => tierColor[ele.data('tier')] || '#1c232d', 'border-width': 1.6, 'border-color': (ele) => tierBorder[ele.data('tier')] || '#586274' } },
      { selector: 'node[gw=1]', style: { shape: 'diamond', height: 40 } },
      { selector: 'node[inf=1]', style: { 'border-style': 'dashed' } },
      { selector: 'node[agg>0]', style: { shape: 'round-rectangle', 'border-style': 'double', 'border-width': 3 } },
      { selector: 'node.ai-tagged', style: { 'border-color': '#39d3ff', 'border-width': 4 } },
      { selector: 'node.dev-linked', style: { 'border-color': '#a78bfa', 'border-width': 3 } },
      { selector: 'node.pinned', style: { 'border-color': '#f0b429', 'border-width': 3, 'border-style': 'solid' } },
      { selector: 'node.drift-new', style: { 'border-color': '#3fb950', 'border-width': 4 } },
      { selector: 'node.drift-vanished', style: { opacity: 0.35, 'border-style': 'dashed', 'border-color': '#8b949e' } },
      { selector: 'node.drift-rank-up,node.drift-rank-down', style: { 'border-color': '#e3a008', 'border-width': 4 } },
      { selector: 'node.drift-undocumented', style: { 'border-color': '#f85149', 'border-width': 4 } },
      { selector: 'node.drift-silent', style: { opacity: 0.35, 'border-style': 'dashed', 'border-color': '#8b949e' } },
      { selector: 'node.drift-contradicted', style: { 'border-color': '#e3a008', 'border-width': 4, 'border-style': 'double' } },
      { selector: 'edge', style: { 'curve-style': 'bezier', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle', width: 'data(width)', label: 'data(label)', 'font-size': 9, color: '#8b949e', 'text-rotation': 'autorotate', 'text-background-color': '#0b0f14', 'text-background-opacity': 0.85, opacity: 0.85 } },
      { selector: 'edge.seg-edge', style: { 'curve-style': 'bezier', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle', width: 'data(segw)', opacity: 0.55, 'z-index': 1, label: '' } },
      { selector: 'edge.e-hide', style: { display: 'none' } },
      { selector: 'edge.e-lit', style: { opacity: 0.95, width: 'mapData(width, 0, 6, 1.5, 7)', 'z-index': 20 } },
      { selector: 'node.nbr', style: { 'border-color': '#5a86ff', 'border-width': 3 } },
      { selector: 'edge.drift-new', style: { 'line-color': '#3fb950', 'target-arrow-color': '#3fb950', 'line-style': 'solid', opacity: 1 } },
      { selector: 'edge.drift-vanished', style: { 'line-color': '#8b949e', 'target-arrow-color': '#8b949e', 'line-style': 'dashed', opacity: 0.35 } },
      { selector: 'node.drift-off', style: { opacity: 1, 'border-width': 1.6, 'border-style': 'solid', 'border-color': (ele) => tierBorder[ele.data('tier')] || '#586274' } },
      { selector: 'edge.drift-off', style: { opacity: 0.85, 'line-style': 'solid', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)' } },
      { selector: '.dim', style: { opacity: 0.12 } },
    ],
  });
  runLayout(curLayout);
  // Same view as before the rebuild? Restore camera + selection instead of the
  // fresh fit runLayout just did — no flash, no lost viewport.
  cy.scratch('_viewKey', viewKey);
  if (restore && restore.key === viewKey) {
    cy.zoom(restore.zoom);
    cy.pan(restore.pan);
    if (restore.selected.length) {
      cy.batch(() => restore.selected.forEach((id) => {
        const el = cy.getElementById(id);
        if (el.nonempty()) el.select();
      }));
    }
  }
  bindContextMenu();
  renderTerrainButton(model);

  // Flow reveal: a full mesh of inter-segment edges is an unreadable hairball,
  // so in the segment-flow overview edges start hidden and light up only for
  // the host/segment you select. Small focused/detail maps show edges outright.
  edgesHidden = !!model.overview && !$('l-flows').checked;
  applyEdgeVisibility();
  if (edgesHidden) logLine('showing high-level segment-to-segment flow — click a host or a VLAN box for its detailed connections, double-click a VLAN to drill in, or check "show all flows"', 'ok');

  // Layer-toggle handlers are bound once at module scope (see below); here we
  // only apply the per-render initial state: heat is on by default in overview.
  $('l-heat').checked = overviewMode;
  $('l-heat').onchange();

  cy.on('tap', 'node:childless', (e) => {
    const n = e.target;
    lightEdgesFor(n);
    if (n.data('agg') > 0) { openHostList(n.data('id'), n.data('device') || n.data('label')); return; }
    showNodeEvidence(n);
  });
  // A flow arrow whose src or dst is a grouped/aggregate node (e.g.
  // "g:external:clients") hides which real IP the traffic went to —
  // clicking the arrow itself reveals it.
  cy.on('tap', 'edge.host-edge', (e) => {
    const ed = e.target;
    const src = ed.source(), dst = ed.target();
    const srcAgg = src.data('agg') > 0, dstAgg = dst.data('agg') > 0;
    if (!srcAgg && !dstAgg) return;
    openFlowIPs(ed.data('source'), ed.data('target'), ed.data('cls'),
      (src.data('label') || ed.data('source')) + ' → ' + (dst.data('label') || ed.data('target')));
  });
  // Segment interaction: single-tap a VLAN box lights up that whole segment's
  // flows (what it talks to); double-tap drills into its full detail.
  cy.on('tap', 'node.drillable', (e) => {
    const g = e.target;
    const now = Date.now();
    if (lastSegTap.id === g.id() && now - lastSegTap.t < 350) {
      lastSegTap = { id: '', t: 0 };
      const cidr = g.data('cidr');
      if (cidr) drillInto(cidr);
      return;
    }
    lastSegTap = { id: g.id(), t: now };
    lightEdgesForSegment(g);
  });
  // Tap a topology device box → show that device's card (all its IPs).
  cy.on('tap', 'node.topo-box', (e) => { showDeviceCard(e.target.data('device')); });
  // Tap empty canvas → back to the clean structure-only view.
  cy.on('tap', (e) => { if (e.target === cy) applyEdgeVisibility(); });
}

function topTerrainNodes(model) {
  return (model.nodes || [])
    .filter((n) => n.rank > 0 && (!n.agg_count || n.device))
    .sort((a, b) => a.rank - b.rank)
    .slice(0, TERRAIN_TOP_N);
}

function renderTerrainButton(model) {
  const count = topTerrainNodes(model).length;
  $('terrainbtn').disabled = count === 0;
  $('terrainbtn').textContent = count ? 'Open key terrain (' + count + ')' : 'No key terrain';
  $('svcauthbtn').disabled = false;
  $('huntbtn').disabled = false;
}

function zoomToTerrain(item) {
  const node = cy && cy.getElementById(item.id);
  if (!node || node.empty()) return;
  cy.animate({ center: { eles: node }, zoom: 1.4, duration: 300 });
  lightEdgesFor(node);
  showNodeEvidence(node);
}

$('terrainbtn').onclick = () => {
  if (currentModel) openTerrainList(currentModel);
};

$('svcauthbtn').onclick = () => openServiceAuthority();
$('huntbtn').onclick = () => openHuntLeads();

let lastSegTap = { id: '', t: 0 };

// lightEdgesForSegment reveals every flow touching a VLAN box's hosts — the
// segment-level answer to "what does this VLAN talk to" — and dims the rest.
function lightEdgesForSegment(g) {
  if (!cy || !edgesHidden) return;
  const edges = g.children().connectedEdges('.host-edge');
  cy.batch(() => {
    cy.edges().addClass('e-hide').removeClass('e-lit');
    edges.removeClass('e-hide').addClass('e-lit');
    cy.nodes().removeClass('nbr');
    edges.connectedNodes().addClass('nbr');
  });
}

let edgesHidden = false;

// applyEdgeVisibility resets to the default view: the high-level segment→segment
// backbone drawn, host-level detail hidden. "show all flows" (!edgesHidden)
// draws every host edge too; small detail/focused maps have no backbone and
// just show their edges.
function applyEdgeVisibility() {
  if (!cy) return;
  cy.batch(() => {
    cy.nodes().removeClass('nbr').removeClass('dim');
    cy.edges().removeClass('e-lit');
    if (edgesHidden) {
      cy.edges('.host-edge').addClass('e-hide');
      cy.edges('.seg-edge').removeClass('e-hide');
    } else {
      cy.edges().removeClass('e-hide');
    }
  });
}

// Layer toggles are bound ONCE here; they read the live `cy` at call time so a
// map rebuild (renderModel) doesn't need to rebind them. renderModel still
// applies the per-render checked/initial state.
$('l-heat').onchange = function () {
  if (!cy) return;
  if (this.checked) {
    cy.nodes(':childless').forEach((n) => {
      const c = n.data('comp');
      n.style('background-color', 'rgb(' + Math.round(40 + 180 * c) + ',' + Math.round(30 + 40 * c) + ',' + Math.round(25 + 20 * c) + ')');
    });
  } else {
    cy.nodes(':childless').forEach((n) => n.removeStyle('background-color'));
  }
};
$('l-lbl').onchange = function () { if (cy) cy.edges().style('text-opacity', this.checked ? 1 : 0); };
$('l-flows').onchange = function () {
  edgesHidden = overviewMode && !this.checked;
  applyEdgeVisibility();
};
$('l-drift').onchange = function () {
  if (!cy) return;
  cy.elements('.drift-new,.drift-vanished,.drift-rank-up,.drift-rank-down,.drift-changed,.drift-undocumented,.drift-silent,.drift-contradicted')
    .toggleClass('drift-off', !this.checked);
};

// lightEdgesFor reveals just the selected host's real (host-level) connections,
// hiding the backbone and everything else — focus+context.
function lightEdgesFor(n) {
  if (!cy || !edgesHidden) return;
  const edges = n.connectedEdges('.host-edge');
  cy.batch(() => {
    cy.edges().addClass('e-hide').removeClass('e-lit');
    edges.removeClass('e-hide').addClass('e-lit');
    cy.nodes().removeClass('nbr');
    edges.connectedNodes().addClass('nbr');
  });
}

let drilledCIDR = '';

function drillInto(cidr) {
  if (!currentSnapshotPath) return;
  LoadFocusedModel(currentSnapshotPath, cidr).then((model) => {
    drilledCIDR = cidr;
    const back = $('backbtn');
    back.style.display = 'inline-block';
    back.textContent = '← overview';
    closeHostList();
    renderModel(model);
    logLine('drilled into ' + cidr + ' (full detail)', 'ok');
  }).catch((err) => logLine('drill-in failed: ' + err, 'err'));
}

$('backbtn').onclick = () => {
  drilledCIDR = '';
  $('backbtn').style.display = 'none';
  if (currentSnapshotPath) openSnapshot(currentSnapshotPath);
};

function showNodeEvidence(n) {
  const ev = $('ev');
  ev.textContent = '';
  activateTab('investigate');
  const ip = n.data('id');
  const aiDismissed = registry.dismissed_hints.includes('ai:' + ip);
  const override = n.data('roleOverride');
  let text =
    n.data('label') +
    (override ? '\nrole: ✎ ' + override + ' (operator)\ninferred: ' + n.data('role') : '\nrole: ' + n.data('role')) +
    (n.data('rank') ? '\nrank: #' + n.data('rank') : '') +
    '\ncomposite: ' + (n.data('comp') || 0).toFixed(2) + (n.data('drift') ? '\ndrift: ' + n.data('drift') : '') +
    (n.data('device') ? '\ndevice: ◈ ' + n.data('device') : '') +
    (n.data('labels') ? '\nlabels: ' + n.data('labels') : '') +
    (n.data('services') ? '\nservices: ' + n.data('services') : '') +
    (n.data('mac') ? '\nMAC: ' + n.data('mac') + (n.data('vendor') ? ' (' + n.data('vendor') + ')' : '') : '') +
    (n.data('ev') ? '\n\n' + n.data('ev') : '\n\n(no role evidence)');
  if (n.data('aiTags') && !aiDismissed) {
    text += '\n\nMODEL SUGGESTION (' + n.data('aiModel') + ', confidence ' + n.data('aiConfidence').toFixed(2) + ')\ntags: ' + n.data('aiTags') + '\n' + n.data('aiRationale');
  }
  ev.appendChild(document.createTextNode(text));
  if (n.data('aiTags') && !aiDismissed) {
    const row = document.createElement('div');
    row.className = 'devcard';
    const accept = document.createElement('button');
    accept.textContent = 'accept tags';
    accept.onclick = async () => {
      try {
        await SetLabels(ip, n.data('aiTags').split(', '));
        logLine('promoted AI tags to durable labels for ' + ip, 'ok');
        await refreshDevices();
        n.data('labels', n.data('aiTags'));
        showNodeEvidence(n);
      } catch (err) { logLine('accept failed: ' + err, 'err'); }
    };
    const dismiss = document.createElement('button');
    dismiss.textContent = 'dismiss suggestion';
    dismiss.onclick = async () => {
      try {
        await DismissHint('ai:' + ip);
        await refreshDevices();
        showNodeEvidence(n);
      } catch (err) { logLine('dismiss failed: ' + err, 'err'); }
    };
    row.appendChild(accept);
    row.appendChild(dismiss);
    ev.appendChild(row);
  }
}

/* ---------------- aggregate-node host list ---------------- */

// ponytail: 14k+ DOM rows make the webview crawl — render the first 1000
// matches and let the filter narrow the rest; virtualize if that ever hurts.
const HL_MAX_ROWS = 1000;
const HL_TAG_CAP = 100; // assist.AssistMaxNodes — per-group tagging cap
let hlHosts = [];
let hlShown = []; // rows currently visible (post-filter, capped)
let aggListNode = ''; // aggregate node id the host list is showing
let hlMode = 'hosts';

async function openHostList(nodeID, title) {
  let hosts;
  try {
    hosts = await AggregateHosts(currentSnapshotPath, nodeID);
  } catch (err) {
    logLine('could not load host list: ' + err, 'err');
    return;
  }
  hlHosts = hosts || [];
  hlMode = 'hosts';
  aggListNode = nodeID;
  $('hl-title').textContent = title;
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'block';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

function openTerrainList(model) {
  hlHosts = topTerrainNodes(model);
  hlMode = 'terrain';
  aggListNode = '';
  $('hl-title').textContent = 'Key Terrain';
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'none';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

async function openFlowIPs(srcID, dstID, cls, title) {
  let ips;
  try {
    ips = await FlowEndpointIPs(currentSnapshotPath, srcID, dstID, cls);
  } catch (err) {
    logLine('could not load flow IPs: ' + err, 'err');
    return;
  }
  if (!ips || !ips.length) { logLine('no underlying IPs found for that flow', 'warn'); return; }
  hlHosts = ips;
  hlMode = 'flowip';
  aggListNode = '';
  $('hl-title').textContent = title;
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'none';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

function renderFlowIPRows(q) {
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q ? hlHosts.filter((ip) => ip.toLowerCase().includes(q)) : hlHosts;
  hlShown = match.slice(0, HL_MAX_ROWS);
  for (const ip of hlShown) {
    const li = document.createElement('li');
    li.textContent = ip;
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? ('showing first ' + HL_MAX_ROWS + ' of ' + match.length)
    : (match.length + ' IP' + (match.length === 1 ? '' : 's'));
}

function closeHostList() {
  $('hostlist').style.display = 'none';
  hlHosts = [];
  hlMode = 'hosts';
}

async function openServiceAuthority() {
  let rows;
  try {
    rows = await LoadServiceAuthority(currentSnapshotPath);
  } catch (err) {
    logLine('could not load service authority: ' + err, 'err');
    return;
  }
  hlHosts = rows || [];
  hlMode = 'services';
  aggListNode = '';
  $('hl-title').textContent = 'Service Authority';
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'none';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

function renderServiceAuthorityRows(q) {
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q
    ? hlHosts.filter((r) => (r.ip + ' ' + (r.hostname || '') + ' ' + r.service + ' ' + r.role).toLowerCase().includes(q))
    : hlHosts;
  hlShown = match.slice(0, HL_MAX_ROWS);
  for (const r of hlShown) {
    const li = document.createElement('li');
    li.textContent = r.ip + ' — ' + r.service;
    const clients = document.createElement('span');
    clients.className = 'role';
    clients.textContent = ' · ' + r.clients + ' client' + (r.clients === 1 ? '' : 's');
    li.appendChild(clients);
    if (r.rank) {
      const rank = document.createElement('span');
      rank.className = 'rank';
      rank.textContent = ' #' + r.rank;
      li.appendChild(rank);
    }
    li.onclick = () => showProviderDossier(r);
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? ('showing first ' + HL_MAX_ROWS + ' of ' + match.length)
    : (match.length + ' provider' + (match.length === 1 ? '' : 's'));
}

function showProviderDossier(r) {
  const ev = $('ev');
  ev.textContent = '';
  activateTab('investigate');
  const text =
    r.ip + (r.hostname ? ' (' + r.hostname + ')' : '') +
    '\nservice: ' + r.service + ' (port ' + r.port + ')' +
    (r.role && r.role !== 'Unknown' ? '\nrole: ' + r.role : '') +
    (r.rank ? '\nrank: #' + r.rank : '') +
    '\nevidence: ' + r.evidence +
    '\nclients: ' + r.clients +
    '\nfirst seen: ' + r.first_seen +
    '\nlast seen: ' + r.last_seen;
  ev.appendChild(document.createTextNode(text));
}

async function openHuntLeads() {
  let leads;
  try {
    leads = await LoadHuntLeads(currentSnapshotPath, '', '');
  } catch (err) {
    logLine('could not load hunt leads: ' + err, 'err');
    return;
  }
  hlHosts = leads || [];
  hlMode = 'leads';
  aggListNode = '';
  $('hl-title').textContent = 'Hunt Leads';
  $('hl-filter').value = '';
  $('hl-tag').style.display = 'none';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

const LEAD_REASON_LABELS = {
  'contradicted': 'role contradicted',
  'undocumented': 'undocumented',
  'new-provider': 'new provider',
  'new-service': 'new service',
  'sole-provider': 'sole provider',
};

function renderLeadRows(q) {
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q
    ? hlHosts.filter((l) => (l.ip + ' ' + (l.hostname || '') + ' ' + l.service + ' ' + l.reason).toLowerCase().includes(q))
    : hlHosts;
  hlShown = match.slice(0, HL_MAX_ROWS);
  for (const l of hlShown) {
    const li = document.createElement('li');
    li.textContent = l.ip + ' — ' + l.service;
    const reason = document.createElement('span');
    reason.className = 'role';
    reason.textContent = ' · ' + (LEAD_REASON_LABELS[l.reason] || l.reason);
    li.appendChild(reason);
    if (l.rank) {
      const rank = document.createElement('span');
      rank.className = 'rank';
      rank.textContent = ' #' + l.rank;
      li.appendChild(rank);
    }
    li.onclick = () => showLeadDossier(l);
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? ('showing first ' + HL_MAX_ROWS + ' of ' + match.length)
    : (match.length + ' lead' + (match.length === 1 ? '' : 's'));
}

function showLeadDossier(l) {
  const ev = $('ev');
  ev.textContent = '';
  activateTab('investigate');
  const text =
    l.ip + (l.hostname ? ' (' + l.hostname + ')' : '') +
    '\nreason: ' + (LEAD_REASON_LABELS[l.reason] || l.reason) +
    '\nservice: ' + l.service + ' (port ' + l.port + ')' +
    (l.inventory_status ? '\ninventory: ' + l.inventory_status : '') +
    (l.rank ? '\nrank: #' + l.rank : '') +
    '\nevidence: ' + l.evidence +
    '\nclients: ' + l.clients + (l.sample_clients ? ' (' + l.sample_clients.join(', ') + ')' : '') +
    (l.subnets ? '\nsubnets: ' + l.subnets.join(', ') : '') +
    (l.sensors ? '\nsensors: ' + l.sensors.join(', ') : '') +
    '\nalternate providers: ' + (l.alternate_providers && l.alternate_providers.length ? l.alternate_providers.join(', ') : 'no alternate provider observed') +
    '\nfirst seen: ' + l.first_seen +
    '\nlast seen: ' + l.last_seen;
  ev.appendChild(document.createTextNode(text));

  const row = document.createElement('div');
  row.className = 'devcard';
  const copyBtn = document.createElement('button');
  copyBtn.textContent = 'copy Hunt query';
  copyBtn.onclick = () => {
    const query = 'destination.ip:"' + l.ip + '" AND destination.port:' + l.port;
    navigator.clipboard.writeText(query).then(
      () => logLine('copied Hunt query for ' + l.ip, 'ok'),
      () => logLine('clipboard copy failed — query: ' + query, 'warn'));
  };
  const approveBtn = document.createElement('button');
  approveBtn.textContent = 'approve (hide this lead)';
  approveBtn.title = 'Marks this as an expected/benign provider — it stops appearing in future scans. Observed evidence is never changed, only this display filter.';
  approveBtn.onclick = async () => {
    try {
      await ApproveProvider(l.ip + ':' + l.port);
      hlHosts = hlHosts.filter((x) => !(x.ip === l.ip && x.port === l.port));
      renderHostList($('hl-filter').value.toLowerCase());
      ev.textContent = 'approved — lead hidden';
      logLine('approved ' + l.ip + ':' + l.port + ' as an expected provider', 'ok');
    } catch (err) { logLine('approve failed: ' + err, 'err'); }
  };
  row.appendChild(copyBtn);
  row.appendChild(approveBtn);
  ev.appendChild(row);
}

function renderHostList(q) {
  if (hlMode === 'snapshots') { renderSnapshotRows(q); return; }
  if (hlMode === 'services') { renderServiceAuthorityRows(q); return; }
  if (hlMode === 'leads') { renderLeadRows(q); return; }
  if (hlMode === 'flowip') { renderFlowIPRows(q); return; }
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q
    ? hlHosts.filter((h) => (h.id + ' ' + h.label + ' ' + h.role + ' ' + (h.role_override || '') + ' ' + (h.services || []).join(' ') + ' ' + (h.device || '') + ' ' + (h.mac || '') + ' ' + (h.vendor || '')).toLowerCase().includes(q))
    : hlHosts;
  hlShown = match.slice(0, HL_MAX_ROWS);
  for (const h of match.slice(0, HL_MAX_ROWS)) {
    const li = document.createElement('li');
    li.textContent = (hlMode === 'terrain' && h.device) ? h.device : h.label.split('\n')[0];
    if (h.rank) {
      const rank = document.createElement('span');
      rank.className = 'rank';
      rank.textContent = ' #' + h.rank;
      li.appendChild(rank);
    }
    if (hlMode === 'terrain' && h.agg_count) {
      const cnt = document.createElement('span');
      cnt.className = 'role';
      cnt.textContent = ' — ' + h.agg_count + ' IPs';
      li.appendChild(cnt);
    }
    if (h.role_override) {
      const role = document.createElement('span');
      role.className = 'role';
      role.textContent = ' — ✎ ' + h.role_override;
      li.appendChild(role);
    } else if (h.role && h.role !== 'Unknown') {
      const role = document.createElement('span');
      role.className = 'role';
      role.textContent = ' — ' + h.role;
      li.appendChild(role);
    }
    if (h.services && h.services.length) {
      const svc = document.createElement('span');
      svc.className = 'role';
      svc.textContent = ' · ' + h.services.join(', ');
      li.appendChild(svc);
    }
    if (h.device) {
      const dev = document.createElement('span');
      dev.className = 'dev';
      dev.textContent = ' ◈ ' + h.device;
      li.appendChild(dev);
    }
    if (h.vendor) {
      const ven = document.createElement('span');
      ven.className = 'role';
      ven.textContent = ' · ' + h.vendor;
      li.appendChild(ven);
    }
    li.title = h.id;
    li.onclick = () => {
      if (hlMode === 'terrain') {
        zoomToTerrain(h);
        return;
      }
      activateTab('investigate');
      $('ev').textContent =
        h.label +
        (h.role_override ? '\nrole: ✎ ' + h.role_override + ' (operator)\ninferred: ' + h.role : '\nrole: ' + h.role) +
        (h.rank ? '\nrank: #' + h.rank : '') +
        '\ncomposite: ' + (h.composite || 0).toFixed(2) +
        (h.device ? '\ndevice: ◈ ' + h.device : '') +
        ((h.labels || []).length ? '\nlabels: ' + h.labels.join(', ') : '') +
        ((h.services || []).length ? '\nservices: ' + h.services.join(', ') : '') +
        (h.mac ? '\nMAC: ' + h.mac + (h.vendor ? ' (' + h.vendor + ')' : '') : '') +
        ((h.evidence || []).length ? '\n\n' + h.evidence.join('\n') : '\n\n(no role evidence)');
    };
    li.oncontextmenu = (ev) => {
      if (!/^[0-9a-f:.]+$/i.test(h.id)) return;
      ev.preventDefault();
      openHostMenu(h.id, h.role_override || '', ev.clientX, ev.clientY);
    };
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? 'showing ' + HL_MAX_ROWS + ' of ' + match.length + ' hosts — type to narrow'
    : match.length + ' host' + (match.length === 1 ? '' : 's');
}

function renderSnapshotRows(q) {
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q
    ? snapshotEntries.filter((en) => (en.Timestamp + ' ' + (en.Snapshot || '')).toLowerCase().includes(q))
    : snapshotEntries;
  hlShown = [];
  for (const en of match.slice(0, HL_MAX_ROWS)) {
    const li = document.createElement('li');
    li.textContent = en.Timestamp;
    if (en.Snapshot === currentSnapshotPath) li.className = 'sel';
    if (en.Snapshot) {
      li.onclick = () => { openSnapshot(en.Snapshot); closeHostList(); };
      li.title = en.Snapshot;
    } else {
      li.style.opacity = '0.4';
      li.title = 'snapshot file missing — map cannot be rebuilt';
    }
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? 'showing ' + HL_MAX_ROWS + ' of ' + match.length + ' snapshots — type to narrow'
    : match.length + ' snapshot' + (match.length === 1 ? '' : 's');
}

$('hl-close').onclick = closeHostList;
$('hl-filter').addEventListener('input', (e) => renderHostList(e.target.value.trim().toLowerCase()));

$('hl-tag').onclick = async () => {
  if (hlMode !== 'hosts') return;
  const req = tagRequest();
  if (!req) { logLine('AI tagging: set endpoint and model in the AI panel first', 'warn'); return; }
  let ips = hlShown.map((h) => h.id);
  if (!ips.length) return;
  if (ips.length > HL_TAG_CAP) {
    logLine('tagging first ' + HL_TAG_CAP + ' of ' + ips.length + ' listed hosts — filter to narrow', 'warn');
    ips = ips.slice(0, HL_TAG_CAP);
  }
  const button = $('hl-tag');
  button.disabled = true;
  $('hl-note').textContent = 'requesting suggestions for ' + ips.length + ' host' + (ips.length === 1 ? '' : 's') + '…';
  try {
    const result = await SuggestTagsForHosts(req, ips);
    const count = (result.tags || []).length;
    logLine('saved ' + count + ' model-assisted tag suggestion' + (count === 1 ? '' : 's') + ' for listed hosts', 'ok');
    const title = $('hl-title').textContent;
    await openSnapshot(currentSnapshotPath);
    // openSnapshot rebuilds the map; reopen the same aggregate list.
    if (aggListNode) openHostList(aggListNode, title);
  } catch (err) {
    logLine('per-group tagging failed: ' + err, 'err');
    $('hl-note').textContent = 'tagging failed';
  } finally {
    button.disabled = false;
  }
};

/* ---------------- devices ---------------- */

let registry = { devices: [], labels: {}, role_overrides: {}, dismissed_hints: [], pinned_ips: [], segments: [] };

async function refreshDevices() {
  try {
    const reg = await ListDevices();
    registry = {
      devices: (reg && reg.devices) || [],
      labels: (reg && reg.labels) || {},
      role_overrides: (reg && reg.role_overrides) || {},
      dismissed_hints: (reg && reg.dismissed_hints) || [],
      pinned_ips: (reg && reg.pinned_ips) || [],
      show_all_private: !!(reg && reg.show_all_private),
      segments: (reg && reg.segments) || [],
    };
  } catch (err) {
    logLine('could not load device registry: ' + err, 'err');
    return;
  }
  $('l-allpriv').checked = registry.show_all_private;
  renderDevices();
  renderHints();
  renderSegments();
  applyDeviceBadges();
}

function renderSegments() {
  const list = $('seglist');
  list.innerHTML = '';
  const segs = registry.segments || [];
  $('segempty').style.display = segs.length ? 'none' : 'block';
  for (const s of segs) {
    const li = document.createElement('li');
    li.textContent = s.cidr + (s.name ? ' — ' + s.name : '') + ' ';
    const rm = document.createElement('button');
    rm.textContent = '✕';
    rm.title = 'remove override';
    rm.onclick = async () => {
      try {
        await RemoveSegment(s.cidr);
        await refreshDevices();
        if (currentSnapshotPath) await openSnapshot(currentSnapshotPath);
      } catch (err) { logLine('remove segment failed: ' + err, 'err'); }
    };
    li.appendChild(rm);
    list.appendChild(li);
  }
}

$('seg-add').onclick = async function () {
  const cidr = $('seg-cidr').value.trim();
  if (!cidr) return;
  try {
    await SetSegment(cidr, $('seg-name').value.trim());
    $('seg-cidr').value = ''; $('seg-name').value = '';
    logLine('segment ' + cidr + ' declared — reloading map', 'ok');
    await refreshDevices();
    if (currentSnapshotPath) await openSnapshot(currentSnapshotPath);
  } catch (err) { logLine('add segment failed: ' + err, 'err'); }
};

$('l-allpriv').onchange = async function () {
  try {
    await SetShowAllPrivate(this.checked);
    registry.show_all_private = this.checked;
    logLine(this.checked ? 'showing all private hosts — reloading map' : 'collapsing private hosts to overview — reloading map', 'ok');
    if (currentSnapshotPath) await openSnapshot(currentSnapshotPath);
  } catch (err) {
    logLine('show-all-private toggle failed: ' + err, 'err');
    this.checked = !this.checked; // revert on failure
  }
};

function renderDevices() {
  const list = $('devlist');
  list.innerHTML = '';
  $('devempty').style.display = registry.devices.length ? 'none' : 'block';
  for (const d of registry.devices) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'dev';
    name.textContent = '◈ ' + d.name;
    li.appendChild(name);
    const count = (d.ips || []).length;
    const meta = (d.type ? d.type + ', ' : '') + count + ' IP' + (count === 1 ? '' : 's');
    li.appendChild(document.createTextNode(' (' + meta + ')'));
    li.onclick = () => showDeviceCard(d.name);
    list.appendChild(li);
  }
}

async function renderHints() {
  const box = $('devhints');
  box.innerHTML = '';
  if (!currentSnapshotPath) return;
  let hints = [];
  try {
    hints = (await DeviceHints(currentSnapshotPath)) || [];
  } catch (err) {
    logLine('could not compute device hints: ' + err, 'err');
    return;
  }
  for (const h of hints) {
    const div = document.createElement('div');
    div.className = 'dh';
    div.appendChild(document.createTextNode('"' + h.hostname + '" seen on ' + h.ips.length + ' IPs — same device?'));
    const act = document.createElement('div');
    act.className = 'act';
    const nameIn = document.createElement('input');
    nameIn.value = h.hostname;
    nameIn.placeholder = h.hostname;
    const link = document.createElement('button');
    link.textContent = 'link';
    link.onclick = async () => {
      const name = nameIn.value.trim() || h.hostname;
      try {
        for (const ip of h.ips) await AssignIP(name, ip);
        logLine('linked ' + h.ips.length + ' IPs as device "' + name + '"', 'ok');
        await refreshDevices();
      } catch (err) { logLine('link failed: ' + err, 'err'); }
    };
    const dis = document.createElement('button');
    dis.textContent = 'dismiss';
    dis.onclick = async () => {
      try { await DismissHint(h.key); await refreshDevices(); }
      catch (err) { logLine('dismiss failed: ' + err, 'err'); }
    };
    act.appendChild(nameIn);
    act.appendChild(link);
    act.appendChild(dis);
    div.appendChild(act);
    box.appendChild(div);
  }
}

function deviceForIP(ip) {
  for (const d of registry.devices) if ((d.ips || []).includes(ip)) return d;
  return null;
}

function applyDeviceBadges() {
  if (!cy) return;
  cy.nodes(':childless').forEach((n) => {
    const d = deviceForIP(n.data('id'));
    n.data('device', d ? d.name : '');
    n.data('labels', (registry.labels[n.data('id')] || []).join(', '));
    n.data('roleOverride', registry.role_overrides[n.data('id')] || '');
    n.toggleClass('dev-linked', !!d);
  });
}

function showDeviceCard(name) {
  const d = registry.devices.find((x) => x.name === name);
  if (!d) return;
  const ev = $('ev');
  ev.textContent = '';
  activateTab('investigate');
  const card = document.createElement('div');
  card.className = 'devcard';
  const head = document.createElement('div');
  head.textContent = '◈ ' + d.name + (d.type ? ' (' + d.type + ')' : '');
  head.style.color = '#a78bfa';
  const pencil = document.createElement('button');
  pencil.textContent = '✎';
  pencil.title = 'rename device';
  const doRename = async (newName) => {
    if (!newName || newName === d.name) { showDeviceCard(d.name); return; }
    try {
      await SaveDevice(d.name, { name: newName, type: d.type || '', notes: d.notes || '', ips: d.ips || [] });
      logLine('renamed "' + d.name + '" → "' + newName + '"', 'ok');
      await refreshDevices();
      showDeviceCard(newName);
    } catch (err) { logLine('rename failed: ' + err, 'err'); }
  };
  pencil.onclick = () => {
    head.textContent = '';
    const inp = document.createElement('input');
    inp.className = 'rename';
    inp.value = d.name;
    const ok = document.createElement('button');
    ok.textContent = 'rename';
    ok.onclick = () => doRename(inp.value.trim());
    const cancel = document.createElement('button');
    cancel.textContent = 'cancel';
    cancel.onclick = () => showDeviceCard(d.name);
    inp.onkeydown = (e) => {
      if (e.key === 'Enter') doRename(inp.value.trim());
      else if (e.key === 'Escape') showDeviceCard(d.name);
    };
    head.appendChild(inp);
    head.appendChild(ok);
    head.appendChild(cancel);
    inp.focus();
    inp.select();
  };
  head.appendChild(document.createTextNode(' '));
  head.appendChild(pencil);
  card.appendChild(head);
  const notes = document.createElement('textarea');
  notes.value = d.notes || '';
  notes.placeholder = 'notes…';
  card.appendChild(notes);
  const save = document.createElement('button');
  save.textContent = 'save notes';
  save.onclick = async () => {
    try {
      await SaveDevice(d.name, { name: d.name, type: d.type || '', notes: notes.value, ips: d.ips || [] });
      logLine('saved notes for ' + d.name, 'ok');
      await refreshDevices();
    } catch (err) { logLine('save failed: ' + err, 'err'); }
  };
  card.appendChild(save);

  // Topology: network layer + owned ranges (drives the topology layout —
  // bands and the flow routing through this device).
  const topo = document.createElement('div');
  topo.style.marginTop = '6px';
  const layLbl = document.createElement('label');
  layLbl.textContent = 'network layer';
  topo.appendChild(layLbl);
  const lay = document.createElement('select');
  for (const [val, txt] of [['', 'none (host)'], ['boundary', 'boundary (firewall/edge)'], ['router', 'router (core)'], ['switch', 'switch']]) {
    const o = document.createElement('option');
    o.value = val; o.textContent = txt;
    if (deviceLayer(d.type) === val) o.selected = true;
    lay.appendChild(o);
  }
  lay.onchange = async () => {
    try {
      await SaveDevice(d.name, { name: d.name, type: lay.value, notes: d.notes || '', ips: d.ips || [] });
      logLine('set ' + d.name + ' layer → ' + (lay.value || 'host'), 'ok');
      await refreshDevices(); showDeviceCard(d.name);
    } catch (err) { logLine('layer set failed: ' + err, 'err'); }
  };
  topo.appendChild(lay);
  const hint = document.createElement('div');
  hint.className = 'hint';
  hint.style.marginTop = '4px';
  hint.textContent = 'in topology view this device is pulled into its layer band; link all its IPs so they move with it';
  topo.appendChild(hint);
  card.appendChild(topo);

  for (const ip of d.ips || []) {
    const row = document.createElement('div');
    const a = document.createElement('span');
    a.className = 'ip';
    a.textContent = ip;
    a.title = 'zoom to node';
    a.onclick = () => {
      if (!cy) return;
      const n = cy.getElementById(ip);
      if (n.nonempty()) { cy.animate({ center: { eles: n }, zoom: 1.4, duration: 300 }); }
      else logLine(ip + ' is not individually visible on this map (aggregated)', 'warn');
    };
    row.appendChild(a);
    const un = document.createElement('button');
    un.textContent = 'unlink';
    un.style.marginLeft = '8px';
    un.onclick = async () => {
      try { await UnassignIP(ip); await refreshDevices(); showDeviceCard(d.name); }
      catch (err) { logLine('unlink failed: ' + err, 'err'); }
    };
    row.appendChild(un);
    card.appendChild(row);
  }
  const del = document.createElement('button');
  del.textContent = 'delete device';
  del.onclick = async () => {
    try { await DeleteDevice(d.name); logLine('deleted device ' + d.name, 'ok'); $('ev').textContent = 'click a node'; await refreshDevices(); }
    catch (err) { logLine('delete failed: ' + err, 'err'); }
  };
  card.appendChild(del);
  ev.appendChild(card);
}

let searchTimer;
$('search').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim().toLowerCase();
  searchTimer = setTimeout(() => {
    if (!cy) return;
    if (!q) { cy.nodes(':childless').removeClass('dim'); return; }
    cy.nodes(':childless').forEach((n) => n.toggleClass('dim', !(n.data('hay') || '').includes(q)));
  }, 150);
});

const ctxmenu = $('ctxmenu');
document.addEventListener('click', (e) => {
  if (!ctxmenu.contains(e.target)) ctxmenu.style.display = 'none';
  const cfg = $('scancfg');
  if (cfg.style.display === 'block' && !cfg.contains(e.target) && e.target !== $('scanbtn')) cfg.style.display = 'none';
  const ai = $('aicfg');
  if (ai.style.display === 'block' && !ai.contains(e.target) && e.target !== $('gearbtn')) ai.style.display = 'none';
});

function ctxAddItem(label, fn) {
  const d = document.createElement('div');
  d.textContent = label;
  d.onclick = fn;
  ctxmenu.appendChild(d);
}

// openHostMenu shows the shared per-host actions (Copy IP / Assign to device /
// Set role) at x,y. Used by both map nodes and host-list rows. extra(addItem)
// appends caller-specific items (map nodes add focus controls).
function openHostMenu(ip, roleOverride, x, y, extra) {
  ctxmenu.innerHTML = '';
  ctxAddItem('Copy IP', () => navigator.clipboard.writeText(ip));
  ctxAddItem('Assign to device…', (click) => {
    // The rebuild below detaches this menu item; without this the same click
    // bubbles to the document close handler, which no longer sees the target
    // inside #ctxmenu and hides the picker instantly.
    click.stopPropagation();
    ctxmenu.innerHTML = '';
    const doAssign = async (name) => {
      try {
        const moved = await AssignIP(name, ip);
        logLine('assigned ' + ip + ' to ' + name + (moved ? ' (moved from ' + moved + ')' : ''), 'ok');
        ctxmenu.style.display = 'none';
        await refreshDevices();
      } catch (err) { logLine('assign failed: ' + err, 'err'); }
    };
    for (const d of registry.devices) ctxAddItem('→ ' + d.name, () => doAssign(d.name));
    const inp = document.createElement('input');
    inp.placeholder = 'new device name…';
    inp.style.margin = '6px';
    inp.style.width = 'calc(100% - 12px)';
    inp.onclick = (ev) => ev.stopPropagation();
    inp.onkeydown = (ev) => { if (ev.key === 'Enter' && inp.value.trim()) doAssign(inp.value.trim()); };
    ctxmenu.appendChild(inp);
    inp.focus();
  });
  ctxAddItem('Set role…', (click) => {
    // Same detach-vs-document-close race as the device picker.
    click.stopPropagation();
    ctxmenu.innerHTML = '';
    const inp = document.createElement('input');
    inp.setAttribute('list', 'role-list');
    inp.placeholder = 'role — empty clears…';
    inp.value = roleOverride || '';
    inp.style.margin = '6px';
    inp.style.width = 'calc(100% - 12px)';
    inp.onclick = (ev) => ev.stopPropagation();
    inp.onkeydown = async (ev) => {
      if (ev.key !== 'Enter') return;
      const role = inp.value.trim();
      try {
        await SetRole(ip, role);
        logLine(role ? 'set role of ' + ip + ' to ' + role : 'cleared role override on ' + ip, 'ok');
        ctxmenu.style.display = 'none';
        await refreshDevices();
      } catch (err) { logLine('set role failed: ' + err, 'err'); }
    };
    ctxmenu.appendChild(inp);
    inp.focus();
  });
  const pinned = (registry.pinned_ips || []).includes(ip);
  ctxAddItem(pinned ? 'Unpin from map' : 'Pin to map', async (click) => {
    click.stopPropagation();
    try {
      if (pinned) await UnpinFromMap(ip); else await PinToMap(ip);
      logLine((pinned ? 'unpinned ' : 'pinned ') + ip + ' — reloading map', 'ok');
      ctxmenu.style.display = 'none';
      await refreshDevices();
      if (currentSnapshotPath) openSnapshot(currentSnapshotPath);
    } catch (err) { logLine('pin toggle failed: ' + err, 'err'); }
  });
  if (extra) extra(ctxAddItem);
  ctxmenu.style.left = x + 'px';
  ctxmenu.style.top = y + 'px';
  ctxmenu.style.display = 'block';
}

function bindContextMenu() {
  cy.on('cxttap', 'node:childless', (e) => {
    const n = e.target;
    const pos = e.renderedPosition || e.position;
    // Aggregate and gateway nodes aren't real single hosts: only offer focus.
    if (n.data('agg') || n.data('gw')) {
      ctxmenu.innerHTML = '';
      ctxAddItem('Copy IP', () => navigator.clipboard.writeText(n.data('id')));
      ctxAddItem('Show evidence', () => cy.emit('tap', [n]));
      ctxAddItem('Focus this group', () => {
        const group = n.data('parent');
        cy.nodes(':childless').forEach((m) => m.toggleClass('dim', m.data('parent') !== group));
      });
      ctxAddItem('Clear focus', () => cy.nodes(':childless').removeClass('dim'));
      ctxmenu.style.left = pos.x + 'px';
      ctxmenu.style.top = pos.y + 'px';
      ctxmenu.style.display = 'block';
      return;
    }
    openHostMenu(n.data('id'), n.data('roleOverride') || '', pos.x, pos.y, (addItem) => {
      addItem('Show evidence', () => cy.emit('tap', [n]));
      addItem('Focus this group', () => {
        const group = n.data('parent');
        cy.nodes(':childless').forEach((m) => m.toggleClass('dim', m.data('parent') !== group));
      });
      addItem('Clear focus', () => cy.nodes(':childless').removeClass('dim'));
    });
  });
}

/* connection trust warnings (insecure TLS, writable key) */
EventsOn('connect:warning', (msg) => logLine('warning: ' + msg, 'warn'));
EventsOn('device:warning', (msg) => logLine('warning: ' + msg, 'warn'));

/* native File-menu events still work in the console */
EventsOn('snapshot:open', openSnapshot);
EventsOn('snapshots:refresh', () => refreshList(false));
