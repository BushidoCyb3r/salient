import { Connect, RunScan, CancelScan, ListSnapshots, LoadModel, ExportMap, ExportImage, Legend, SuggestTags, AggregateHosts, ListDevices, SaveDevice, DeleteDevice, AssignIP, UnassignIP, SetLabels, DismissHint, DeviceHints } from '../wailsjs/go/main/App.js';
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
  } catch (err) {
    $('connerr').textContent = 'Connect failed: ' + err;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Connect';
  }
});

/* ---------------- snapshot list ---------------- */

async function refreshList(loadNewest) {
  let entries;
  try {
    entries = await ListSnapshots();
  } catch (err) {
    logLine('could not list snapshots: ' + err, 'err');
    return;
  }
  entries = entries || [];
  const list = $('snaplist');
  list.innerHTML = '';
  $('snaplist-empty').style.display = entries.length === 0 ? 'block' : 'none';
  for (const en of entries) {
    const li = document.createElement('li');
    li.textContent = en.Timestamp;
    if (en.Snapshot) {
      li.onclick = () => {
        openSnapshot(en.Snapshot);
        list.querySelectorAll('li').forEach((x) => x.classList.toggle('sel', x === li));
      };
    } else {
      li.style.opacity = '0.4';
      li.title = 'snapshot file missing — map cannot be rebuilt';
    }
    list.appendChild(li);
  }
  if (loadNewest && entries.length && entries[0].Snapshot) {
    openSnapshot(entries[0].Snapshot);
    list.firstChild.classList.add('sel');
  }
}

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
const tierColor = { core: '#241a15', service: '#141d2b', client: '#1c232d' };
const tierBorder = { core: '#d9773f', service: '#4d8fe0', client: '#586274' };
const layouts = {
  fcose: { name: 'fcose', animate: false, nodeSeparation: 120, idealEdgeLength: () => 140 },
  dagre: { name: 'dagre', animate: false, rankDir: 'TB', ranker: 'tight-tree', rankSep: 90, nodeSep: 30, transform: (n, p) => p },
};

function runLayout(name) {
  curLayout = name;
  cy.layout(layouts[name]).run();
  $('b-fcose').classList.toggle('on', name === 'fcose');
  $('b-dagre').classList.toggle('on', name === 'dagre');
}
$('b-fcose').onclick = () => { if (cy) runLayout('fcose'); };
$('b-dagre').onclick = () => { if (cy) runLayout('dagre'); };

let currentSnapshotPath = '';

function openSnapshot(path) {
  LoadModel(path).then((model) => {
    currentSnapshotPath = path;
    closeHostList();
    $('exportbtn').disabled = false;
    $('ai-tagbtn').disabled = false;
    $('ai-status').textContent = 'ready';
    renderModel(model);
    refreshDevices();
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

$('ai-tagbtn').onclick = async () => {
  if (!currentSnapshotPath) return;
  const button = $('ai-tagbtn');
  const model = $('ai-model').value.trim();
  let endpoint = $('ai-endpoint').value.trim();
  if (!model || !endpoint) {
    $('ai-status').textContent = 'endpoint and model are required';
    return;
  }
  endpoint = endpoint.replace('{model}', encodeURIComponent(model));
  button.disabled = true;
  $('ai-status').textContent = 'requesting suggestions…';
  try {
    const result = await SuggestTags({
      SnapshotPath: currentSnapshotPath,
      Provider: $('ai-provider').value,
      Endpoint: endpoint,
      Model: model,
      APIKey: $('ai-key').value,
      AllowRemote: $('ai-egress').checked,
    });
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
        device: n.device || '', deviceType: n.device_type || '', labels: (n.labels || []).join(', '),
        aiTags: (n.suggested_tags || []).join(', '), aiConfidence: n.suggestion_confidence || 0,
        aiRationale: n.suggestion_rationale || '', aiModel: n.suggestion_model || '',
      },
      classes: (n.drift ? 'drift-' + n.drift + ' ' : '') + (n.device ? 'dev-linked ' : '') + (n.suggested_tags?.length ? 'ai-tagged' : ''),
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
    container: $('cy'), elements: els, wheelSensitivity: 0.2,
    style: [
      { selector: 'node.grp', style: { 'background-color': '#161b22', 'background-opacity': 0.6, 'border-color': '#30363d', 'border-width': 1, shape: 'round-rectangle', label: 'data(label)', 'text-valign': 'top', 'font-size': 12, 'font-weight': 600, color: '#8b949e', padding: 18 } },
      { selector: 'node.grp.blind', style: { 'border-color': '#a0424a', 'border-style': 'dashed', 'background-color': '#2a1416' } },
      { selector: 'node:childless', style: { shape: 'round-rectangle', width: 120, height: 34, label: (ele) => ele.data('device') ? ele.data('device') + ' · ' + ele.data('label') : ele.data('label'), 'text-valign': 'center', 'font-size': 10, color: '#c9d1d9', 'background-color': (ele) => tierColor[ele.data('tier')] || '#1c232d', 'border-width': 1.6, 'border-color': (ele) => tierBorder[ele.data('tier')] || '#586274' } },
      { selector: 'node[gw=1]', style: { shape: 'diamond', height: 40 } },
      { selector: 'node[inf=1]', style: { 'border-style': 'dashed' } },
      { selector: 'node[agg>0]', style: { shape: 'round-rectangle', 'border-style': 'double', 'border-width': 3 } },
      { selector: 'node.ai-tagged', style: { 'border-color': '#39d3ff', 'border-width': 4 } },
      { selector: 'node.dev-linked', style: { 'border-color': '#a78bfa', 'border-width': 3 } },
      { selector: 'node.drift-new', style: { 'border-color': '#3fb950', 'border-width': 4 } },
      { selector: 'node.drift-vanished', style: { opacity: 0.35, 'border-style': 'dashed', 'border-color': '#8b949e' } },
      { selector: 'node.drift-rank-up,node.drift-rank-down', style: { 'border-color': '#e3a008', 'border-width': 4 } },
      { selector: 'node.drift-undocumented', style: { 'border-color': '#f85149', 'border-width': 4 } },
      { selector: 'node.drift-silent', style: { opacity: 0.35, 'border-style': 'dashed', 'border-color': '#8b949e' } },
      { selector: 'node.drift-contradicted', style: { 'border-color': '#e3a008', 'border-width': 4, 'border-style': 'double' } },
      { selector: 'edge', style: { 'curve-style': 'bezier', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle', width: 'data(width)', label: 'data(label)', 'font-size': 9, color: '#8b949e', 'text-rotation': 'autorotate', 'text-background-color': '#0b0f14', 'text-background-opacity': 0.85, opacity: 0.85 } },
      { selector: 'edge.drift-new', style: { 'line-color': '#3fb950', 'target-arrow-color': '#3fb950', 'line-style': 'solid', opacity: 1 } },
      { selector: 'edge.drift-vanished', style: { 'line-color': '#8b949e', 'target-arrow-color': '#8b949e', 'line-style': 'dashed', opacity: 0.35 } },
      { selector: 'node.drift-off', style: { opacity: 1, 'border-width': 1.6, 'border-style': 'solid', 'border-color': (ele) => tierBorder[ele.data('tier')] || '#586274' } },
      { selector: 'edge.drift-off', style: { opacity: 0.85, 'line-style': 'solid', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)' } },
      { selector: '.dim', style: { opacity: 0.12 } },
    ],
  });
  runLayout(curLayout);
  bindContextMenu();

  $('l-heat').onchange = function () {
    if (this.checked) {
      cy.nodes(':childless').forEach((n) => {
        const c = n.data('comp');
        n.style('background-color', 'rgb(' + Math.round(40 + 180 * c) + ',' + Math.round(30 + 40 * c) + ',' + Math.round(25 + 20 * c) + ')');
      });
    } else {
      cy.nodes(':childless').forEach((n) => n.removeStyle('background-color'));
    }
  };
  $('l-lbl').onchange = function () { cy.edges().style('text-opacity', this.checked ? 1 : 0); };
  $('l-drift').onchange = function () {
    cy.elements('.drift-new,.drift-vanished,.drift-rank-up,.drift-rank-down,.drift-changed,.drift-undocumented,.drift-silent,.drift-contradicted')
      .toggleClass('drift-off', !this.checked);
  };

  cy.on('tap', 'node:childless', (e) => {
    const n = e.target;
    if (n.data('agg') > 0) { openHostList(n.data('id'), n.data('label')); return; }
    showNodeEvidence(n);
  });
}

function showNodeEvidence(n) {
  const ev = $('ev');
  ev.textContent = '';
  const ip = n.data('id');
  const aiDismissed = registry.dismissed_hints.includes('ai:' + ip);
  let text =
    n.data('label') + '\nrole: ' + n.data('role') + (n.data('rank') ? '\nrank: #' + n.data('rank') : '') +
    '\ncomposite: ' + (n.data('comp') || 0).toFixed(2) + (n.data('drift') ? '\ndrift: ' + n.data('drift') : '') +
    (n.data('device') ? '\ndevice: ◈ ' + n.data('device') : '') +
    (n.data('labels') ? '\nlabels: ' + n.data('labels') : '') +
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
let hlHosts = [];

async function openHostList(nodeID, title) {
  let hosts;
  try {
    hosts = await AggregateHosts(currentSnapshotPath, nodeID);
  } catch (err) {
    logLine('could not load host list: ' + err, 'err');
    return;
  }
  hlHosts = hosts || [];
  $('hl-title').textContent = title;
  $('hl-filter').value = '';
  $('hostlist').style.display = 'flex';
  renderHostList('');
  $('hl-filter').focus();
}

function closeHostList() {
  $('hostlist').style.display = 'none';
  hlHosts = [];
}

function renderHostList(q) {
  const list = $('hl-list');
  list.innerHTML = '';
  const match = q
    ? hlHosts.filter((h) => (h.id + ' ' + h.label + ' ' + h.role).toLowerCase().includes(q))
    : hlHosts;
  for (const h of match.slice(0, HL_MAX_ROWS)) {
    const li = document.createElement('li');
    li.textContent = h.label.split('\n')[0];
    if (h.rank) {
      const rank = document.createElement('span');
      rank.className = 'rank';
      rank.textContent = ' #' + h.rank;
      li.appendChild(rank);
    }
    if (h.role && h.role !== 'Unknown') {
      const role = document.createElement('span');
      role.className = 'role';
      role.textContent = ' — ' + h.role;
      li.appendChild(role);
    }
    if (h.device) {
      const dev = document.createElement('span');
      dev.className = 'dev';
      dev.textContent = ' ◈ ' + h.device;
      li.appendChild(dev);
    }
    li.title = h.id;
    li.onclick = () => {
      $('ev').textContent =
        h.label + '\nrole: ' + h.role + (h.rank ? '\nrank: #' + h.rank : '') +
        '\ncomposite: ' + (h.composite || 0).toFixed(2) +
        ((h.evidence || []).length ? '\n\n' + h.evidence.join('\n') : '\n\n(no role evidence)');
    };
    list.appendChild(li);
  }
  $('hl-note').textContent = match.length > HL_MAX_ROWS
    ? 'showing ' + HL_MAX_ROWS + ' of ' + match.length + ' hosts — type to narrow'
    : match.length + ' host' + (match.length === 1 ? '' : 's');
}

$('hl-close').onclick = closeHostList;
$('hl-filter').addEventListener('input', (e) => renderHostList(e.target.value.trim().toLowerCase()));

/* ---------------- devices ---------------- */

let registry = { devices: [], labels: {}, dismissed_hints: [] };

async function refreshDevices() {
  try {
    const reg = await ListDevices();
    registry = {
      devices: (reg && reg.devices) || [],
      labels: (reg && reg.labels) || {},
      dismissed_hints: (reg && reg.dismissed_hints) || [],
    };
  } catch (err) {
    logLine('could not load device registry: ' + err, 'err');
    return;
  }
  renderDevices();
  renderHints();
  applyDeviceBadges();
}

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
    const link = document.createElement('button');
    link.textContent = 'link as ' + h.hostname;
    link.onclick = async () => {
      try {
        for (const ip of h.ips) await AssignIP(h.hostname, ip);
        logLine('linked ' + h.ips.length + ' IPs as device "' + h.hostname + '"', 'ok');
        await refreshDevices();
      } catch (err) { logLine('link failed: ' + err, 'err'); }
    };
    const dis = document.createElement('button');
    dis.textContent = 'dismiss';
    dis.onclick = async () => {
      try { await DismissHint(h.key); await refreshDevices(); }
      catch (err) { logLine('dismiss failed: ' + err, 'err'); }
    };
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
    n.toggleClass('dev-linked', !!d);
  });
}

function showDeviceCard(name) {
  const d = registry.devices.find((x) => x.name === name);
  if (!d) return;
  const ev = $('ev');
  ev.textContent = '';
  const card = document.createElement('div');
  card.className = 'devcard';
  const head = document.createElement('div');
  head.textContent = '◈ ' + d.name + (d.type ? ' (' + d.type + ')' : '');
  head.style.color = '#a78bfa';
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

$('search').addEventListener('input', (e) => {
  if (!cy) return;
  const q = e.target.value.trim().toLowerCase();
  if (!q) { cy.nodes(':childless').removeClass('dim'); return; }
  cy.nodes(':childless').forEach((n) => {
    const hay = (n.data('label') + ' ' + n.data('role') + ' ' + n.data('ev') + ' ' + n.data('aiTags') + ' ' + n.data('device') + ' ' + n.data('labels')).toLowerCase();
    n.toggleClass('dim', !hay.includes(q));
  });
});

const ctxmenu = $('ctxmenu');
document.addEventListener('click', (e) => {
  if (!ctxmenu.contains(e.target)) ctxmenu.style.display = 'none';
  const cfg = $('scancfg');
  if (cfg.style.display === 'block' && !cfg.contains(e.target) && e.target !== $('scanbtn')) cfg.style.display = 'none';
});

function bindContextMenu() {
  cy.on('cxttap', 'node:childless', (e) => {
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
    if (!n.data('agg') && !n.data('gw')) {
      addItem('Assign to device…', (click) => {
        // The rebuild below detaches this menu item; without this the same
        // click bubbles to the document close handler, which no longer sees
        // the target inside #ctxmenu and hides the picker instantly.
        click.stopPropagation();
        ctxmenu.innerHTML = '';
        const ip = n.data('id');
        const doAssign = async (name) => {
          try {
            const moved = await AssignIP(name, ip);
            logLine('assigned ' + ip + ' to ' + name + (moved ? ' (moved from ' + moved + ')' : ''), 'ok');
            ctxmenu.style.display = 'none';
            await refreshDevices();
          } catch (err) { logLine('assign failed: ' + err, 'err'); }
        };
        for (const d of registry.devices) addItem('→ ' + d.name, () => doAssign(d.name));
        const inp = document.createElement('input');
        inp.placeholder = 'new device name…';
        inp.style.margin = '6px';
        inp.style.width = 'calc(100% - 12px)';
        inp.onclick = (ev) => ev.stopPropagation();
        inp.onkeydown = (ev) => { if (ev.key === 'Enter' && inp.value.trim()) doAssign(inp.value.trim()); };
        ctxmenu.appendChild(inp);
        inp.focus();
      });
    }
    addItem('Show evidence', () => cy.emit('tap', [n]));
    addItem('Focus this group', () => {
      const group = n.data('parent');
      cy.nodes(':childless').forEach((m) => m.toggleClass('dim', m.data('parent') !== group));
    });
    addItem('Clear focus', () => cy.nodes(':childless').removeClass('dim'));
    ctxmenu.style.left = pos.x + 'px';
    ctxmenu.style.top = pos.y + 'px';
    ctxmenu.style.display = 'block';
  });
}

/* connection trust warnings (insecure TLS, writable key) */
EventsOn('connect:warning', (msg) => logLine('warning: ' + msg, 'warn'));
EventsOn('device:warning', (msg) => logLine('warning: ' + msg, 'warn'));

/* native File-menu events still work in the console */
EventsOn('snapshot:open', openSnapshot);
EventsOn('snapshots:refresh', () => refreshList(false));
