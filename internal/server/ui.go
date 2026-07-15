package server

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netc</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --surface-0: #f6f7f9;
      --surface-1: #ffffff;
      --surface-2: #fbfcfd;
      --ink: #182230;
      --muted: #667085;
      --text-muted: #667085;
      --border: #d8dee8;
      --border-strong: #c5cdd8;
      --accent: #155eef;
      --accent-soft: #e7efff;
      --bg-accent: #e7efff;
      --border-accent: #84adff;
      --text-accent: #155eef;
      --ok: #067647;
      --ok-soft: #e7f6ee;
      --bg-success: #e7f6ee;
      --text-success: #067647;
      --bad: #b42318;
      --bad-soft: #fdeceb;
      --text-danger: #b42318;
      --warn: #b54708;
      --warn-soft: #fff2df;
      --radius: 12px;
      --focus: #155eef;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    [data-theme="dark"] {
      color-scheme: dark;
      --bg: #111418;
      --surface-0: #111418;
      --surface-1: #171b21;
      --surface-2: #1d222a;
      --ink: #e6e9ef;
      --muted: #aab2c0;
      --text-muted: #aab2c0;
      --border: #333a46;
      --border-strong: #434b58;
      --accent: #7aa7ff;
      --accent-soft: #172946;
      --bg-accent: #172946;
      --border-accent: #4d78c4;
      --text-accent: #7aa7ff;
      --ok: #5fd49d;
      --ok-soft: #123426;
      --bg-success: #123426;
      --text-success: #5fd49d;
      --bad: #ff8a80;
      --bad-soft: #3d1716;
      --text-danger: #ff8a80;
      --warn: #ffc46b;
      --warn-soft: #382713;
      --focus: #9bbcff;
    }
    * { box-sizing: border-box; }
    body { margin:0; font:400 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }
    button, input, select, a { border-radius: 8px; }
    button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    header {
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--surface-1);
      border-bottom: 0.5px solid var(--border);
    }
    .topbar {
      height: 56px;
      display: flex;
      align-items: center;
      gap: 18px;
      padding: 0 18px;
    }
    .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .brand-mark {
      display: grid;
      place-items: center;
      width: 32px;
      height: 32px;
      border: 0.5px solid var(--border);
      border-radius: 8px;
      color: var(--accent);
      font: 500 15px/1 var(--mono);
    }
    .brand strong { font-size: 18px; font-weight: 500; }
    .header-nav { display: flex; align-items: center; gap: 4px; margin-left: 4px; }
    .nav-link {
      color: var(--muted);
      text-decoration: none;
      font-weight: 500;
      font-size: 13px;
      padding: 7px 10px;
      border: 0.5px solid transparent;
      border-radius: 8px;
    }
    .nav-link:hover, .nav-link:focus-visible {
      color: var(--accent);
      background: var(--bg-accent);
      border-color: var(--border);
    }
    .nav-link.nav-active {
      color: var(--text-accent);
      background: var(--bg-accent);
      border-color: var(--border-accent);
    }
    .header-actions { margin-left: auto; display: flex; align-items: center; gap: 10px; }
    .status-text { color: var(--muted); font-size: 13px; white-space: nowrap; }
    main { display:grid; grid-template-columns:300px 1fr; min-height:calc(100vh - 56px); }
    aside { border-right:0.5px solid var(--border); background:var(--surface-1); padding:14px; overflow:auto; }
    section { padding:16px; overflow:auto; }
    .metrics { display:grid; grid-template-columns:repeat(2,1fr); gap:8px; margin-bottom:14px; }
    .metric { border:0.5px solid var(--border); border-radius:10px; padding:9px; background:var(--surface-2); }
    .metric b { display:block; font-size:19px; }
    nav.view-nav { display:flex; gap:8px; margin-bottom:14px; border-bottom:0.5px solid var(--border); }
    nav.view-nav button { border:0; border-bottom:2px solid transparent; border-radius:0; color:var(--muted); background:transparent; padding:10px 8px; cursor:pointer; }
    nav.view-nav button.active { color:var(--accent); border-bottom-color:var(--accent); }
    form, .toolbar { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; align-items:flex-end; }
    .query-form { align-items: stretch; }
    label { display:block; color:var(--muted); font-size:12px; margin-bottom:5px; }
    input, select {
      min-width:160px;
      padding:7px 9px;
      border:0.5px solid var(--border);
      border-radius:8px;
      font:inherit;
      background:var(--surface-1);
      color:inherit;
      min-height:36px;
    }
    input.grow { flex:1; min-width:260px; }
    button {
      padding:7px 11px;
      border:0.5px solid var(--accent);
      border-radius:8px;
      background:var(--accent);
      color:#fff;
      font:inherit;
      font-weight:500;
      cursor:pointer;
      min-height:36px;
    }
    [data-theme="dark"] button { color:#0b1220; }
    button.secondary { color:var(--ink); background:var(--surface-1); border-color:var(--border); font-weight:400; }
    button.subtle { color:var(--muted); background:var(--surface-1); border-color:var(--border); font-weight:400; }
    a.cta-link {
      display:inline-flex;
      align-items:center;
      justify-content:center;
      padding:7px 12px;
      border:0.5px solid var(--accent);
      border-radius:8px;
      background:var(--accent-soft);
      color:var(--accent);
      text-decoration:none;
      font-weight:500;
      min-height:36px;
      white-space:nowrap;
    }
    a.cta-link:hover, a.cta-link:focus-visible { background:var(--accent); color:#fff; }
    [data-theme="dark"] a.cta-link:hover, [data-theme="dark"] a.cta-link:focus-visible { color:#0b1220; }
    table { width:100%; border-collapse:collapse; background:var(--surface-1); border:0.5px solid var(--border); border-radius:10px; overflow:hidden; }
    th, td { text-align:left; border-bottom:0.5px solid var(--border); padding:8px 10px; vertical-align:top; }
    th { background:var(--surface-2); font-size:12px; color:var(--muted); position:sticky; top:0; }
    code { font-family: var(--mono); font-size:12px; }
    pre { margin:4px 0 0; white-space:pre-wrap; max-height:120px; overflow:auto; }
    .hint { color:var(--muted); margin:4px 0 12px; font-size:13px; line-height:1.6; }
    .examples { display:inline-flex; flex-wrap:wrap; gap:6px; align-items:center; margin-left:4px; }
    .example-chip {
      border:0.5px solid var(--border);
      background:var(--surface-1);
      color:var(--ink);
      padding:3px 9px;
      min-height:28px;
      font-size:12px;
      font-weight:400;
      cursor:pointer;
    }
    .example-chip:hover { border-color:var(--accent); background:var(--accent-soft); color:var(--accent); }
    .query-help {
      display:none;
      margin:0 0 12px;
      padding:10px 12px;
      border:0.5px solid var(--border);
      border-radius:10px;
      background:var(--surface-2);
      color:var(--muted);
      font-size:13px;
      line-height:1.55;
    }
    .query-help.open { display:block; }
    .error { color:var(--bad); margin:0 0 12px; }
    .error-box {
      padding:10px 12px;
      border:0.5px solid var(--bad);
      border-radius:10px;
      background:var(--bad-soft);
      color:var(--bad);
    }
    .pill { display:inline-block; border:0.5px solid var(--border); border-radius:999px; padding:2px 7px; color:var(--muted); background:var(--surface-2); }
    .badge { display:inline-block; border-radius:999px; padding:2px 7px; color:white; background:#44546a; font-size:12px; }
    .badge.vlan { background:#155eef; }
    .badge.interface { background:#227a52; }
    .badge.route { background:#7a4d00; }
    .badge.acl { background:#7346a1; }
    .badge.device { background:#455569; }
    .badge.access { background:#227a52; }
    .badge.trunk { background:#7a4d00; }
    .badge.trunk_broad { background:#8a6116; }
    .badge.declared { background:#657386; }
    .evidence-path { display:flex; gap:6px; align-items:center; flex-wrap:wrap; }
    .empty {
      padding:18px 16px;
      border:0.5px dashed var(--border);
      border-radius:10px;
      color:var(--muted);
      background:var(--surface-2);
      text-align:center;
      line-height:1.5;
    }
    .empty strong { display:block; color:var(--ink); font-weight:500; margin-bottom:4px; }
    .viz-wrap { border:0.5px solid var(--border); background:var(--surface-1); overflow:auto; margin-bottom:12px; border-radius:10px; }
    .viz { min-width:720px; width:100%; height:360px; display:block; }
    .viz-node { fill:var(--surface-1); stroke:#7890a8; stroke-width:1.2; }
    .viz-node.access { stroke:#227a52; }
    .viz-node.trunk { stroke:#7a4d00; }
    .viz-node.trunk_broad { stroke:#8a6116; stroke-dasharray:4 3; }
    .viz-line { stroke:#9aaaba; stroke-width:2; }
    .viz-line.access { stroke:#227a52; }
    .viz-line.trunk { stroke:#7a4d00; }
    .viz-line.trunk_broad { stroke:#8a6116; stroke-dasharray:5 4; }
    .viz-text { fill:var(--ink); font:12px var(--mono); }
    .viz-muted { fill:var(--muted); font:11px system-ui, -apple-system, Segoe UI, sans-serif; }
    .critical { color:var(--bad); font-weight:600; }
    .warning { color:var(--warn); font-weight:600; }
    .view { display:none; }
    .view.active { display:block; }
    .hidden { display:none !important; }
    .device-meta {
      display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px;
    }
    .device-config { display:flex; flex-direction:column; gap:14px; }
    .norm-section {
      border:0.5px solid var(--border);
      border-radius:var(--radius);
      background:var(--surface-2);
      overflow:hidden;
    }
    .norm-section h3 {
      margin:0;
      padding:10px 12px;
      font-size:13px;
      font-weight:500;
      background:var(--surface-2);
      border-bottom:0.5px solid var(--border);
      color:var(--muted);
    }
    .norm-list { margin:0; padding:0; list-style:none; }
    .norm-item {
      padding:12px 14px;
      border-bottom:0.5px solid var(--border);
      background:var(--surface-1);
    }
    .norm-item:last-child { border-bottom:0; }
    .norm-line {
      font-family:var(--mono);
      font-size:12px;
      line-height:1.55;
      color:var(--ink);
      word-break:break-word;
    }
    .norm-line .tag {
      display:inline-block;
      border:0.5px solid var(--border);
      border-radius:999px;
      padding:0 7px;
      margin-right:6px;
      color:var(--muted);
      font-size:11px;
      font-family:system-ui, -apple-system, sans-serif;
    }
    .norm-evidence {
      margin-top:8px;
    }
    .norm-evidence > summary {
      cursor:pointer;
      list-style:none;
      display:inline-flex;
      align-items:center;
      gap:6px;
      color:var(--muted);
      font-size:12px;
      user-select:none;
    }
    .norm-evidence > summary::-webkit-details-marker { display:none; }
    .norm-evidence > summary::before {
      content:"+";
      display:inline-grid;
      place-items:center;
      width:18px;
      height:18px;
      border:0.5px solid var(--border);
      border-radius:6px;
      font-weight:600;
      line-height:1;
      color:var(--accent);
      background:var(--surface-2);
    }
    .norm-evidence[open] > summary::before { content:"−"; }
    .norm-evidence-body {
      margin-top:8px;
      padding:10px 12px;
      border:0.5px solid var(--border);
      border-radius:8px;
      background:var(--surface-2);
    }
    .norm-evidence-body pre.conf,
    pre.conf {
      margin:0;
      padding:10px 0;
      overflow-x:auto;
      background:var(--surface-1);
      font:400 13px/1.45 var(--mono);
      border-radius:var(--radius);
    }
    .code-line {
      display:grid;
      grid-template-columns:58px minmax(max-content,1fr);
      gap:12px;
      min-height:19px;
      padding:0 10px;
    }
    .code-line.context { opacity:0.55; color:var(--text-muted); }
    .code-line.match {
      opacity:1;
      background:var(--bg-accent);
      color:var(--text-accent);
      border-left:2px solid var(--border-accent);
      margin:0 -10px;
      padding:0 8px 0 10px;
    }
    .line-no { color:var(--text-muted); text-align:right; user-select:none; }
    .evidence-card {
      border:0.5px solid var(--border);
      border-radius:var(--radius);
      background:var(--surface-2);
      overflow:hidden;
    }
    .evidence-card .evidence-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:8px;
      padding:8px 10px;
      border-bottom:0.5px solid var(--border);
      font-size:12px;
    }
    .diff-toolbar {
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      align-items:center;
      margin:0 0 12px;
    }
    .mode-toggle {
      display:inline-flex;
      border:0.5px solid var(--border);
      border-radius:var(--radius);
      overflow:hidden;
      background:var(--surface-1);
    }
    .mode-toggle button {
      border:0;
      border-radius:0;
      background:transparent;
      color:var(--text-muted);
      font-weight:500;
      min-height:34px;
      padding:6px 12px;
    }
    .mode-toggle button.active {
      background:var(--bg-accent);
      color:var(--text-accent);
    }
    .mode-toggle button + button { border-left:0.5px solid var(--border); }
    .diff-summary-bar {
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-bottom:12px;
    }
    .diff-list { display:grid; gap:10px; padding:10px 12px 12px; }
    .diff-change-card {
      border:0.5px solid var(--border);
      border-radius:var(--radius);
      background:var(--surface-1);
      padding:12px 14px;
    }
    .diff-change-head {
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      gap:8px;
      margin-bottom:8px;
    }
    .diff-type-badge {
      display:inline-flex;
      align-items:center;
      border-radius:999px;
      padding:2px 9px;
      font-size:12px;
      font-weight:500;
      text-transform:lowercase;
    }
    .diff-type-badge.diff-add { background:var(--bg-success); color:var(--text-success); }
    .diff-type-badge.diff-remove { background:var(--bad-soft); color:var(--text-danger); }
    .diff-type-badge.diff-change { background:var(--warn-soft); color:var(--warn); }
    td.diff-add, .diff-pane.diff-add { background:var(--bg-success); }
    td.diff-remove, .diff-pane.diff-remove { background:var(--bad-soft); }
    td.diff-change, .diff-pane.diff-change { background:var(--warn-soft); }
    .diff-summary { flex:1; min-width:180px; font-family:var(--mono); font-size:12px; }
    .diff-panes {
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:10px;
      margin-bottom:8px;
    }
    .diff-panes.stacked { grid-template-columns:1fr; }
    .diff-pane {
      border:0.5px solid var(--border);
      border-radius:8px;
      padding:8px 10px;
      min-width:0;
    }
    .diff-label {
      display:block;
      font-size:11px;
      color:var(--text-muted);
      margin-bottom:4px;
      text-transform:uppercase;
      letter-spacing:0.04em;
    }
    .diff-pane-line {
      font-family:var(--mono);
      font-size:12px;
      line-height:1.55;
      word-break:break-word;
    }
    .type-added { color:var(--text-success); font-weight:500; }
    .type-removed { color:var(--text-danger); font-weight:500; }
    .type-changed { color:var(--warn); font-weight:500; }
    @media (max-width: 850px) {
      main { grid-template-columns:1fr; }
      aside { border-right:0; border-bottom:0.5px solid var(--border); }
      .header-actions .status-text { display:none; }
      .diff-panes { grid-template-columns:1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div class="brand">
        <div class="brand-mark">nc</div>
        <strong>netc</strong>
      </div>
      <nav class="header-nav" aria-label="App navigation">
        <a href="/" class="nav-link nav-active">Dashboard</a>
        <a href="/path" class="nav-link">Path</a>
      </nav>
      <div class="header-actions">
        <span id="status" class="status-text">loading</span>
        <button type="button" id="themeButton" class="subtle" aria-pressed="false">Dark</button>
      </div>
    </div>
  </header>
  <main>
    <aside>
      <div class="metrics" id="metrics"></div>
      <label>Devices</label>
      <input id="deviceFilter" placeholder="filter devices" autocomplete="off" style="width:100%; margin-bottom:8px;">
      <table id="devices"><thead><tr><th>device</th><th>if</th><th>vlans</th></tr></thead><tbody></tbody></table>
    </aside>
    <section>
      <nav class="view-nav" aria-label="Views">
        <button class="active secondary" data-view="queryView">Query</button>
        <button class="secondary" data-view="vlanPathView">VLAN Path</button>
        <button class="secondary" data-view="checkView">Compliance</button>
        <button class="secondary" data-view="diffView">Diff</button>
        <button class="secondary" data-view="deviceView">Device</button>
      </nav>

      <div id="queryView" class="view active">
        <form id="queryForm" class="query-form">
          <input id="query" class="grow" value="vlan 2048" autocomplete="off" aria-label="Query">
          <input id="queryLimit" type="number" value="100" min="0" title="limit" aria-label="Result limit">
          <button type="submit">Query</button>
          <a href="/path" class="cta-link">Open path tracer</a>
        </form>
        <div class="hint">
          Try
          <span class="examples">
            <button type="button" class="example-chip secondary" data-query="vlan 42">vlan 42</button>
            <button type="button" class="example-chip secondary" data-query="trunks">trunks</button>
            <button type="button" class="example-chip secondary" data-query="default route">default route</button>
            <button type="button" class="example-chip secondary" data-query="ntp">ntp</button>
            <button type="button" class="example-chip secondary" data-query="route to 192.168.50.0">route to 192.168.50.0</button>
            <button type="button" class="example-chip secondary" data-query="help">help</button>
          </span>
        </div>
        <div id="queryHelp" class="query-help" role="region" aria-label="Query help">
          <strong style="color:var(--ink);">Query language</strong><br>
          <code>vlan 42</code> · <code>trunks</code> · <code>default route</code> · <code>ntp</code> · <code>route to 192.168.50.0</code> · <code>help</code><br>
          Natural language: <code>where is vlan 42</code>, <code>route par defaut</code>, <code>serveurs ntp</code>. Prefix with <code>find</code> if you like.
        </div>
        <div class="toolbar">
          <select id="queryTypeFilter" title="result type">
            <option value="">all types</option>
          </select>
          <select id="queryRoleFilter" title="result role">
            <option value="">all roles</option>
          </select>
          <input id="queryTextFilter" class="grow" placeholder="filter current results" autocomplete="off">
          <span id="queryCount" class="pill">0 results</span>
        </div>
        <div id="queryError" class="error" hidden></div>
        <table id="results"><thead><tr><th>type</th><th>role</th><th>device</th><th>summary</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>

      <div id="vlanPathView" class="view">
        <form id="vlanPathForm">
          <input id="vlanPathId" type="number" value="2048" min="1" max="4094">
          <input id="vlanPathLimit" type="number" value="500" min="0" title="limit">
          <label style="display:flex; align-items:center; gap:6px; margin:0;">
            <input id="vlanPathBroad" type="checkbox" checked style="min-width:auto;">
            broad trunks
          </label>
          <button type="submit">Draw</button>
        </form>
        <div id="vlanPathSummary" class="hint"></div>
        <div id="vlanPathError" class="error" hidden></div>
        <div class="viz-wrap"><svg id="vlanPathSvg" class="viz" role="img"></svg></div>
        <table id="vlanPathRows"><thead><tr><th>role</th><th>device</th><th>summary</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>

      <div id="checkView" class="view">
        <form id="checkForm">
          <input id="ntp" class="grow" value="10.10.10.1,10.10.10.2" autocomplete="off">
          <input id="syslog" class="grow" value="10.10.20.5" autocomplete="off">
          <input id="forbidSnmp" value="public" autocomplete="off">
          <input id="checkLimit" type="number" value="100" min="0">
          <button type="submit">Check</button>
        </form>
        <div id="checkSummary" class="hint"></div>
        <div id="checkError" class="error" hidden></div>
        <table id="findings"><thead><tr><th>severity</th><th>device</th><th>rule</th><th>finding</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>

      <div id="deviceView" class="view">
        <form id="deviceForm">
          <input id="deviceName" class="grow" value="SW-A-02" autocomplete="off">
          <button type="submit">Open</button>
        </form>
        <div id="deviceError" class="error" hidden></div>
        <div id="deviceMeta" class="device-meta"></div>
        <div id="deviceConfig" class="device-config"></div>
      </div>

      <div id="diffView" class="view">
        <form id="diffForm">
          <input id="beforePath" class="grow" placeholder="/path/before.cfg" autocomplete="off">
          <input id="afterPath" class="grow" placeholder="/path/after.cfg" autocomplete="off">
          <button type="submit">Diff</button>
        </form>
        <div id="diffError" class="error" hidden></div>
        <div class="diff-toolbar" id="diffToolbar" hidden>
          <div class="mode-toggle" role="group" aria-label="Diff display mode">
            <button type="button" class="secondary" data-diff-mode="normalized">Normalized diff</button>
            <button type="button" class="secondary" data-diff-mode="table">Table</button>
          </div>
          <div class="mode-toggle" id="diffSubToggle" role="group" aria-label="Normalized diff layout" hidden>
            <button type="button" class="secondary" data-diff-sub="side">Side by side</button>
            <button type="button" class="secondary" data-diff-sub="stacked">Stacked</button>
            <button type="button" class="secondary" data-diff-sub="config">Config lines</button>
          </div>
          <div class="diff-summary-bar" id="diffSummaryBar" hidden></div>
          <span id="diffCount" class="pill">0 changes</span>
        </div>
        <div id="diffResults"></div>
        <table id="diffs" class="hidden"><thead><tr><th>type</th><th>device</th><th>object</th><th>summary</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const THEME_KEY = 'netc.theme';
    let queryRows = [];
    let diffRows = [];
    let diffMode = localStorage.getItem('netc.diffMode') || 'normalized';
    let diffSubMode = localStorage.getItem('netc.diffSubMode') || 'side';
    function setError(id, message) {
      const el = $(id);
      if (!message) {
        el.textContent = '';
        el.className = 'error';
        el.hidden = true;
        return;
      }
      el.textContent = message;
      el.className = 'error error-box';
      el.hidden = false;
    }
    function emptyRow(colspan, title, detail) {
      return '<tr><td colspan="'+colspan+'"><div class="empty"><strong>'+esc(title)+'</strong>'+esc(detail)+'</div></td></tr>';
    }
    async function getJSON(url) {
      const r = await fetch(url);
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.statusText);
      return j;
    }
    function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function evidenceHighlightPre(ev) {
      const raw = String(ev?.raw_block || '');
      if (!raw) return '<span class="code-line"><span class="line-no">?</span><code>No raw block reported</code></span>';
      const lines = raw.split('\n');
      const start = Number(ev.start_line || 1);
      const end = Number(ev.end_line || start);
      return lines.map((line, offset) => {
        const lineNo = start + offset;
        const isMatch = lineNo >= start && lineNo <= end;
        const klass = isMatch ? 'match' : 'context';
        return '<span class="code-line '+klass+'"><span class="line-no">'+esc(lineNo)+'</span><code>'+esc(line || ' ')+'</code></span>';
      }).join('');
    }
    function evidenceCell(ev) {
      if (!ev || !ev.file) return '';
      const loc = esc(ev.file)+':'+(ev.start_line||'?');
      return '<article class="evidence-card"><div class="evidence-head"><code>'+loc+'</code></div><pre class="conf">'+evidenceHighlightPre(ev)+'</pre></article>';
    }
    function evidenceDetails(ev, label) {
      if (!ev || !ev.file) return '';
      const loc = esc(ev.file)+':'+(ev.start_line||'?')+'-'+(ev.end_line || ev.start_line);
      return '<details class="norm-evidence"><summary>'+esc(label || 'Evidence')+' · '+loc+'</summary><div class="norm-evidence-body"><code>'+loc+'</code><pre class="conf">'+evidenceHighlightPre(ev)+'</pre></div></details>';
    }
    function diffSectionKey(object) {
      const o = String(object || '');
      if (o.startsWith('vlan:')) return 'VLANs';
      if (o.startsWith('interface:')) return 'Interfaces';
      if (o.startsWith('route:')) return 'Routes';
      if (o.startsWith('acl:')) return 'ACLs';
      return 'Other';
    }
    function diffTypeClass(type) {
      if (type === 'added') return 'diff-add';
      if (type === 'removed') return 'diff-remove';
      return 'diff-change';
    }
    function diffTypeLabel(type) {
      if (type === 'added') return 'added';
      if (type === 'removed') return 'removed';
      return 'changed';
    }
    function formatDiffObject(obj) {
      if (!obj || typeof obj !== 'object') return String(obj ?? '—');
      if (obj.id !== undefined && (obj.name !== undefined || obj.id !== null)) {
        return 'vlan '+obj.id+(obj.name ? ' '+obj.name : '');
      }
      if (obj.name && (obj.mode || obj.access_vlan || obj.trunk_vlans || obj.ipv4)) {
        const parts = [obj.mode || 'interface', obj.name];
        if (obj.access_vlan) parts.push('access vlan '+obj.access_vlan);
        if (obj.trunk_vlans && obj.trunk_vlans.length) parts.push('trunk '+obj.trunk_vlans.join(','));
        if (obj.ipv4) parts.push('ip '+obj.ipv4);
        if (obj.shutdown) parts.push('shutdown');
        if (obj.description) parts.push(obj.description);
        return parts.join(' · ');
      }
      if (obj.destination) {
        return [obj.destination, obj.next_hop, obj.interface].filter(Boolean).join(' → ');
      }
      if (obj.name) return String(obj.name);
      return JSON.stringify(obj);
    }
    function diffEvidenceBlocks(row) {
      const blocks = [];
      const beforeEv = row.before?.evidence || (row.type === 'removed' ? row.evidence : null);
      const afterEv = row.after?.evidence || (row.type === 'added' ? row.evidence : (row.type === 'changed' ? row.evidence : null));
      if (beforeEv && beforeEv.file) blocks.push({ label: 'Before', ev: beforeEv });
      if (afterEv && afterEv.file) blocks.push({ label: 'After', ev: afterEv });
      if (!blocks.length && row.evidence && row.evidence.file) {
        blocks.push({ label: 'Evidence', ev: row.evidence });
      }
      return blocks;
    }
    function renderDiffEvidenceSection(row) {
      return diffEvidenceBlocks(row).map(b => evidenceDetails(b.ev, b.label)).join('');
    }
    function renderDiffChangeCard(row) {
      const cls = diffTypeClass(row.type);
      const beforeLine = row.before ? formatDiffObject(row.before) : '';
      const afterLine = row.after ? formatDiffObject(row.after) : '';
      let panes = '';
      if (diffSubMode === 'config') {
        const blocks = diffEvidenceBlocks(row);
        if (blocks.length) {
          panes = blocks.map(b =>
            '<div class="diff-pane '+cls+'"><span class="diff-label">'+esc(b.label)+'</span><pre class="conf">'+evidenceHighlightPre(b.ev)+'</pre></div>'
          ).join('');
        }
      } else if (beforeLine || afterLine) {
        const stacked = diffSubMode === 'stacked';
        panes = '<div class="diff-panes'+(stacked ? ' stacked' : '')+'">'+
          (beforeLine ? '<div class="diff-pane diff-remove"><span class="diff-label">Before</span><div class="diff-pane-line">'+esc(beforeLine)+'</div></div>' : '')+
          (afterLine ? '<div class="diff-pane diff-add"><span class="diff-label">After</span><div class="diff-pane-line">'+esc(afterLine)+'</div></div>' : '')+
        '</div>';
      }
      const evidence = renderDiffEvidenceSection(row);
      return '<article class="diff-change-card '+cls+'">'+
        '<div class="diff-change-head">'+
          '<span class="diff-type-badge '+cls+'">'+esc(diffTypeLabel(row.type))+'</span>'+
          '<code>'+esc(row.device)+'</code>'+
          '<code>'+esc(row.object)+'</code>'+
          '<span class="diff-summary">'+esc(row.summary)+'</span>'+
        '</div>'+
        panes+
        evidence+
      '</article>';
    }
    function renderNormalizedDiff(rows) {
      const groups = {};
      rows.forEach(r => {
        const sec = diffSectionKey(r.object);
        (groups[sec] ||= []).push(r);
      });
      const order = ['Interfaces', 'VLANs', 'Routes', 'ACLs', 'Other'];
      const html = order.filter(s => groups[s]).map(section => {
        const items = groups[section].map(r => renderDiffChangeCard(r)).join('');
        return '<section class="norm-section"><h3>'+esc(section)+'</h3><div class="diff-list">'+items+'</div></section>';
      }).join('');
      return html || '<div class="empty"><strong>No differences</strong>Configs match for the selected before and after files.</div>';
    }
    function renderDiffTable(rows) {
      if (!rows.length) {
        return '<table id="diffTableView"><tbody>'+emptyRow(5, 'No differences', 'Configs match for the selected before and after files.')+'</tbody></table>';
      }
      const body = rows.map(d => {
        const cls = diffTypeClass(d.type);
        return '<tr><td><span class="diff-type-badge '+cls+'">'+esc(diffTypeLabel(d.type))+'</span></td><td><code>'+esc(d.device)+'</code></td><td><code>'+esc(d.object)+'</code></td><td>'+esc(d.summary)+'</td><td>'+evidenceCell(d.evidence)+'</td></tr>';
      }).join('');
      return '<table id="diffTableView"><thead><tr><th>type</th><th>device</th><th>object</th><th>summary</th><th>evidence</th></tr></thead><tbody>'+body+'</tbody></table>';
    }
    function diffCounts(rows) {
      const counts = { added: 0, removed: 0, changed: 0 };
      rows.forEach(r => {
        if (r.type === 'added') counts.added++;
        else if (r.type === 'removed') counts.removed++;
        else counts.changed++;
      });
      return counts;
    }
    function updateDiffToolbar() {
      const toolbar = $('diffToolbar');
      const hasRows = diffRows.length > 0;
      toolbar.hidden = !hasRows;
      $('diffSubToggle').hidden = !(hasRows && diffMode === 'normalized');
      $('diffCount').textContent = diffRows.length + ' change' + (diffRows.length === 1 ? '' : 's');
      const summaryBar = $('diffSummaryBar');
      if (hasRows) {
        const c = diffCounts(diffRows);
        summaryBar.hidden = false;
        summaryBar.innerHTML = [
          '<span class="diff-type-badge diff-add">'+c.added+' added</span>',
          '<span class="diff-type-badge diff-remove">'+c.removed+' removed</span>',
          '<span class="diff-type-badge diff-change">'+c.changed+' changed</span>'
        ].join('');
      } else {
        summaryBar.hidden = true;
        summaryBar.innerHTML = '';
      }
      document.querySelectorAll('[data-diff-mode]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.diffMode === diffMode);
      });
      document.querySelectorAll('[data-diff-sub]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.diffSub === diffSubMode);
      });
    }
    function renderDiffResults() {
      updateDiffToolbar();
      if (!diffRows.length) {
        $('diffResults').innerHTML = '<div class="empty"><strong>No differences</strong>Configs match for the selected before and after files.</div>';
        return;
      }
      $('diffResults').innerHTML = diffMode === 'table' ? renderDiffTable(diffRows) : renderNormalizedDiff(diffRows);
    }
    function setDiffMode(mode) {
      diffMode = mode;
      localStorage.setItem('netc.diffMode', mode);
      updateDiffToolbar();
      renderDiffResults();
    }
    function setDiffSubMode(mode) {
      diffSubMode = mode;
      localStorage.setItem('netc.diffSubMode', mode);
      updateDiffToolbar();
      renderDiffResults();
    }
    function normItem(lineHtml, ev, evLabel) {
      return '<li class="norm-item"><div class="norm-line">'+lineHtml+'</div>'+evidenceDetails(ev, evLabel)+'</li>';
    }
    function normSection(title, itemsHtml) {
      if (!itemsHtml) return '';
      return '<section class="norm-section"><h3>'+esc(title)+'</h3><ul class="norm-list">'+itemsHtml+'</ul></section>';
    }
    function tag(text) { return '<span class="tag">'+esc(text)+'</span>'; }
    function joinTags(parts) { return parts.filter(Boolean).join(' '); }
    function renderDeviceConfig(d) {
      const ifs = (d.interfaces || []).slice().sort((a,b) => String(a.name).localeCompare(String(b.name)));
      const vlans = (d.vlans || []).slice().sort((a,b) => (a.id||0) - (b.id||0));
      const routes = (d.routes || []).slice().sort((a,b) => String(a.destination).localeCompare(String(b.destination)));
      const acls = (d.acls || []).slice().sort((a,b) => String(a.name).localeCompare(String(b.name)));
      const zones = (d.zones || []).slice().sort((a,b) => String(a.name).localeCompare(String(b.name)));
      const policies = (d.security_policies || []).slice().sort((a,b) => String(a.name).localeCompare(String(b.name)));
      const ntp = (d.services?.ntp_servers || []).slice().sort((a,b) => String(a.value).localeCompare(String(b.value)));
      const syslog = (d.services?.syslog_hosts || []).slice().sort((a,b) => String(a.value).localeCompare(String(b.value)));
      const snmp = (d.services?.snmp_communities || []).slice().sort((a,b) => String(a.value).localeCompare(String(b.value)));
      $('deviceMeta').innerHTML = [
        '<span class="pill">'+esc(d.hostname)+'</span>',
        d.vendor ? '<span class="pill">'+esc(d.vendor)+'</span>' : '',
        d.source_file ? '<span class="pill"><code>'+esc(d.source_file)+'</code></span>' : '',
        '<span class="pill">'+ifs.length+' if</span>',
        '<span class="pill">'+vlans.length+' vlan</span>',
        '<span class="pill">'+routes.length+' route</span>'
      ].join(' ');
      const sections = [
        normSection('Interfaces', ifs.map(i => {
          const parts = [tag(i.mode || 'unknown'), esc(i.name)];
          if (i.description) parts.push(tag(i.description));
          if (i.access_vlan) parts.push(tag('access vlan '+i.access_vlan));
          if (i.trunk_vlans && i.trunk_vlans.length) parts.push(tag('trunk '+i.trunk_vlans.join(',')));
          if (i.ipv4) parts.push(tag('ip '+i.ipv4));
          if (i.shutdown) parts.push(tag('shutdown'));
          return normItem(joinTags(parts), i.evidence, 'Interface');
        }).join('')),
        normSection('VLANs', vlans.map(v => {
          const parts = [tag('vlan '+v.id)];
          if (v.name) parts.push(esc(v.name));
          return normItem(joinTags(parts), v.evidence, 'VLAN');
        }).join('')),
        normSection('Routes', routes.map(r => {
          const parts = [esc(r.destination)];
          if (r.next_hop) parts.push('→ '+esc(r.next_hop));
          if (r.interface) parts.push(tag('via '+r.interface));
          if (r.vrf) parts.push(tag('vrf '+r.vrf));
          return normItem(joinTags(parts), r.evidence, 'Route');
        }).join('')),
        normSection('ACLs', acls.map(a => {
          const entries = (a.entries || []).length;
          return normItem(joinTags([tag('acl'), esc(a.name), tag(entries+' entr'+(entries===1?'y':'ies'))]), a.evidence, 'ACL');
        }).join('')),
        normSection('Zones', zones.map(z => {
          const ifs = (z.interfaces || []).join(', ');
          return normItem(joinTags([tag('zone'), esc(z.name), ifs ? tag(ifs) : '']), z.evidence, 'Zone');
        }).join('')),
        normSection('Security policies', policies.map(p => {
          const parts = [tag('policy'), esc(p.name)];
          if (p.from_zone || p.to_zone) parts.push(tag((p.from_zone||'?')+' → '+(p.to_zone||'?')));
          if (p.action) parts.push(tag(p.action));
          if (p.service) parts.push(tag(p.service));
          return normItem(joinTags(parts), p.evidence, 'Policy');
        }).join('')),
        normSection('Services', [
          ...ntp.map(s => normItem(joinTags([tag('ntp'), esc(s.value)]), s.evidence, 'NTP')),
          ...syslog.map(s => normItem(joinTags([tag('syslog'), esc(s.value)]), s.evidence, 'Syslog')),
          ...snmp.map(s => normItem(joinTags([tag('snmp'), esc(s.value)]), s.evidence, 'SNMP'))
        ].join(''))
      ].filter(Boolean);
      $('deviceConfig').innerHTML = sections.length
        ? sections.join('')
        : '<div class="empty"><strong>No normalized objects</strong>This device has no parsed interfaces, VLANs, or routes in inventory.</div>';
    }
    function params(obj) {
      const p = new URLSearchParams();
      Object.entries(obj).forEach(([k,v]) => p.set(k, v));
      return p.toString();
    }
    function applyTheme(theme) {
      document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
      $('themeButton').textContent = theme === 'dark' ? 'Light' : 'Dark';
      $('themeButton').setAttribute('aria-pressed', String(theme === 'dark'));
    }
    async function load() {
      const s = await getJSON('/api/summary');
      const vendors = await getJSON('/api/vendors');
      $('status').textContent = s.devices + ' devices · ' + vendors.join(', ');
      const keys = ['devices','interfaces','vlans','routes','acls','ntp_servers','syslog_hosts','snmp_communities'];
      $('metrics').innerHTML = keys.map(k => '<div class="metric"><b>'+esc(s[k] ?? 0)+'</b>'+esc(k)+'</div>').join('');
      await loadPolicy();
      loadDevices();
      runQuery();
      runVlanPath();
      runCheck();
    }
    async function loadPolicy() {
      const p = await getJSON('/api/policy');
      $('ntp').value = (p.required_ntp_servers || []).join(',');
      $('syslog').value = (p.required_syslog_hosts || []).join(',');
      $('forbidSnmp').value = (p.forbidden_snmp_communities || []).join(',');
    }
    async function loadDevices() {
      const devices = await getJSON('/api/devices?q=' + encodeURIComponent($('deviceFilter').value));
      $('devices').querySelector('tbody').innerHTML = devices.slice(0, 120).map(d => '<tr><td><button class="secondary device-open" data-device="'+esc(d.hostname)+'"><code>'+esc(d.hostname)+'</code></button></td><td>'+d.interfaces+'</td><td>'+d.vlans+'</td></tr>').join('');
      if (devices.length > 0 && !$('beforePath').value) $('beforePath').value = devices[0].source_file;
      if (devices.length > 1 && !$('afterPath').value) $('afterPath').value = devices[1].source_file;
    }
    async function runQuery() {
      setError('queryError', '');
      try {
        queryRows = await getJSON('/api/query?' + params({brief:'1', limit:$('queryLimit').value, q:$('query').value}));
        updateQueryTypeFilter(queryRows);
        updateQueryRoleFilter(queryRows);
        renderQueryRows();
      } catch (e) {
        queryRows = [];
        renderQueryRows();
        setError('queryError', e.message);
      }
    }
    async function runVlanPath() {
      setError('vlanPathError', '');
      const vlan = $('vlanPathId').value;
      try {
        const data = await getJSON('/api/vlan-path?' + params({vlan:vlan, include_broad:$('vlanPathBroad').checked ? '1' : '0'}));
        if ($('vlanPathLimit').value > 0) data.rows = data.rows.slice(0, Number($('vlanPathLimit').value));
        renderVlanPath(data);
      } catch (e) {
        $('vlanPathSummary').textContent = '';
        $('vlanPathSvg').innerHTML = '';
        $('vlanPathRows').querySelector('tbody').innerHTML = emptyRow(4, 'No path data', 'Run Draw again or pick another VLAN.');
        setError('vlanPathError', e.message);
      }
    }
    function renderVlanPath(data) {
      $('vlanPathSummary').innerHTML = [
        '<span class="pill">vlan '+esc(data.vlan)+'</span>',
        '<span class="pill">devices '+esc(data.summary.devices)+'</span>',
        '<span class="pill">physical links '+esc(data.summary.physical_links)+'</span>',
        '<span class="pill">access '+esc(data.summary.access)+'</span>',
        '<span class="pill">trunks '+esc(data.summary.trunks)+'</span>',
        '<span class="pill">broad '+esc(data.summary.broad)+'</span>',
        '<span class="pill">declared '+esc(data.summary.declared)+'</span>'
      ].join(' ');
      if (data.warnings && data.warnings.length) {
        $('vlanPathSummary').innerHTML += ' ' + data.warnings.map(w => '<span class="pill">'+esc(w)+'</span>').join(' ');
      }
      drawVlanPathSVG(data);
      $('vlanPathRows').querySelector('tbody').innerHTML = data.rows.length
        ? data.rows.map(r => '<tr><td>'+(r.role ? '<span class="badge '+esc(r.role)+'">'+esc(r.role)+'</span>' : '')+'</td><td><code>'+esc(r.device)+'</code></td><td>'+esc(r.summary)+'</td><td>'+evidenceCell(r.evidence)+'</td></tr>').join('')
        : emptyRow(4, 'No VLAN path data', 'No interfaces carry this VLAN in the loaded inventory.');
    }
    function drawVlanPathSVG(data) {
      const svg = $('vlanPathSvg');
      const nodes = data.nodes || [];
      const edges = data.edges || [];
      const width = Math.max(760, nodes.length * 190 + 80);
      const height = edges.length > 0 ? 420 : 340;
      const centerY = edges.length > 0 ? 170 : 100;
      const accessY = edges.length > 0 ? 310 : 230;
      svg.setAttribute('viewBox', '0 0 '+width+' '+height);
      svg.innerHTML = '';
      if (nodes.length === 0) {
        svg.innerHTML = '<text x="24" y="48" class="viz-muted">No interfaces carry VLAN '+esc(data.vlan)+'</text>';
        return;
      }
      svg.insertAdjacentHTML('beforeend', '<text x="24" y="34" class="viz-text">VLAN '+esc(data.vlan)+' physical candidate path</text>');
      const positions = new Map();
      nodes.forEach((dev, i) => positions.set(dev.device, {x:70 + i * 190, y:centerY}));
      if (edges.length === 0) {
        svg.insertAdjacentHTML('beforeend', '<line x1="40" y1="'+centerY+'" x2="'+(width-40)+'" y2="'+centerY+'" class="viz-line trunk_broad"></line>');
      }
      edges.forEach(edge => {
        const a = positions.get(edge.a.device);
        const b = positions.get(edge.b.device);
        if (!a || !b) return;
        const cls = edge.confidence >= 0.9 ? 'trunk' : 'trunk_broad';
        const midX = (a.x + b.x) / 2;
        svg.insertAdjacentHTML('beforeend', '<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" class="viz-line '+cls+'"></line>');
        svg.insertAdjacentHTML('beforeend', '<text x="'+midX+'" y="'+(a.y-14)+'" text-anchor="middle" class="viz-muted">'+esc(edge.sources.join(','))+' '+esc(edge.confidence.toFixed(2))+'</text>');
      });
      nodes.forEach((dev) => {
        const pos = positions.get(dev.device);
        const x = pos.x;
        const role = dev.trunks > 0 ? 'trunk' : dev.broad > 0 ? 'trunk_broad' : 'access';
        const trunkCount = dev.trunks + dev.broad;
        const lineClass = role === 'access' ? 'access' : role;
        svg.insertAdjacentHTML('beforeend', '<line x1="'+x+'" y1="'+centerY+'" x2="'+x+'" y2="'+accessY+'" class="viz-line '+lineClass+'"></line>');
        svg.insertAdjacentHTML('beforeend', '<rect x="'+(x-52)+'" y="'+(centerY-30)+'" width="104" height="60" rx="6" class="viz-node '+role+'"></rect>');
        svg.insertAdjacentHTML('beforeend', '<text x="'+x+'" y="'+(centerY-7)+'" text-anchor="middle" class="viz-text">'+esc(short(dev.device, 14))+'</text>');
        svg.insertAdjacentHTML('beforeend', '<text x="'+x+'" y="'+(centerY+14)+'" text-anchor="middle" class="viz-muted">T '+trunkCount+' / A '+dev.access+'</text>');
        (dev.interfaces || []).slice(0, 4).forEach((name, n) => {
          const y = accessY + n * 24;
          svg.insertAdjacentHTML('beforeend', '<circle cx="'+x+'" cy="'+y+'" r="5" class="viz-node access"></circle>');
          svg.insertAdjacentHTML('beforeend', '<text x="'+(x+10)+'" y="'+(y+4)+'" class="viz-muted">'+esc(short(name, 18))+'</text>');
        });
      });
    }
    function short(s, max) {
      s = String(s || '');
      return s.length > max ? s.slice(0, Math.max(1, max-3)) + '...' : s;
    }
    function updateQueryTypeFilter(rows) {
      const current = $('queryTypeFilter').value;
      const types = [...new Set(rows.map(r => r.type).filter(Boolean))].sort();
      $('queryTypeFilter').innerHTML = '<option value="">all types</option>' + types.map(t => '<option value="'+esc(t)+'">'+esc(t)+'</option>').join('');
      if (types.includes(current)) $('queryTypeFilter').value = current;
    }
    function updateQueryRoleFilter(rows) {
      const current = $('queryRoleFilter').value;
      const roles = [...new Set(rows.map(r => r.role).filter(Boolean))].sort();
      $('queryRoleFilter').innerHTML = '<option value="">all roles</option>' + roles.map(r => '<option value="'+esc(r)+'">'+esc(r)+'</option>').join('');
      if (roles.includes(current)) $('queryRoleFilter').value = current;
    }
    function filteredQueryRows() {
      const type = $('queryTypeFilter').value;
      const role = $('queryRoleFilter').value;
      const text = $('queryTextFilter').value.toLowerCase().trim();
      return queryRows.filter(r => {
        if (type && r.type !== type) return false;
        if (role && r.role !== role) return false;
        if (!text) return true;
        return [r.type, r.role, r.device, r.summary, r.evidence?.file, r.evidence?.raw_block].some(v => String(v || '').toLowerCase().includes(text));
      });
    }
    function renderQueryRows() {
      const rows = filteredQueryRows();
      $('queryCount').textContent = rows.length + ' / ' + queryRows.length + ' results';
      const tbody = $('results').querySelector('tbody');
      if (rows.length === 0) {
        const title = queryRows.length ? 'No matching results' : 'No results yet';
        const detail = queryRows.length ? 'Relax filters or try another query.' : 'Run a query or pick an example above.';
        tbody.innerHTML = emptyRow(5, title, detail);
        return;
      }
      tbody.innerHTML = rows.map(r => '<tr><td><span class="badge '+esc(r.type)+'">'+esc(r.type)+'</span></td><td>'+(r.role ? '<span class="badge '+esc(r.role)+'">'+esc(r.role)+'</span>' : '')+'</td><td><code>'+esc(r.device)+'</code></td><td>'+esc(r.summary)+'</td><td>'+evidenceCell(r.evidence)+'</td></tr>').join('');
    }
    async function runCheck() {
      setError('checkError', '');
      const base = {ntp:$('ntp').value, syslog:$('syslog').value, forbid_snmp:$('forbidSnmp').value};
      try {
        const summary = await getJSON('/api/check/summary?' + params(base));
        $('checkSummary').innerHTML = '<span class="pill">findings '+summary.findings+'</span> <span class="pill">warning '+(summary.by_severity.warning || 0)+'</span> <span class="pill">critical '+(summary.by_severity.critical || 0)+'</span>';
        const rows = await getJSON('/api/check?' + params({...base, limit:$('checkLimit').value}));
        $('findings').querySelector('tbody').innerHTML = rows.length
          ? rows.map(f => '<tr><td class="'+esc(f.severity)+'">'+esc(f.severity)+'</td><td><code>'+esc(f.device)+'</code></td><td>'+esc(f.rule)+'</td><td>'+esc(f.summary)+'</td><td>'+evidenceCell(f.evidence)+'</td></tr>').join('')
          : emptyRow(5, 'No compliance findings', 'All checked devices match the current policy.');
      } catch (e) {
        setError('checkError', e.message);
      }
    }
    async function openDevice(name) {
      showView('deviceView');
      $('deviceName').value = name;
      setError('deviceError', '');
      $('deviceMeta').innerHTML = '';
      $('deviceConfig').innerHTML = '<div class="empty"><strong>Loading…</strong>Fetching normalized config.</div>';
      try {
        const d = await getJSON('/api/device?name=' + encodeURIComponent(name));
        renderDeviceConfig(d);
      } catch (e) {
        $('deviceMeta').innerHTML = '';
        $('deviceConfig').innerHTML = '';
        setError('deviceError', e.message);
      }
    }
    async function runDiff() {
      setError('diffError', '');
      try {
        diffRows = await getJSON('/api/diff?' + params({before:$('beforePath').value, after:$('afterPath').value}));
        if (diffRows.length && diffMode === 'normalized') {
          /* keep normalized default when changes exist */
        } else if (!diffRows.length) {
          diffMode = localStorage.getItem('netc.diffMode') || 'normalized';
        }
        renderDiffResults();
      } catch (e) {
        diffRows = [];
        $('diffResults').innerHTML = '';
        updateDiffToolbar();
        setError('diffError', e.message);
      }
    }
    function showView(id) {
      document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
      document.querySelectorAll('nav.view-nav button').forEach(b => b.classList.toggle('active', b.dataset.view === id));
    }
    document.querySelectorAll('nav.view-nav button').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
    document.querySelectorAll('.example-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        if (chip.dataset.query) {
          $('query').value = chip.dataset.query;
          runQuery();
          return;
        }
        if (chip.dataset.action === 'ntp') {
          showView('checkView');
          $('ntp').focus();
          return;
        }
        if (chip.dataset.action === 'help') {
          $('queryHelp').classList.toggle('open');
        }
      });
    });
    $('themeButton').addEventListener('click', () => {
      const dark = document.documentElement.dataset.theme !== 'dark';
      const theme = dark ? 'dark' : 'light';
      applyTheme(theme);
      localStorage.setItem(THEME_KEY, theme);
    });
    applyTheme(localStorage.getItem(THEME_KEY) || 'light');
    $('deviceFilter').addEventListener('input', () => loadDevices().catch(e => setError('deviceError', e.message)));
    $('devices').addEventListener('click', e => {
      const button = e.target.closest('.device-open');
      if (button) openDevice(button.dataset.device);
    });
    $('queryForm').addEventListener('submit', e => { e.preventDefault(); runQuery(); });
    $('vlanPathForm').addEventListener('submit', e => { e.preventDefault(); runVlanPath(); });
    $('vlanPathBroad').addEventListener('change', runVlanPath);
    $('queryTypeFilter').addEventListener('change', renderQueryRows);
    $('queryRoleFilter').addEventListener('change', renderQueryRows);
    $('queryTextFilter').addEventListener('input', renderQueryRows);
    $('checkForm').addEventListener('submit', e => { e.preventDefault(); runCheck(); });
    $('deviceForm').addEventListener('submit', e => { e.preventDefault(); openDevice($('deviceName').value); });
    $('diffForm').addEventListener('submit', e => { e.preventDefault(); runDiff(); });
    document.querySelectorAll('[data-diff-mode]').forEach(btn => {
      btn.addEventListener('click', () => setDiffMode(btn.dataset.diffMode));
    });
    document.querySelectorAll('[data-diff-sub]').forEach(btn => {
      btn.addEventListener('click', () => setDiffSubMode(btn.dataset.diffSub));
    });
    updateDiffToolbar();
    load().catch(e => setError('queryError', e.message));
  </script>
</body>
</html>`
