package server

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netc</title>
  <style>
    :root { color-scheme: light; --border:#d6dde5; --muted:#5f6b7a; --ink:#17212f; --bg:#f5f7f9; --panel:#fff; --accent:#0b66c3; --warn:#b54708; --crit:#b42318; }
    * { box-sizing: border-box; }
    body { margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color:var(--ink); background:var(--bg); }
    header { height:56px; display:flex; align-items:center; gap:18px; padding:0 18px; border-bottom:1px solid var(--border); background:var(--panel); }
    header strong { font-size:18px; }
    header span { color:var(--muted); }
    main { display:grid; grid-template-columns:300px 1fr; min-height:calc(100vh - 56px); }
    aside { border-right:1px solid var(--border); background:var(--panel); padding:14px; overflow:auto; }
    section { padding:16px; overflow:auto; }
    .metrics { display:grid; grid-template-columns:repeat(2,1fr); gap:8px; margin-bottom:14px; }
    .metric { border:1px solid var(--border); border-radius:6px; padding:9px; background:#fbfcfd; }
    .metric b { display:block; font-size:19px; }
    nav { display:flex; gap:8px; margin-bottom:14px; border-bottom:1px solid var(--border); }
    nav button { border:0; border-bottom:2px solid transparent; border-radius:0; color:var(--muted); background:transparent; padding:10px 8px; }
    nav button.active { color:var(--accent); border-bottom-color:var(--accent); }
    form, .toolbar { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }
    label { display:block; color:var(--muted); font-size:12px; margin-bottom:5px; }
    input { min-width:160px; padding:8px 9px; border:1px solid var(--border); border-radius:6px; font:inherit; background:white; }
    input.grow { flex:1; min-width:260px; }
    button { padding:8px 11px; border:1px solid #0a5bad; border-radius:6px; background:var(--accent); color:white; font:inherit; cursor:pointer; }
    button.secondary { color:var(--ink); background:white; border-color:var(--border); }
    table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); }
    th, td { text-align:left; border-bottom:1px solid var(--border); padding:8px 10px; vertical-align:top; }
    th { background:#edf2f7; font-size:12px; color:#344255; position:sticky; top:0; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
    pre { margin:4px 0 0; white-space:pre-wrap; max-height:120px; overflow:auto; }
    .hint, .error { color:var(--muted); margin:8px 0 12px; }
    .error { color:var(--crit); }
    .pill { display:inline-block; border:1px solid var(--border); border-radius:999px; padding:2px 7px; color:var(--muted); background:#fbfcfd; }
    .critical { color:var(--crit); font-weight:600; }
    .warning { color:var(--warn); font-weight:600; }
    .view { display:none; }
    .view.active { display:block; }
    @media (max-width: 850px) { main { grid-template-columns:1fr; } aside { border-right:0; border-bottom:1px solid var(--border); } }
  </style>
</head>
<body>
  <header><strong>netc</strong><span id="status">loading</span></header>
  <main>
    <aside>
      <div class="metrics" id="metrics"></div>
      <label>Devices</label>
      <input id="deviceFilter" placeholder="filter devices" autocomplete="off" style="width:100%; margin-bottom:8px;">
      <table id="devices"><thead><tr><th>device</th><th>if</th><th>vlans</th></tr></thead><tbody></tbody></table>
    </aside>
    <section>
      <nav>
        <button class="active secondary" data-view="queryView">Query</button>
        <button class="secondary" data-view="checkView">Compliance</button>
        <button class="secondary" data-view="diffView">Diff</button>
        <button class="secondary" data-view="deviceView">Device</button>
      </nav>

      <div id="queryView" class="view active">
        <form id="queryForm">
          <input id="query" class="grow" value="vlan 2048" autocomplete="off">
          <input id="queryLimit" type="number" value="100" min="0" title="limit">
          <button>Query</button>
        </form>
        <div class="hint">Try: <code>vlan 2048</code>, <code>interfaces trunk</code>, <code>acl 10</code>, <code>device SW-A-02</code></div>
        <div id="queryError" class="error"></div>
        <table id="results"><thead><tr><th>type</th><th>device</th><th>summary</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>

      <div id="checkView" class="view">
        <form id="checkForm">
          <input id="ntp" class="grow" value="10.10.10.1,10.10.10.2" autocomplete="off">
          <input id="syslog" class="grow" value="10.10.20.5" autocomplete="off">
          <input id="forbidSnmp" value="public" autocomplete="off">
          <input id="checkLimit" type="number" value="100" min="0">
          <button>Check</button>
        </form>
        <div id="checkSummary" class="hint"></div>
        <div id="checkError" class="error"></div>
        <table id="findings"><thead><tr><th>severity</th><th>device</th><th>rule</th><th>finding</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>

      <div id="deviceView" class="view">
        <form id="deviceForm">
          <input id="deviceName" class="grow" value="SW-A-02" autocomplete="off">
          <button>Open</button>
        </form>
        <div id="deviceError" class="error"></div>
        <table id="deviceDetail"><tbody></tbody></table>
      </div>

      <div id="diffView" class="view">
        <form id="diffForm">
          <input id="beforePath" class="grow" placeholder="/path/before.cfg" autocomplete="off">
          <input id="afterPath" class="grow" placeholder="/path/after.cfg" autocomplete="off">
          <button>Diff</button>
        </form>
        <div id="diffError" class="error"></div>
        <table id="diffs"><thead><tr><th>type</th><th>device</th><th>object</th><th>summary</th><th>evidence</th></tr></thead><tbody></tbody></table>
      </div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    async function getJSON(url) {
      const r = await fetch(url);
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.statusText);
      return j;
    }
    function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function evidenceCell(ev) {
      if (!ev || !ev.file) return '';
      return '<code>'+esc(ev.file)+':'+ev.start_line+'-'+ev.end_line+'</code><pre>'+esc(ev.raw_block)+'</pre>';
    }
    function params(obj) {
      const p = new URLSearchParams();
      Object.entries(obj).forEach(([k,v]) => p.set(k, v));
      return p.toString();
    }
    async function load() {
      const s = await getJSON('/api/summary');
      $('status').textContent = s.devices + ' devices';
      const keys = ['devices','interfaces','vlans','routes','acls','ntp_servers','syslog_hosts','snmp_communities'];
      $('metrics').innerHTML = keys.map(k => '<div class="metric"><b>'+esc(s[k] ?? 0)+'</b>'+esc(k)+'</div>').join('');
      await loadPolicy();
      loadDevices();
      runQuery();
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
      $('queryError').textContent = '';
      try {
        const rows = await getJSON('/api/query?' + params({brief:'1', limit:$('queryLimit').value, q:$('query').value}));
        $('results').querySelector('tbody').innerHTML = rows.map(r => '<tr><td>'+esc(r.type)+'</td><td><code>'+esc(r.device)+'</code></td><td>'+esc(r.summary)+'</td><td>'+evidenceCell(r.evidence)+'</td></tr>').join('');
      } catch (e) {
        $('queryError').textContent = e.message;
      }
    }
    async function runCheck() {
      $('checkError').textContent = '';
      const base = {ntp:$('ntp').value, syslog:$('syslog').value, forbid_snmp:$('forbidSnmp').value};
      try {
        const summary = await getJSON('/api/check/summary?' + params(base));
        $('checkSummary').innerHTML = '<span class="pill">findings '+summary.findings+'</span> <span class="pill">warning '+(summary.by_severity.warning || 0)+'</span> <span class="pill">critical '+(summary.by_severity.critical || 0)+'</span>';
        const rows = await getJSON('/api/check?' + params({...base, limit:$('checkLimit').value}));
        $('findings').querySelector('tbody').innerHTML = rows.map(f => '<tr><td class="'+esc(f.severity)+'">'+esc(f.severity)+'</td><td><code>'+esc(f.device)+'</code></td><td>'+esc(f.rule)+'</td><td>'+esc(f.summary)+'</td><td>'+evidenceCell(f.evidence)+'</td></tr>').join('');
      } catch (e) {
        $('checkError').textContent = e.message;
      }
    }
    async function openDevice(name) {
      showView('deviceView');
      $('deviceName').value = name;
      $('deviceError').textContent = '';
      try {
        const d = await getJSON('/api/device?brief=1&name=' + encodeURIComponent(name));
        $('deviceDetail').querySelector('tbody').innerHTML = [
          ['hostname', d.hostname],
          ['source', d.source_file],
          ['interfaces', d.interfaces],
          ['vlans', d.vlans],
          ['routes', d.routes],
          ['acls', d.acls],
          ['ntp', (d.ntp_servers || []).join(', ')],
          ['syslog', (d.syslog_hosts || []).join(', ')],
          ['snmp communities', (d.snmp_communities || []).join(', ')]
        ].map(r => '<tr><th>'+esc(r[0])+'</th><td>'+esc(r[1])+'</td></tr>').join('');
      } catch (e) {
        $('deviceError').textContent = e.message;
      }
    }
    async function runDiff() {
      $('diffError').textContent = '';
      try {
        const rows = await getJSON('/api/diff?' + params({before:$('beforePath').value, after:$('afterPath').value}));
        $('diffs').querySelector('tbody').innerHTML = rows.map(d => '<tr><td>'+esc(d.type)+'</td><td><code>'+esc(d.device)+'</code></td><td><code>'+esc(d.object)+'</code></td><td>'+esc(d.summary)+'</td><td>'+evidenceCell(d.evidence)+'</td></tr>').join('');
      } catch (e) {
        $('diffError').textContent = e.message;
      }
    }
    function showView(id) {
      document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
      document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.view === id));
    }
    document.querySelectorAll('nav button').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
    $('deviceFilter').addEventListener('input', () => loadDevices().catch(e => $('deviceError').textContent = e.message));
    $('devices').addEventListener('click', e => {
      const button = e.target.closest('.device-open');
      if (button) openDevice(button.dataset.device);
    });
    $('queryForm').addEventListener('submit', e => { e.preventDefault(); runQuery(); });
    $('checkForm').addEventListener('submit', e => { e.preventDefault(); runCheck(); });
    $('deviceForm').addEventListener('submit', e => { e.preventDefault(); openDevice($('deviceName').value); });
    $('diffForm').addEventListener('submit', e => { e.preventDefault(); runDiff(); });
    load().catch(e => $('queryError').textContent = e.message);
  </script>
</body>
</html>`
