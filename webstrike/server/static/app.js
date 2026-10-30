const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const state = { id: null, target: "", findings: [], surface: new Set(), endpoints: new Set(),
                surfaceStats: null, newFps: new Set(), t0: 0, timer: null };
let profile = "balanced";
let enabled = new Set();

function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

$$('#profile button').forEach((b) => {
  b.onclick = () => {
    $$('#profile button').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    profile = b.dataset.v;
    loadModules();
  };
});

$$('.tabs button').forEach((b) => {
  b.onclick = () => {
    $$('.tabs button').forEach((x) => x.classList.remove('active'));
    $$('.panel').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    const panel = $('#tab-' + b.dataset.tab);
    if (panel) panel.classList.add('active');
    if (b.dataset.tab === 'history') loadHistory();
    if (b.dataset.tab === 'screens') renderScreens();
    if (b.dataset.tab === 'surface') renderSurface();
    if (b.dataset.tab === 'endpoints') renderEndpoints();
    if (b.dataset.tab === 'graph') renderGraph();
  };
});

$$('#sevchips button').forEach((b) => {
  b.onclick = () => { b.classList.toggle('on'); render(); };
});

on($('#search'), 'input', render);
on($('#exp-report'), 'click', () => state.id && window.open('/api/scan/' + state.id + '/report'));
on($('#exp-json'), 'click', () => state.id && window.open('/api/scan/' + state.id + '/export?fmt=json'));
on($('#exp-md'), 'click', () => state.id && window.open('/api/scan/' + state.id + '/export?fmt=md'));
on($('#launch'), 'click', launch);
on($('#stop-btn'), 'click', async () => {
  if (!state.id) return;
  try {
    const res = await fetch('/api/scan/' + state.id + '/stop', { method: 'POST' });
    if (res.ok) {
      logLine('Scan stop requested.', 'warn');
      setStatus('stopped');
      if (state.timer) { clearInterval(state.timer); state.timer = null; }
    }
  } catch (e) {
    logLine('Failed to stop scan: ' + e, 'err');
  }
});

window.addEventListener('click', (e) => {
  if (e.target === $('#scope-modal')) closeScopeModal();
  if (e.target === $('#upd-modal')) closeUpdatesModal();
  if (e.target === $('#diff-modal')) closeDiffModal();
});

// ---- Scope Allowlist Modal ----
async function openScopeModal() {
  const modal = $('#scope-modal');
  if (!modal) return;
  const msg = $('#scope-msg');
  if (msg) msg.style.display = 'none';
  modal.style.display = 'flex';
  try {
    const res = await fetch('/api/scope');
    if (res.ok) {
      const data = await res.json();
      const enf = $('#scope-enforce');
      const doms = $('#scope-domains');
      if (enf) enf.checked = Boolean(data.enforce);
      if (doms) doms.value = (data.domains || []).join('\n');
    }
  } catch (e) {}
}

function closeScopeModal() {
  const modal = $('#scope-modal');
  if (modal) modal.style.display = 'none';
}

async function handleScopeSubmit(e) {
  if (e && e.preventDefault) e.preventDefault();
  const enf = Boolean(($('#scope-enforce') || {}).checked);
  const raw = (($('#scope-domains') || {}).value || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const msg = $('#scope-msg');
  try {
    const res = await fetch('/api/scope', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ enforce: enf, domains: raw })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to save scope');
    if ($('#scope-domains')) $('#scope-domains').value = (data.domains || []).join('\n');
    if (msg) {
      msg.textContent = 'Scope settings saved (' + (data.domains || []).length + ' entries).';
      msg.style.background = 'rgba(77,212,172,0.14)';
      msg.style.border = '1px solid #4dd4ac';
      msg.style.color = '#4dd4ac';
      msg.style.display = 'block';
    }
    setTimeout(closeScopeModal, 900);
  } catch (err) {
    if (msg) {
      msg.textContent = err.message;
      msg.style.background = 'rgba(255,59,107,0.14)';
      msg.style.border = '1px solid #ff3b6b';
      msg.style.color = '#ff3b6b';
      msg.style.display = 'block';
    }
  }
}

// ---- Updates & Backup Modal ----
async function renderUpdateStatus(forceRefresh) {
  const box = $('#upd-status-box');
  if (!box) return;
  box.textContent = 'Checking version & update channel...';
  try {
    const url = '/api/version' + (forceRefresh ? '?refresh=true' : '');
    const res = await fetch(url);
    const ver = res.ok ? await res.json() : {};
    let html =
      '<div style="color:#22d3ee;font-weight:700;font-size:13.5px;margin-bottom:4px;">WebStrike v' + esc(ver.current || '1.1.0') + ' — Free Edition</div>' +
      '<div style="color:#7d8ca6;">Database Schema: <b>v' + esc(ver.schema_version || 2) + '</b> (automatic migrations enabled)</div>';
    if (ver.update_available) {
      html += '<div style="margin-top:8px;color:#4dd4ac;font-weight:700;">★ New update available: v' + esc(ver.latest) + '</div>';
      if (ver.notes) html += '<div style="font-size:12px;color:#e7edf7;">' + esc(ver.notes) + '</div>';
      if (ver.download) html += '<div style="margin-top:6px;"><a href="' + esc(ver.download) + '" target="_blank" style="color:#22d3ee;">Download latest update →</a></div>';
    } else {
      html += '<div style="margin-top:8px;color:#4dd4ac;">✓ You are running the latest version.</div>';
    }
    box.innerHTML = html;
  } catch (e) {
    box.textContent = 'Could not check for updates right now.';
  }
}

async function openUpdatesModal() {
  const modal = $('#upd-modal');
  if (!modal) return;
  const actMsg = $('#upd-action-msg');
  if (actMsg) actMsg.style.display = 'none';
  modal.style.display = 'flex';
  await renderUpdateStatus(false);
}

function closeUpdatesModal() {
  const modal = $('#upd-modal');
  if (modal) modal.style.display = 'none';
}

function showUpdActionMsg(text, ok) {
  const actMsg = $('#upd-action-msg');
  if (!actMsg) return;
  actMsg.textContent = text;
  actMsg.style.background = ok ? 'rgba(77,212,172,0.14)' : 'rgba(255,59,107,0.14)';
  actMsg.style.border = ok ? '1px solid #4dd4ac' : '1px solid #ff3b6b';
  actMsg.style.color = ok ? '#4dd4ac' : '#ff3b6b';
  actMsg.style.display = 'block';
}

async function checkUpdatesNow() {
  await renderUpdateStatus(true);
  await loadVersion();
}

async function applyGitUpdate() {
  showUpdActionMsg('Running git pull --ff-only...', true);
  try {
    const res = await fetch('/api/update/pull', { method: 'POST' });
    const data = await res.json();
    showUpdActionMsg(data.message || 'Done', Boolean(data.ok));
    if (data.ok) await checkUpdatesNow();
  } catch (e) {
    showUpdActionMsg('Update failed: ' + e.message, false);
  }
}

async function handleBackupRestore(ev) {
  const file = ev && ev.target && ev.target.files ? ev.target.files[0] : null;
  if (!file) return;
  try {
    const text = await file.text();
    const payload = JSON.parse(text);
    const res = await fetch('/api/backup/restore', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Restore failed');
    showUpdActionMsg(
      '✓ Backup restored: ' + (data.scans_restored || 0) + ' scans, ' + (data.findings_restored || 0) + ' findings.',
      true
    );
    loadHistory();
  } catch (e) {
    showUpdActionMsg('Restore failed: ' + e.message, false);
  } finally {
    if (ev && ev.target) ev.target.value = '';
  }
}

// ---- Scan Comparison / Diff Modal ----
async function openDiffModal(scanId, otherId, label) {
  const modal = $('#diff-modal');
  const body = $('#diff-body');
  const title = $('#diff-title');
  if (!modal || !body) return;
  if (title) title.textContent = 'Scan Comparison — ' + (label || (scanId + ' vs ' + otherId));
  body.innerHTML = '<div style="color:var(--muted);padding:12px;">Comparing scans...</div>';
  modal.style.display = 'flex';
  try {
    const res = await fetch('/api/scan/' + scanId + '/compare/' + otherId);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Comparison failed');
    const c = data.counts || { new: 0, resolved: 0, unchanged: 0 };
    let html =
      '<div style="display:flex;gap:12px;margin-bottom:8px;">' +
      '<span class="badge high" style="padding:6px 12px;">+ ' + c.new + ' New</span>' +
      '<span class="badge low" style="padding:6px 12px;">✓ ' + c.resolved + ' Resolved</span>' +
      '<span class="badge info" style="padding:6px 12px;">= ' + c.unchanged + ' Unchanged</span>' +
      '</div>';

    const renderGroup = (heading, items, color) => {
      if (!items || !items.length) return '';
      let s = '<div style="font-size:12px;font-weight:700;color:' + color + ';margin-top:8px;">' + esc(heading) + '</div>';
      items.forEach((f) => {
        s += '<div class="f" style="cursor:default;padding:9px 12px;">' +
          '<div class="badge ' + esc(f.severity) + '">' + esc(f.severity) + '</div>' +
          '<div><div class="title">' + esc(f.title) + '</div>' +
          '<div class="meta">' + esc(f.url || f.target || '') + '</div></div>' +
          '<div class="cat">' + esc(f.category) + '</div></div>';
      });
      return s;
    };

    html += renderGroup('New Findings (appeared in ' + scanId + ')', data.new, '#ff7a45');
    html += renderGroup('Resolved Findings (fixed since ' + otherId + ')', data.resolved, '#4dd4ac');
    html += renderGroup('Unchanged Findings', data.unchanged, '#7d8ca6');
    body.innerHTML = html;
  } catch (err) {
    body.innerHTML = '<div style="color:var(--crit);padding:12px;">' + esc(err.message) + '</div>';
  }
}

function closeDiffModal() {
  const modal = $('#diff-modal');
  if (modal) modal.style.display = 'none';
}

async function loadVersion() {
  try {
    const res = await fetch('/api/version');
    if (!res.ok) return;
    const v = await res.json();
    const vb = $('#app-ver');
    if (vb && v.current) vb.textContent = 'v' + v.current;
    const ub = $('#update-badge');
    if (ub && v.update_available) {
      ub.style.display = 'inline-block';
      ub.textContent = 'Update v' + v.latest;
      if (v.download) ub.href = v.download;
    }
  } catch (e) {}
}

async function loadModules() {
  try {
    const mods = await (await fetch('/api/modules')).json();
    const box = $('#modules');
    if (!box) return;
    box.innerHTML = '';
    enabled = new Set();
    mods.forEach((m) => {
      const el = document.createElement('div');
      el.className = 'mod';
      el.innerHTML = '<span>' + esc(m.name) + '</span><small>' + esc(m.phase) + '</small>';
      if (m.profiles.includes(profile)) { el.classList.add('on'); enabled.add(m.id); }
      el.onclick = () => {
        el.classList.toggle('on');
        if (el.classList.contains('on')) enabled.add(m.id);
        else enabled.delete(m.id);
        const mc = $('#modcount');
        if (mc) mc.textContent = '(' + enabled.size + ')';
      };
      box.appendChild(el);
    });
    const mc = $('#modcount');
    if (mc) mc.textContent = '(' + enabled.size + ')';
  } catch (e) { logLine('failed to load modules: ' + e, 'err'); }
}

async function loadHistory() {
  const box = $('#history');
  if (!box) return;
  try {
    const rows = await (await fetch('/api/history')).json();
    box.innerHTML = '';
    if (!rows.length) {
      box.innerHTML = '<div style="color:var(--muted);padding:14px;font-size:13px;">No scan history yet.</div>';
      return;
    }
    rows.forEach((r) => {
      const el = document.createElement('div');
      el.className = 'f';
      const when = new Date(r.started * 1000).toLocaleString();
      el.innerHTML = '<div class="badge info">' + esc(r.profile) + '</div>' +
        '<div style="cursor:pointer;" class="hist-main"><div class="title">' + esc(r.target) + ' <small style="color:var(--muted);">#' + esc(r.id) + '</small></div>' +
        '<div class="meta">' + when + ' - ' + r.findings + ' findings</div></div>' +
        '<div style="display:flex;align-items:center;gap:8px;"><div class="cat">' + esc(r.status) + '</div>' +
        '<button class="diff-btn" title="Compare with another scan of this target">Diff</button>' +
        '<button class="del-btn" title="Delete scan">&times;</button></div>';

      const mainDiv = el.querySelector('.hist-main');
      if (mainDiv) mainDiv.onclick = () => loadPast(r.id, r.target);

      const diffBtn = el.querySelector('.diff-btn');
      if (diffBtn) {
        diffBtn.onclick = (e) => {
          e.stopPropagation();
          const baseline = rows.find((other) => other.id !== r.id && other.target === r.target) ||
                           rows.find((other) => other.id !== r.id);
          if (!baseline) {
            alert('Run at least two scans to compare findings.');
            return;
          }
          openDiffModal(r.id, baseline.id, r.target + ' (#' + r.id + ' vs #' + baseline.id + ')');
        };
      }

      const delBtn = el.querySelector('.del-btn');
      if (delBtn) {
        delBtn.onclick = async (e) => {
          e.stopPropagation();
          if (!confirm('Are you sure you want to delete scan for ' + r.target + ' (' + r.id + ')?')) return;
          try {
            const res = await fetch('/api/scan/' + r.id, { method: 'DELETE' });
            if (res.ok) {
              loadHistory();
              if (state.id === r.id) {
                reset();
                const t = $('#tgt'); if (t) t.textContent = 'no target';
                setStatus('idle');
              }
            } else {
              alert('Failed to delete scan');
            }
          } catch (err) {
            alert('Error deleting scan: ' + err.message);
          }
        };
      }
      box.appendChild(el);
    });
  } catch (e) { logLine('history failed: ' + e, 'err'); }
}

async function loadPast(sid, target) {
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
  setStatus('done');
  let rows = [];
  let surfStats = null;
  try {
    const res = await fetch('/api/scan/' + sid);
    if (res.ok) {
      const scanData = await res.json();
      rows = scanData.findings || [];
      surfStats = scanData.surface || null;
    } else {
      rows = await (await fetch('/api/scan/' + sid + '/findings')).json();
    }
  } catch (e) {
    rows = await (await fetch('/api/scan/' + sid + '/findings')).json();
  }
  state.findings = rows;
  state.surfaceStats = surfStats;
  state.newFps = new Set();
  state.id = sid;
  state.target = target;
  const t = $('#tgt'); if (t) t.textContent = target + ' (history)';
  const ft = $('.tabs button[data-tab="findings"]');
  if (ft) ft.click();
  render();
}

async function launch() {
  const tEl = $('#target');
  const target = tEl ? tEl.value.trim() : '';
  if (!target) return;
  const authChk = $('#auth-confirm');
  if (authChk && !authChk.checked) {
    alert('Please confirm that you have authorization to test this target.');
    return;
  }
  if (!enabled.size) {
    alert('Please select at least one scan module.');
    return;
  }
  const body = {
    target: target,
    profile: profile,
    only_modules: Array.from(enabled),
    bearer: ($('#bearer') || {}).value || null,
    basic: ($('#basic') || {}).value || null,
    proxy: ($('#proxy') || {}).value || null,
    webhook: ($('#webhook') || {}).value || null,
    concurrency: Number(($('#conc') || {}).value) || 30,
    rate: Number(($('#rate') || {}).value) || 0,
    authorized: authChk ? Boolean(authChk.checked) : true
  };
  const ck = $('#cookies'), hd = $('#headers');
  try { body.cookies = ck && ck.value ? JSON.parse(ck.value) : null; } catch (e) {}
  try { body.headers = hd && hd.value ? JSON.parse(hd.value) : null; } catch (e) {}

  reset();
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    const r = await resp.json();
    if (!resp.ok) {
      const msg = r.detail || 'Scan blocked';
      logLine(msg, 'err');
      alert(msg);
      return;
    }
    state.id = r.id;
    state.target = target;
    state.t0 = Date.now();
    const t = $('#tgt'); if (t) t.textContent = target;
    setStatus('running');
    state.timer = setInterval(() => {
      const e = $('#s-time');
      if (e) e.textContent = Math.round((Date.now() - state.t0) / 1000) + 's';
    }, 500);
    const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    const ws = new WebSocket(proto + location.host + '/ws/' + r.id);
    ws.onmessage = (e) => handle(JSON.parse(e.data));
    ws.onclose = () => {
      if (state.timer) { clearInterval(state.timer); state.timer = null; }
      const curr = $('#status') ? $('#status').textContent : '';
      if (curr !== 'stopped') setStatus('done');
    };
  } catch (e) { logLine('launch failed: ' + e, 'err'); }
}

function setStatus(s) {
  const p = $('#status');
  if (p) {
    p.className = 'pill ' + s;
    p.textContent = s;
  }
  const stopBtn = $('#stop-btn');
  if (stopBtn) {
    stopBtn.style.display = (s === 'running') ? 'inline-block' : 'none';
  }
}

function reset() {
  state.findings = [];
  state.surface = new Set();
  state.endpoints = new Set();
  state.surfaceStats = null;
  state.newFps = new Set();
  ['#findings', '#surface', '#endpoints', '#log', '#screens', '#graph-container'].forEach((s) => {
    const e = $(s); if (e) e.innerHTML = '';
  });
  const ib = $('#infra-banner'); if (ib) { ib.innerHTML = ''; ib.style.display = 'none'; }
  ['#s-find', '#s-crit', '#s-sub', '#s-ep', '#s-url', '#s-time'].forEach((s) => {
    const e = $(s); if (e) e.textContent = '0';
  });
}

function handle(ev) {
  const k = ev.kind;
  if (k === 'finding') { state.findings.push(ev.finding); render(); }
  else if (k === 'log') logLine(ev.message, ev.level);
  else if (k === 'module_start') logLine('> ' + ev.name, 'info');
  else if (k === 'module_error') logLine('x ' + ev.module + ': ' + ev.error, 'err');
  else if (k === 'module_done') logLine('ok ' + ev.module, 'good');
  else if (k === 'phase') logLine('-- phase: ' + ev.phase + ' --', 'warn');
  else if (k === 'scan_diff') {
    state.newFps = new Set(ev.new_fps || []);
    if (ev.new) logLine('delta ' + ev.new + ' new vs ' + (ev.prev || 'none') +
                        ', ' + ev.resolved + ' resolved', 'warn');
    render();
  }
  else if (k === 'scan_done') {
    setStatus(ev.status || 'done');
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    if (ev.surface) state.surfaceStats = ev.surface;
    logLine('scan complete in ' + ev.elapsed + 's - ' + ev.total + ' findings', 'good');
    render();
    renderScreens();
    renderGraph();
  }
}

function logLine(msg, level) {
  const box = $('#log');
  if (!box) return;
  const t = new Date().toLocaleTimeString();
  const el = document.createElement('div');
  el.className = 'l';
  el.innerHTML = '<span class="t">' + t + '</span><span class="msg ' +
                 (level || 'info') + '">' + esc(msg) + '</span>';
  box.appendChild(el);
  box.scrollTop = 1e9;
}

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function render() {
  const searchEl = $('#search');
  const q = searchEl ? searchEl.value.toLowerCase() : '';
  const on = new Set($$('#sevchips button.on').map((b) => b.dataset.s));
  const list = state.findings
    .filter((f) => !on.size || on.has(f.severity))
    .filter((f) => !q || (f.title + (f.url || '') + (f.target || '') + f.category)
      .toLowerCase().includes(q))
    .sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));

  const box = $('#findings');
  if (box) {
    box.innerHTML = '';
    list.forEach((f) => {
      const el = document.createElement('div');
      el.className = 'f';
      const isNew = f.fp && state.newFps.has(f.fp);
      el.innerHTML = '<div class="badge ' + esc(f.severity) + '">' + esc(f.severity) + '</div>' +
        '<div><div class="title">' + esc(f.title) +
        (isNew ? '<span class="new">NEW</span>' : '') + '</div>' +
        '<div class="meta">' + esc(f.url || f.target || '') + ' - ' + esc(f.module) + '</div>' +
        '<div class="ev">' + esc(f.evidence || '') + '</div></div>' +
        '<div class="cat">' + esc(f.category) + '</div>';
      el.onclick = () => el.classList.toggle('open');
      box.appendChild(el);
    });
  }

  const crit = state.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  setText('#s-find', state.findings.length);
  setText('#s-crit', crit);

  const epFromCat = state.findings.filter((f) => f.category === 'endpoints').map((f) => f.evidence || f.url).filter(Boolean);
  const epFromDisc = state.findings.filter((f) => (f.category === 'discovery' || f.category === 'surface') && f.url).map((f) => f.url).filter(Boolean);
  state.endpoints = new Set([...epFromCat, ...epFromDisc]);

  state.surface = new Set(
    state.findings
      .filter((f) => (f.category === 'surface' || f.category === 'network' || f.category === 'takeover') && f.target)
      .map((f) => f.target)
  );
  const urls = new Set(state.findings.filter((f) => f.url).map((f) => f.url));

  const ss = state.surfaceStats || {};
  setText('#s-ep', Math.max(state.endpoints.size, ss.endpoints || 0));
  setText('#s-sub', Math.max(state.surface.size, ss.hosts || 0, ss.subdomains || 0));
  setText('#s-url', Math.max(urls.size, ss.urls || 0));

  renderEndpoints();
  renderSurface();
  if ($('#tab-graph') && $('#tab-graph').classList.contains('active')) {
    renderGraph();
  }
}

function setText(sel, v) { const e = $(sel); if (e) e.textContent = v; }

function renderEndpoints() {
  const box = $('#endpoints');
  if (!box) return;
  box.innerHTML = '';
  const items = Array.from(state.endpoints).sort().slice(0, 500);
  if (!items.length) {
    box.innerHTML = '<div style="color:var(--muted);padding:14px;font-size:13px;">No endpoints discovered yet.</div>';
    return;
  }
  items.forEach((ep) => {
    const el = document.createElement('div');
    el.className = 'f';
    el.innerHTML = '<div class="badge info">path</div>' +
      '<div><div class="title">' + esc(ep) + '</div></div><div class="cat">endpoint</div>';
    box.appendChild(el);
  });
}

function renderSurface() {
  const infraBox = $('#infra-banner');
  const infraFindings = state.findings.filter((f) => f.category === 'infra');
  if (infraBox) {
    if (infraFindings.length) {
      infraBox.style.display = 'grid';
      infraBox.innerHTML = '';
      infraFindings.forEach((f) => {
        const card = document.createElement('div');
        card.className = 'infra-card';
        card.innerHTML = '<span>' + esc(f.title) + '</span><strong>' + esc(f.evidence || '') + '</strong>';
        infraBox.appendChild(card);
      });
    } else {
      infraBox.style.display = 'none';
    }
  }

  const box = $('#surface');
  if (!box) return;
  box.innerHTML = '';
  const items = Array.from(state.surface).sort();
  if (!items.length && !infraFindings.length) {
    box.innerHTML = '<div style="color:var(--muted);padding:14px;font-size:13px;">No hosts, subdomains, or open ports discovered yet.</div>';
    return;
  }
  items.forEach((s) => {
    const a = document.createElement('a');
    a.href = s.startsWith('http') ? s : 'https://' + s;
    a.target = '_blank';
    a.textContent = s;
    box.appendChild(a);
  });
}

function renderGraph() {
  const box = $('#graph-container');
  if (!box) return;
  const rootTarget = state.target || 'Target';
  const hosts = Array.from(state.surface).slice(0, 15);
  const eps = Array.from(state.endpoints).slice(0, 12);
  const threats = state.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 12);

  const width = Math.max(800, box.clientWidth || 800);
  const height = 550;
  const cx = width / 2;
  const cy = height / 2;

  let svg = '<svg class="graph-svg" viewBox="0 0 ' + width + ' ' + height + '">';
  svg += '<defs><radialGradient id="tgtGrad"><stop offset="0%" stop-color="#22d3ee"/><stop offset="100%" stop-color="#a855f7"/></radialGradient></defs>';

  // Links to endpoints
  eps.forEach((ep, i) => {
    const angle = (i / Math.max(1, eps.length)) * Math.PI * 2 + 0.4;
    const x = cx + Math.cos(angle) * 105;
    const y = cy + Math.sin(angle) * 105;
    svg += '<line class="graph-link" stroke="#1e293b" x1="' + cx + '" y1="' + cy + '" x2="' + x + '" y2="' + y + '"/>';
  });

  // Links to hosts
  hosts.forEach((h, i) => {
    const angle = (i / Math.max(1, hosts.length)) * Math.PI * 2;
    const x = cx + Math.cos(angle) * 165;
    const y = cy + Math.sin(angle) * 165;
    svg += '<line class="graph-link" x1="' + cx + '" y1="' + cy + '" x2="' + x + '" y2="' + y + '"/>';
  });

  // Links to threats
  threats.forEach((th, i) => {
    const angle = (i / Math.max(1, threats.length)) * Math.PI * 2 + 0.2;
    const x = cx + Math.cos(angle) * 230;
    const y = cy + Math.sin(angle) * 230;
    svg += '<line class="graph-link" stroke="#ff3b6b" stroke-dasharray="2 2" x1="' + cx + '" y1="' + cy + '" x2="' + x + '" y2="' + y + '"/>';
  });

  // Center Target Node
  svg += '<g class="graph-node">' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="28" fill="url(#tgtGrad)" stroke="#1a2334" stroke-width="4"/>' +
    '<text x="' + cx + '" y="' + (cy + 42) + '" text-anchor="middle" font-weight="700">' + esc(rootTarget.slice(0, 24)) + '</text>' +
    '</g>';

  // Endpoint Nodes
  eps.forEach((ep, i) => {
    const angle = (i / Math.max(1, eps.length)) * Math.PI * 2 + 0.4;
    const x = cx + Math.cos(angle) * 105;
    const y = cy + Math.sin(angle) * 105;
    const shortEp = ep.length > 18 ? ep.slice(0, 16) + '..' : ep;
    svg += '<g class="graph-node">' +
      '<circle cx="' + x + '" cy="' + y + '" r="8" fill="#4dd4ac" stroke="#1a2334" stroke-width="2"/>' +
      '<text x="' + x + '" y="' + (y + 18) + '" text-anchor="middle">' + esc(shortEp) + '</text>' +
      '</g>';
  });

  // Hosts Nodes
  hosts.forEach((h, i) => {
    const angle = (i / Math.max(1, hosts.length)) * Math.PI * 2;
    const x = cx + Math.cos(angle) * 165;
    const y = cy + Math.sin(angle) * 165;
    const shortLabel = h.length > 20 ? h.slice(0, 18) + '..' : h;
    svg += '<g class="graph-node">' +
      '<circle cx="' + x + '" cy="' + y + '" r="12" fill="#a855f7" stroke="#1a2334" stroke-width="2"/>' +
      '<text x="' + x + '" y="' + (y + 22) + '" text-anchor="middle">' + esc(shortLabel) + '</text>' +
      '</g>';
  });

  // Critical/High Threat Nodes
  threats.forEach((th, i) => {
    const angle = (i / Math.max(1, threats.length)) * Math.PI * 2 + 0.2;
    const x = cx + Math.cos(angle) * 230;
    const y = cy + Math.sin(angle) * 230;
    const shortTitle = th.title.length > 22 ? th.title.slice(0, 20) + '..' : th.title;
    svg += '<g class="graph-node">' +
      '<circle cx="' + x + '" cy="' + y + '" r="10" fill="#ff3b6b" stroke="#05070d" stroke-width="2"/>' +
      '<text x="' + x + '" y="' + (y + 20) + '" text-anchor="middle" fill="#ff7a45">' + esc(shortTitle) + '</text>' +
      '</g>';
  });

  svg += '</svg>';
  box.innerHTML = svg;
}

function renderScreens() {
  const box = $('#screens');
  if (!box) return;
  box.innerHTML = '';
  const shots = state.id ? state.findings.filter((f) => f.meta && f.meta.file) : [];
  if (!shots.length) {
    box.innerHTML = '<div style="color:var(--muted);padding:14px;font-size:13px;">No screenshots captured yet (requires Danger profile + Screenshots module).</div>';
    return;
  }
  shots.forEach((f) => {
    const a = document.createElement('a');
    a.className = 'shot';
    a.href = f.url || '#';
    a.target = '_blank';
    a.innerHTML = '<img src="/scans/' + state.id + '/screens/' + esc(f.meta.file) +
                  '" loading="lazy"/><span>' + esc(f.title) + '</span>';
    box.appendChild(a);
  });
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

loadModules();
loadVersion();
