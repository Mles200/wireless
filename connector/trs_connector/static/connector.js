/* Tenable Report Studio: the connector panel.
   Injected by the connector service when it serves the Studio.  It adds a "Tenable" button that
   lists the pulls the connector holds (weekly, or on demand with "Pull now"), loads a pull into
   the Studio through the Studio's own addFiles() (so the files behave exactly like dropped
   exports), shows the risk acceptances and the recent scans of Security Center, and keeps the
   report settings and the risk register on the server so the team shares them.

   The script removes its own <script> element first: the Studio captures its own source at
   start-up (SELF_SOURCE) for the HTML report and the archive copy, and those must stay plain
   Studio files that work from a folder. */
(function () {
  'use strict';
  const me = document.currentScript; if (me && me.parentNode) me.parentNode.removeChild(me);
  if (typeof addFiles !== 'function' || typeof state === 'undefined') return;   // not the Studio

  const CONN = { status: null, pulls: [], selected: new Set(), polling: null, open: false, shared: { settings: null, register: null, enabled: false } };
  const api = async (path, opts) => {
    const r = await fetch(path, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, opts || {}));
    if (!r.ok) { let msg = r.statusText; try { const j = await r.json(); msg = j.detail || j.error || JSON.stringify(j); } catch (e) { try { msg = await r.text(); } catch (e2) {} } const err = new Error(`${r.status} ${msg}`); err.status = r.status; throw err; }
    return r.status === 204 ? null : r.json();
  };
  const when = ts => ts ? new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '';
  const whenIso = s => s ? String(s).slice(0, 16).replace('T', ' ') + ' UTC' : '';
  const mb = b => b == null ? '' : (b / 1048576).toFixed(1) + ' MB';
  const sevLine = s => s ? ['Critical', 'High', 'Medium', 'Low', 'Info'].filter(k => s[k]).map(k => `${fmt(s[k])} ${k.slice(0, 1)}`).join(' · ') : '';

  /* ---------- styling (the Studio's variables) ---------- */
  const style = document.createElement('style');
  style.textContent = `
    .trs-conn-hint{margin:10px 0 0;font-size:13px;color:var(--ink-2);display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:center}
    .trs-bar{height:8px;border-radius:4px;background:var(--surface-2);overflow:hidden;margin:6px 0}
    .trs-bar > div{height:100%;background:var(--brand-2);transition:width .4s}
    .trs-status{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:12.5px;color:var(--ink-2);margin:4px 0 10px}
    .trs-status b{color:var(--ink)}
    .trs-pulls td, .trs-pulls th{vertical-align:top}
    .trs-pulls tr.sel{background:var(--surface-2)}
    .trs-log{font-family:var(--mono);font-size:11px;max-height:120px;overflow:auto;background:var(--surface-2);padding:6px 8px;border-radius:6px;white-space:pre-wrap;margin-top:6px}
    .trs-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--muted)}
    .trs-dot.ok{background:var(--good)} .trs-dot.bad{background:var(--bad)} .trs-dot.busy{background:var(--warn)}
    #btnTenable .trs-dot{margin-right:6px;vertical-align:middle}
    .trs-sect{margin-top:12px}
    .trs-sect summary{cursor:pointer;font-weight:600;font-size:13px}
  `;
  document.head.appendChild(style);

  /* ---------- start-up ---------- */
  function ready(fn) { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn(); }
  ready(() => {
    if (state.reportMode) return;
    const btn = document.createElement('button'); btn.className = 'btn ghost'; btn.id = 'btnTenable'; btn.type = 'button'; btn.innerHTML = '<span class="trs-dot" id="trsDot"></span>Tenable';
    btn.title = 'Exports pulled from Tenable by the connector: load the latest, pull a fresh one, see the risk acceptances and the recent scans';
    const anchor = $('#btnAddFiles'); if (anchor) anchor.after(btn); else $('.actions').prepend(btn);
    btn.onclick = openPanel;
    const how = $('#emptyState .how');
    if (how) { const p = document.createElement('p'); p.className = 'trs-conn-hint'; p.innerHTML = '<span>Served by the Tenable connector:</span><button class="btn primary" type="button" id="btnTenableEmpty">Load the latest Tenable pull</button>'; how.before(p); $('#btnTenableEmpty').onclick = () => openPanel(); }
    refreshStatus().catch(() => {});
    initSharedState();
  });

  async function refreshStatus() {
    try { CONN.status = await api('api/status'); } catch (e) { CONN.status = { error: e.message }; }
    const dot = $('#trsDot'); const s = CONN.status;
    if (dot) { dot.className = 'trs-dot ' + (s.error ? 'bad' : (s.job && s.job.running) ? 'busy' : s.latest ? 'ok' : ''); dot.title = s.error ? 'Connector not reachable: ' + s.error : s.latest ? 'Last pull ' + (s.latest.id || '') : 'No pull yet'; }
    return CONN.status;
  }

  /* ---------- the panel ---------- */
  let host = null;
  function panelHost() { if (!host) { host = document.createElement('div'); host.id = 'tenableHost'; host.hidden = true; document.body.appendChild(host); } return host; }
  async function openPanel() {
    const h = panelHost(); h.hidden = false; CONN.open = true;
    h.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="Tenable"><div class="box" style="width:min(980px,100%)"><h2>Tenable Security Center</h2><p class="small muted">Loading…</p></div></div>`;
    h.querySelector('.modal').addEventListener('click', e => { if (e.target.classList.contains('modal')) closePanel(); });
    await Promise.all([refreshStatus(), loadPulls()]);
    render();
    if (CONN.status && CONN.status.job && CONN.status.job.running) startPolling();
  }
  function closePanel() { const h = panelHost(); h.hidden = true; h.innerHTML = ''; CONN.open = false; stopPolling(); }
  async function loadPulls() { try { CONN.pulls = await api('api/exports'); } catch (e) { CONN.pulls = []; CONN.pullsError = e.message; } if (!CONN.selected.size && CONN.pulls.length) CONN.selected.add(CONN.pulls[0].id); }

  function sourceLine() {
    const s = CONN.status || {}; const src = s.source || {}; const latest = s.latest || {}; const sched = s.schedule || {};
    const parts = [];
    parts.push(`<span><span class="trs-dot ${s.error ? 'bad' : 'ok'}"></span>Connector <b>${esc(s.connector ? s.connector.version : '?')}</b>${s.error ? ' · <span style="color:var(--bad)">' + esc(s.error) + '</span>' : ''}</span>`);
    parts.push(`<span>Source <b>${esc(src.label || '')}</b> ${esc(src.url || '')}${src.configured === false ? ' <span style="color:var(--bad)">(API keys not configured)</span>' : ''}${latest.source && latest.source.version ? ' · version ' + esc(latest.source.version) : ''}</span>`);
    parts.push(`<span>Last pull <b>${latest.id ? esc(latest.id) : 'none yet'}</b>${latest.finished ? ' (' + esc(whenIso(latest.finished)) + ')' : ''}</span>`);
    parts.push(`<span>Schedule <b>${sched.enabled ? esc(`${sched.weekday} ${sched.time} ${sched.timezone}`) : 'off'}</b>${sched.next_run ? ' · next ' + esc(whenIso(sched.next_run)) : ''}${sched.last_result ? ' · last scheduled run: ' + esc(sched.last_result) : ''}</span>`);
    if (s.studio) parts.push(`<span>Studio <b>${esc(s.studio.version)}</b> served from ${esc(s.studio.file)}${s.studio.shared_state ? ' · settings and risk register shared on the server' : ''}</span>`);
    if (CONN.shared.enabled) parts.push(`<span>${sharedLine()}</span>`);
    return `<div class="trs-status">${parts.join('')}</div>`;
  }

  function render() {
    const h = panelHost(); if (h.hidden) return;
    const s = CONN.status || {}; const job = s.job; const running = !!(job && job.running);
    const loaded = new Set(state.files.map(f => f.name));
    const rows = CONN.pulls.map(p => {
      const va = (p.files || []).find(f => f.kind === 'va') || {}; const cmp = (p.files || []).find(f => f.kind === 'compliance') || {};
      const inStudio = (p.files || []).some(f => loaded.has(f.display_name || f.name));
      return `<tr class="${CONN.selected.has(p.id) ? 'sel' : ''}"><td><label class="check"><input type="checkbox" class="trs-sel" data-id="${esc(p.id)}" ${CONN.selected.has(p.id) ? 'checked' : ''}> <b>${esc(p.id)}</b></label><div class="small muted">${esc(whenIso(p.finished))} · ${esc(p.trigger || '')} · ${p.duration_s != null ? p.duration_s + ' s' : ''}${inStudio ? ' · <span style="color:var(--good)">loaded</span>' : ''}</div></td>
        <td class="small">${fmt(va.rows || 0)} vulnerability rows on ${fmt(va.hosts || 0)} hosts<div class="muted">${esc(sevLine(va.severity))}</div>${cmp.rows ? `<div>${fmt(cmp.rows)} compliance rows on ${fmt(cmp.hosts)} hosts</div>` : '<div class="muted">no compliance rows</div>'}</td>
        <td class="small">${esc((p.source && p.source.label) || (p.source && p.source.type === 'nessus' ? 'Nessus' : 'Security Center'))} ${esc((p.source && p.source.version) || '')}<div class="muted">${esc((p.repositories || []).join(', '))}</div>${p.risk_rules ? `<div>${fmt(p.risk_rules.accept)} accept-risk · ${fmt(p.risk_rules.recast)} recast rules</div>` : ''}${p.has_scans ? `<div>${fmt(p.scans)} scan results</div>` : ''}</td>
        <td class="small">${mb((p.files || []).reduce((a, f) => a + (f.bytes || 0), 0))}${(p.warnings || []).length ? `<div style="color:var(--bad)">${(p.warnings || []).map(esc).join('<br>')}</div>` : ''}</td>
        <td class="nowrap"><a class="btn sm" href="api/exports/${encodeURIComponent(p.id)}/files/${encodeURIComponent(va.name || '')}?download=1" title="Download the vulnerability export">VA csv</a> ${cmp.name ? `<a class="btn sm" href="api/exports/${encodeURIComponent(p.id)}/files/${encodeURIComponent(cmp.name)}?download=1" title="Download the compliance export">CIS csv</a>` : ''}</td></tr>`;
    }).join('');
    const newest = CONN.pulls[0];
    h.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="Tenable"><div class="box" style="width:min(1040px,100%)">
      <h2>Tenable Security Center</h2>
      ${sourceLine()}
      <div id="trsJob">${jobHtml(job)}</div>
      <p class="small muted" style="margin:8px 0 6px">Each pull holds the vulnerability export (Critical to Low plus the inventory rows that keep hosts without findings listed) and the compliance export (Info, Medium, High). Tick one pull to report on it, or several: the newest becomes <b>now</b> and the older ones <b>history</b> for the trend, Validate fixes and the risk register, exactly as with dropped files.</p>
      <div class="table-wrap"><table class="data trs-pulls"><thead><tr><th>Pull</th><th>Content</th><th>Source</th><th>Size</th><th>Files</th></tr></thead><tbody>${rows || `<tr><td colspan="5" class="muted">${CONN.pullsError ? esc(CONN.pullsError) : 'No pull yet. Click Pull now.'}</td></tr>`}</tbody></table></div>
      ${newest ? `<details class="trs-sect" id="trsRules"><summary>Risk acceptances in Security Center at the pull of ${esc(newest.id)}${newest.risk_rules ? ` (${fmt(newest.risk_rules.accept)} accept-risk, ${fmt(newest.risk_rules.recast)} recast rules)` : ''}</summary><div id="trsRulesBody" class="small muted" style="margin-top:6px">Open to load.</div></details>
      <details class="trs-sect" id="trsScans"><summary>Recent scans at the pull of ${esc(newest.id)}${newest.has_scans ? ` (${fmt(newest.scans)})` : ''}</summary><div id="trsScansBody" class="small muted" style="margin-top:6px">Open to load.</div></details>` : ''}
      <div id="trsResult"></div>
      <div class="foot"><button class="btn" type="button" id="trsPull" ${running || (s.source && s.source.configured === false) ? 'disabled' : ''}>${running ? 'Pull running…' : 'Pull now'}</button><button class="btn" type="button" id="trsCheck" title="Check the connection to Tenable now">Check connection</button><span style="flex:1"></span><button class="btn" type="button" id="trsClose">Close</button><button class="btn primary" type="button" id="trsLoad" ${CONN.selected.size ? '' : 'disabled'}>Load ${CONN.selected.size > 1 ? CONN.selected.size + ' pulls' : 'selected pull'}</button></div>
    </div></div>`;
    h.querySelector('.modal').addEventListener('click', e => { if (e.target.classList.contains('modal') && !h.dataset.busy) closePanel(); });
    $('#trsClose').onclick = closePanel;
    $$('.trs-sel', h).forEach(cb => cb.onchange = () => { if (cb.checked) CONN.selected.add(cb.dataset.id); else CONN.selected.delete(cb.dataset.id); render(); });
    $('#trsPull').onclick = pullNow;
    $('#trsLoad').onclick = loadSelected;
    $('#trsCheck').onclick = checkConnection;
    const rules = $('#trsRules'); if (rules) rules.ontoggle = () => { if (rules.open) showRules(newest.id); };
    const scans = $('#trsScans'); if (scans) scans.ontoggle = () => { if (scans.open) showScans(newest.id); };
  }

  function jobHtml(job) {
    if (!job) return '';
    const pct = job.total ? Math.min(100, Math.round(100 * job.rows / job.total)) : null;
    if (job.running) return `<div class="notice"><b>Pull in progress</b> (${esc(job.trigger)}, ${job.elapsed} s): ${esc(job.message)}<div class="trs-bar"><div style="width:${pct == null ? 15 : pct}%"></div></div><div class="trs-log">${(job.log || []).slice(-6).map(esc).join('\n')}</div></div>`;
    if (job.error) return `<div class="notice bad"><b>Last pull failed</b> (${esc(whenIsoTs(job.finished))}): ${esc(job.error)}<div class="trs-log">${(job.log || []).slice(-8).map(esc).join('\n')}</div></div>`;
    return `<div class="notice good small">Last pull ${esc(job.pull_id || '')} finished in ${job.elapsed} s: ${esc(job.message)}</div>`;
  }
  const whenIsoTs = ts => ts ? when(ts) : '';

  async function pullNow() {
    const b = $('#trsPull'); if (b) { b.disabled = true; b.textContent = 'Starting…'; }
    try { await api('api/pull', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); }
    catch (e) { $('#trsResult').innerHTML = `<div class="notice bad">The pull could not be started: ${esc(e.message)}</div>`; if (b) { b.disabled = false; b.textContent = 'Pull now'; } return; }
    await refreshStatus(); render(); startPolling();
  }
  function startPolling() { stopPolling(); CONN.polling = setInterval(async () => { const s = await refreshStatus(); const jobEl = $('#trsJob'); if (jobEl) jobEl.innerHTML = jobHtml(s.job); if (!s.job || !s.job.running) { stopPolling(); const before = CONN.pulls.length ? CONN.pulls[0].id : null; await loadPulls(); if (s.job && !s.job.error && CONN.pulls.length && CONN.pulls[0].id !== before) { CONN.selected = new Set([CONN.pulls[0].id]); } render(); } }, 2000); }
  function stopPolling() { if (CONN.polling) { clearInterval(CONN.polling); CONN.polling = null; } }

  async function checkConnection() {
    const b = $('#trsCheck'); b.disabled = true; b.textContent = 'Checking…';
    try { const r = await api('api/tenable/check'); $('#trsResult').innerHTML = `<div class="notice good small">Connected to ${esc(r.type === 'nessus' ? 'Nessus' : 'Security Center')} ${esc(r.version || '')} at ${esc(r.url)}${r.user ? ' as ' + esc(r.user) : ''}${r.repositories ? ': repositories ' + r.repositories.map(x => esc(x.name)).join(', ') : ''}${r.selected ? ': scans ' + r.selected.map(esc).join(', ') : ''}.</div>`; }
    catch (e) { $('#trsResult').innerHTML = `<div class="notice bad">Connection check failed: ${esc(e.message)}</div>`; }
    finally { b.disabled = false; b.textContent = 'Check connection'; }
  }

  async function loadSelected() {
    const ids = CONN.pulls.map(p => p.id).filter(id => CONN.selected.has(id)); if (!ids.length) return;
    const h = panelHost(); h.dataset.busy = '1'; const b = $('#trsLoad'); b.disabled = true; const res = $('#trsResult');
    try {
      const files = []; const loaded = new Set(state.files.map(f => f.name));
      for (const id of ids) {
        const m = await api(`api/exports/${encodeURIComponent(id)}`);
        for (const f of (m.files || [])) {
          const name = f.display_name || f.name;
          if (loaded.has(name)) continue;   // already in the Studio
          res.innerHTML = `<div class="notice small">Downloading ${esc(name)} (${mb(f.bytes)} compressed)…</div>`;
          const r = await fetch(`api/exports/${encodeURIComponent(id)}/files/${encodeURIComponent(f.name)}`, { credentials: 'same-origin', cache: 'no-store' });
          if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
          const blob = await r.blob();
          files.push(new File([blob], name, { type: 'text/csv', lastModified: Date.parse(m.finished) || Date.now() }));
        }
      }
      if (!files.length) { res.innerHTML = '<div class="notice small">These exports are already loaded.</div>'; return; }
      res.innerHTML = `<div class="notice small">Parsing ${files.length} files…</div>`;
      await new Promise(r => setTimeout(r, 30));
      await addFiles(files);
      closePanel();
      showNotice(`Loaded from the Tenable connector: ${ids.map(esc).join(', ')} (${files.map(f => esc(f.name)).join(', ')}). The newest export is "now"; older pulls are history.`);
    } catch (e) { res.innerHTML = `<div class="notice bad">Loading failed: ${esc(e.message)}</div>`; }
    finally { h.dataset.busy = ''; if (b) b.disabled = false; }
  }

  async function showRules(id) {
    const el = $('#trsRulesBody'); if (!el || el.dataset.loaded) return;
    try {
      const r = await api(`api/exports/${encodeURIComponent(id)}/risk-rules`); el.dataset.loaded = '1';
      const row = (x, kind) => `<tr><td>${esc(kind)}</td><td>${esc((x.plugin || {}).id || '')}</td><td class="wrap">${esc((x.plugin || {}).name || '')}</td><td>${esc(x.hostType === 'all' ? 'all hosts' : (x.hostValue || x.hostType || ''))}${x.port && x.port !== '-1' ? ' port ' + esc(x.port) : ''}</td><td>${esc(kind === 'Recast' ? ((x.newSeverity || {}).name || '') : (x.expires && x.expires !== '-1' ? 'until ' + fmtDate(+x.expires * 1000) : 'no expiry'))}</td><td class="wrap">${esc(x.comments || '')}</td><td>${esc((x.user || {}).username || '')}</td><td>${x.createdTime ? fmtDate(+x.createdTime * 1000) : ''}</td></tr>`;
      const rows = (r.accept || []).map(x => row(x, 'Accept')).concat((r.recast || []).map(x => row(x, 'Recast')));
      el.className = 'small'; el.innerHTML = rows.length ? `<p class="muted" style="margin-bottom:6px">Findings covered by an Accept Risk rule leave the export, and the report, automatically; a Recast Risk rule changes the severity in Security Center. This list is the audit trail of those decisions at the time of the pull.</p><div class="table-wrap"><table class="data"><thead><tr><th>Rule</th><th>Plugin</th><th>Vulnerability</th><th>Hosts</th><th>Expiry / new severity</th><th>Comment</th><th>By</th><th>Created</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>` : 'No Accept Risk or Recast Risk rules in Security Center at the time of the pull.';
    } catch (e) { el.textContent = 'Not available: ' + e.message; }
  }
  async function showScans(id) {
    const el = $('#trsScansBody'); if (!el || el.dataset.loaded) return;
    try {
      const r = await api(`api/exports/${encodeURIComponent(id)}/scans`); el.dataset.loaded = '1';
      const list = (r.results || []).slice().sort((a, b) => (+b.finishTime || 0) - (+a.finishTime || 0)).slice(0, 40);
      el.className = 'small'; el.innerHTML = list.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Scan</th><th>Repository</th><th>Status</th><th>Finished</th><th class="num">Hosts scanned</th><th>Import</th></tr></thead><tbody>${list.map(x => `<tr><td>${esc(x.name || '')}</td><td>${esc(typeof x.repository === 'object' && x.repository ? x.repository.name : (x.repository || ''))}</td><td>${esc(x.status || '')}</td><td class="nowrap">${esc(when(+x.finishTime))}</td><td class="num">${esc(x.scannedIPs != null ? `${x.scannedIPs} of ${x.totalIPs}` : '')}</td><td>${esc(x.importStatus || '')}</td></tr>`).join('')}</tbody></table></div>` : 'No scan results in the period.';
    } catch (e) { el.textContent = 'Not available: ' + e.message; }
  }

  /* ---------- shared state: report settings and the risk register on the server ----------
     The overrides are installed now, while the page is still being parsed, so that init() (which
     runs at DOMContentLoaded and loads the register) already goes through them.  If the server
     answers 404 the shared state is disabled and the Studio's own storage is used. */
  const origSaveSettings = window.saveSettings, origSaveRegister = window.riskSaveRegister, origLoadRegister = window.riskLoadRegister;
  let settingsTimer = null, registerTimer = null, registerBase = null, pushing = false;
  CONN.shared.enabled = null;   // unknown until the first answer
  function sharedLine() {
    const s = CONN.shared; const parts = [];
    parts.push(s.settings && s.settings.present ? `settings shared (updated ${esc(when(s.settings.server_updated))})` : 'settings: this browser only until saved');
    parts.push(s.register && s.register.present ? `risk register shared (${fmt(Object.keys(s.register.items || {}).length)} findings, updated ${esc(when(s.register.server_updated))})` : 'risk register: this browser only until saved');
    return 'Shared on the server: ' + parts.join(' · ');
  }
  const disabledByServer = e => { if (e && e.status === 404) { CONN.shared.enabled = false; return true; } return false; };
  window.riskLoadRegister = async function () {
    if (RISK_REG) return RISK_REG;
    if (CONN.shared.enabled !== false) {
      try {
        const r = await api('api/state/register');
        CONN.shared.enabled = true; CONN.shared.register = r;
        if (r && r.present && r.items) { RISK_REG = { trsRisk: 1, items: r.items, overrides: r.overrides || {}, exportDate: r.exportDate || 0, updated: r.updated || 0 }; registerBase = r.server_updated; origSaveRegister(); return RISK_REG; }
        const local = await origLoadRegister();
        if (local && Object.keys(local.items || {}).length) pushRegister();   // first browser on this server: seed it with the local register
        return local;
      } catch (e) { if (!disabledByServer(e)) console.warn('shared register not available', e); }
    }
    return origLoadRegister();
  };
  window.riskSaveRegister = function () { origSaveRegister(); if (CONN.shared.enabled === false) return; if (registerTimer) clearTimeout(registerTimer); registerTimer = setTimeout(pushRegister, 800); };
  window.saveSettings = function () { origSaveSettings(); if (CONN.shared.enabled === false) return; if (settingsTimer) clearTimeout(settingsTimer); settingsTimer = setTimeout(pushSettings, 800); };
  async function initSharedState() {
    let srv;
    try { srv = await api('api/state/settings'); } catch (e) { disabledByServer(e); return; }
    CONN.shared.enabled = true; CONN.shared.settings = srv;
    if (srv && srv.present && srv.settings) {
      const keepLogo = state.settings.logo;
      const next = Object.assign(DEFAULT_SETTINGS(), srv.settings); if (!next.logo) next.logo = keepLogo; next.v = SETTINGS_VERSION;
      const changed = JSON.stringify(next) !== JSON.stringify(state.settings);
      state.settings = next; origSaveSettings();
      if (changed) { applyBrand(); if (state.findings.length || state.checks.length) { buildHosts(); renderAll(); } }
    } else if (srv && !srv.present) { pushSettings(); }   // first browser on this server: seed it
  }
  async function pushSettings() {
    try { const r = await api('api/state/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ trsSettings: 1, settings: state.settings, updated: Date.now() }) }); CONN.shared.settings = { present: true, server_updated: r.server_updated }; }
    catch (e) { if (disabledByServer(e)) return; console.warn('settings not saved to the server', e); showNotice('The report settings could not be saved on the server (' + esc(e.message) + '); they are kept in this browser.', 'bad'); }
  }
  async function pushRegister(retry) {
    if (!RISK_REG || pushing || CONN.shared.enabled === false) return; pushing = true;
    try {
      const body = Object.assign({ if_server_updated: registerBase }, RISK_REG);
      const r = await api('api/state/register', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      registerBase = r.server_updated; CONN.shared.register = { present: true, server_updated: r.server_updated, items: RISK_REG.items };
    } catch (e) {
      if (e.status === 409 && !retry) {   // someone else saved first: take their register, re-derive the states from the loaded export, save again
        try {
          const srv = await api('api/state/register');
          if (srv && srv.present) {
            const mine = RISK_REG; const ov = Object.assign({}, srv.overrides || {});
            for (const [k, v] of Object.entries(mine.overrides || {})) if (!ov[k] || (v.date || '') >= (ov[k].date || '')) ov[k] = v;
            RISK_REG = { trsRisk: 1, items: srv.items || {}, overrides: ov, exportDate: srv.exportDate || 0, updated: Date.now() }; registerBase = srv.server_updated;
            if (state.findings.length) { riskSync(); renderRisk(); }
            origSaveRegister(); pushing = false; await pushRegister(true);
            showNotice('The risk register was updated by someone else in the meantime; it was merged and saved again.');
          }
        } catch (e2) { console.warn(e2); }
      } else if (!disabledByServer(e)) { console.warn('register not saved to the server', e); showNotice('The risk register could not be saved on the server (' + esc(e.message) + '); it is kept in this browser.', 'bad'); }
    } finally { pushing = false; }
  }

  window.TRS_CONNECTOR = { open: openPanel, status: () => CONN.status, pulls: () => CONN.pulls, load: loadSelected, select: id => { CONN.selected = new Set([id]); } };
})();
