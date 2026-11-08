/* Mitigation tab and the data folder (Studio 4.9).

   The Studio's register (RISK_REG, kept by riskSync) already knows every finding ever seen: when
   it was first seen, last seen, whether it is open or closed, and the date it was closed (no
   longer reported while its host was still scanned).  This block builds the mitigation view on
   it: what got mitigated, what is pending, what is new or reopened, what is in the environment,
   a history per pull, an Excel tracker; and keeps everything in a folder you choose (your
   Desktop): the pulls as files, the register as JSON and CSV, the history, the reports.

   Added to the Studio by tools/build_tenable.py (marker block before </body>).  Studio only:
   hidden in the HTML report. */
(function () {
  'use strict';
  if (typeof state === 'undefined' || typeof riskSync !== 'function' || typeof addSheet !== 'function') return;
  const M = { folder: null, folderName: '', pulls: [], saving: null, lastSaved: null, pending: false };
  const sevRank = s => SEV_RANK[s] ?? 0;
  const productName = name => (typeof productOf === 'function' ? productOf(name) : name) || name;
  const slaDays = (sev, external) => (state.settings.sla[sev] || [90, 90])[external ? 0 : 1];
  const exportDateNow = () => { const cur = state.files.filter(f => f.kind === 'current' && f.date); return cur.length ? Math.max(...cur.map(f => f.date)) : 0; };

  /* ---------- history: one entry per pull, derived from the register ---------- */
  function updateHistory() {
    if (!RISK_REG || state.reportMode) return;
    const date = exportDateNow(); if (!date || RISK_REG.stale) return;
    const items = Object.values(RISK_REG.items || {});
    const e = { date, open: { Critical: 0, High: 0, Medium: 0, Low: 0, total: 0 }, unverified: 0, closed: 0, opened: 0, reopened: 0, hosts: 0, hostsAbsent: 0, files: state.files.filter(f => f.kind === 'current').map(f => f.name) };
    const seen = new Set(), absent = new Set();
    for (const it of items) {
      if (it.status === 'Open') { if (it.hostSeen === false) { e.unverified++; absent.add(it.ip); } else { e.open[it.severity] = (e.open[it.severity] || 0) + 1; e.open.total++; } }
      if (it.closedOn === date) e.closed++;
      if (it.openedOn === date && !it.reopened) e.opened++;
      if (it.reopenedOn === date) e.reopened++;
    }
    for (const h of state.hosts.values()) seen.add(h.ip);
    e.hosts = seen.size; e.hostsAbsent = absent.size;
    const hist = (RISK_REG.history || []).filter(x => x.date !== date);
    if (!hist.some(x => x.date < date)) { e.baseline = e.opened; e.opened = 0; }   // the first pull is the baseline: nothing in it is "new"
    hist.push(e); hist.sort((a, b) => a.date - b.date);
    RISK_REG.history = hist;
  }
  const origRiskSync = window.riskSync;
  let renderTimer = null; const queueRender = () => { if (renderTimer) clearTimeout(renderTimer); renderTimer = setTimeout(() => { renderTimer = null; try { renderMitigation(); } catch (e) { console.error(e); } }, 0); };
  window.riskSync = function () { const r = origRiskSync.apply(this, arguments); try { updateHistory(); if (RISK_REG && !RISK_REG.stale) { riskSaveRegister(); scheduleSave(); } queueRender(); } catch (e) { console.error(e); } return r; };

  /* ---------- the figures ---------- */
  function mitigationData(period) {
    const reg = RISK_REG || { items: {}, history: [] }; const date = exportDateNow(); const items = Object.values(reg.items || {});
    const hist = (reg.history || []).slice(); const idx = hist.findIndex(h => h.date === date); const prev = idx > 0 ? hist[idx - 1] : (idx < 0 && hist.length ? hist[hist.length - 1] : null);
    const since = period === 'prev' ? (prev ? prev.date : 0) : period === '30' ? date - 30 * DAY : period === '90' ? date - 90 * DAY : 0;
    const baseline = hist.length ? hist[0].date : date;   // what the very first pull saw is the baseline, never "new"
    const u = state.ui; const inScope = it => { if (u.scopeVal === '__all') return true; const h = state.hosts.get(it.ip); if (h) return hostDim(h, u.scopeDim) === u.scopeVal; return u.scopeDim === 'env' ? it.env === u.scopeVal : u.scopeDim === 'site' ? it.site === u.scopeVal : false; };
    const live = new Map(); for (const f of state.findings) live.set(f.plugin + '|' + f.ip, f);
    const rows = [];
    for (const [k, it] of Object.entries(reg.items || {})) {
      if (!inScope(it)) continue;
      const f = live.get(k); const h = state.hosts.get(it.ip);
      const external = f ? !!f.host.external : !!it.external; const days = slaDays(it.severity, external); const due = it.firstSeen ? it.firstSeen + days * DAY : null;
      const r = { key: k, plugin: it.plugin, name: it.name || (f && f.name) || String(it.plugin), severity: it.severity || (f && f.severity) || 'Info', ip: it.ip, host: h ? h.display : (it.host || it.ip), env: h ? h.env : (it.env || ''), site: h ? h.site : (it.site || ''), hostObj: h || null,
        status: it.status, inExport: it.status === 'Open' ? it.hostSeen !== false : true, firstSeen: it.firstSeen, lastSeen: it.lastSeen, closedOn: it.closedOn || null, reopened: it.reopened || 0, openedOn: it.openedOn || it.firstSeen, reopenedOn: it.reopenedOn || null,
        due, overdue: it.status === 'Open' && due != null && todayUTC() > due, product: productName(it.name || (f && f.name) || ''), cve: it.cve || '', kev: f ? !!f.kev : /CISA-KNOWN-EXPLOITED/i.test(it.cve || ''), solution: f ? f.solution : '', action: productName(it.name || (f && f.name) || '') };
      r.daysOpen = r.firstSeen ? Math.max(0, Math.round(((r.status === 'Closed' && r.closedOn ? r.closedOn : date || todayUTC()) - r.firstSeen) / DAY)) : null;
      r.withinTimeline = r.status === 'Closed' && r.closedOn && due != null ? r.closedOn <= due : null;
      r.inPeriod = r.status === 'Closed' ? (r.closedOn || 0) >= since : false;
      r.isNew = r.status === 'Open' && (r.openedOn || 0) > baseline && (r.openedOn || 0) >= since && (period !== 'prev' || (!!prev && (r.openedOn || 0) > prev.date));
      r.isReopened = (r.reopenedOn || 0) >= since && (r.reopenedOn || 0) > 0 && r.status === 'Open';
      rows.push(r);
    }
    const open = rows.filter(r => r.status === 'Open' && r.inExport), unverified = rows.filter(r => r.status === 'Open' && !r.inExport), closed = rows.filter(r => r.status === 'Closed'), mitigated = closed.filter(r => r.inPeriod);
    const bySev = list => { const c = { Critical: 0, High: 0, Medium: 0, Low: 0 }; for (const r of list) c[r.severity] = (c[r.severity] || 0) + 1; return c; };
    const group = (list, keyFn, init) => { const m = new Map(); for (const r of list) { const k = keyFn(r); let g = m.get(k); if (!g) { g = Object.assign({ key: k, rows: [], open: 0, closed: 0, unverified: 0, mitigated: 0, hostsOpen: new Set(), hostsFixed: new Set(), firstSeen: null, due: null, overdue: 0, closedOn: null, daysSum: 0, daysN: 0, within: 0, withinN: 0 }, init(r)); m.set(k, g); }
      g.rows.push(r); if (sevRank(r.severity) > sevRank(g.severity)) g.severity = r.severity;
      if (r.status === 'Open' && r.inExport) { g.open++; g.hostsOpen.add(r.host); if (r.firstSeen && (!g.firstSeen || r.firstSeen < g.firstSeen)) g.firstSeen = r.firstSeen; if (r.due && (!g.due || r.due < g.due)) g.due = r.due; if (r.overdue) g.overdue++; }
      else if (r.status === 'Open') g.unverified++;
      else { g.closed++; if (r.inPeriod) { g.mitigated++; g.hostsFixed.add(r.host); if (!g.closedOn || r.closedOn > g.closedOn) g.closedOn = r.closedOn; if (r.daysOpen != null) { g.daysSum += r.daysOpen; g.daysN++; } if (r.withinTimeline != null) { g.withinN++; if (r.withinTimeline) g.within++; } } } }
      for (const g of m.values()) { g.total = g.rows.length; g.done = g.open + g.unverified === 0 ? 100 : Math.round(100 * g.closed / g.total); g.state = g.open + g.unverified === 0 ? 'Done' : g.closed > 0 ? 'In progress' : 'Not started'; g.avgDays = g.daysN ? Math.round(g.daysSum / g.daysN) : null; g.withinPct = g.withinN ? Math.round(100 * g.within / g.withinN) : null; }
      return [...m.values()]; };
    const byVuln = group(rows, r => r.plugin, r => ({ plugin: r.plugin, name: r.name, severity: r.severity, action: r.action }));
    const byAction = group(rows, r => r.action, r => ({ action: r.action, severity: r.severity, plugins: new Set() })); for (const g of byAction) for (const r of g.rows) g.plugins.add(r.plugin);
    const envs = new Map(); const envOf = r => r.env || 'Unknown';
    for (const h of state.hosts.values()) { if (u.scopeVal !== '__all' && hostDim(h, u.scopeDim) !== u.scopeVal) continue; const k = h.env || 'Unknown'; let g = envs.get(k); if (!g) { g = { env: k, hosts: 0, withFindings: 0, clean: 0, open: 0, mitigated: 0, unverified: 0, absent: new Set(), newHosts: 0 }; envs.set(k, g); } g.hosts++; if (h.active) g.withFindings++; else g.clean++; }
    for (const r of rows) { const k = envOf(r); let g = envs.get(k); if (!g) { g = { env: k, hosts: 0, withFindings: 0, clean: 0, open: 0, mitigated: 0, unverified: 0, absent: new Set(), newHosts: 0 }; envs.set(k, g); } if (r.status === 'Open' && r.inExport) g.open++; else if (r.status === 'Open') { g.unverified++; g.absent.add(r.ip); } else if (r.inPeriod) g.mitigated++; }
    const absentHosts = new Map(); for (const r of unverified) { let a = absentHosts.get(r.ip); if (!a) { a = { ip: r.ip, host: r.host, env: r.env, lastSeen: r.lastSeen, open: 0 }; absentHosts.set(r.ip, a); } a.open++; if (r.lastSeen > (a.lastSeen || 0)) a.lastSeen = r.lastSeen; }
    const earliest = new Map(); for (const it of items) { const d = it.openedOn || it.firstSeen || 0; if (!earliest.has(it.ip) || d < earliest.get(it.ip)) earliest.set(it.ip, d); }
    const newHosts = [...state.hosts.values()].filter(h => (u.scopeVal === '__all' || hostDim(h, u.scopeDim) === u.scopeVal) && prev && (earliest.get(h.ip) || 0) > prev.date && h.active);
    for (const h of newHosts) { const g = envs.get(h.env || 'Unknown'); if (g) g.newHosts++; }
    return { date, prev, since, period, rows, open, unverified, closed, mitigated, newOpen: open.filter(r => r.isNew), reopened: open.filter(r => r.isReopened), overdue: open.filter(r => r.overdue), bySev, byVuln, byAction, envs: [...envs.values()].sort((a, b) => b.open - a.open), absentHosts: [...absentHosts.values()].sort((a, b) => b.open - a.open), newHosts, history: hist, stale: !!(RISK_REG && RISK_REG.stale) };
  }

  /* ---------- the tab ---------- */
  function ensureTab() {
    if (state.reportMode || $('#mitTab')) return;
    const bar = $('#tabBar'); const report = bar.querySelector('.tab[data-tab="reportTab"]');
    const b = document.createElement('button'); b.className = 'tab'; b.setAttribute('role', 'tab'); b.dataset.tab = 'mitTab'; b.type = 'button'; b.title = 'What got mitigated, what is pending, what is new, what is in the environment; the data folder on this computer'; b.innerHTML = 'Mitigation <span class="count" id="cntMit">0</span>';
    report ? bar.insertBefore(b, report) : bar.appendChild(b); b.onclick = () => switchTab('mitTab');
    const pane = document.createElement('div'); pane.id = 'mitTab'; pane.className = 'tabpane'; pane.hidden = true; $('#reportTab').before(pane);
  }
  const origRenderAll = window.renderAll;
  window.renderAll = function () { const r = origRenderAll.apply(this, arguments); try { renderMitigation(); } catch (e) { console.error(e); } return r; };
  function renderMitigation() {
    if (state.reportMode) return; ensureTab(); const el = $('#mitTab'); if (!el) return; const u = state.ui;
    if (!u.mitPeriod) { u.mitPeriod = 'prev'; u.mitSev = new Set(['Critical', 'High', 'Medium', 'Low']); u.mitSearch = ''; u.mitLimit = 100; }
    if (!RISK_REG) { el.innerHTML = '<div class="notice">The register is still loading.</div>'; return; }
    const D = mitigationData(u.mitPeriod); const sevOk = r => u.mitSev.has(r.severity); const q = u.mitSearch;
    const match = r => !q || r.name.toLowerCase().includes(q) || String(r.plugin).includes(q) || r.host.toLowerCase().includes(q) || r.ip.includes(q) || r.action.toLowerCase().includes(q);
    const filt = list => list.filter(r => sevOk(r) && match(r));
    const periodLabel = D.period === 'prev' ? (D.prev ? 'since the previous pull (' + fmtDate(D.prev.date) + ')' : 'since the previous pull (none yet: everything counts)') : D.period === '30' ? 'in the last 30 days' : D.period === '90' ? 'in the last 90 days' : 'since tracking began';
    const cnt = $('#cntMit'); if (cnt) cnt.textContent = fmt(D.open.length);
    const sevLine = c => `${fmt(c.Critical)} C · ${fmt(c.High)} H · ${fmt(c.Medium)} M · ${fmt(c.Low)} L`;
    const stale = D.stale ? `<div class="notice">The loaded export (${fmtDate(exportDateNow())}) is older than the pull the register last saw (${fmtDate(RISK_REG.exportDate)}): the figures below are the register's, nothing was moved. Load the newest pull to update.</div>` : '';
    const folderLine = folderLineHtml();
    el.innerHTML = `
      <div class="toolbar">
        <span class="sevchips" role="group" aria-label="Severity">${['Critical', 'High', 'Medium', 'Low'].map(s => `<button type="button" class="${s.toLowerCase()}" data-ms="${s}" aria-pressed="${u.mitSev.has(s)}">${s}</button>`).join('')}</span>
        <select id="mitPeriod" aria-label="Period"><option value="prev" ${u.mitPeriod === 'prev' ? 'selected' : ''}>Mitigated since the previous pull</option><option value="30" ${u.mitPeriod === '30' ? 'selected' : ''}>Mitigated in the last 30 days</option><option value="90" ${u.mitPeriod === '90' ? 'selected' : ''}>Mitigated in the last 90 days</option><option value="all" ${u.mitPeriod === 'all' ? 'selected' : ''}>Mitigated since tracking began</option></select>
        <input type="search" id="mitSearch" placeholder="Search vulnerability, plugin ID, host, IP, action…" value="${esc(q)}" aria-label="Search">
        <span style="flex:1"></span>
        <button class="btn sm primary" type="button" id="mitUpdate" title="Pull the newest results from Tenable and update the register and the data folder">Update from Tenable</button>
        <button class="btn sm" type="button" id="mitFolder">Data folder</button>
        <button class="btn sm" type="button" id="mitExcel">Excel</button>
      </div>
      ${stale}
      <div class="kpis">
        ${kpi('Pending (open now)', fmt(D.open.length), sevLine(D.bySev(D.open)), 'accent')}
        ${kpi('Mitigated', fmt(D.mitigated.length), periodLabel, 'good')}
        ${kpi('New', fmt(D.newOpen.length), 'open findings first seen in the period', D.newOpen.length ? 'bad' : '')}
        ${kpi('Reopened', fmt(D.reopened.length), 'closed before, reported again', D.reopened.length ? 'bad' : '')}
        ${kpi('Overdue', fmt(D.overdue.length), 'open past the Tenable due date', D.overdue.length ? 'bad' : 'good')}
        ${kpi('Hosts in the environment', fmt(hostsOf().length), `${fmt([...state.hosts.values()].filter(h => !h.active).length)} scanned clean · ${fmt(D.newHosts.length)} new`)}
        ${kpi('Not verified', fmt(D.unverified.length), `${fmt(D.absentHosts.length)} hosts not in this pull`, D.unverified.length ? 'medium' : '')}
        ${kpi('Mitigated ever', fmt(D.closed.length), RISK_REG.history && RISK_REG.history.length ? `${fmt(RISK_REG.history.length)} pulls tracked` : 'register')}
      </div>
      <div class="grid two">
        <div class="panel"><h3>Open findings per pull <span class="hint">from the register's history</span></h3><div class="chart"><canvas id="mitTrend"></canvas></div></div>
        <div class="panel"><h3>Mitigated and new per pull</h3><div class="chart"><canvas id="mitFlow"></canvas></div></div>
      </div>
      <div class="panel"><h3>Remediation actions <span class="hint">one action per product or update family: done when nothing is open; % done = closed of everything ever seen</span></h3>${actionsTable(D)}</div>
      <div class="panel"><h3>Mitigated ${esc(periodLabel)} <span class="hint">no longer reported on a host that was still scanned; days = first seen to closed; within timeline = closed before the Tenable due date</span></h3>${vulnTable(D, 'mitigated', filt)}</div>
      <div class="panel"><h3>Pending <span class="hint">open now, oldest first seen first; click a vulnerability for the hosts</span></h3>${vulnTable(D, 'open', filt)}</div>
      <div class="grid two">
        <div class="panel"><h3>Environment <span class="hint">hosts in this pull by environment</span></h3>${envTable(D)}</div>
        <div class="panel"><h3>Hosts not in this pull <span class="hint">their open findings are not verified until they are scanned again</span></h3>${absentTable(D)}</div>
      </div>
      <div class="panel" id="mitData"><h3>Data folder <span class="hint">every pull, the register and the history as files on this computer</span></h3><p class="small">${folderLine}</p><div id="mitPulls"></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">${canPickFolder() ? `<button class="btn sm" type="button" id="mitChoose">${M.folder ? 'Change folder' : 'Choose folder'}</button><button class="btn sm" type="button" id="mitSave" ${M.folder ? '' : 'disabled'}>Save this pull and the register now</button><button class="btn sm" type="button" id="mitRefresh" ${M.folder ? '' : 'disabled'}>Refresh the list</button>` : ''}<button class="btn sm" type="button" id="mitZip">Download data ZIP</button></div></div>`;
    $$('#mitTab .sevchips button').forEach(b => b.onclick = () => { const s = b.dataset.ms; if (u.mitSev.has(s)) u.mitSev.delete(s); else u.mitSev.add(s); renderMitigation(); });
    $('#mitPeriod').onchange = e => { u.mitPeriod = e.target.value; renderMitigation(); };
    $('#mitSearch').oninput = e => { u.mitSearch = e.target.value.trim().toLowerCase(); renderMitigation(); const s = $('#mitSearch'); if (s) { s.focus(); s.setSelectionRange(s.value.length, s.value.length); } };
    $('#mitUpdate').onclick = () => { if (window.TRS_TENABLE) TRS_TENABLE.open(); else $('#fileInput').click(); };
    $('#mitFolder').onclick = () => { $('#mitData').scrollIntoView({ behavior: 'smooth' }); };
    $('#mitExcel').onclick = exportMitigationExcel;
    const ch = $('#mitChoose'); if (ch) ch.onclick = chooseFolder; const sv = $('#mitSave'); if (sv) sv.onclick = () => saveAll(true); const rf = $('#mitRefresh'); if (rf) rf.onclick = () => listPulls().then(renderPulls); $('#mitZip').onclick = downloadDataZip;
    bindExpand(el, D); bindHostLinks(el); renderPulls(); drawCharts(D);
  }
  function actionsTable(D) {
    const list = D.byAction.slice().sort((a, b) => ({ 'Not started': 0, 'In progress': 1, Done: 2 })[a.state] - ({ 'Not started': 0, 'In progress': 1, Done: 2 })[b.state] || sevRank(b.severity) - sevRank(a.severity) || b.open - a.open).slice(0, 60);
    if (!list.length) return '<p class="muted">Nothing tracked yet.</p>';
    const stateFlag = s => `<span class="flag" style="background:${s === 'Done' ? 'var(--good)' : s === 'In progress' ? 'var(--warn)' : 'var(--bad)'};color:#fff">${s}</span>`;
    return `<div class="table-wrap"><table class="data"><thead><tr><th>Remediation action</th><th>Status</th><th>Severity</th><th class="num">Open</th><th class="num">Not verified</th><th class="num">Mitigated (period)</th><th class="num">Closed ever</th><th class="num">% done</th><th>Oldest open</th><th>Due</th><th class="num">Overdue</th><th>Hosts open</th></tr></thead><tbody>${list.map(g => `<tr><td class="wrap"><b>${esc(g.action)}</b><div class="small muted">${fmt(g.plugins.size)} plugins</div></td><td>${stateFlag(g.state)}</td><td>${pill(g.severity)}</td><td class="num">${fmt(g.open)}</td><td class="num">${g.unverified || ''}</td><td class="num">${fmt(g.mitigated)}</td><td class="num">${fmt(g.closed)}</td><td class="num">${g.done}%</td><td class="nowrap">${fmtDate(g.firstSeen)}</td><td class="nowrap">${fmtDate(g.due)}</td><td class="num">${g.overdue || ''}</td><td class="wrap hostlist">${[...g.hostsOpen].slice(0, 8).map(esc).join(', ')}${g.hostsOpen.size > 8 ? ` <span class="muted">+${g.hostsOpen.size - 8}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>${D.byAction.length > 60 ? `<p class="small muted">${fmt(D.byAction.length - 60)} further actions in the Excel.</p>` : ''}`;
  }
  function vulnTable(D, mode, filt) {
    const groups = D.byVuln.map(g => Object.assign({}, g, { rows: filt(g.rows.filter(r => mode === 'open' ? (r.status === 'Open' && r.inExport) : (r.status === 'Closed' && r.inPeriod))) })).filter(g => g.rows.length);
    if (mode === 'open') groups.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (a.firstSeen || Infinity) - (b.firstSeen || Infinity) || b.rows.length - a.rows.length); else groups.sort((a, b) => (b.closedOn || 0) - (a.closedOn || 0) || sevRank(b.severity) - sevRank(a.severity));
    if (!groups.length) return `<p class="muted">${mode === 'open' ? 'Nothing pending for this selection.' : 'Nothing mitigated in this period for this selection.'}</p>`;
    const shown = groups.slice(0, state.ui.mitLimit);
    const head = mode === 'open' ? '<th>Plugin</th><th>Severity</th><th>Vulnerability</th><th>Action</th><th class="num">Hosts open</th><th>Oldest first seen</th><th>Due</th><th class="num">Overdue</th><th class="num">New</th>' : '<th>Plugin</th><th>Severity</th><th>Vulnerability</th><th>Action</th><th class="num">Hosts fixed</th><th>Closed on</th><th class="num">Days to fix</th><th class="num">Within timeline</th><th>Hosts</th>';
    const minDate = list => { const v = list.filter(Boolean); return v.length ? Math.min(...v) : null; };
    const row = g => mode === 'open'
      ? `<tr><td><span class="ref">${g.plugin}</span></td><td>${pill(g.severity)}</td><td class="wrap"><span class="link" data-mx="${mode}:${g.plugin}"><b>${esc(g.name)}</b></span></td><td class="wrap small">${esc(g.action)}</td><td class="num">${fmt(g.rows.length)}</td><td class="nowrap">${fmtDate(minDate(g.rows.map(r => r.firstSeen)))}</td><td class="nowrap">${fmtDate(minDate(g.rows.map(r => r.due)))}</td><td class="num">${g.rows.filter(r => r.overdue).length || ''}</td><td class="num">${g.rows.filter(r => r.isNew).length || ''}</td></tr>`
      : `<tr><td><span class="ref">${g.plugin}</span></td><td>${pill(g.severity)}</td><td class="wrap"><span class="link" data-mx="${mode}:${g.plugin}"><b>${esc(g.name)}</b></span></td><td class="wrap small">${esc(g.action)}</td><td class="num">${fmt(g.rows.length)}</td><td class="nowrap">${fmtDate(Math.max(...g.rows.map(r => r.closedOn || 0)) || null)}</td><td class="num">${(() => { const d = g.rows.filter(r => r.daysOpen != null); return d.length ? Math.round(d.reduce((a, r) => a + r.daysOpen, 0) / d.length) : ''; })()}</td><td class="num">${(() => { const w = g.rows.filter(r => r.withinTimeline != null); return w.length ? Math.round(100 * w.filter(r => r.withinTimeline).length / w.length) + '%' : ''; })()}</td><td class="wrap hostlist">${g.rows.slice(0, 6).map(r => esc(r.host)).join(', ')}${g.rows.length > 6 ? ` <span class="muted">+${g.rows.length - 6}</span>` : ''}</td></tr>`;
    return `<div class="table-wrap"><table class="data mit-${mode}"><thead><tr>${head}</tr></thead><tbody>${shown.map(row).join('')}</tbody></table></div>${groups.length > shown.length ? `<div class="more"><button class="btn" type="button" data-mitmore="1">Show more (${fmt(groups.length - shown.length)} left)</button></div>` : ''}`;
  }
  function bindExpand(root, D) {
    $$('[data-mx]', root).forEach(a => a.onclick = () => {
      const tr = a.closest('tr'); const nx = tr.nextElementSibling; if (nx && nx.classList.contains('expand')) { nx.remove(); return; }
      const [mode, plugin] = a.dataset.mx.split(':'); const g = D.byVuln.find(x => String(x.plugin) === plugin); if (!g) return;
      const rows = g.rows.filter(r => mode === 'open' ? (r.status === 'Open' && r.inExport) : (r.status === 'Closed' && r.inPeriod)).sort((x, y) => (x.firstSeen || 0) - (y.firstSeen || 0));
      const row = document.createElement('tr'); row.className = 'expand'; row.innerHTML = `<td colspan="${tr.children.length}"><div class="table-wrap"><table class="data"><thead><tr><th>Host</th><th>IP</th><th>Environment</th><th>First seen</th><th>${mode === 'open' ? 'Due' : 'Closed on'}</th><th class="num">Days</th><th>${mode === 'open' ? 'Status' : 'Within timeline'}</th></tr></thead><tbody>${rows.map(r => `<tr><td class="nowrap">${r.hostObj ? hostLink(r.hostObj) : esc(r.host)}</td><td class="mono nowrap">${esc(r.ip)}</td><td class="small">${esc(r.env)}</td><td class="nowrap">${fmtDate(r.firstSeen)}</td><td class="nowrap">${fmtDate(mode === 'open' ? r.due : r.closedOn)}</td><td class="num">${r.daysOpen ?? ''}</td><td>${mode === 'open' ? (r.overdue ? '<span class="flag over">overdue</span>' : r.isReopened ? '<span class="flag over">reopened</span>' : r.isNew ? '<span class="flag kev">new</span>' : 'open') : (r.withinTimeline == null ? '' : r.withinTimeline ? 'yes' : 'no')}</td></tr>`).join('')}</tbody></table></div></td>`;
      tr.after(row); bindHostLinks(row);
    });
    $$('[data-mitmore]', root).forEach(b => b.onclick = () => { state.ui.mitLimit += 100; renderMitigation(); });
  }
  function envTable(D) {
    if (!D.envs.length) return '<p class="muted">No hosts.</p>';
    return `<div class="table-wrap"><table class="data"><thead><tr><th>Environment</th><th class="num">Hosts</th><th class="num">With findings</th><th class="num">Clean</th><th class="num">New hosts</th><th class="num">Open</th><th class="num">Mitigated</th><th class="num">Not verified</th></tr></thead><tbody>${D.envs.map(g => `<tr><td>${esc(g.env)}</td><td class="num">${fmt(g.hosts)}</td><td class="num">${fmt(g.withFindings)}</td><td class="num">${g.clean || ''}</td><td class="num">${g.newHosts || ''}</td><td class="num">${fmt(g.open)}</td><td class="num">${fmt(g.mitigated)}</td><td class="num">${g.unverified || ''}</td></tr>`).join('')}</tbody></table></div>${D.newHosts.length ? `<p class="small"><b>New hosts since the previous pull:</b> ${D.newHosts.slice(0, 20).map(h => hostLink(h)).join(', ')}${D.newHosts.length > 20 ? ` <span class="muted">+${D.newHosts.length - 20}</span>` : ''}</p>` : ''}`;
  }
  function absentTable(D) {
    if (!D.absentHosts.length) return '<p class="muted">Every host with open findings was in this pull.</p>';
    return `<div class="table-wrap"><table class="data"><thead><tr><th>Host</th><th>IP</th><th>Environment</th><th>Last seen</th><th class="num">Open findings</th></tr></thead><tbody>${D.absentHosts.slice(0, 40).map(a => `<tr><td>${esc(a.host)}</td><td class="mono nowrap">${esc(a.ip)}</td><td class="small">${esc(a.env)}</td><td class="nowrap">${fmtDate(a.lastSeen)}</td><td class="num">${fmt(a.open)}</td></tr>`).join('')}</tbody></table></div>${D.absentHosts.length > 40 ? `<p class="small muted">${fmt(D.absentHosts.length - 40)} more in the Excel.</p>` : ''}`;
  }
  function drawCharts(D) {
    const h = D.history; const c1 = $('#mitTrend'), c2 = $('#mitFlow'); if (!c1 || !c2) return;
    if (!h.length) { c1.parentElement.innerHTML = '<p class="muted small">The history fills with every pull.</p>'; c2.parentElement.innerHTML = '<p class="muted small">The history fills with every pull.</p>'; return; }
    const labels = h.map(e => fmtDate(e.date)); const col = SEVCOLOR();
    barChart(c1, labels, ['Critical', 'High', 'Medium', 'Low'].map(s => ({ label: s, data: h.map(e => (e.open || {})[s] || 0), backgroundColor: col[s] })), { stacked: true, id: 'mitTrend', thick: 26 });
    barChart(c2, labels, [{ label: 'Mitigated', data: h.map(e => e.closed || 0), backgroundColor: cssVar('--good') }, { label: 'New', data: h.map(e => e.opened || 0), backgroundColor: cssVar('--bad') }, { label: 'Reopened', data: h.map(e => e.reopened || 0), backgroundColor: cssVar('--warn') }], { id: 'mitFlow', thick: 18, legend: true });
  }

  /* ---------- Excel: the mitigation tracker ---------- */
  const mitExcelName = () => `${state.settings.org}_Tenable_Mitigation_Tracker_${state.settings.date}.xlsx`;
  async function buildMitigationWorkbook() {
    const st = state.settings; const keep = { dim: state.ui.scopeDim, val: state.ui.scopeVal }; state.ui.scopeVal = '__all';
    let D; try { D = mitigationData(state.ui.mitPeriod || 'prev'); } finally { state.ui.scopeDim = keep.dim; state.ui.scopeVal = keep.val; }
    const wb = new ExcelJS.Workbook(); wb.creator = `${st.org} Tenable Report Studio ${STUDIO_VERSION}`; wb.created = new Date();
    SHEETS_META.length = 0;
    const sum = wb.addWorksheet('Summary', { properties: { tabColor: { argb: 'FF' + TABS.summary } } });
    const statusOf = r => r.status === 'Closed' ? 'Mitigated' : (r.inExport ? (r.overdue ? 'Overdue' : 'Open') : 'Not verified');
    const rows = D.rows.slice().sort((a, b) => (a.status === 'Open' ? 0 : 1) - (b.status === 'Open' ? 0 : 1) || sevRank(b.severity) - sevRank(a.severity) || (a.firstSeen || 0) - (b.firstSeen || 0));
    addSheet(wb, 'Mitigation tracker', { tab: TABS.action, note: 'One row per finding ever seen (vulnerability on a host). Mitigated = no longer reported while the host was still scanned, with the date; Open = reported in the newest pull; Not verified = still open at the last sight of a host the newest pull does not contain. Filter Status, Remediation action, Host.',
      columns: [{ h: 'Status', w: 12, k: 'vstatus' }, { h: 'Severity', w: 10, k: 'sev' }, { h: 'Plugin ID', w: 10, k: 'dec' }, { h: 'Vulnerability', w: 52, k: 'wrap' }, { h: 'Remediation action', w: 34, k: 'wrap' }, { h: 'Host', w: 24 }, { h: 'IP', w: 15 }, { h: 'Environment', w: 14 }, { h: 'Site', w: 14 }, { h: 'First seen', w: 11, k: 'date' }, { h: 'Last seen', w: 11, k: 'date' }, { h: 'Due date', w: 11, k: 'date' }, { h: 'Closed on', w: 11, k: 'date' }, { h: 'Days open', w: 9, k: 'num' }, { h: 'Within timeline', w: 9 }, { h: 'Reopened', w: 8, k: 'num' }, { h: 'In newest pull', w: 9 }, { h: 'CVE', w: 28, k: 'wrap' }],
      rows: rows.map(r => [statusOf(r) === 'Overdue' ? 'Remaining' : statusOf(r) === 'Open' ? 'Remaining' : statusOf(r), r.severity, r.plugin, r.name, r.action, r.host, r.ip, r.env, r.site, xdate(r.firstSeen), xdate(r.lastSeen), xdate(r.due), xdate(r.closedOn), r.daysOpen ?? '', r.withinTimeline == null ? '' : (r.withinTimeline ? 'Yes' : 'No'), r.reopened || '', r.inExport ? 'Yes' : 'No', r.cve]), rowHeight: 30,
      purpose: 'Every finding ever seen with its status, dates and the days it stayed open.' });
    addSheet(wb, 'Pending', { tab: TABS.action, note: 'Open findings in the newest pull, one row per vulnerability: hosts open, oldest first seen, earliest due date, overdue and new counts.',
      columns: [{ h: 'Severity', w: 10, k: 'sev' }, { h: 'Plugin ID', w: 10, k: 'dec' }, { h: 'Vulnerability', w: 52, k: 'wrap' }, { h: 'Remediation action', w: 34, k: 'wrap' }, { h: 'Hosts open', w: 9, k: 'num' }, { h: 'Oldest first seen', w: 11, k: 'date' }, { h: 'Earliest due date', w: 11, k: 'date' }, { h: 'Overdue', w: 8, k: 'num' }, { h: 'New in period', w: 8, k: 'num' }, { h: 'Hosts', w: 70, k: 'wrap' }],
      rows: D.byVuln.map(g => ({ g, o: g.rows.filter(r => r.status === 'Open' && r.inExport) })).filter(x => x.o.length).sort((a, b) => sevRank(b.g.severity) - sevRank(a.g.severity) || b.o.length - a.o.length).map(({ g, o }) => { const fs = o.map(r => r.firstSeen).filter(Boolean), ds = o.map(r => r.due).filter(Boolean); return [g.severity, g.plugin, g.name, g.action, o.length, xdate(fs.length ? Math.min(...fs) : null), xdate(ds.length ? Math.min(...ds) : null), o.filter(r => r.overdue).length, o.filter(r => r.isNew).length, o.map(r => r.host).sort().join(', ')]; }), rowHeight: 30,
      purpose: 'What is still to be fixed, by vulnerability.' });
    addSheet(wb, 'Mitigated', { tab: TABS.va, note: `Findings mitigated ${D.period === 'all' ? 'since tracking began' : D.period === 'prev' ? 'since the previous pull' : 'in the last ' + D.period + ' days'}, one row per vulnerability: hosts fixed, latest closed date, average days to fix and the share closed within the Tenable timeline.`,
      columns: [{ h: 'Severity', w: 10, k: 'sev' }, { h: 'Plugin ID', w: 10, k: 'dec' }, { h: 'Vulnerability', w: 52, k: 'wrap' }, { h: 'Remediation action', w: 34, k: 'wrap' }, { h: 'Hosts fixed', w: 9, k: 'num' }, { h: 'Closed on (latest)', w: 11, k: 'date' }, { h: 'Average days to fix', w: 9, k: 'num' }, { h: 'Within timeline', w: 9 }, { h: 'Hosts', w: 70, k: 'wrap' }],
      rows: D.byVuln.filter(g => g.mitigated).sort((a, b) => (b.closedOn || 0) - (a.closedOn || 0)).map(g => [g.severity, g.plugin, g.name, g.action, g.mitigated, xdate(g.closedOn), g.avgDays ?? '', g.withinPct == null ? '' : g.withinPct + '%', [...g.hostsFixed].sort().join(', ')]), rowHeight: 30,
      purpose: 'What got fixed in the period, by vulnerability.' });
    addSheet(wb, 'Remediation actions', { tab: TABS.action, note: 'Progress per remediation action (product or update family): Done when nothing is open, In progress when part is closed, Not started otherwise; % done = closed of everything ever seen under the action.',
      columns: [{ h: 'Remediation action', w: 44, k: 'wrap' }, { h: 'Status', w: 12, k: 'vstatus' }, { h: 'Severity', w: 10, k: 'sev' }, { h: 'Open', w: 8, k: 'num' }, { h: 'Not verified', w: 9, k: 'num' }, { h: 'Mitigated in period', w: 9, k: 'num' }, { h: 'Closed ever', w: 9, k: 'num' }, { h: 'Ever seen', w: 9, k: 'num' }, { h: '% done', w: 8, k: 'num' }, { h: 'Oldest open first seen', w: 11, k: 'date' }, { h: 'Earliest due', w: 11, k: 'date' }, { h: 'Overdue', w: 8, k: 'num' }, { h: 'Plugins', w: 8, k: 'num' }, { h: 'Hosts open', w: 60, k: 'wrap' }],
      rows: D.byAction.slice().sort((a, b) => ({ 'Not started': 0, 'In progress': 1, Done: 2 })[a.state] - ({ 'Not started': 0, 'In progress': 1, Done: 2 })[b.state] || sevRank(b.severity) - sevRank(a.severity) || b.open - a.open).map(g => [g.action, g.state, g.severity, g.open, g.unverified, g.mitigated, g.closed, g.total, g.done, xdate(g.firstSeen), xdate(g.due), g.overdue, g.plugins.size, [...g.hostsOpen].sort().join(', ')]), rowHeight: 30,
      purpose: 'Progress per remediation action.' });
    addSheet(wb, 'Environment', { tab: TABS.hosts, note: 'Hosts of the newest pull by environment, with the open, mitigated and not-verified findings; then the hosts not in this pull with their last sight and open findings.',
      columns: [{ h: 'Environment', w: 18 }, { h: 'Hosts', w: 8, k: 'num' }, { h: 'With findings', w: 9, k: 'num' }, { h: 'Clean', w: 8, k: 'num' }, { h: 'New hosts', w: 8, k: 'num' }, { h: 'Open', w: 8, k: 'num' }, { h: 'Mitigated in period', w: 9, k: 'num' }, { h: 'Not verified', w: 9, k: 'num' }, { h: 'Hosts not in this pull', w: 60, k: 'wrap' }],
      rows: D.envs.map(g => [g.env, g.hosts, g.withFindings, g.clean, g.newHosts, g.open, g.mitigated, g.unverified, D.absentHosts.filter(a => a.env === g.env).map(a => `${a.host} (last seen ${fmtDate(a.lastSeen)}, ${a.open} open)`).join(', ')]), rowHeight: 24,
      purpose: 'What is in the environment.' });
    addSheet(wb, 'Pull history', { tab: TABS.hosts, note: 'One row per pull: open findings by severity at that pull, findings mitigated and new since the previous pull, reopened, hosts scanned and hosts absent.',
      columns: [{ h: 'Pull date', w: 11, k: 'date' }, { h: 'Open', w: 8, k: 'num' }, { h: 'Critical', w: 8, k: 'num' }, { h: 'High', w: 8, k: 'num' }, { h: 'Medium', w: 8, k: 'num' }, { h: 'Low', w: 8, k: 'num' }, { h: 'Mitigated', w: 9, k: 'num' }, { h: 'New', w: 8, k: 'num' }, { h: 'Reopened', w: 8, k: 'num' }, { h: 'Not verified', w: 9, k: 'num' }, { h: 'Hosts scanned', w: 9, k: 'num' }, { h: 'Hosts absent', w: 9, k: 'num' }, { h: 'Files', w: 60, k: 'wrap' }],
      rows: D.history.map(e => [xdate(e.date), e.open.total, e.open.Critical, e.open.High, e.open.Medium, e.open.Low, e.closed, e.opened, e.reopened, e.unverified, e.hosts, e.hostsAbsent, (e.files || []).join(', ')]), rowHeight: 18,
      purpose: 'The trend, one row per pull.' });
    const ws = sum; ws.getColumn(1).width = 46; for (let i = 2; i <= 8; i++) ws.getColumn(i).width = 13;
    let r = 1; const put = (vals, fn) => { const rr = ws.getRow(r++); rr.values = vals.map(xs); if (fn) fn(rr); return rr; };
    const section = t => { r++; put([t], rr => { rr.getCell(1).font = { bold: true, size: 12, color: { argb: XC.copper } }; rr.getCell(1).border = { bottom: { style: 'medium', color: { argb: XC.copper } } }; }); };
    const header = vals => put(vals, rr => { vals.forEach((v, i) => { const c = rr.getCell(i + 1); c.font = { bold: true, color: { argb: XC.white } }; c.fill = xfill(XC.ink); c.alignment = { horizontal: i ? 'right' : 'left', vertical: 'middle', wrapText: true }; }); rr.height = 26; });
    const line = (vals, bold) => put(vals, rr => { vals.forEach((v, i) => { const c = rr.getCell(i + 1); if (i) c.alignment = { horizontal: 'right' }; if (typeof v === 'number') c.numFmt = '#,##0'; if (bold) c.font = { bold: true }; if (i === 0 && XSEV[v]) { c.fill = xfill(XSEV[v][0]); c.font = { bold: true, color: { argb: XSEV[v][1] } }; } }); });
    put([`${st.org} · Mitigation tracker · ${st.date}`], rr => { rr.getCell(1).font = { bold: true, size: 16 }; });
    put([`${st.title} · ${st.period} · prepared by ${st.preparedBy} · ${st.classification}`], rr => { rr.getCell(1).font = { size: 10 }; });
    put([`Newest pull: ${fmtDate(D.date)}${D.prev ? ' · previous pull: ' + fmtDate(D.prev.date) : ''} · period: ${D.period === 'all' ? 'since tracking began' : D.period === 'prev' ? 'since the previous pull' : 'last ' + D.period + ' days'} · ${fmt(D.history.length)} pulls in the history`], rr => { rr.getCell(1).font = { italic: true, size: 10, color: { argb: XC.ink2 } }; });
    section('Figures'); header(['Measure', 'Value']);
    for (const [k, v] of [['Open findings (pending)', D.open.length], ['Mitigated in the period', D.mitigated.length], ['New in the period', D.newOpen.length], ['Reopened in the period', D.reopened.length], ['Overdue open findings', D.overdue.length], ['Not verified (host not in this pull)', D.unverified.length], ['Mitigated since tracking began', D.closed.length], ['Hosts in this pull', hostsOf().length], ['Hosts not in this pull with open findings', D.absentHosts.length], ['New hosts since the previous pull', D.newHosts.length]]) line([k, v]);
    section('By severity'); header(['Severity', 'Open', 'Mitigated in period', 'Not verified', 'Mitigated ever']);
    const bo = D.bySev(D.open), bm = D.bySev(D.mitigated), bu = D.bySev(D.unverified), bc = D.bySev(D.closed);
    for (const s of ['Critical', 'High', 'Medium', 'Low']) line([s, bo[s], bm[s], bu[s], bc[s]]);
    line(['Total', D.open.length, D.mitigated.length, D.unverified.length, D.closed.length], true);
    section('By environment'); header(['Environment', 'Hosts', 'Open', 'Mitigated in period', 'Not verified', 'New hosts']);
    for (const g of D.envs) line([g.env, g.hosts, g.open, g.mitigated, g.unverified, g.newHosts]);
    section('Remediation actions'); header(['Status', 'Actions']);
    for (const s of ['Not started', 'In progress', 'Done']) line([s, D.byAction.filter(a => a.state === s).length]);
    section('Sheets in this workbook'); header(['Sheet', 'What it holds']);
    for (const m of SHEETS_META) { const rr = put([m.name, m.purpose]); rr.getCell(1).value = { text: m.name, hyperlink: `#'${m.name}'!A1` }; rr.getCell(1).font = { color: { argb: XC.blue }, underline: true }; ws.mergeCells(r - 1, 2, r - 1, 8); rr.getCell(2).alignment = { wrapText: true, vertical: 'top' }; rr.height = 28; }
    ws.views = [{ showGridLines: false }];
    return wb;
  }
  async function mitExcelBlob() { const wb = await buildMitigationWorkbook(); const buf = await wb.xlsx.writeBuffer(); return new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }); }
  async function exportMitigationExcel() {
    const b = $('#mitExcel'); if (b) { b.disabled = true; b.textContent = 'Building…'; }
    try { await new Promise(r => setTimeout(r, 20)); downloadBlob(await mitExcelBlob(), mitExcelName()); }
    catch (e) { console.error(e); showNotice('The mitigation tracker could not be built (' + esc(e.message) + ').', 'bad'); }
    finally { if (b) { b.disabled = false; b.textContent = 'Excel'; } }
  }
  const origArchiveFiles = window.archiveFiles;
  if (typeof origArchiveFiles === 'function') window.archiveFiles = async function (opts, status) { const out = await origArchiveFiles.apply(this, arguments); if (state.findings.length && RISK_REG) { try { status('mit', 'busy', 'Mitigation tracker'); out.push({ name: mitExcelName(), blob: await mitExcelBlob() }); out.push({ name: 'findings-register.csv', blob: new Blob([registerCsv()], { type: 'text/csv' }) }); status('mit', 'done', 'Mitigation tracker'); } catch (e) { status('mit', 'fail', 'Mitigation tracker: ' + e.message); } } return out; };

  /* ---------- the data folder ---------- */
  const csvCell = v => { const s = v == null ? '' : String(v); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  function registerCsv() {
    const cols = ['Status', 'Severity', 'Plugin ID', 'Vulnerability', 'Remediation action', 'Host', 'IP', 'Environment', 'Site', 'First seen', 'Last seen', 'Closed on', 'Reopened', 'In newest pull', 'Residual risk', 'Inherent risk', 'CVE'];
    const lines = ['﻿' + cols.join(',')];
    for (const it of Object.values((RISK_REG && RISK_REG.items) || {})) lines.push([it.status, it.severity, it.plugin, it.name, productName(it.name), it.host, it.ip, it.env, it.site, fmtDate(it.firstSeen), fmtDate(it.lastSeen), fmtDate(it.closedOn), it.reopened || 0, it.hostSeen === false ? 'No' : 'Yes', it.risk || '', it.inherent || '', it.cve || ''].map(csvCell).join(','));
    return lines.join('\r\n') + '\r\n';
  }
  function historyCsv() {
    const lines = ['﻿Pull date,Open,Critical,High,Medium,Low,Mitigated,New,Reopened,Not verified,Hosts scanned,Hosts absent,Files'];
    for (const e of (RISK_REG && RISK_REG.history) || []) lines.push([fmtDate(e.date), e.open.total, e.open.Critical, e.open.High, e.open.Medium, e.open.Low, e.closed, e.opened, e.reopened, e.unverified, e.hosts, e.hostsAbsent, (e.files || []).join('; ')].map(csvCell).join(','));
    return lines.join('\r\n') + '\r\n';
  }
  const README = () => `${state.settings.org} Tenable data folder (Tenable Report Studio ${STUDIO_VERSION})

pulls/<date>/           the exports of each pull exactly as loaded into the Studio (SC VA export, SC Compliance export),
                        manifest.json (counts, filters, load figures) and risk-rules.json (Accept / Recast Risk rules at that time).
register/findings-register.json   every finding ever seen: first seen, last seen, Open or Closed, closed on, reopened,
                        risk values and the per-vulnerability overrides. Drop it on the Studio to restore the register.
register/findings-register.csv    the same as a flat table.
register/history.json, history.csv   one row per pull: open by severity, mitigated, new, reopened, hosts.
reports/                the archives made with the Studio's Archive button (one folder per run).

To update: open the Studio, Mitigation tab, "Update from Tenable" (or the Tenable button), then the files here are refreshed.
To look at an earlier pull: Mitigation tab, Data folder, Load next to the pull.
`;
  async function restoreFolder() {
    if (!canPickFolder()) return;
    const h = await kvGet('dataDir'); if (!h || typeof h.getDirectoryHandle !== 'function') return;
    M.folder = h; M.folderName = h.name;
    try { if (typeof h.queryPermission === 'function' && (await h.queryPermission({ mode: 'readwrite' })) === 'granted') { await listPulls(); await loadRegisterFromFolder(); } else M.pending = true; } catch (e) { console.warn(e); }
  }
  async function chooseFolder() {
    try { const h = await window.showDirectoryPicker({ mode: 'readwrite', id: 'trs-data', startIn: 'desktop' }); await useFolder(h); }
    catch (e) { if (!(e && e.name === 'AbortError')) showNotice('The folder could not be opened (' + esc(e.message) + ').', 'bad'); }
  }
  async function useFolder(h) {
    M.folder = h; M.folderName = h.name; M.pending = false; await kvSet('dataDir', h);
    for (const sub of ['pulls', 'register', 'reports']) await h.getDirectoryHandle(sub, { create: true });
    try { await kvSet('archiveDir', await h.getDirectoryHandle('reports')); } catch (e) {}
    await writeFile(h, 'README.txt', README());
    await listPulls(); await loadRegisterFromFolder(); await saveAll(false); renderMitigation(); updateEmptyHint();
    showNotice(`Data folder: <b>${esc(h.name || 'chosen folder')}</b> (pulls, register, history and the archives go there).`);
  }
  async function writeFile(dir, name, data) { const fh = await dir.getFileHandle(name, { create: true }); const w = await fh.createWritable(); await w.write(data); await w.close(); }
  async function readText(dir, name) { try { const fh = await dir.getFileHandle(name); return await (await fh.getFile()).text(); } catch (e) { return null; } }
  async function ensurePermission() { if (!M.folder) return false; if (typeof M.folder.queryPermission !== 'function') return true; if ((await M.folder.queryPermission({ mode: 'readwrite' })) === 'granted') return true; const ok = (await M.folder.requestPermission({ mode: 'readwrite' })) === 'granted'; if (ok) { M.pending = false; await listPulls(); } return ok; }
  async function saveAll(interactive) {
    if (!M.folder || state.reportMode) return false;
    if (!(await ensurePermission())) { if (interactive) showNotice('The data folder is not accessible; choose it again.', 'bad'); return false; }
    const h = M.folder; const date = exportDateNow(); const stamp = fmtDate(date || Date.now());
    const pulls = await h.getDirectoryHandle('pulls', { create: true }); const reg = await h.getDirectoryHandle('register', { create: true });
    // every loaded export goes to pulls/<its date>/ (the newest and the history files alike); the manifest of a Tenable pull goes with its files
    const byDate = new Map(); for (const f of state.files.filter(x => x.file && x.date)) { const k = fmtDate(f.date); if (!byDate.has(k)) byDate.set(k, []); byDate.get(k).push(f); }
    for (const [k, files] of byDate) {
      const d = await pulls.getDirectoryHandle(k, { create: true });
      for (const f of files) { try { const existing = await d.getFileHandle(f.name).catch(() => null); if (!existing) await writeFile(d, f.name, f.file); } catch (e) { console.warn(e); } }
      const last = window.TRS_LAST_PULL; const names = new Set(files.map(f => f.name));
      if (last && last.manifest && (last.manifest.files || []).some(x => names.has(x.name))) { await writeFile(d, 'manifest.json', JSON.stringify(last.manifest, null, 1)); if (last.rules) await writeFile(d, 'risk-rules.json', JSON.stringify(last.rules, null, 1)); }
      else if (!(await readText(d, 'manifest.json'))) await writeFile(d, 'manifest.json', JSON.stringify({ pulledAt: new Date().toISOString(), tool: `Studio ${STUDIO_VERSION}`, date: k, files: files.map(f => ({ name: f.name, rows: f.rows, va: f.va.length, compliance: f.cmp.length })), note: 'files loaded by hand into the Studio' }, null, 1));
    }
    if (RISK_REG) { await writeFile(reg, 'findings-register.json', JSON.stringify(Object.assign({ version: STUDIO_VERSION, exported: new Date().toISOString() }, RISK_REG), null, 1)); await writeFile(reg, 'findings-register.csv', registerCsv()); await writeFile(reg, 'history.json', JSON.stringify(RISK_REG.history || [], null, 1)); await writeFile(reg, 'history.csv', historyCsv()); }
    M.lastSaved = new Date().toISOString().slice(0, 16).replace('T', ' '); await listPulls(); if (interactive) { renderMitigation(); showNotice(`Saved to <b>${esc(M.folderName)}</b>: pull ${esc(stamp)}, the register and the history.`); } else renderPulls();
    updateEmptyHint();
    return true;
  }
  let saveTimer = null; function scheduleSave() { if (!M.folder || M.pending) return; if (saveTimer) clearTimeout(saveTimer); saveTimer = setTimeout(() => saveAll(false).catch(e => console.warn(e)), 1500); }
  async function listPulls() {
    M.pulls = []; if (!M.folder) return M.pulls;
    try { const pulls = await M.folder.getDirectoryHandle('pulls', { create: true });
      for await (const [name, h] of pulls.entries()) { if (h.kind !== 'directory') continue; const files = []; for await (const [fn, fh] of h.entries()) if (fh.kind === 'file' && /\.csv$/i.test(fn)) files.push(fn); let manifest = null; try { manifest = JSON.parse(await readText(h, 'manifest.json') || 'null'); } catch (e) {} M.pulls.push({ name, files: files.sort(), manifest, handle: h }); }
      M.pulls.sort((a, b) => b.name.localeCompare(a.name)); } catch (e) { console.warn(e); }
    return M.pulls;
  }
  function folderLineHtml() {
    return M.folder ? `Data folder: <b>${esc(M.folderName || 'chosen folder')}</b>${M.lastSaved ? ' · last saved ' + esc(M.lastSaved) : ''}${M.pulls.length ? ' · ' + fmt(M.pulls.length) + ' pulls stored' : ''}` : (canPickFolder() ? 'No data folder yet: choose a folder on this computer (for example a "Tenable Data" folder on the Desktop) to keep every pull, the register and the history as files.' : 'This browser cannot write folders; the data can be downloaded as a ZIP.');
  }
  function renderPulls(el, onLoaded) {
    el = el || $('#mitPulls'); if (!el) return;
    if (M.pending) { el.innerHTML = `<div class="notice small">The data folder <b>${esc(M.folderName)}</b> needs your permission again in this session: <button class="btn sm" type="button" data-mitperm="1">Allow access</button></div>`; el.querySelector('[data-mitperm]').onclick = async () => { if (await ensurePermission()) { await loadRegisterFromFolder(); renderMitigation(); renderPulls(el, onLoaded); updateEmptyHint(); } }; return; }
    if (!M.folder) { el.innerHTML = ''; return; }
    const loaded = new Set(state.files.map(f => f.name));
    el.innerHTML = M.pulls.length ? `<div class="table-wrap"><table class="data"><thead><tr><th>Pull</th><th>Files</th><th>Summary</th><th></th></tr></thead><tbody>${M.pulls.map((p, i) => `<tr><td class="nowrap"><b>${esc(p.name)}</b></td><td class="small">${p.files.map(f => `${esc(f)}${loaded.has(f) ? ' <span style="color:var(--good)">loaded</span>' : ''}`).join('<br>')}</td><td class="small wrap">${esc((p.manifest && p.manifest.summary) || '')}</td><td class="nowrap"><button class="btn sm" type="button" data-mitload="${i}" title="Load this pull into the Studio (next to what is loaded: the newest is now, older ones history)">Load</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="small muted">No pull stored yet. "Save this pull and the register now" writes the loaded exports; "Update from Tenable" saves automatically.</p>';
    $$('[data-mitload]', el).forEach(b => b.onclick = async () => { const p = M.pulls[+b.dataset.mitload]; b.disabled = true; try { const files = []; for (const fn of p.files) { if (loaded.has(fn)) continue; const fh = await p.handle.getFileHandle(fn); files.push(await fh.getFile()); } if (files.length) { await addFiles(files); if (onLoaded) onLoaded(); } else showNotice('These files are already loaded.'); } catch (e) { showNotice('The pull could not be loaded: ' + esc(e.message), 'bad'); } finally { b.disabled = false; } });
  }
  /* the data folder as a dialog: reachable from the empty state, before anything is loaded */
  function openFolderDialog() {
    const host = $('#modalHost'); host.hidden = false;
    host.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="Data folder"><div class="box" style="width:min(900px,100%)"><h2>Data folder</h2><p class="small muted" style="margin-bottom:8px">${folderLineHtml()}</p><div id="mitPullsDlg"></div>
      <div class="foot">${canPickFolder() ? `<button class="btn" type="button" id="mitChooseDlg">${M.folder ? 'Change folder' : 'Choose folder'}</button>` : ''}<span style="flex:1"></span><button class="btn" type="button" id="mitCloseDlg">Close</button></div></div></div>`;
    const close = () => { host.hidden = true; host.innerHTML = ''; };
    host.querySelector('.modal').addEventListener('click', e => { if (e.target.classList.contains('modal')) close(); });
    $('#mitCloseDlg').onclick = close; const c = $('#mitChooseDlg'); if (c) c.onclick = async () => { await chooseFolder(); openFolderDialog(); };
    renderPulls($('#mitPullsDlg'), close);
  }
  function updateEmptyHint() { const h = $('#mitEmptyHint'); if (!h) return; h.innerHTML = M.folder ? `<span>Data folder <b>${esc(M.folderName || '')}</b>: ${fmt(M.pulls.length)} pulls stored${M.pending ? ' (access to allow)' : ''}.</span><button class="btn" type="button" id="btnDataFolder">Open the data folder</button>` : `<span>Earlier pulls can be kept in a data folder on this computer.</span><button class="btn" type="button" id="btnDataFolder">Data folder</button>`; $('#btnDataFolder').onclick = openFolderDialog; }
  async function loadRegisterFromFolder() {
    if (!M.folder || M.pending) return;
    try { const reg = await M.folder.getDirectoryHandle('register', { create: true }); const text = await readText(reg, 'findings-register.json'); if (!text) return; const p = JSON.parse(text); if (!p || !p.items) return;
      await riskLoadRegister(); const mine = RISK_REG || { updated: 0, items: {} };
      if ((p.updated || 0) > (mine.updated || 0) || !Object.keys(mine.items || {}).length) { RISK_REG = { trsRisk: 1, items: p.items, overrides: p.overrides || {}, exportDate: p.exportDate || 0, updated: p.updated || 0, history: p.history || [] }; riskSaveRegister(); if (state.findings.length) { riskSync(); if (typeof renderRisk === 'function') renderRisk(); renderMitigation(); } }
    } catch (e) { console.warn('register in the data folder not readable', e); }
  }
  async function downloadDataZip() {
    const entries = []; const stamp = fmtDate(exportDateNow() || Date.now());
    for (const f of state.files.filter(x => x.kind === 'current' && x.file)) entries.push({ name: `Tenable Data/pulls/${stamp}/${f.name}`, blob: f.file });
    if (RISK_REG) { entries.push({ name: 'Tenable Data/register/findings-register.json', blob: new Blob([JSON.stringify(Object.assign({ version: STUDIO_VERSION, exported: new Date().toISOString() }, RISK_REG), null, 1)], { type: 'application/json' }) }); entries.push({ name: 'Tenable Data/register/findings-register.csv', blob: new Blob([registerCsv()], { type: 'text/csv' }) }); entries.push({ name: 'Tenable Data/register/history.csv', blob: new Blob([historyCsv()], { type: 'text/csv' }) }); }
    entries.push({ name: 'Tenable Data/README.txt', blob: new Blob([README()], { type: 'text/plain' }) });
    const zip = await makeZip(entries); downloadBlob(zip, `Tenable Data ${stamp}.zip`);
  }

  /* ---------- start-up ---------- */
  function ready(fn) { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn(); }
  ready(() => {
    if (state.reportMode) return; ensureTab();
    const how = $('#emptyState .how'); if (how) { const p = document.createElement('p'); p.className = 'trs-tenable-hint'; p.id = 'mitEmptyHint'; how.before(p); updateEmptyHint(); }
    restoreFolder().then(() => { updateEmptyHint(); if (state.findings.length) renderMitigation(); });
  });
  window.TRS_MITIGATION = { data: mitigationData, render: renderMitigation, saveAll, useFolder, listPulls, pulls: () => M.pulls, excel: mitExcelBlob, registerCsv, historyCsv, folder: () => M.folder, openFolderDialog };
})();
