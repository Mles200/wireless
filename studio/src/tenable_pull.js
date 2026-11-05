/* Tenable Pull: a browser-side client for Tenable Security Center (REST API, API keys) and
   Nessus (port 8834) that produces the export files the Studio reads, with the column layout of
   the Security Center "Vulnerability Detail List" export.  No server: fetch() from the page.

   Used by Tenable_Pull.html (the standalone tool) and by the Studio's Tenable panel; both are
   built from this file by tools/build_tenable.py.  Also loadable in Node for the unit checks. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TenablePull = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const VERSION = '1.0';
  const INVENTORY_PLUGINS = [11936, 55472, 19506, 45590, 209654];   // Info rows the Studio keeps for the host inventory

  /* ---------- export schema: header, record field candidates, kind ---------- */
  const COLUMNS = [
    ['Plugin', ['pluginID'], 'text'], ['Plugin Name', ['pluginName'], 'text'], ['Family', ['family.name'], 'text'], ['Severity', ['severity.name'], 'text'],
    ['IP Address', ['ip'], 'text'], ['Protocol', ['protocol'], 'text'], ['Port', ['port'], 'text'], ['Exploit?', ['exploitAvailable'], 'yesno'],
    ['Repository', ['repository.name'], 'text'], ['MAC Address', ['macAddress'], 'text'], ['DNS Name', ['dnsName'], 'text'], ['NetBIOS Name', ['netbiosName'], 'text'],
    ['Plugin Text', ['pluginText'], 'text'], ['Synopsis', ['synopsis'], 'text'], ['Description', ['description'], 'text'], ['Steps to Remediate', ['solution'], 'text'],
    ['See Also', ['seeAlso'], 'text'], ['Risk Factor', ['riskFactor'], 'text'], ['STIG Severity', ['stigSeverity'], 'text'], ['VPR Score', ['vprScore'], 'num'],
    ['Exploit Prediction Scoring System (EPSS)', ['epssScore', 'epss'], 'num'], ['CVSS V2 Base Score', ['baseScore'], 'num'], ['CVSS V3 Base Score', ['cvssV3BaseScore'], 'num'],
    ['CVSS V2 Temporal Score', ['temporalScore'], 'num'], ['CVSS V3 Temporal Score', ['cvssV3TemporalScore'], 'num'], ['CVSS V2 Vector', ['cvssVector'], 'text'], ['CVSS V3 Vector', ['cvssV3Vector'], 'text'],
    ['CPE', ['cpe'], 'text'], ['CVE', ['cve'], 'text'], ['BID', ['bid'], 'text'], ['Cross References', ['xref'], 'text'],
    ['Vuln Publication Date', ['vulnPubDate'], 'date'], ['Patch Publication Date', ['patchPubDate'], 'date'], ['Plugin Publication Date', ['pluginPubDate'], 'date'], ['Plugin Modification Date', ['pluginModDate'], 'date'],
    ['Exploit Ease', ['exploitEase'], 'text'], ['Exploit Frameworks', ['exploitFrameworks'], 'text'], ['Security End of Life Date', ['seolDate', 'securityEndOfLifeDate', 'seol'], 'date'],
    ['First Discovered', ['firstSeen'], 'date'], ['Last Observed', ['lastSeen'], 'date'], ['Check Type', ['checkType'], 'text'], ['Version', ['version'], 'text'],
    ['Host ID', ['hostUUID', 'hostUuid', 'uuid'], 'text'], ['Agent ID', ['agentID', 'agentUUID', 'agentId', 'agentUuid'], 'text'],
    ['Accept Risk Comment', ['acceptRiskRuleComment', 'acceptRiskComment', 'acceptRisk.comments'], 'text'], ['Recast Risk Comment', ['recastRiskRuleComment', 'recastRiskComment', 'recastRisk.comments'], 'text'],
  ];
  const HEADERS = COLUMNS.map(c => c[0]);

  const field = (rec, path) => { let cur = rec; for (const p of path.split('.')) { if (!cur || typeof cur !== 'object') return null; cur = cur[p]; } if (cur && typeof cur === 'object') cur = cur.name != null ? cur.name : cur.id; return cur == null ? null : cur; };
  const firstField = (rec, cands) => { for (const c of cands) { const v = field(rec, c); if (v != null && v !== '') return v; } return null; };
  const pad = n => String(n).padStart(2, '0');
  function fmtDate(v) {
    if (v == null || v === '') return '';
    if (typeof v === 'string') { const s = v.trim(); if (!s || s === '-1' || s === '0' || s === 'N/A') return ''; if (!/^-?\d+$/.test(s)) return s; v = parseInt(s, 10); }
    v = Number(v); if (!Number.isFinite(v) || v <= 0) return '';
    if (v > 1e10) v = Math.floor(v / 1000);
    const d = new Date(v * 1000);
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
  }
  const fmtNum = v => { if (v == null) return ''; const s = String(v).trim(); return (s === '' || s === '-1' || s === 'N/A' || s === 'null') ? '' : s; };
  const yesNo = v => typeof v === 'boolean' ? (v ? 'Yes' : 'No') : (/^(yes|true|1)$/i.test(String(v).trim()) ? 'Yes' : 'No');
  const fmtText = v => v == null ? '' : (Array.isArray(v) ? v.map(fmtText).join(', ') : String(v).replace(/\r\n/g, '\n').replace(/\r/g, '\n'));
  function recordToRow(rec) {
    const row = {};
    for (const [h, cands, kind] of COLUMNS) { const v = firstField(rec, cands); row[h] = kind === 'date' ? fmtDate(v) : kind === 'num' ? fmtNum(v) : kind === 'yesno' ? (v == null ? '' : yesNo(v)) : fmtText(v); }
    if (!row.Port) row.Port = '0';
    row.Protocol = row.Protocol.toUpperCase();
    return row;
  }
  const isCompliance = rec => String(field(rec, 'family.type') || '').toLowerCase() === 'compliance' || (parseInt(rec.pluginID, 10) || 0) >= 1000000;
  const dedupKey = rec => [rec.pluginID, rec.ip, rec.port || '0', String(rec.protocol || '').toUpperCase(), field(rec, 'repository.id') || field(rec, 'repository.name') || '', isCompliance(rec) ? (rec.pluginName || '') : ''].join('|');
  const hasField = (rec, path) => { let cur = rec; for (const p of path.split('.')) { if (!cur || typeof cur !== 'object' || !(p in cur)) return false; cur = cur[p]; } return true; };
  /* which record field each column comes from, by key presence (an empty value is still a present field), merged over several records */
  function resolveMapping(rec, prev) { const out = prev || {}; for (const [h, cands] of COLUMNS) { if (out[h]) continue; out[h] = cands.find(c => hasField(rec, c)) || null; } return out; }

  /* ---------- CSV ---------- */
  const csvCell = v => { const s = v == null ? '' : String(v); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  class CsvFile {
    constructor(name) { this.name = name; this.parts = ['﻿' + HEADERS.map(csvCell).join(',') + '\r\n']; this.rows = 0; this.hosts = new Set(); this.severity = {}; this.bytes = this.parts[0].length; }
    add(row) { const line = HEADERS.map(h => csvCell(row[h])).join(',') + '\r\n'; this.parts.push(line); this.rows++; this.bytes += line.length; if (row['IP Address']) this.hosts.add(row['IP Address']); const s = row.Severity || 'Info'; this.severity[s] = (this.severity[s] || 0) + 1; }
    text() { return this.parts.join(''); }
    blob() { return new Blob(this.parts, { type: 'text/csv' }); }
    file() { return new File(this.parts, this.name, { type: 'text/csv', lastModified: Date.now() }); }
    summary() { return { name: this.name, rows: this.rows, hosts: this.hosts.size, severity: this.severity, bytes: this.bytes }; }
  }
  /* a small CSV reader (quotes, embedded newlines) for the optional previous export (first seen carried forward) */
  function parseCsv(text) {
    const rows = []; let row = [], cell = '', q = false; text = text.replace(/^﻿/, '');
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) { if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; }
      else if (ch === '"') q = true; else if (ch === ',') { row.push(cell); cell = ''; } else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
      else cell += ch;
    }
    if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
    const head = rows.shift() || [];
    return rows.filter(r => r.length > 1).map(r => { const o = {}; head.forEach((h, i) => o[h] = r[i] == null ? '' : r[i]); return o; });
  }

  /* ---------- errors ---------- */
  class PullError extends Error { constructor(kind, message, detail) { super(message); this.kind = kind; this.detail = detail || ''; } }
  function describeFetchFailure(url, e) {
    return new PullError('network', `The browser could not get an answer from ${url} (${e && e.message ? e.message : e}).`,
      'Three causes look the same from a page: (1) the certificate is not trusted: open the endpoint in a new tab and accept or import it, then retry; ' +
      '(2) the host or port is not reachable from this computer; (3) the server answered but did not allow this page to read the answer (CORS: the server sends no Access-Control-Allow-Origin header). ' +
      'Security Center and Nessus do not allow it by default; see "If the connection is blocked" below for the options.');
  }
  /* ---------- transport: one request at a time, paced, with timeouts and backoff ----------
     The analysis endpoint runs a database query per page; the pull therefore never has more
     than one request in flight, waits `interval` ms between requests, gives up on a request
     after `timeout` ms, and on 429 / 502 / 503 / 504 or a timeout waits (Retry-After when the
     server says so, otherwise 2 s, 4 s, 8 s… with jitter) and retries up to `retries` times. */
  const PACING = {
    gentle: { interval: 2000, retries: 4, timeout: 180000, pageSize: 500, compliancePageSize: 250, label: 'Gentle: 2 s between requests, pages of 500 / 250 rows' },
    normal: { interval: 750, retries: 3, timeout: 120000, pageSize: 1000, compliancePageSize: 500, label: 'Normal: 0.75 s between requests, pages of 1,000 / 500 rows' },
    fast: { interval: 150, retries: 2, timeout: 120000, pageSize: 2500, compliancePageSize: 1000, label: 'Fast: 0.15 s between requests, pages of 2,500 / 1,000 rows' },
  };
  class Transport {
    constructor(opts) { Object.assign(this, { interval: 750, retries: 3, timeout: 120000, maxRequests: 20000 }, opts || {}); this.lastEnd = 0; this.chain = Promise.resolve(); this.stats = { requests: 0, retries: 0, waitedMs: 0, busyMs: 0, slowest: 0 }; this.onEvent = opts && opts.onEvent; }
    reset() { this.stats = { requests: 0, retries: 0, waitedMs: 0, busyMs: 0, slowest: 0 }; }
    sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
    /* serialise every request through one chain so that concurrency is always 1 */
    request(url, opts, auth, retries) { const run = () => this._request(url, opts, auth, retries == null ? this.retries : retries); const p = this.chain.then(run, run); this.chain = p.catch(() => {}); return p; }
    async _request(url, opts, auth, retries) {
      if (this.stats.requests >= this.maxRequests) throw new PullError('limit', `Stopped after ${this.maxRequests} requests in one pull (safety limit).`);
      for (let attempt = 0; ; attempt++) {
        const gap = this.lastEnd + this.interval - Date.now(); if (gap > 0) { this.stats.waitedMs += gap; await this.sleep(gap); }
        const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null; const timer = ctl ? setTimeout(() => ctl.abort(), this.timeout) : null;
        const t0 = Date.now(); let resp, failure = null;
        try { resp = await fetch(url, Object.assign({ mode: 'cors', cache: 'no-store', credentials: auth === 'session' ? 'include' : 'omit', signal: ctl ? ctl.signal : undefined }, opts)); }
        catch (e) { failure = e; }
        finally { if (timer) clearTimeout(timer); this.lastEnd = Date.now(); const took = this.lastEnd - t0; this.stats.requests++; this.stats.busyMs += took; if (took > this.stats.slowest) this.stats.slowest = took; }
        if (failure) {
          const timedOut = failure && failure.name === 'AbortError';
          if (attempt < retries && timedOut) { const wait = this.backoff(attempt); this.stats.retries++; if (this.onEvent) this.onEvent(`request timed out after ${Math.round(this.timeout / 1000)} s; retrying in ${Math.round(wait / 1000)} s`); await this.sleep(wait); continue; }
          if (timedOut) throw new PullError('timeout', `No answer from ${url} within ${Math.round(this.timeout / 1000)} s (after ${attempt} retries).`, 'Lower the page size or choose the Gentle pacing; Security Center builds each page with a database query.');
          throw describeFetchFailure(url, failure);
        }
        if ((resp.status === 429 || resp.status === 502 || resp.status === 503 || resp.status === 504) && attempt < retries) {
          const ra = parseFloat(resp.headers.get('retry-after')); const wait = Number.isFinite(ra) && ra >= 0 ? Math.min(ra * 1000, 120000) : this.backoff(attempt);
          this.stats.retries++; if (this.onEvent) this.onEvent(`HTTP ${resp.status} from the server; waiting ${Math.round(wait / 1000)} s before retrying`);
          await resp.text().catch(() => ''); await this.sleep(wait); continue;
        }
        return resp;
      }
    }
    backoff(attempt) { return Math.min(60000, 2000 * Math.pow(2, attempt)) * (0.75 + Math.random() * 0.5); }
    describe() { const s = this.stats; return `${s.requests} requests, one at a time, ${(this.interval / 1000).toFixed(2)} s apart (${Math.round(s.waitedMs / 1000)} s paused, ${Math.round(s.busyMs / 1000)} s waiting for the server, slowest ${(s.slowest / 1000).toFixed(1)} s${s.retries ? ', ' + s.retries + ' retries' : ''})`; }
  }
  const defaultTransport = new Transport();
  async function fetchJson(url, opts, auth, transport, retries) {
    const resp = await (transport || defaultTransport).request(url, opts, auth, retries);
    const text = await resp.text();
    let data = null; try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
    if (resp.status === 401 || resp.status === 403) throw new PullError('auth', `HTTP ${resp.status} from ${url}: ${(data && (data.error_msg || data.error)) || text.slice(0, 200) || 'not authorised'}`, 'Check the API keys and the user\'s permissions (API keys must be enabled in Security Center: Settings > Configuration > Security > Allow API Keys).');
    if (resp.status === 429) throw new PullError('http', `HTTP 429 from ${url}: the server is rate limiting this client.`, 'Choose the Gentle pacing and try again later.');
    if (resp.status >= 400) throw new PullError('http', `HTTP ${resp.status} from ${url}: ${text.slice(0, 300)}`);
    if (data == null) throw new PullError('format', `${url} did not return JSON (is this the right endpoint? got ${resp.headers.get('content-type') || 'no content type'}).`);
    return data;
  }

  /* ---------- Security Center client ---------- */
  class SecurityCenter {
    constructor({ url, accessKey, secretKey, username, password, transport }) {
      let base = String(url || '').trim().replace(/\/+$/, ''); if (!base) throw new PullError('config', 'The Security Center endpoint is empty.');
      if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
      this.base = (base.endsWith('/rest') ? base : base + '/rest') + '/';
      this.accessKey = accessKey; this.secretKey = secretKey; this.username = username; this.password = password; this.token = null; this.transport = transport || new Transport();
      if (!(accessKey && secretKey) && !(username && password)) throw new PullError('config', 'Enter the API keys (access key and secret key), or a username and password.');
    }
    get authMode() { return this.accessKey && this.secretKey ? 'keys' : 'session'; }
    headers() { const h = { Accept: 'application/json' }; if (this.authMode === 'keys') h['X-APIKey'] = `accessKey=${this.accessKey}; secretKey=${this.secretKey}`; else if (this.token) h['X-SecurityCenter'] = this.token; return h; }
    async login() { if (this.authMode === 'keys' || this.token) return; const d = await fetchJson(this.base + 'token', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ username: this.username, password: this.password }) }, 'session', this.transport); if (d.error_code) throw new PullError('auth', d.error_msg || 'login failed'); this.token = String((d.response || {}).token || ''); }
    async logout() { if (this.token) { try { await fetchJson(this.base + 'token', { method: 'DELETE', headers: this.headers() }, 'session', this.transport, 0); } catch (e) {} this.token = null; } }
    async call(method, path, body, retries) {
      await this.login();
      const h = this.headers(); if (body !== undefined) h['Content-Type'] = 'application/json';
      const d = await fetchJson(this.base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }, this.authMode, this.transport, retries);
      if (d && d.error_code) throw new PullError('api', `${method} ${path}: ${d.error_msg || 'error'} (error_code ${d.error_code})`, '', d.error_code);
      return d && Object.prototype.hasOwnProperty.call(d, 'response') ? d.response : d;
    }
    system() { return this.call('GET', 'system'); }
    currentUser() { return this.call('GET', 'currentUser?fields=id,username,firstname,lastname,role,organization'); }
    repositories() { return this.call('GET', 'repository?fields=id,name,description,type,dataFormat'); }
    acceptRiskRules() { return this.call('GET', 'acceptRiskRule?fields=id,hostType,hostValue,port,protocol,expires,status,comments,createdTime,modifiedTime,plugin,repository,user'); }
    recastRiskRules() { return this.call('GET', 'recastRiskRule?fields=id,hostType,hostValue,port,protocol,newSeverity,status,comments,createdTime,modifiedTime,plugin,repository,user'); }
    async scanResults(days) { const since = Math.floor(Date.now() / 1000) - (days || 45) * 86400; let r = await this.call('GET', `scanResult?fields=id,name,status,startTime,finishTime,scannedIPs,totalIPs,completedIPs,importStatus,totalChecks,repository&optimizeCompletedScanResults=true&startTime=${since}`); if (r && !Array.isArray(r)) r = r.usable || r.manageable || []; return r || []; }
    analysisPage(query, start, limit, sortField) { const q = Object.assign({}, query, { startOffset: start, endOffset: start + limit }); const payload = { type: q.type || 'vuln', sourceType: 'cumulative', query: q }; if (sortField) { payload.sortField = sortField; payload.sortDir = 'ASC'; } return this.call('POST', 'analysis', payload); }
    /* every record of a vulndetails query, page by page; a filter the installed version rejects is dropped with a warning */
    async iterAnalysis(query, pageSize, onPage, onWarn) {
      query = Object.assign({ type: 'vuln', tool: 'vulndetails' }, query, { filters: (query.filters || []).slice() });
      const out = []; let start = 0, total = null;
      for (;;) {
        let page;
        try { page = await this.analysisPage(query, start, pageSize, query.sortField); }
        catch (e) { const m = /The filter '([^']+)' is invalid/.exec(e.message || ''); if (m && query.filters.some(f => f.filterName === m[1])) { if (onWarn) onWarn(`Security Center does not accept the filter "${m[1]}"; retrying without it`); query.filters = query.filters.filter(f => f.filterName !== m[1]); continue; } throw e; }
        const results = (page && page.results) || []; const t = page && page.totalRecords; if (t != null && t !== '') { const n = parseInt(t, 10); if (!isNaN(n)) total = n; }
        for (const r of results) out.push(r);
        start += results.length; if (onPage) await onPage(start, total);
        if (!results.length || results.length < pageSize || (total != null && start >= total)) break;
      }
      return out;
    }
  }
  function vulnFilters({ severities, repositories, pluginType, pluginIds, excludeWas, extra }) {
    const f = [];
    if (severities) f.push({ filterName: 'severity', operator: '=', value: severities });
    if (repositories && repositories.length) f.push({ filterName: 'repository', operator: '=', value: repositories.map(r => ({ id: String(r.id != null ? r.id : r) })) });
    if (pluginType) f.push({ filterName: 'pluginType', operator: '=', value: pluginType });
    if (pluginIds && pluginIds.length) f.push({ filterName: 'pluginID', operator: '=', value: pluginIds.join(',') });
    if (excludeWas !== false) f.push({ filterName: 'wasVuln', operator: '=', value: 'excludeWas' });
    for (const x of extra || []) if (x && x.filterName) f.push({ filterName: x.filterName, operator: x.operator || '=', value: x.value == null ? '' : x.value });
    return f;
  }

  /* ---------- the Security Center pull ---------- */
  const today = () => new Date().toISOString().slice(0, 10);
  async function pullSecurityCenter(client, opts, progress) {
    opts = Object.assign({ severities: '4,3,2,1', complianceSeverities: '0,1,2,3,4', includeInventory: true, inventoryPlugins: INVENTORY_PLUGINS, pageSize: 1000, compliancePageSize: 500, repositories: [], excludeWas: true, riskRules: true, scanResults: true, scanDays: 45, extraFilters: [], compliance: true }, opts || {});
    const say = (phase, message, rows, total) => { if (progress) progress({ phase, message, rows, total }); };
    const started = Date.now(); const date = opts.date || today(); client.transport.reset(); client.transport.onEvent = m => say('transport', m);
    say('connect', `Connecting to ${client.base}`);
    const system = await client.system(); let user = {};
    try { user = await client.currentUser(); } catch (e) { say('connect', `currentUser not readable: ${e.message}`); }
    const reposAll = await client.repositories();
    const repos = (opts.repositories || []).length ? reposAll.filter(r => opts.repositories.some(w => String(w) === String(r.id) || String(w).toLowerCase() === String(r.name || '').toLowerCase())) : [];
    if ((opts.repositories || []).length && repos.length !== opts.repositories.length) throw new PullError('config', `Repository not found: ${opts.repositories.filter(w => !repos.some(r => String(w) === String(r.id) || String(w).toLowerCase() === String(r.name || '').toLowerCase())).join(', ')} (available: ${reposAll.map(r => r.name).join(', ')})`);
    say('connect', `Security Center ${system.version || '?'}: ${reposAll.length} repositories, exporting ${repos.length ? repos.length : 'all'}`);
    const va = new CsvFile(`SC VA export ${date}.csv`), cmp = new CsvFile(`SC Compliance export ${date}.csv`);
    const seen = new Set(); let dup = 0; const warnings = []; const counts = {};
    const queries = [['vulnerabilities', { filters: vulnFilters({ severities: opts.severities, repositories: repos, excludeWas: opts.excludeWas, extra: opts.extraFilters }) }, opts.pageSize]];
    if (opts.includeInventory && opts.inventoryPlugins.length) queries.push(['inventory', { filters: vulnFilters({ severities: '0', repositories: repos, pluginIds: opts.inventoryPlugins, excludeWas: opts.excludeWas }) }, opts.pageSize]);
    if (opts.compliance) queries.push(['compliance', { filters: vulnFilters({ severities: opts.complianceSeverities, repositories: repos, pluginType: 'compliance', excludeWas: opts.excludeWas }) }, opts.compliancePageSize]);
    let mapping = {}, mapped = 0;
    for (const [name, query, pageSize] of queries) {
      const t0 = Date.now(); const before = va.rows + cmp.rows;
      say(name, `Fetching ${name} (page size ${pageSize})`, 0, null);
      const recs = await client.iterAnalysis(Object.assign({ sortField: opts.sortField }, query), pageSize, (n, total) => say(name, `Fetching ${name}: ${n.toLocaleString()}${total ? ' of ' + total.toLocaleString() : ''} rows`, n, total), w => warnings.push(w));
      for (const rec of recs) { const k = dedupKey(rec); if (seen.has(k)) { dup++; continue; } seen.add(k); if (mapped < 500 && !isCompliance(rec)) { mapping = resolveMapping(rec, mapping); mapped++; } (isCompliance(rec) ? cmp : va).add(recordToRow(rec)); }
      counts[name] = { rows: va.rows + cmp.rows - before, seconds: Math.round((Date.now() - t0) / 100) / 10 };
      say(name, `${name}: ${(va.rows + cmp.rows - before).toLocaleString()} rows in ${Math.round((Date.now() - t0) / 1000)} s`);
    }
    const result = { source: { type: 'sc', url: client.base.replace(/\/rest\/$/, ''), version: system.version, build: system.buildID, user: user.username, organization: user.organization && user.organization.name, repositories: (repos.length ? repos : reposAll).map(r => ({ id: r.id, name: r.name, type: r.type })) },
      date, files: [Object.assign(va.summary(), { kind: 'va', csv: va }), Object.assign(cmp.summary(), { kind: 'compliance', csv: cmp })], counts: Object.assign(counts, { duplicatesSkipped: dup }), warnings, mapping, queries: queries.map(([n, q, p]) => ({ name: n, filters: q.filters, pageSize: p })) };
    if (opts.riskRules) { say('rules', 'Fetching Accept Risk and Recast Risk rules'); try { result.rules = { accept: await client.acceptRiskRules(), recast: await client.recastRiskRules() }; } catch (e) { warnings.push(`risk rules: ${e.message}`); } }
    if (opts.scanResults) { say('scans', 'Fetching recent scan results'); try { result.scans = (await client.scanResults(opts.scanDays)).map(s => ({ id: s.id, name: s.name, status: s.status, finishTime: parseInt(s.finishTime, 10) || null, startTime: parseInt(s.startTime, 10) || null, scannedIPs: s.scannedIPs, totalIPs: s.totalIPs, importStatus: s.importStatus, repository: s.repository && s.repository.name })).sort((a, b) => (b.finishTime || 0) - (a.finishTime || 0)); } catch (e) { warnings.push(`scan results: ${e.message}`); } }
    result.duration = Math.round((Date.now() - started) / 100) / 10; result.transport = client.transport.describe(); result.transportStats = Object.assign({ interval: client.transport.interval }, client.transport.stats);
    result.summary = summarize(result);
    say('done', `Pull complete: ${result.summary}`);
    return result;
  }
  function summarize(result) {
    const parts = [];
    for (const f of result.files) { const s = f.severity || {}; parts.push(f.kind === 'va' ? `${f.rows.toLocaleString()} vulnerability rows on ${f.hosts.toLocaleString()} hosts (${(s.Critical || 0).toLocaleString()} Critical, ${(s.High || 0).toLocaleString()} High, ${(s.Medium || 0).toLocaleString()} Medium, ${(s.Low || 0).toLocaleString()} Low, ${(s.Info || 0).toLocaleString()} Info)` : `${f.rows.toLocaleString()} compliance rows on ${f.hosts.toLocaleString()} hosts`); }
    if (result.counts && result.counts.duplicatesSkipped) parts.push(`${result.counts.duplicatesSkipped.toLocaleString()} rows returned twice`);
    return parts.join('; ');
  }

  /* ---------- Nessus (port 8834) ---------- */
  class Nessus {
    constructor({ url, accessKey, secretKey, transport }) {
      let base = String(url || '').trim().replace(/\/+$/, ''); if (!base) throw new PullError('config', 'The Nessus endpoint is empty.');
      if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
      this.base = base + '/'; this.accessKey = accessKey; this.secretKey = secretKey; this.transport = transport || new Transport();
      if (!(accessKey && secretKey)) throw new PullError('config', 'Enter the Nessus API keys (My Account > API Keys).');
    }
    headers() { return { Accept: 'application/json', 'X-ApiKeys': `accessKey=${this.accessKey}; secretKey=${this.secretKey}` }; }
    async call(method, path, body, retries) { const h = this.headers(); if (body !== undefined) h['Content-Type'] = 'application/json'; return fetchJson(this.base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }, 'keys', this.transport, retries); }
    properties() { return this.call('GET', 'server/properties'); }
    scans() { return this.call('GET', 'scans'); }
    async exportNessus(scanId, onStatus) {
      const tok = await this.call('POST', `scans/${scanId}/export`, { format: 'nessus' }); const fileId = tok.file; if (!fileId) throw new PullError('api', `scan ${scanId}: export did not return a file id`);
      const pollMs = Math.max(3000, this.transport.interval * 2);   // the status poll is the one place a client can nag a server: never more often than every 3 s
      for (let i = 0; ; i++) { const st = await this.call('GET', `scans/${scanId}/export/${fileId}/status`); if (st.status === 'ready') break; if (st.status === 'error' || st.status === 'cancelled') throw new PullError('api', `scan ${scanId}: export ${st.status}`); if (i * pollMs > 3600000) throw new PullError('timeout', `scan ${scanId}: the export was not ready after an hour`); if (onStatus) onStatus(st.status || 'loading'); await this.transport.sleep(pollMs); }
      const url = this.base + `scans/${scanId}/export/${fileId}/download`;
      const resp = await this.transport.request(url, { headers: this.headers() }, 'keys');
      if (!resp.ok) throw new PullError('http', `HTTP ${resp.status} downloading the export of scan ${scanId}`);
      return resp.text();
    }
  }
  const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(str) { const u8 = new TextEncoder().encode(str); let c = 0xFFFFFFFF; for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  /* the same stable compliance plugin IDs as the Python connector: 1,000,000 + crc32(audit|name) mod 99,000,000 */
  const compliancePluginId = (name, audit) => 1000000 + crc32(String(audit || '').trim().toLowerCase() + '|' + String(name || '').trim()) % 99000000;
  const SEV_NAMES = { 0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
  const CM = 'http://www.nessus.org/cm';
  function nessusDate(s) {
    s = String(s || '').trim(); if (!s) return ''; if (/^\d+$/.test(s)) return s;
    let m = /^[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$/.exec(s);
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    if (m) return String(Math.floor(Date.UTC(+m[6], months[m[1]], +m[2], +m[3], +m[4], +m[5]) / 1000));
    m = /^(\d{4})[\/-](\d{2})[\/-](\d{2})/.exec(s); if (m) return String(Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3]) / 1000));
    return '';
  }
  function parseNessus(xmlText, repositoryName) {
    const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new PullError('format', 'The .nessus export could not be parsed as XML.');
    const text = (el, tag) => { const x = el.getElementsByTagName(tag)[0]; return x && x.parentNode === el ? (x.textContent || '').trim() : ''; };
    const texts = (el, tag) => Array.from(el.getElementsByTagName(tag)).filter(x => x.parentNode === el).map(x => (x.textContent || '').trim()).filter(Boolean).join(', ');
    const cm = (el, local) => { const x = el.getElementsByTagNameNS(CM, local)[0]; return x ? (x.textContent || '').trim() : ''; };
    const out = [];
    for (const host of Array.from(doc.getElementsByTagName('ReportHost'))) {
      const hp = {}; for (const t of Array.from(host.getElementsByTagName('tag'))) hp[t.getAttribute('name') || ''] = (t.textContent || '').trim();
      const name = host.getAttribute('name') || ''; const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(name);
      const ip = hp['host-ip'] || (isIp ? name : ''); const fqdn = hp['host-fqdn'] || (isIp ? '' : name); const last = nessusDate(hp.HOST_END || '');
      for (const it of Array.from(host.getElementsByTagName('ReportItem'))) {
        const pid = it.getAttribute('pluginID') || '0'; const fam = it.getAttribute('pluginFamily') || ''; const sevId = it.getAttribute('severity') || '0';
        const result = cm(it, 'compliance-result'); const compliance = !!result || fam.toLowerCase() === 'policy compliance';
        const rec = { pluginID: pid, pluginName: it.getAttribute('pluginName') || '', family: { id: '', name: fam, type: compliance ? 'compliance' : 'active' }, severity: { id: sevId, name: SEV_NAMES[sevId] || 'Info' },
          ip, port: it.getAttribute('port') || '0', protocol: it.getAttribute('protocol') || 'tcp', netbiosName: hp['netbios-name'] || '', dnsName: fqdn, macAddress: (hp['mac-address'] || '').split('\n')[0], hostUUID: hp['host-uuid'] || '', agentID: hp.tenable_agent_uuid || hp['agent-uuid'] || '',
          firstSeen: '', lastSeen: last, exploitAvailable: text(it, 'exploit_available'), exploitEase: text(it, 'exploitability_ease'),
          exploitFrameworks: [['Metasploit', 'exploit_framework_metasploit'], ['Core Impact', 'exploit_framework_core'], ['Canvas', 'exploit_framework_canvas']].filter(([, t]) => text(it, t).toLowerCase() === 'true').map(x => x[0]).join(', '),
          synopsis: text(it, 'synopsis'), description: text(it, 'description'), solution: text(it, 'solution'), seeAlso: text(it, 'see_also'), riskFactor: text(it, 'risk_factor'), stigSeverity: text(it, 'stig_severity'),
          baseScore: text(it, 'cvss_base_score'), temporalScore: text(it, 'cvss_temporal_score'), cvssVector: text(it, 'cvss_vector'), cvssV3BaseScore: text(it, 'cvss3_base_score'), cvssV3TemporalScore: text(it, 'cvss3_temporal_score'), cvssV3Vector: text(it, 'cvss3_vector'),
          cpe: texts(it, 'cpe'), vprScore: text(it, 'vpr_score'), epssScore: text(it, 'epss_score'), cve: texts(it, 'cve'), bid: texts(it, 'bid'), xref: texts(it, 'xref'),
          pluginPubDate: nessusDate(text(it, 'plugin_publication_date')), pluginModDate: nessusDate(text(it, 'plugin_modification_date')), vulnPubDate: nessusDate(text(it, 'vuln_publication_date')), patchPubDate: nessusDate(text(it, 'patch_publication_date')),
          checkType: text(it, 'plugin_type'), version: text(it, 'script_version'), seolDate: nessusDate(text(it, 'seol_date')), pluginText: text(it, 'plugin_output'), repository: { id: repositoryName, name: repositoryName }, operatingSystem: hp['operating-system'] || '' };
        if (compliance) {
          const cname = cm(it, 'compliance-check-name') || rec.pluginName; const audit = cm(it, 'compliance-audit-file');
          rec.nessusPluginID = pid; rec.pluginID = String(compliancePluginId(cname, audit)); rec.pluginName = cname;
          rec.severity = { id: { FAILED: '3', WARNING: '2', ERROR: '2' }[result] || '0', name: { FAILED: 'High', WARNING: 'Medium', ERROR: 'Medium' }[result] || 'Info' };
          const parts = [`"${cname}" : [${result || 'PASSED'}]`, '']; const info = cm(it, 'compliance-info'); if (info) parts.push(`Information: ${info}`, '');
          parts.push(`Result: ${result || 'PASSED'}`, '', `Actual Value: ${cm(it, 'compliance-actual-value')}`, '', `Policy Value: ${cm(it, 'compliance-policy-value')}`, '');
          const sol = cm(it, 'compliance-solution'); if (sol) parts.push(`Solution: ${sol}`, ''); const sa = cm(it, 'compliance-see-also'); if (sa) parts.push(`See Also: ${sa}`, ''); const ref = cm(it, 'compliance-reference'); if (ref) parts.push(`Reference Information: ${ref}`);
          rec.pluginText = parts.join('\n').trim(); rec.xref = `auditFile #${/unix|linux/i.test(audit) ? 'unix' : 'windows'}, nessusPlugin:${pid}`; rec.solution = '';
        }
        out.push(rec);
      }
    }
    return out;
  }
  function selectScans(listing, wanted, folder, maxAgeDays, now) {
    now = now || Math.floor(Date.now() / 1000); const folders = {}; for (const f of listing.folders || []) folders[String(f.id)] = f.name;
    return (listing.scans || []).filter(s => String(s.status || '').toLowerCase() === 'completed' && (!folder || folders[String(s.folder_id)] === folder)
      && (!(wanted && wanted.length) || wanted.some(w => String(s.id) === String(w) || String(s.name || '').trim().toLowerCase() === String(w).trim().toLowerCase()))
      && (!maxAgeDays || !s.last_modification_date || (now - s.last_modification_date) <= maxAgeDays * 86400));
  }
  /* First Discovered carried forward from a previous export's rows: (plugin|ip|port|protocol) -> earliest date */
  function firstSeenIndex(rows) { const m = new Map(); for (const r of rows || []) { const k = [r.Plugin, r['IP Address'], r.Port || '0', String(r.Protocol || '').toUpperCase()].join('|'); const d = r['First Discovered'] || r['Last Observed'] || ''; if (d && (!m.has(k) || d < m.get(k))) m.set(k, d); } return m; }
  async function pullNessus(client, opts, progress) {
    opts = Object.assign({ scans: [], folder: '', maxAgeDays: 45, previousRows: null }, opts || {});
    const say = (phase, message, rows, total) => { if (progress) progress({ phase, message, rows, total }); };
    const started = Date.now(); const date = opts.date || today(); client.transport.reset(); client.transport.onEvent = m => say('transport', m);
    say('connect', `Connecting to ${client.base}`);
    const props = await client.properties(); const listing = await client.scans();
    const chosen = selectScans(listing, opts.scans, opts.folder, opts.maxAgeDays);
    if (!chosen.length) throw new PullError('config', 'No completed scan matches the selection (scans, folder, maximum age).');
    say('connect', `Nessus ${props.server_version || '?'} (${props.nessus_type || ''}): exporting ${chosen.length} scans`);
    const carried = firstSeenIndex(opts.previousRows); const va = new CsvFile(`Nessus VA export ${date}.csv`), cmp = new CsvFile(`Nessus Compliance export ${date}.csv`);
    const seen = new Set(); let dup = 0, newFirst = 0; const warnings = [];
    for (let i = 0; i < chosen.length; i++) {
      const s = chosen[i]; say('export', `Exporting scan ${i + 1}/${chosen.length}: ${s.name}`);
      const xml = await client.exportNessus(s.id, st => say('export', `Scan ${s.name}: export ${st}`));
      say('export', `Parsing scan ${s.name} (${(xml.length / 1048576).toFixed(1)} MB)`);
      let n = 0;
      for (const rec of parseNessus(xml, String(s.name || s.id))) {
        const k = dedupKey(rec); if (seen.has(k)) { dup++; continue; } seen.add(k);
        const k2 = [rec.pluginID, rec.ip, rec.port || '0', String(rec.protocol || '').toUpperCase()].join('|');
        rec.firstSeen = carried.get(k2) || rec.lastSeen; if (!carried.has(k2)) newFirst++;
        (isCompliance(rec) ? cmp : va).add(recordToRow(rec)); n++;
      }
      say('export', `Scan ${s.name}: ${n.toLocaleString()} rows`, va.rows + cmp.rows);
    }
    const result = { source: { type: 'nessus', url: client.base, version: props.server_version, product: props.nessus_type, repositories: chosen.map(s => ({ id: s.id, name: s.name })), scans: chosen.map(s => ({ id: s.id, name: s.name, last_modification_date: s.last_modification_date })) },
      date, files: [Object.assign(va.summary(), { kind: 'va', csv: va }), Object.assign(cmp.summary(), { kind: 'compliance', csv: cmp })], counts: { duplicatesSkipped: dup, firstSeenNew: newFirst, firstSeenCarried: carried.size }, warnings,
      scans: (listing.scans || []).map(s => ({ id: s.id, name: s.name, status: s.status, finishTime: s.last_modification_date || null, repository: s.name })) };
    result.duration = Math.round((Date.now() - started) / 100) / 10; result.transport = client.transport.describe(); result.transportStats = Object.assign({ interval: client.transport.interval }, client.transport.stats); result.summary = summarize(result);
    say('done', `Pull complete: ${result.summary}`);
    return result;
  }

  /* ---------- the files for the Studio ---------- */
  const toFiles = result => result.files.map(f => f.csv.file());
  const manifest = result => ({ pulledAt: new Date().toISOString(), tool: `Tenable Pull ${VERSION}`, source: result.source, date: result.date, files: result.files.map(f => ({ name: f.name, kind: f.kind, rows: f.rows, hosts: f.hosts, severity: f.severity, bytes: f.bytes })), counts: result.counts, warnings: result.warnings, duration: result.duration, summary: result.summary, transport: result.transportStats, queries: result.queries, mapping: result.mapping, rules: result.rules ? { accept: result.rules.accept.length, recast: result.rules.recast.length } : undefined, scans: result.scans ? result.scans.length : undefined });

  /* ---------- settings kept in the browser ---------- */
  const SETTINGS_KEY = 'trs.tenable';
  function loadSettings() { let s = {}; try { s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') || {}; } catch (e) {} try { const sec = sessionStorage.getItem(SETTINGS_KEY + '.secret'); if (sec && !s.secretKey) s.secretKey = sec; const pw = sessionStorage.getItem(SETTINGS_KEY + '.password'); if (pw && !s.password) s.password = pw; } catch (e) {} return Object.assign({ source: 'auto', url: '', accessKey: '', secretKey: '', username: '', password: '', remember: false, severities: ['4', '3', '2', '1'], includeInventory: true, compliance: true, pacing: 'normal', pageSize: PACING.normal.pageSize, compliancePageSize: PACING.normal.compliancePageSize, repositories: [], scans: [], maxAgeDays: 45, studioPath: 'ALTANFEETHI_Tenable_Report_Studio.html' }, s); }

  /* the explanation of every field, shown in the standalone page (open) and in the Studio's panel (collapsed) */
  const HELP_HTML = `
    <h4>Which Tenable product do I connect to?</h4>
    <p><b>Tenable Security Center</b> (also called Tenable.sc) is the management console: the one with <i>Analysis › Vulnerabilities</i>, <i>Repositories</i>, <i>Organizations</i>, <i>Accept Risk</i>, where the CSV exports for the weekly report were taken until now. It holds the cumulative results of every scan, with the dates a finding was first and last seen. <b>This is the one to use.</b></p>
    <p><b>Nessus / Nessus Manager</b> is the scanner itself, the console with <i>Scans</i>, <i>Agents</i>, <i>Policies</i> on port 8834; the agents report to it and Security Center imports from it. Use it only when there is no Security Center: it gives the same findings but no history (no "first discovered" date; the tool carries the dates forward from a previous export instead) and no Accept/Recast Risk rules.</p>
    <p>Not sure which address you have? Leave <b>Source</b> on <i>Detect automatically</i> and click <b>Check connection</b>: the tool asks the address as Security Center first, then as Nessus, and tells you what answered (product, version, user, repositories or scans).</p>
    <h4>What to enter</h4>
    <table class="data tp-fields"><tbody>
      <tr><th>Source</th><td><i>Detect automatically</i> (recommended), or the product explicitly. Security Center queries the cumulative database by repository; Nessus exports the completed scans you tick.</td></tr>
      <tr><th>API endpoint</th><td>The address you type in the browser to open that console, with no path after it. Security Center: <code>https://10.70.30.2</code> or <code>https://tenable.altanfeethi.local</code> (add the port if the console is reached on one, for example <code>https://10.70.30.2:8000</code>). Nessus: <code>https://10.70.30.2:8834</code>. The tool adds <code>/rest/…</code> or the Nessus paths itself.</td></tr>
      <tr><th>Access key, Secret key</th><td>The API keys of a read-only service account. Security Center: <i>Users › the user › Generate API Keys</i> (API keys must be allowed under <i>Settings › Configuration › Security › Allow API Keys</i>; the built-in Auditor role with access to every repository is enough). Nessus: <i>My Account › API Keys</i>. The secret is shown once when generated.</td></tr>
      <tr><th>Username, password</th><td>Security Center only, instead of the keys: the tool logs in like the console does (session token) and logs out at the end. Keys are preferred; a session login is for an installation where API keys are not allowed.</td></tr>
      <tr><th>Remember</th><td>Unticked: the address, access key and options are kept in this browser profile, the secret only until the tab is closed. Ticked: the secret is kept too, unencrypted, like a saved password.</td></tr>
      <tr><th>Pull options</th><td>Which severities to export (the report uses Critical to Low), whether to add the inventory rows that keep hosts without findings listed (keep it on), the compliance export (keep it on for the CIS part of the report), the request pacing, and which repositories (Security Center) or scans (Nessus) to include: after Check connection they are listed; none ticked means all.</td></tr>
    </tbody></table>
    <h4>What you get</h4>
    <p>Two CSV files with the layout of the Security Center "Vulnerability Detail List" export: <code>SC VA export &lt;date&gt;.csv</code> (vulnerabilities, Critical to Low, plus the inventory rows) and <code>SC Compliance export &lt;date&gt;.csv</code> (CIS checks: Info = passed, Medium = warning, High = failed), with <code>manifest.json</code> (counts, filters, load figures) and <code>risk-rules.json</code> (the Accept/Recast Risk rules at that moment). The Studio loads them exactly like the exports it received by hand: the newest is "now", an older pull loaded next to it is the history for the trend, Validate fixes and the risk register.</p>`;
  function saveSettings(s) { const keep = Object.assign({}, s); if (!s.remember) { delete keep.secretKey; delete keep.password; } try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(keep)); } catch (e) {} try { if (s.secretKey) sessionStorage.setItem(SETTINGS_KEY + '.secret', s.secretKey); else sessionStorage.removeItem(SETTINGS_KEY + '.secret'); if (s.password) sessionStorage.setItem(SETTINGS_KEY + '.password', s.password); else sessionStorage.removeItem(SETTINGS_KEY + '.password'); } catch (e) {} }
  function forgetSecrets() { try { const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') || {}; delete s.secretKey; delete s.password; s.remember = false; localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch (e) {} try { sessionStorage.removeItem(SETTINGS_KEY + '.secret'); sessionStorage.removeItem(SETTINGS_KEY + '.password'); } catch (e) {} }

  /* ---------- the shared panel (standalone page and Studio modal) ---------- */
  const CSS = `
    .tp{font-size:13.5px}
    .tp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px 16px;align-items:start}
    .tp-grid > label, .tp label{display:flex;flex-direction:column;gap:4px;font-size:12.5px;color:var(--ink-2,#5b5752)}
    .tp input[type=text], .tp input:not([type]), .tp input[type=password], .tp input[type=number], .tp select{font:inherit;font-size:13.5px;padding:7px 9px;border:1px solid var(--line-2,#cfc4b3);border-radius:6px;background:var(--surface,#fff);color:var(--ink,#2b2a28);min-width:0}
    .tp input[type=file]{font-size:12.5px}
    .tp-wide{grid-column:1 / -1}
    .tp-check{display:flex !important;flex-direction:row !important;align-items:center;gap:6px;font-size:12.5px;color:var(--ink,#2b2a28)}
    .tp-check input{margin:0}
    .tp-chips{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:4px}
    .tp-opts{margin-top:12px;padding:10px 12px;border:1px solid var(--line,#e5ddd0);border-radius:8px;background:var(--surface-2,#f6f1e8)}
    .tp-opts > summary{cursor:pointer;font-weight:600;font-size:13px}
    .tp-opts > .tp-grid{margin-top:10px}
    .tp-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
    .tp-flex{flex:1}
    .tp-small{font-size:12px}
    .tp-muted{color:var(--muted,#8e8882)}
    .tp-bar{height:8px;border-radius:4px;background:var(--surface-2,#f6f1e8);overflow:hidden;margin:6px 0}
    .tp-bar > div{height:100%;background:var(--brand-2,#a8683b);transition:width .4s}
    .tp-log{font-family:var(--mono,ui-monospace,Consolas,monospace);font-size:11px;max-height:130px;overflow:auto;background:var(--surface-2,#f6f1e8);padding:6px 8px;border-radius:6px;white-space:pre-wrap;margin-top:6px}
    .tp-sect{margin-top:12px}
    .tp-sect > summary{cursor:pointer;font-weight:600;font-size:13px}
    .tp-ol{margin:6px 0 0 18px;padding:0}
    .tp-ol li{margin:4px 0}
    .tp code{font-family:var(--mono,ui-monospace,Consolas,monospace);font-size:11.5px;background:var(--surface-2,#f6f1e8);padding:1px 4px;border-radius:3px}
    .tp-hint{font-size:11.5px;color:var(--muted,#8e8882);line-height:1.35}
    .tp-help{margin:0 0 14px;padding:10px 12px;border:1px solid var(--line,#e5ddd0);border-radius:8px;background:var(--surface,#fff)}
    .tp-help > summary{cursor:pointer;font-weight:600;font-size:13px}
    .tp-help-body{margin-top:8px;font-size:13px;color:var(--ink,#2b2a28)}
    .tp-help-body h4{margin:10px 0 4px;font-size:13px}
    .tp-help-body p{margin:4px 0}
    .tp-fields th{width:150px;text-align:left;vertical-align:top;font-size:12px;text-transform:none;letter-spacing:0}
    .tp-fields td{font-size:12.5px}
    #tp_status, #tp_progress, #tp_result{margin-top:10px}
  `;
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtN = n => (n == null ? 0 : n).toLocaleString('en-US');
  const whenTs = ts => ts ? new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '';
  const mb = b => b == null ? '' : (b / 1048576).toFixed(1) + ' MB';
  const dl = (blob, name) => { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500); };
  function mount(container, options) {
    options = Object.assign({ mode: 'standalone', onFiles: null, onClose: null }, options || {});
    const S = loadSettings(); let client = null, checked = null, result = null, running = false;
    const $ = sel => container.querySelector(sel); const $$ = sel => Array.from(container.querySelectorAll(sel));
    const sevOpts = [['4', 'Critical'], ['3', 'High'], ['2', 'Medium'], ['1', 'Low']];
    const isSc = S.source !== 'nessus';   // "auto" shows the Security Center options until the check says otherwise
    container.innerHTML = `
      <div class="tp">
        <details class="tp-help" id="tp_help" ${options.helpOpen === false ? '' : 'open'}><summary>What to enter (Security Center or Nessus, endpoint, keys, options)</summary><div class="tp-help-body">${HELP_HTML}</div></details>
        <div class="tp-grid">
          <label>Source<select id="tp_source"><option value="auto" ${S.source === 'auto' ? 'selected' : ''}>Detect automatically (recommended)</option><option value="sc" ${S.source === 'sc' ? 'selected' : ''}>Tenable Security Center, the management console (Analysis, Repositories)</option><option value="nessus" ${S.source === 'nessus' ? 'selected' : ''}>Nessus / Nessus Manager, the scanner console (port 8834)</option></select><span class="tp-hint" id="tp_source_hint"></span></label>
          <label>API endpoint<input id="tp_url" value="${esc(S.url)}" placeholder="https://10.70.30.2" autocomplete="off" spellcheck="false"><span class="tp-hint">The address you open in the browser for the console, no path after it: <code>https://10.70.30.2</code> or <code>https://tenable.altanfeethi.local</code>; add the port if there is one (<code>https://10.70.30.2:8834</code> for Nessus).</span></label>
          <label>Access key<input id="tp_ak" value="${esc(S.accessKey)}" autocomplete="off" spellcheck="false"><span class="tp-hint">Security Center: Users › the user › Generate API Keys. Nessus: My Account › API Keys.</span></label>
          <label>Secret key<input id="tp_sk" type="password" value="${esc(S.secretKey)}" autocomplete="off"><span class="tp-hint">Shown once when the keys are generated; sent only to the endpoint above.</span></label>
          <div class="tp-sc-only" ${isSc ? '' : 'hidden'}><details><summary class="tp-small">Or a username and password (Security Center session login) instead of keys</summary><div class="tp-grid"><label>Username<input id="tp_user" value="${esc(S.username)}" autocomplete="off"></label><label>Password<input id="tp_pw" type="password" value="${esc(S.password)}" autocomplete="off"></label></div></details></div>
          <label class="tp-check tp-wide"><input type="checkbox" id="tp_remember" ${S.remember ? 'checked' : ''}> Remember the secret key / password on this computer (stored unencrypted in this browser profile; otherwise kept only until the tab is closed)</label>
        </div>
        <details class="tp-opts"><summary>Pull options</summary><div class="tp-grid">
          <div class="tp-sc-only" ${isSc ? '' : 'hidden'}><span class="tp-small">Vulnerability severities</span><div class="tp-chips">${sevOpts.map(([v, l]) => `<label class="tp-check"><input type="checkbox" class="tp-sev" value="${v}" ${S.severities.includes(v) ? 'checked' : ''}> ${l}</label>`).join('')}</div></div>
          <div class="tp-sc-only" ${isSc ? '' : 'hidden'}><label class="tp-check"><input type="checkbox" id="tp_inv" ${S.includeInventory ? 'checked' : ''}> Add the inventory rows (Info rows of the OS, hostname, scan info, CPE and patch-assessment plugins) so hosts with no findings stay listed as scanned</label><label class="tp-check"><input type="checkbox" id="tp_cmp" ${S.compliance ? 'checked' : ''}> Compliance export (Info = passed, Medium = warning, High = failed)</label></div>
          <div class="tp-wide"><label>Request pacing (one request at a time; the pause between requests, the retries on 429 / 503 and the page sizes)<select id="tp_pacing">${Object.entries(PACING).map(([k, p]) => `<option value="${k}" ${S.pacing === k ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></label></div>
          <div class="tp-sc-only" ${isSc ? '' : 'hidden'}><label>Rows per page (vulnerabilities)<input id="tp_page" type="number" min="100" max="5000" value="${esc(S.pageSize)}"></label><label>Rows per page (compliance)<input id="tp_cpage" type="number" min="100" max="5000" value="${esc(S.compliancePageSize)}"></label></div>
          <div class="tp-sc-only tp-wide" ${isSc ? '' : 'hidden'}><span class="tp-small">Repositories (after Check connection; none ticked = all)</span><div id="tp_repos" class="tp-chips tp-muted">not checked yet</div></div>
          <div class="tp-nessus-only tp-wide" ${isSc ? 'hidden' : ''}><span class="tp-small">Scans to export (after Check connection; none ticked = every completed scan of the last <input id="tp_age" type="number" min="1" max="3650" value="${esc(S.maxAgeDays)}" style="width:64px"> days)</span><div id="tp_scans" class="tp-chips tp-muted">not checked yet</div></div>
          <div class="tp-nessus-only tp-wide" ${isSc ? 'hidden' : ''}><label>Previous VA export (optional): Nessus has no "first discovered", so the dates are carried forward from this file<input id="tp_prev" type="file" accept=".csv"></label></div>
        </div></details>
        <div class="tp-actions"><button type="button" class="btn" id="tp_check">Check connection</button><button type="button" class="btn primary" id="tp_pull">Pull</button><a class="tp-small" id="tp_open" href="#" target="_blank" rel="noopener" hidden>open the endpoint in a new tab (certificate)</a><span class="tp-flex"></span>${options.mode === 'studio' ? '<button type="button" class="btn" id="tp_close">Close</button>' : ''}</div>
        <div id="tp_status"></div>
        <div id="tp_progress"></div>
        <div id="tp_result"></div>
      </div>`;
    const read = () => { S.source = $('#tp_source').value; S.url = $('#tp_url').value.trim(); S.accessKey = $('#tp_ak').value.trim(); S.secretKey = $('#tp_sk').value; S.username = ($('#tp_user') || {}).value || ''; S.password = ($('#tp_pw') || {}).value || ''; S.remember = $('#tp_remember').checked;
      S.severities = $$('.tp-sev').filter(c => c.checked).map(c => c.value); S.includeInventory = $('#tp_inv').checked; S.compliance = $('#tp_cmp').checked; S.pacing = PACING[$('#tp_pacing').value] ? $('#tp_pacing').value : 'normal';
      S.pageSize = Math.min(5000, Math.max(100, parseInt($('#tp_page').value, 10) || PACING[S.pacing].pageSize)); S.compliancePageSize = Math.min(5000, Math.max(100, parseInt($('#tp_cpage').value, 10) || PACING[S.pacing].compliancePageSize)); S.maxAgeDays = parseInt($('#tp_age').value, 10) || 45;
      S.repositories = $$('#tp_repos input:checked').map(c => c.value); S.scans = $$('#tp_scans input:checked').map(c => c.value); saveSettings(S); return S; };
    const SOURCE_HINT = { auto: 'The check asks the address as Security Center first, then as Nessus, and sets this field to what answered.', sc: 'The management console: Analysis › Vulnerabilities, Repositories, Accept Risk; cumulative results with first-seen dates. The one the weekly exports came from.', nessus: 'The scanner console (Scans, Agents, Policies, port 8834). Same findings, no history: use it only without Security Center.' };
    const showSource = () => { const v = $('#tp_source').value; const sc = v !== 'nessus'; $$('.tp-sc-only').forEach(el => el.hidden = !sc); $$('.tp-nessus-only').forEach(el => el.hidden = sc); $('#tp_url').placeholder = sc ? 'https://10.70.30.2' : 'https://10.70.30.2:8834'; $('#tp_source_hint').textContent = SOURCE_HINT[v] || ''; };
    $('#tp_source').onchange = showSource; showSource();
    $('#tp_pacing').onchange = () => { const p = PACING[$('#tp_pacing').value] || PACING.normal; $('#tp_page').value = p.pageSize; $('#tp_cpage').value = p.compliancePageSize; };
    const transportFor = (retriesOverride) => { const p = PACING[S.pacing] || PACING.normal; return new Transport({ interval: p.interval, retries: retriesOverride == null ? p.retries : retriesOverride, timeout: p.timeout }); };
    $('#tp_url').oninput = () => { const u = $('#tp_url').value.trim(); const a = $('#tp_open'); if (u) { a.href = (/^https?:\/\//i.test(u) ? u : 'https://' + u).replace(/\/+$/, '') + ($('#tp_source').value === 'nessus' ? '/server/status' : '/rest/system'); a.hidden = false; } else a.hidden = true; }; $('#tp_url').oninput();
    if (options.mode === 'studio') $('#tp_close').onclick = () => options.onClose && options.onClose();
    const status = (html, cls) => { $('#tp_status').innerHTML = html ? `<div class="notice ${cls || ''}">${html}</div>` : ''; };
    const errorHtml = e => `<b>${esc(e.message || e)}</b>${e.detail ? `<div class="tp-small" style="margin-top:4px">${esc(e.detail)}</div>` : ''}`;
    const makeClient = (retries, source) => { read(); const transport = transportFor(retries); return (source || S.source) !== 'nessus' ? new SecurityCenter({ url: S.url, accessKey: S.accessKey, secretKey: S.secretKey, username: S.username, password: S.password, transport }) : new Nessus({ url: S.url, accessKey: S.accessKey, secretKey: S.secretKey, transport }); };
    /* "Detect automatically": ask the address as Security Center, then as Nessus; the first that answers wins */
    async function detect(retries) {
      read(); if (S.source !== 'auto') return { source: S.source, client: makeClient(retries) };
      let scErr = null, nErr = null;
      try { const c = makeClient(retries, 'sc'); const sys = await c.system(); return { source: 'sc', client: c, sys }; } catch (e) { scErr = e; }
      try { const c = makeClient(retries, 'nessus'); const props = await c.properties(); return { source: 'nessus', client: c, props }; } catch (e) { nErr = e; }
      throw (scErr.kind === 'network' || nErr.kind === 'config') ? scErr : (nErr.kind === 'network' ? nErr : scErr);
    }
    const setSource = src => { S.source = src; $('#tp_source').value = src; showSource(); saveSettings(S); };
    async function check() {
      const b = $('#tp_check'); b.disabled = true; b.textContent = 'Checking…'; status('');
      try {
        const d = await detect(0);   // a check answers quickly: no retries
        client = d.client; if (d.source !== $('#tp_source').value) setSource(d.source);
        if (d.source === 'sc') {
          const sys = d.sys || await client.system(); let u = {}; try { u = await client.currentUser(); } catch (e) {}
          const repos = await client.repositories(); checked = { sys, u, repos };
          $('#tp_repos').className = 'tp-chips'; $('#tp_repos').innerHTML = repos.map(r => `<label class="tp-check"><input type="checkbox" value="${esc(r.id)}" ${S.repositories.includes(String(r.id)) ? 'checked' : ''}> ${esc(r.name)} <span class="tp-muted">(${esc(r.type || '')})</span></label>`).join('') || '<span class="tp-muted">no repository visible to this user</span>';
          status(`Connected to <b>Tenable Security Center ${esc(sys.version || '?')}</b> (build ${esc(sys.buildID || '?')}, licence ${esc(sys.licenseStatus || '?')})${u.username ? ` as <b>${esc(u.username)}</b>${u.role && u.role.name ? ' (' + esc(u.role.name) + ')' : ''}` : ''}. Repositories: ${repos.map(r => esc(r.name)).join(', ') || 'none'}. This is the management console; Pull will export the cumulative results.`, 'good');
        } else {
          const props = d.props || await client.properties(); const listing = await client.scans(); checked = { props, listing };
          const scans = (listing.scans || []).filter(s => String(s.status || '').toLowerCase() === 'completed');
          $('#tp_scans').className = 'tp-chips'; $('#tp_scans').innerHTML = scans.map(s => `<label class="tp-check"><input type="checkbox" value="${esc(s.id)}" ${S.scans.includes(String(s.id)) || S.scans.includes(String(s.name)) ? 'checked' : ''}> ${esc(s.name)} <span class="tp-muted">(${esc(whenTs(s.last_modification_date))})</span></label>`).join('') || '<span class="tp-muted">no completed scan</span>';
          status(`Connected to <b>${esc(props.nessus_type || 'Nessus')} ${esc(props.server_version || '?')}</b>, the scanner console. ${scans.length} completed scans, ${(listing.scans || []).length} in total. Pull will export the completed scans ticked under Pull options (none ticked = all of the last ${esc(S.maxAgeDays)} days).`, 'good');
        }
        read();
      } catch (e) { status(errorHtml(e), 'bad'); if (e.kind === 'network') await explainNetworkFailure(); }
      finally { b.disabled = false; b.textContent = 'Check connection'; }
    }
    async function explainNetworkFailure() {
      const prog = $('#tp_progress'); prog.innerHTML = '<div class="notice tp-small">Diagnosing: is the server there at all?</div>';
      try { const d = await diagnoseConnection(S.url, S.source === 'nessus' ? 'nessus' : 'sc'); prog.innerHTML = diagnosisHtml(d) + corsHelp(); }
      catch (e) { prog.innerHTML = corsHelp(); }
    }
    async function pull() {
      if (running) return; running = true; const b = $('#tp_pull'); b.disabled = true; b.textContent = 'Pulling…'; $('#tp_check').disabled = true; status(''); $('#tp_result').innerHTML = ''; result = null;
      const log = []; const prog = $('#tp_progress');
      const progress = p => { log.push(`${new Date().toISOString().slice(11, 19)} ${p.message}`); if (log.length > 300) log.shift(); const pct = p.total ? Math.min(100, Math.round(100 * (p.rows || 0) / p.total)) : null; prog.innerHTML = `<div class="notice"><b>${esc(p.phase)}</b>: ${esc(p.message)}<div class="tp-bar"><div style="width:${pct == null ? (p.phase === 'done' ? 100 : 12) : pct}%"></div></div><div class="tp-log">${log.slice(-8).map(esc).join('\n')}</div></div>`; };
      try {
        const d = await detect(); client = d.client; if (d.source !== $('#tp_source').value) setSource(d.source);
        if (d.source === 'sc') result = await pullSecurityCenter(client, { severities: (S.severities.length ? S.severities : ['4', '3', '2', '1']).join(','), includeInventory: S.includeInventory, compliance: S.compliance, pageSize: S.pageSize, compliancePageSize: S.compliancePageSize, repositories: S.repositories }, progress);
        else { let previousRows = null; const f = $('#tp_prev').files[0]; if (f) previousRows = parseCsv(await f.text()); result = await pullNessus(client, { scans: S.scans, maxAgeDays: S.maxAgeDays, previousRows }, progress); }
        renderResult();
        if (options.mode === 'studio' && options.onFiles) { await options.onFiles(toFiles(result), result); }
      } catch (e) { status(errorHtml(e), 'bad'); if (e.kind === 'network') await explainNetworkFailure(); }
      finally { running = false; b.disabled = false; b.textContent = 'Pull'; $('#tp_check').disabled = false; if (client && client.logout) client.logout(); }
    }
    function renderResult() {
      const r = result; const el = $('#tp_result');
      const files = r.files.map((f, i) => `<tr><td><b>${esc(f.name)}</b></td><td class="num">${fmtN(f.rows)}</td><td class="num">${fmtN(f.hosts)}</td><td class="tp-small">${['Critical', 'High', 'Medium', 'Low', 'Info'].filter(k => f.severity[k]).map(k => `${fmtN(f.severity[k])} ${k}`).join(' · ')}</td><td class="num">${mb(f.bytes)}</td><td><button type="button" class="btn sm tp-dl" data-i="${i}">Download</button></td></tr>`).join('');
      const warn = (r.warnings || []).length ? `<div class="notice bad tp-small">${r.warnings.map(esc).join('<br>')}</div>` : '';
      const missing = r.mapping ? Object.entries(r.mapping).filter(([h, src]) => !src && ['Exploit Prediction Scoring System (EPSS)', 'Security End of Life Date', 'Host ID', 'Agent ID', 'Accept Risk Comment', 'Recast Risk Comment', 'First Discovered', 'Last Observed', 'Plugin Text', 'Steps to Remediate', 'VPR Score', 'CVSS V3 Vector', 'CPE'].includes(h)).map(x => x[0]) : [];
      el.innerHTML = `<div class="notice good"><b>Pull complete</b> in ${r.duration} s: ${esc(r.summary)}.<div class="tp-small tp-muted" style="margin-top:4px">Load on the server: ${esc(r.transport || '')}.</div></div>${warn}
        ${missing.length ? `<div class="notice tp-small">Columns this ${r.source.type === 'sc' ? 'Security Center' : 'Nessus'} did not return (they stay empty in the export): ${missing.map(esc).join(', ')}. The record fields with no column are listed in the manifest.</div>` : ''}
        <table class="data"><thead><tr><th>File</th><th class="num">Rows</th><th class="num">Hosts</th><th>By severity</th><th class="num">Size</th><th></th></tr></thead><tbody>${files}</tbody></table>
        <div class="tp-actions"><button type="button" class="btn primary" id="tp_dlall">Download both files</button><button type="button" class="btn" id="tp_manifest">Download manifest.json</button>${r.rules ? '<button type="button" class="btn" id="tp_rules">Download risk-rules.json</button>' : ''}${options.mode === 'standalone' ? `<span class="tp-flex"></span><label class="tp-small">Studio file <input id="tp_studio" value="${esc(S.studioPath)}" style="width:300px"></label><button type="button" class="btn primary" id="tp_send">Open the Studio and load these files</button>` : ''}</div>
        <div id="tp_send_status"></div>
        ${r.rules ? `<details class="tp-sect"><summary>Risk acceptances in Security Center (${fmtN(r.rules.accept.length)} accept-risk, ${fmtN(r.rules.recast.length)} recast rules)</summary>${rulesTable(r.rules)}</details>` : ''}
        ${r.scans ? `<details class="tp-sect"><summary>Recent scans (${fmtN(r.scans.length)})</summary>${scansTable(r.scans)}</details>` : ''}`;
      $$('.tp-dl').forEach(b => b.onclick = () => { const f = r.files[+b.dataset.i]; dl(f.csv.blob(), f.name); });
      $('#tp_dlall').onclick = async () => { for (const f of r.files) { dl(f.csv.blob(), f.name); await new Promise(res => setTimeout(res, 700)); } };
      $('#tp_manifest').onclick = () => dl(new Blob([JSON.stringify(manifest(r), null, 1)], { type: 'application/json' }), `manifest ${r.date}.json`);
      if (r.rules) $('#tp_rules').onclick = () => dl(new Blob([JSON.stringify(r.rules, null, 1)], { type: 'application/json' }), `risk-rules ${r.date}.json`);
      if (options.mode === 'standalone') $('#tp_send').onclick = sendToStudio;
    }
    function rulesTable(rules) {
      const row = (x, kind) => `<tr><td>${esc(kind)}</td><td>${esc((x.plugin || {}).id || '')}</td><td class="wrap">${esc((x.plugin || {}).name || '')}</td><td>${esc(x.hostType === 'all' ? 'all hosts' : (x.hostValue || x.hostType || ''))}${x.port && x.port !== '-1' ? ' port ' + esc(x.port) : ''}</td><td>${esc(kind === 'Recast' ? ((x.newSeverity || {}).name || '') : (x.expires && x.expires !== '-1' ? 'until ' + fmtDate(x.expires).slice(0, 10) : 'no expiry'))}</td><td class="wrap">${esc(x.comments || '')}</td><td>${esc((x.user || {}).username || '')}</td><td>${esc(fmtDate(x.createdTime).slice(0, 10))}</td></tr>`;
      const rows = (rules.accept || []).map(x => row(x, 'Accept')).concat((rules.recast || []).map(x => row(x, 'Recast')));
      return rows.length ? `<p class="tp-small tp-muted">Findings under an Accept Risk rule leave the export and the report; a Recast Risk rule changes the severity in Security Center. This is the audit trail of those decisions at the time of the pull.</p><div class="table-wrap"><table class="data"><thead><tr><th>Rule</th><th>Plugin</th><th>Vulnerability</th><th>Hosts</th><th>Expiry / new severity</th><th>Comment</th><th>By</th><th>Created</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>` : '<p class="tp-small tp-muted">No Accept Risk or Recast Risk rules.</p>';
    }
    function scansTable(scans) { return `<div class="table-wrap"><table class="data"><thead><tr><th>Scan</th><th>Repository</th><th>Status</th><th>Finished</th><th class="num">Hosts</th><th>Import</th></tr></thead><tbody>${scans.slice(0, 40).map(s => `<tr><td>${esc(s.name || '')}</td><td>${esc(s.repository || '')}</td><td>${esc(s.status || '')}</td><td class="nowrap">${esc(whenTs(s.finishTime))}</td><td class="num">${s.scannedIPs != null ? esc(s.scannedIPs + ' of ' + s.totalIPs) : ''}</td><td>${esc(s.importStatus || '')}</td></tr>`).join('')}</tbody></table></div>`; }
    /* open the Studio (same folder by default) and hand the files over once it says it is ready */
    function sendToStudio() {
      S.studioPath = $('#tp_studio').value.trim() || S.studioPath; saveSettings(S); const st = $('#tp_send_status');
      const files = toFiles(result); const win = window.open(S.studioPath, 'trs-studio');
      if (!win) { st.innerHTML = '<div class="notice bad">The browser blocked the pop-up; allow pop-ups for this file and try again, or download the files and drop them on the Studio.</div>'; return; }
      st.innerHTML = '<div class="notice">Waiting for the Studio to open…</div>';
      let sent = false; const send = () => { if (sent) return; sent = true; win.postMessage({ type: 'trs-files', files, pulled: manifest(result) }, '*'); st.innerHTML = `<div class="notice good">${files.length} files sent to the Studio window.</div>`; };
      const onMsg = e => { if (e.source === win && e.data && e.data.type === 'trs-ready') { window.removeEventListener('message', onMsg); send(); } };
      window.addEventListener('message', onMsg);
      setTimeout(() => { if (!sent) { window.removeEventListener('message', onMsg); st.innerHTML = '<div class="notice bad">The Studio did not answer (it needs version 4.8 or later in that path, and pop-ups allowed). Download the files and drop them on the Studio instead.</div>'; } }, 20000);
    }
    $('#tp_check').onclick = check; $('#tp_pull').onclick = pull;
    return { check, pull, settings: () => S, result: () => result, read };
  }
  /* ---------- diagnosis of a failed connection ----------
     A request in "no-cors" mode is sent without the CORS rules and comes back opaque: the page
     cannot read it, but it resolves if the server answered at all and rejects if the connection
     failed (nothing listens, blocked port, untrusted certificate).  That separates "the server
     is there but does not allow this page" from "no connection".  The ports Tenable products
     commonly use are probed the same way to suggest the right endpoint. */
  async function probeReachable(url, timeoutMs) {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null; const t = ctl ? setTimeout(() => ctl.abort(), timeoutMs || 8000) : null;
    try { await fetch(url, { mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: ctl ? ctl.signal : undefined }); return true; } catch (e) { return false; } finally { if (t) clearTimeout(t); }
  }
  async function diagnoseConnection(url, source) {
    let base = String(url || '').trim().replace(/\/+$/, ''); if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
    const probe = base + (source === 'nessus' ? '/server/status' : '/rest/system');
    const out = { base, probe, reachable: await probeReachable(probe, 8000), alternatives: [] };
    if (!out.reachable) {
      let host = ''; try { host = new URL(base).hostname; } catch (e) {}
      if (host) for (const u of [`https://${host}`, `https://${host}:8000`, `http://${host}:8000`, `https://${host}:8443`, `https://${host}:8834`].filter(u => u !== base)) out.alternatives.push({ url: u, reachable: await probeReachable(u + '/', 5000) });
    }
    return out;
  }
  function diagnosisHtml(d) {
    if (d.reachable) return `<div class="notice good"><b>Diagnosis: the server is there.</b> <code>${esc(d.probe)}</code> answers and its certificate is accepted by this browser; the address and the network are fine. The only problem is that the server does not allow this page to read the answer (CORS). Pick one of the options below: the quickest to try today is the dedicated browser profile (option 3); the clean one for daily use is serving this file from the Security Center web root (option 1).</div>`;
    const alts = d.alternatives.filter(a => a.reachable);
    return `<div class="notice bad"><b>Diagnosis: no connection at all</b> to <code>${esc(d.probe)}</code> from this browser: either the certificate is not trusted, or nothing listens at that address and port from this computer (the CORS options below do not apply yet).
      <ol class="tp-ol"><li>Open <a href="${esc(d.probe)}" target="_blank" rel="noopener">${esc(d.probe)}</a> in a new tab. A certificate warning: accept it (or import the internal CA), then click Check connection again. "This site can't be reached": the address or port is wrong, or blocked between this computer and the server.</li>
      <li>The endpoint is the address you use to log in to the Security Center console, port included when it has one (for example <code>https://10.70.30.3:8000</code>).</li>
      ${alts.length ? `<li>Something answers at ${alts.map(a => `<code>${esc(a.url)}</code>`).join(', ')}: try ${alts.length > 1 ? 'these' : 'this'} as the endpoint${alts.some(a => /:8834$/.test(a.url)) ? ' (8834 is Nessus, the scanner console)' : ''}.</li>` : '<li>None of the usual ports (443, 8000, 8443, 8834) answered on that host either.</li>'}</ol></div>`;
  }
  function corsHelp() {
    return `<div class="notice tp-small"><b>If the connection is blocked.</b> A page can only read another server's answers when that server allows it (an <code>Access-Control-Allow-Origin</code> header); Security Center and Nessus do not send it by default, and the browser then reports a plain network failure. Options, in order of preference:
      <ol class="tp-ol"><li><b>Serve this file from the Tenable server itself</b> (same origin, nothing to allow): copy it into the Security Center web root (the DocumentRoot in <code>/opt/sc/support/conf/*.conf</code>) and open it as <code>https://&lt;security-center&gt;/Tenable_Pull.html</code>.</li>
      <li><b>Allow this page on the Tenable side:</b> in the Security Center Apache configuration add <code>Header always set Access-Control-Allow-Origin "null"</code> (for a file opened from a folder) or the origin that serves the file, <code>Header always set Access-Control-Allow-Headers "X-APIKey, Content-Type, Accept"</code>, <code>Header always set Access-Control-Allow-Methods "GET, POST, DELETE, OPTIONS"</code>, and answer OPTIONS with 204.</li>
      <li><b>A dedicated browser profile without web security</b> for this tool only, for example a shortcut <code>chrome.exe --user-data-dir="%LOCALAPPDATA%\\TenablePull" --disable-web-security</code>; never browse anything else in that profile.</li>
      <li>The optional connector service in this repository, which does the pull server-side on a schedule.</li></ol>
      First rule out the certificate: open the endpoint link above in a new tab; if the browser warns, accept the certificate once (or import the internal CA) and retry.</div>`;
  }

  return { VERSION, CSS, COLUMNS, HEADERS, INVENTORY_PLUGINS, PACING, Transport, SecurityCenter, Nessus, vulnFilters, probeReachable, diagnoseConnection, diagnosisHtml, pullSecurityCenter, pullNessus, parseNessus, selectScans, recordToRow, isCompliance, dedupKey, fmtDate, csvCell, CsvFile, parseCsv, firstSeenIndex, compliancePluginId, crc32, toFiles, manifest, summarize, loadSettings, saveSettings, forgetSecrets, mount, corsHelp, PullError };
});
