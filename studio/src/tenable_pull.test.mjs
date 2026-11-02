// Unit checks of the Tenable Pull engine in Node (node --test studio/src/tenable_pull.test.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const TP = require('./tenable_pull.js');

test('csv cells are quoted when needed, with a BOM, CRLF and the Studio headers', () => {
  assert.equal(TP.csvCell('plain'), 'plain');
  assert.equal(TP.csvCell('a,b'), '"a,b"');
  assert.equal(TP.csvCell('say "hi"\nnext'), '"say ""hi""\nnext"');
  const f = new TP.CsvFile('x.csv');
  f.add({ Plugin: '1', 'IP Address': '10.0.0.1', Severity: 'High', 'Plugin Text': 'line1\nline2' });
  const text = f.text();
  assert.ok(text.startsWith('﻿Plugin,Plugin Name,Family,Severity,IP Address'));
  assert.equal(text.split('\r\n').length, 3, 'header, one row, trailing CRLF; the newline inside the cell is quoted');
  assert.ok(text.includes('"line1\nline2"'));
  assert.deepEqual(f.summary().severity, { High: 1 });
  const back = TP.parseCsv(text);
  assert.equal(back.length, 1); assert.equal(back[0]['Plugin Text'], 'line1\nline2'); assert.equal(back[0].Severity, 'High');
});

test('dates: epoch seconds, milliseconds, none and already formatted', () => {
  const ts = Math.floor(Date.UTC(2026, 9, 25, 6, 12, 33) / 1000);
  assert.equal(TP.fmtDate(String(ts)), '2026-10-25T06:12:33Z');
  assert.equal(TP.fmtDate(ts * 1000), '2026-10-25T06:12:33Z');
  assert.equal(TP.fmtDate('-1'), ''); assert.equal(TP.fmtDate(''), ''); assert.equal(TP.fmtDate(null), '');
  assert.equal(TP.fmtDate('2026-10-25T06:12:33Z'), '2026-10-25T06:12:33Z');
});

test('a vulndetails record becomes an export row; compliance detection and the dedup key', () => {
  const rec = { pluginID: '208296', pluginName: 'KB5044281', family: { id: '1', name: 'Windows : Microsoft Bulletins', type: 'active' }, severity: { id: '4', name: 'Critical' }, ip: '10.70.10.11', port: '0', protocol: 'tcp', exploitAvailable: 'Yes', repository: { id: '2', name: 'Compliance Repository' }, firstSeen: '1700000000', lastSeen: '1700500000', solution: 'Apply Security Update 5044281', pluginText: 'missing update', vprScore: '9.2', cvssV3Vector: 'CVSS:3.0/AV:N' };
  const row = TP.recordToRow(rec);
  assert.equal(Object.keys(row).length, TP.HEADERS.length);
  assert.equal(row.Plugin, '208296'); assert.equal(row.Severity, 'Critical'); assert.equal(row['Exploit?'], 'Yes'); assert.equal(row.Protocol, 'TCP'); assert.equal(row.Port, '0');
  assert.equal(row['Steps to Remediate'], 'Apply Security Update 5044281'); assert.equal(row['First Discovered'], '2023-11-14T22:13:20Z'); assert.equal(row['VPR Score'], '9.2'); assert.equal(row['CVSS V3 Vector'], 'CVSS:3.0/AV:N');
  assert.equal(TP.isCompliance(rec), false);
  assert.equal(TP.isCompliance({ pluginID: '1000005', family: { type: 'compliance' } }), true);
  assert.equal(TP.isCompliance({ pluginID: '1000005', family: { type: 'active' } }), true);
  assert.equal(TP.dedupKey(rec), '208296|10.70.10.11|0|TCP|2|');
  const c1 = { pluginID: '21156', ip: '1.1.1.1', port: '0', protocol: 'tcp', family: { type: 'compliance' }, pluginName: 'check A', repository: { name: 'S' } };
  assert.notEqual(TP.dedupKey(c1), TP.dedupKey(Object.assign({}, c1, { pluginName: 'check B' })));
});

test('crc32 and the compliance plugin ids match the Python connector (zlib.crc32)', () => {
  assert.equal(TP.crc32('hello'), 0x3610a686);
  assert.equal(TP.crc32(''), 0);
  const id = TP.compliancePluginId("1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'", 'CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0_L1_MS.audit');
  assert.ok(id >= 1000000 && id < 100000000);
  assert.equal(id, TP.compliancePluginId("1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'", 'cis_microsoft_windows_server_2022_benchmark_v3.0.0_l1_ms.audit'), 'audit file name is case-insensitive');
});

test('scan selection and the first-seen index', () => {
  const now = 1800000000;
  const listing = { folders: [{ id: 3, name: 'My Scans' }], scans: [{ id: 1, name: 'Weekly', status: 'completed', folder_id: 3, last_modification_date: now - 86400 }, { id: 2, name: 'Old', status: 'completed', folder_id: 3, last_modification_date: now - 100 * 86400 }, { id: 3, name: 'Running', status: 'running', folder_id: 3, last_modification_date: now }] };
  assert.deepEqual(TP.selectScans(listing, [], '', 45, now).map(s => s.id), [1]);
  assert.deepEqual(TP.selectScans(listing, ['old'], '', 0, now).map(s => s.id), [2]);
  const idx = TP.firstSeenIndex([{ Plugin: '1', 'IP Address': '10.0.0.1', Port: '0', Protocol: 'tcp', 'First Discovered': '2026-01-01T00:00:00Z', 'Last Observed': '2026-02-01T00:00:00Z' }, { Plugin: '1', 'IP Address': '10.0.0.1', Port: '0', Protocol: 'TCP', 'First Discovered': '', 'Last Observed': '2025-12-01T00:00:00Z' }]);
  assert.equal(idx.get('1|10.0.0.1|0|TCP'), '2025-12-01T00:00:00Z');
});

test('the transport sends one request at a time, paces them, retries on 429 with Retry-After and gives up after the retries', async () => {
  const calls = []; let n = 0;
  globalThis.fetch = async (url, opts) => { calls.push({ url, t: Date.now(), inflight: ++n }); await new Promise(r => setTimeout(r, 20)); n--; const i = calls.length;
    if (i === 2) return new Response('slow down', { status: 429, headers: { 'Retry-After': '0' } });
    if (url.endsWith('/boom')) return new Response('down', { status: 503 });
    return new Response(JSON.stringify({ response: { ok: i } }), { status: 200, headers: { 'Content-Type': 'application/json' } }); };
  const t = new TP.Transport({ interval: 120, retries: 1 });
  const results = await Promise.all([t.request('http://x/a', {}, 'keys'), t.request('http://x/b', {}, 'keys'), t.request('http://x/c', {}, 'keys')]);
  assert.deepEqual(results.map(r => r.status), [200, 200, 200]);
  assert.equal(calls.length, 4, 'three requests plus one retry');
  assert.ok(calls.every(c => c.inflight === 1), 'never two in flight');
  for (let i = 1; i < calls.length; i++) assert.ok(calls[i].t - calls[i - 1].t >= 100, `request ${i} started ${calls[i].t - calls[i - 1].t} ms after the previous one`);
  assert.equal(t.stats.requests, 4); assert.equal(t.stats.retries, 1);
  const r = await t.request('http://x/boom', {}, 'keys');
  assert.equal(r.status, 503, 'after the retries the response is handed back');
  assert.equal(t.stats.retries, 2);
  assert.match(t.describe(), /requests, one at a time/);
});

test('fetchJson style errors: auth, format and the CORS explanation', async () => {
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
  const sc = new TP.SecurityCenter({ url: 'sc.example', accessKey: 'a', secretKey: 'b', transport: new TP.Transport({ interval: 0, retries: 0 }) });
  assert.equal(sc.base, 'https://sc.example/rest/');
  await assert.rejects(sc.system(), e => e.kind === 'network' && /Access-Control-Allow-Origin/.test(e.detail));
  globalThis.fetch = async () => new Response('{"error_code":2,"error_msg":"Invalid API key"}', { status: 403 });
  await assert.rejects(sc.system(), e => e.kind === 'auth' && /Allow API Keys/.test(e.detail));
  globalThis.fetch = async () => new Response('<html>login</html>', { status: 200, headers: { 'Content-Type': 'text/html' } });
  await assert.rejects(sc.system(), e => e.kind === 'format');
  assert.throws(() => new TP.SecurityCenter({ url: '', accessKey: 'a', secretKey: 'b' }), e => e.kind === 'config');
  assert.throws(() => new TP.SecurityCenter({ url: 'x', accessKey: '', secretKey: '' }), e => e.kind === 'config');
});

test('iterAnalysis pages, honours totalRecords and drops a filter the server rejects', async () => {
  const seen = [];
  globalThis.fetch = async (url, opts) => { const body = JSON.parse(opts.body); seen.push(body); const names = body.query.filters.map(f => f.filterName);
    if (names.includes('wasVuln')) return new Response(JSON.stringify({ error_code: 146, error_msg: "Invalid parameters specified for vuln query.  The filter 'wasVuln' is invalid (valid filters: severity)." }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    const start = body.query.startOffset, end = Math.min(body.query.endOffset, 7); const results = []; for (let i = start; i < end; i++) results.push({ pluginID: String(i) });
    return new Response(JSON.stringify({ response: { totalRecords: '7', returnedRecords: results.length, results } }), { status: 200, headers: { 'Content-Type': 'application/json' } }); };
  const sc = new TP.SecurityCenter({ url: 'https://sc', accessKey: 'a', secretKey: 'b', transport: new TP.Transport({ interval: 0, retries: 0 }) });
  const warnings = []; const pages = [];
  const recs = await sc.iterAnalysis({ filters: TP.vulnFilters({ severities: '4,3' }) }, 3, (n, total) => pages.push([n, total]), w => warnings.push(w));
  assert.equal(recs.length, 7); assert.deepEqual(pages, [[3, 7], [6, 7], [7, 7]]);
  assert.equal(warnings.length, 1); assert.match(warnings[0], /wasVuln/);
  assert.ok(seen.slice(1).every(b => !b.query.filters.some(f => f.filterName === 'wasVuln')));
  assert.equal(seen[0].sourceType, 'cumulative'); assert.equal(seen[1].query.tool, 'vulndetails');
});
