/* The Studio's Tenable button: pulls the exports straight from Security Center or Nessus with
   the TenablePull engine (API keys, paced requests) and loads them through addFiles(), exactly
   like dropped files.  Also receives files sent by Tenable_Pull.html ("Open the Studio and load
   these files").  Inert in the HTML report (report mode). */
(function () {
  'use strict';
  if (typeof TenablePull === 'undefined' || typeof addFiles !== 'function' || typeof state === 'undefined') return;
  function ready(fn) { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn(); }
  const style = document.createElement('style'); style.textContent = TenablePull.CSS + '\n.trs-tenable-hint{margin:10px 0 0;font-size:13px;color:var(--ink-2);display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:center}'; document.head.appendChild(style);

  /* files handed over by Tenable_Pull.html through window.opener */
  window.addEventListener('message', e => {
    if (!e.data || e.data.type !== 'trs-files' || state.reportMode) return;
    if (!window.opener || e.source !== window.opener) return;
    const files = (e.data.files || []).filter(f => f instanceof Blob).map(f => f instanceof File ? f : new File([f], f.name || 'export.csv', { type: 'text/csv' }));
    if (!files.length) return;
    addFiles(files);
    const p = e.data.pulled || {};
    showNotice(`Loaded ${files.length} files sent by Tenable Pull${p.summary ? ': ' + esc(p.summary) : ''}.`);
  });

  ready(() => {
    if (state.reportMode) return;
    if (window.opener) { try { window.opener.postMessage({ type: 'trs-ready', studio: STUDIO_VERSION }, '*'); } catch (e) {} }
    const btn = document.createElement('button'); btn.className = 'btn ghost'; btn.id = 'btnTenable'; btn.type = 'button'; btn.textContent = 'Tenable';
    btn.title = 'Pull the exports straight from Tenable Security Center or Nessus (API keys, one paced request at a time) and load them';
    const anchor = $('#btnAddFiles'); if (anchor) anchor.after(btn); else $('.actions').prepend(btn);
    btn.onclick = openTenable;
    const how = $('#emptyState .how');
    if (how) { const p = document.createElement('p'); p.className = 'trs-tenable-hint'; p.innerHTML = '<span>Or pull the exports directly from Tenable:</span><button class="btn primary" type="button" id="btnTenableEmpty">Load from Tenable</button>'; how.before(p); $('#btnTenableEmpty').onclick = openTenable; }
  });

  function openTenable() {
    const host = $('#modalHost'); host.hidden = false;
    host.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="Load from Tenable"><div class="box" style="width:min(1000px,100%)">
      <h2>Load from Tenable</h2>
      <p class="small muted" style="margin-bottom:10px">The exports are pulled by this page from Security Center (REST API) or Nessus with the service account's API keys, in the layout of the Security Center export, and loaded exactly like dropped files. One request at a time, paced (see Pull options). Nothing is sent anywhere but the endpoint.</p>
      <div id="tenablePanel"></div></div></div>`;
    const close = () => { host.hidden = true; host.innerHTML = ''; };
    host.querySelector('.modal').addEventListener('click', e => { if (e.target.classList.contains('modal') && !host.dataset.busy) close(); });
    TenablePull.mount($('#tenablePanel'), {
      mode: 'studio', onClose: close, helpOpen: !(TenablePull.loadSettings().url),   // the explanation stays open until an endpoint has been saved once
      onFiles: async (files, result) => {
        host.dataset.busy = '1';
        try { await addFiles(files); close(); showNotice(`Loaded from ${result.source.type === 'sc' ? 'Tenable Security Center' : 'Nessus'} ${esc(result.source.version || '')}: ${files.map(f => esc(f.name)).join(', ')} (${esc(result.summary)}; ${esc(result.transport || '')}).`); }
        finally { host.dataset.busy = ''; }
      },
    });
  }
  window.TRS_TENABLE = { open: openTenable };
})();
