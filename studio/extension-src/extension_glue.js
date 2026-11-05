/* Studio page inside the add-on.  The extension CSP forbids inline scripts, so the build split the
   Studio's scripts into files; the Studio, however, builds its HTML report and its archive copy
   from its own source (SELF_SOURCE = the page's outerHTML), which would then reference those
   files.  The single-file Studio ships inside the add-on as studio.single.html and replaces
   SELF_SOURCE once the page has started, so the HTML report stays a self-contained file that
   works from any folder, exactly as before. */
(function () {
  'use strict';
  const single = fetch(chrome.runtime.getURL('studio.single.html')).then(r => r.text());
  const apply = () => single.then(text => { SELF_SOURCE = text; }).catch(e => console.warn('single-file Studio not available for the HTML report', e));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', apply); else apply();
  document.documentElement.dataset.trsAddon = chrome.runtime.getManifest().version;
})();
