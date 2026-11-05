/* Tenable Pull page inside the add-on (the inline start-up script of the standalone page, moved
   to a file because the extension CSP forbids inline scripts). */
(function () {
  const style = document.createElement('style'); style.textContent = TenablePull.CSS; document.head.appendChild(style);
  document.getElementById('ver').textContent = 'version ' + TenablePull.VERSION + ' · add-on'; document.getElementById('ver2').textContent = TenablePull.VERSION;
  window.TP = TenablePull.mount(document.getElementById('app'), { mode: 'standalone', helpOpen: !TenablePull.loadSettings().url });
  document.documentElement.dataset.trsAddon = chrome.runtime.getManifest().version;
})();
