const open = page => chrome.tabs.create({ url: chrome.runtime.getURL(page) });
document.getElementById('openStudio').onclick = () => open('ALTANFEETHI_Tenable_Report_Studio.html');
document.getElementById('openPull').onclick = () => open('Tenable_Pull.html');
