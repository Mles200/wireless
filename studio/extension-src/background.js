/* Tenable Report Studio add-on: the service worker only opens the Studio once after the install.
   The pages themselves (the Studio and Tenable Pull) do all the work; as extension pages they may
   call the hosts listed under host_permissions without the CORS restriction that blocks a page
   opened from a folder. */
chrome.runtime.onInstalled.addListener(details => {
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('ALTANFEETHI_Tenable_Report_Studio.html') });
});
