const DEFAULT_API = "http://localhost:5000";

// Right-click context menu: scan any link or the current page
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "Scan link with Threat Intel",
    contexts: ["link"]
  });
  chrome.contextMenus.create({
    id: "scan-page",
    title: "Scan this page with Threat Intel",
    contexts: ["page"]
  });
});

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API).replace(/\/$/, "");
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === "scan-link" ? info.linkUrl : (tab && tab.url);
  if (!url || !/^https?:\/\//i.test(url)) return;

  try {
    const api = await getApiBase();
    const res = await fetch(`${api}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    const score = data.risk_score ?? 0;
    const level = score >= 70 ? "HIGH RISK" : score >= 40 ? "MEDIUM" : "LOW RISK";
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `${level} - score ${score}/100`,
      message: `${data.threat || "Unknown"}\n${url.slice(0, 80)}`
    });
  } catch (e) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Scan failed",
      message: "Could not reach the backend. Open the extension popup to set the backend URL."
    });
  }
});
