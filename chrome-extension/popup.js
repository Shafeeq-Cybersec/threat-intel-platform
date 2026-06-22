const DEFAULT_API = "http://localhost:5000";

function bandColor(score) {
  return score >= 70 ? "#F87171" : score >= 40 ? "#FBBF24" : "#34D399";
}
function bandText(score) {
  return score >= 70 ? "HIGH RISK" : score >= 40 ? "MEDIUM" : "LOW RISK";
}
function rgba(score) {
  return score >= 70 ? "rgba(248,113,113,0.14)"
       : score >= 40 ? "rgba(251,191,36,0.14)" : "rgba(52,211,153,0.14)";
}

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API).replace(/\/$/, "");
}

let currentUrl = "";

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab?.url || "";
  document.getElementById("urlBox").textContent = currentUrl || "(no URL)";

  const api = await getApiBase();
  document.getElementById("apiBase").value = api;

  // A pending scan from the right-click context menu
  const { pendingScan } = await chrome.storage.local.get("pendingScan");
  if (pendingScan) {
    currentUrl = pendingScan;
    document.getElementById("urlBox").textContent = pendingScan;
    chrome.storage.local.remove("pendingScan");
    scan();
  }
}

async function scan() {
  if (!currentUrl || !/^https?:\/\//i.test(currentUrl)) {
    showErr("This page can't be scanned (not an http/https URL).");
    return;
  }
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  document.getElementById("err").style.display = "none";
  document.getElementById("result").style.display = "none";
  document.getElementById("spinner").style.display = "flex";

  try {
    const api = await getApiBase();
    const res = await fetch(`${api}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });
    const data = await res.json();
    if (data.error) { showErr(data.error); return; }
    render(data);
  } catch (e) {
    showErr("Could not reach the backend. Check the URL in Backend settings, and make sure the server is running.");
  } finally {
    btn.disabled = false;
    document.getElementById("spinner").style.display = "none";
  }
}

function render(data) {
  const score = data.risk_score ?? 0;
  const c = bandColor(score);
  const sources = (data.sources || []).map(s => `<span class="chip">${s}</span>`).join("")
                  || '<span class="chip">no sources</span>';
  document.getElementById("result").innerHTML = `
    <div class="verdict-card">
      <div class="score-row">
        <div>
          <div class="score" style="color:${c}">${score}</div>
          <div class="score-cap">risk / 100</div>
        </div>
        <span class="pill" style="color:${c};background:${rgba(score)}">${bandText(score)}</span>
        <span class="pill" style="color:var(--muted);background:var(--elevated)">${data.threat || "Unknown"}</span>
      </div>
      ${data.reasoning ? `<div class="meta">${data.reasoning}</div>` : ""}
      <div class="chips">${sources}</div>
      ${data.cached ? '<div class="meta">Served from cache.</div>' : ""}
    </div>`;
  document.getElementById("result").style.display = "block";
}

function showErr(msg) {
  const el = document.getElementById("err");
  el.textContent = msg;
  el.style.display = "block";
}

document.getElementById("scanBtn").addEventListener("click", scan);
document.getElementById("saveBtn").addEventListener("click", async () => {
  const v = document.getElementById("apiBase").value.trim();
  await chrome.storage.local.set({ apiBase: v || DEFAULT_API });
  const btn = document.getElementById("saveBtn");
  btn.textContent = "Saved";
  setTimeout(() => (btn.textContent = "Save"), 1200);
});

init();
