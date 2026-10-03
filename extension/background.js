const API = "http://127.0.0.1:5000/predict";
const COLORS = { safe: "#2e9e5b", suspicious: "#e0a100", dangerous: "#d93025" };
const BADGE = { safe: "OK", suspicious: "!", dangerous: "X" };

async function saveHistory(data) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift({
    url: data.url,
    verdict: data.verdict,
    score: data.risk_score,
    time: Date.now(),
  });
  await chrome.storage.local.set({ history: history.slice(0, 20) });
}

async function analyze(tabId, url) {
  if (!url || !/^https?:/.test(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    await chrome.storage.local.set({ ["result_" + tabId]: data });
    chrome.action.setBadgeText({ tabId, text: BADGE[data.verdict] || "" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[data.verdict] || "#888" });
    await saveHistory(data);

    if (data.verdict === "suspicious" || data.verdict === "dangerous") {
      chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_ALERT", data }).catch(() => {});
    }
  } catch (e) {
    // API offline or unreachable
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#888888" });
    await chrome.storage.local.set({
      ["result_" + tabId]: { url, verdict: "error", risk_score: 0, reasons: [String(e.message || e)] },
    });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") analyze(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove("result_" + tabId);
});