const LABELS = {
  safe: "✅ Safe",
  suspicious: "⚠️ Suspicious",
  dangerous: "🚫 Dangerous",
  error: "Cannot reach PhishGuard server",
};

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const key = "result_" + tab.id;
  const store = await chrome.storage.local.get([key, "history"]);
  const r = store[key];
  const box = document.getElementById("status");

  if (!r) {
    box.textContent = "No scan for this page yet. Open a website or refresh the page.";
  } else {
    box.className = "card " + r.verdict;
    box.textContent = "";

    const v = document.createElement("div");
    v.className = "verdict";
    v.textContent = LABELS[r.verdict] || r.verdict;

    const u = document.createElement("div");
    u.className = "url";
    u.textContent = r.url;

    box.append(v, u);

        if (r.verdict !== "error") {
      const pct = Math.round(r.risk_score * 100);
      const label = document.createElement("div");
      label.textContent = "Risk score: " + pct + "%";
      const meter = document.createElement("div");
      meter.className = "meter";
      const fill = document.createElement("div");
      fill.className = "fill " + r.verdict;
      fill.style.width = Math.max(pct, 3) + "%";
      meter.appendChild(fill);
      box.append(label, meter);
    }
    if (r.reasons && r.reasons.length) {
      const ul = document.createElement("ul");
      r.reasons.forEach((x) => {
        const li = document.createElement("li");
        li.textContent = x;
        ul.appendChild(li);
      });
      box.appendChild(ul);
    }
  }

  const list = document.getElementById("history");
  (store.history || []).forEach((h) => {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = "dot " + h.verdict;
    const t = document.createElement("span");
    t.className = "h-url";
    t.textContent = h.url;
    t.title = h.url;
    li.append(dot, t);
    list.appendChild(li);
  });
}

init();