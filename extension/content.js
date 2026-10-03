chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "PHISHGUARD_ALERT") return;
  if (document.getElementById("phishguard-root")) return;

  const { verdict, risk_score, reasons } = msg.data;
  const pct = Math.round(risk_score * 100);
  const danger = verdict === "dangerous";

  const host = document.createElement("div");
  host.id = "phishguard-root";
  const root = host.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = `
    * { box-sizing: border-box; font-family: Segoe UI, Arial, sans-serif; }
    .overlay { position: fixed; inset: 0; z-index: 2147483647; background: #7a0f0a;
      color: #fff; display: flex; align-items: center; justify-content: center; }
    .card { max-width: 560px; padding: 32px; }
    h1 { margin: 0 0 8px; font-size: 32px; }
    .score { font-size: 18px; opacity: .9; margin-bottom: 16px; }
    ul { padding-left: 20px; line-height: 1.7; }
    .btns { margin-top: 24px; display: flex; gap: 12px; }
    button { padding: 12px 20px; border-radius: 8px; border: 0; font-size: 15px; cursor: pointer; }
    .safe { background: #fff; color: #7a0f0a; font-weight: 600; }
    .proceed { background: transparent; color: #fff; border: 1px solid #fff; }
    .banner { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: #e0a100; color: #1a1a1a; padding: 10px 16px; display: flex;
      align-items: center; justify-content: space-between; font-size: 14px; }
    .banner button { background: #1a1a1a; color: #fff; padding: 6px 14px; }
  `;
  root.appendChild(style);

  const wrap = document.createElement("div");

  if (danger) {
    wrap.className = "overlay";
    wrap.innerHTML = `
      <div class="card">
        <h1>⚠ Deceptive site ahead</h1>
        <div class="score"></div>
        <p>PhishGuard thinks this page may be trying to steal your passwords or personal information.</p>
        <ul></ul>
        <div class="btns">
          <button class="safe">Go back to safety</button>
          <button class="proceed">Proceed anyway</button>
        </div>
      </div>`;
    wrap.querySelector(".score").textContent = `Risk score: ${pct}%`;
    const ul = wrap.querySelector("ul");
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      ul.appendChild(li);
    });
    wrap.querySelector(".safe").onclick = () => {
      if (history.length > 1) history.back();
      else window.location.href = "https://www.google.com";
    };
    wrap.querySelector(".proceed").onclick = () => host.remove();
  } else {
    wrap.className = "banner";
    const text = document.createElement("span");
    text.textContent = `⚠ PhishGuard: this site looks suspicious (risk ${pct}%). ` + reasons.slice(0, 2).join(" · ");
    const btn = document.createElement("button");
    btn.textContent = "Dismiss";
    btn.onclick = () => host.remove();
    wrap.append(text, btn);
  }

  root.appendChild(wrap);
  document.documentElement.appendChild(host);
});