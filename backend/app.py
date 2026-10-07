import os, json
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from features import extract_features, _extract, HOSTING_PLATFORMS

BASE = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE, "model_v2.pkl"))
columns = joblib.load(os.path.join(BASE, "feature_columns_v2.pkl"))

try:
    THRESHOLD = json.load(open(os.path.join(BASE, "threshold.json")))["threshold"]
except FileNotFoundError:
    THRESHOLD = 0.7          # fallback if you skipped saving a threshold

SUSPICIOUS_FROM = THRESHOLD - 0.2   # yellow zone starts here

# trusted sites are never flagged (matched on the REAL registered domain)
WHITELIST = {
    "google.com", "youtube.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "amazon.in", "wikipedia.org", "linkedin.com", "facebook.com",
    "instagram.com", "twitter.com", "x.com", "stackoverflow.com", "kaggle.com",
    "anthropic.com", "claude.ai", "kluniversity.in", "leetcode.com",
    "codechef.com", "netflix.com", "whatsapp.com", "zoom.us", "paypal.com",
}

try:
    with open(os.path.join(BASE, "top_domains.txt")) as f:
        WHITELIST |= {line.strip().lower() for line in f if line.strip()}
except FileNotFoundError:
    pass

WHITELIST -= HOSTING_PLATFORMS   # shared hosting must never be whitelisted

app = Flask(__name__)
CORS(app)


def get_reasons(f):
    """Human-readable explanations for why a URL looks risky."""
    reasons = []
    if f["has_ip"]:
        reasons.append("Uses an IP address instead of a domain name")
    if f["has_at"]:
        reasons.append("Contains '@' which can hide the real destination")
    if f["num_subdomains"] >= 3:
        reasons.append(f"Has {f['num_subdomains']} subdomains (often used to imitate brands)")
    if f["num_suspicious_words"] >= 2:
        reasons.append(f"Contains {f['num_suspicious_words']} bait words like login, verify or secure")
    if f["suspicious_tld"]:
        reasons.append("Uses a domain ending commonly abused by scammers")
    if f["is_shortener"]:
        reasons.append("Uses a URL shortener that hides the destination")
    if f["url_length"] > 75:
        reasons.append(f"Unusually long URL ({f['url_length']} characters)")
    if f["host_entropy"] > 3.8:
        reasons.append("Domain name looks random")
    if f["num_hyphens"] >= 3:
        reasons.append("Contains many hyphens")
    if f["brand_in_host_mismatch"]:
        reasons.append("Uses a famous brand name in a domain that doesn't belong to that brand")
    if f["on_hosting_platform"]:
        reasons.append("Hosted on a free website platform often abused for phishing")
    if f["has_uuid_or_hex"]:
        reasons.append("Contains a long random ID in the address")
    if f["brand_in_path_mismatch"]:
        reasons.append("Mentions a brand name in the path of an unrelated site")
    return reasons


@app.route("/health")
def health():
    return jsonify({"status": "ok", "threshold": THRESHOLD})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # skip browser-internal pages like chrome:// or about:blank
    if url.startswith(("chrome://", "chrome-extension://", "about:", "file://", "edge://")):
        return jsonify({"url": url, "verdict": "skipped", "risk_score": 0.0, "reasons": []})

    try:
        ext = _extract(url)
        registered = f"{ext.domain}.{ext.suffix}".lower()
        if registered in WHITELIST:
            return jsonify({"url": url, "verdict": "safe", "risk_score": 0.0,
                            "reasons": ["Trusted domain"], "whitelisted": True})

        feats = extract_features(url)
        X = pd.DataFrame([feats])[columns]          # same column order as training
        score = float(model.predict_proba(X)[0][1])

        # rule layer: a famous brand name + free hosting platform + bait word
        # is almost always phishing, so never leave it in the yellow zone
        rule_hit = (feats["brand_in_host_mismatch"] and feats["on_hosting_platform"]
                    and feats["num_suspicious_words"] >= 1)
        if rule_hit:
            score = max(score, THRESHOLD)

        if score >= THRESHOLD:
            verdict = "dangerous"
        elif score >= SUSPICIOUS_FROM:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return jsonify({
            "url": url,
            "verdict": verdict,
            "risk_score": round(score, 3),
            "reasons": get_reasons(feats) if verdict != "safe" else [],
            "whitelisted": False,
        })
    except Exception as e:
        return jsonify({"error": f"Could not analyze URL: {e}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)