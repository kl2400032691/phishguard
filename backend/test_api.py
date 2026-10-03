import requests

tests = [
    ("https://www.google.com", "safe"),
    ("https://github.com/anthropics", "safe"),
    ("http://paypal.com.secure-login.verify-account.xyz/webscr?cmd=login", "dangerous"),
    ("http://192.168.1.1/login/verify/account", None),
    ("http://secure-update-bankofamerica.verify-login.tk/signin?id=8f3a9c", None),
    ("chrome://extensions", "skipped"),
]

for url, expected in tests:
    r = requests.post("http://127.0.0.1:5000/predict", json={"url": url}).json()
    ok = "" if expected is None else ("PASS" if r["verdict"] == expected else "FAIL")
    print(f"{ok:4} {r['verdict']:10} score={r['risk_score']:<6} {url[:60]}")
    for reason in r.get("reasons", []):
        print("       -", reason)