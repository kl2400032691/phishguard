import re
import math
from urllib.parse import urlparse
import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank",
                    "signin", "confirm", "password", "webscr", "security", "wallet"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd",
              "1url.at", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"]
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work",
                   "sbs", "cfd", "icu", "buzz", "cyou", "rest", "monster", "quest"]
BRANDS = ["facebook", "instagram", "whatsapp", "google", "gmail", "paypal",
          "amazon", "microsoft", "icloud", "netflix", "roblox", "linkedin",
          "twitter", "telegram", "binance", "coinbase", "metamask", "paytm",
          "hdfc", "icici", "spotify", "steam", "discord", "dropbox", "adobe",
          "outlook", "ebay", "wellsfargo", "bankofamerica"]
HOSTING_PLATFORMS = {
    "blogspot.com", "pages.dev", "weebly.com", "wixsite.com", "github.io",
    "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "glitch.me",
    "workers.dev", "herokuapp.com", "godaddysites.com", "000webhostapp.com",
    "webflow.io", "wordpress.com", "carrd.co", "square.site", "framer.app",
    "sites.google.com", "r2.dev", "repl.co", "onrender.com",
}


def _entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(url):
    # remove the scheme so http:// vs https:// never affects the counts
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(url).strip())
    full = "http://" + url

    try:
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
    except ValueError:
        full = full.replace("[", "").replace("]", "")
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()

    path = (parsed.path or "").lower()
    query = parsed.query or ""
    ext = _extract(full)
    lower = url.lower()
    registered = f"{ext.domain}.{ext.suffix}".lower()
    sub_labels = [l for l in ext.subdomain.split(".") if l and l != "www"]
    domain = ext.domain.lower()

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "has_at": int("@" in url),
        "num_digits": sum(c.isdigit() for c in url),
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "num_subdomains": len(sub_labels),
        "domain_hyphens": domain.count("-"),
        "host_entropy": _entropy(host),
        "path_depth": len([p for p in path.split("/") if p]),
        "num_suspicious_words": sum(w in lower for w in SUSPICIOUS_WORDS),
        "is_shortener": int(any(s in host for s in SHORTENERS)),
        "suspicious_tld": int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        # new features
        "on_hosting_platform": int(registered in HOSTING_PLATFORMS),
        "brand_in_host_mismatch": int(any(b in host and domain != b for b in BRANDS)),
        "brand_in_path_mismatch": int(any(b in path and domain != b for b in BRANDS)),
        "has_uuid_or_hex": int(bool(re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}|[0-9a-f]{20,}", lower))),
    }