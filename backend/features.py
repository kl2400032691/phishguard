import re
import math
from urllib.parse import urlparse
import tldextract

# offline mode: uses the TLD list bundled with the package (fast, no internet)
_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank",
                    "signin", "confirm", "password", "webscr", "paypal", "ebay"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work"]


def _entropy(s):
    """How random a string looks (higher = more random)."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(url):
    url = str(url).strip()
    # add a scheme only so the parser works; we do NOT use it as a feature
    full = url if re.match(r"^[a-zA-Z]+://", url) else "http://" + url


    try:
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
    except ValueError:
        # malformed URLs (e.g. stray [ ] brackets) crash urlparse
        full = full.replace("[", "").replace("]", "")
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    ext = _extract(full)
    lower = url.lower()

    sub_labels = [l for l in ext.subdomain.split(".") if l and l != "www"]

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
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
        "domain_hyphens": ext.domain.count("-"),
        "host_entropy": _entropy(host),
        "path_depth": len([p for p in path.split("/") if p]),
        "num_suspicious_words": sum(w in lower for w in SUSPICIOUS_WORDS),
        "is_shortener": int(any(s in host for s in SHORTENERS)),
        "suspicious_tld": int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
    }