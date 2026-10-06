from __future__ import annotations

import math
import re
import tldextract
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_TOKENS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "passwd",
    "confirm",
    "billing",
    "invoice",
    "suspend",
    "locked",
    "unlock",
    "wallet",
    "bank",
    "alert",
    "expire",
    "reset",
    "wp-admin",
    "paypal",
    "appleid",
    "microsoft",
    "office365",
    "google",
    "amazon",
    "netflix",
    "facebook",
    "dropbox",
    "wellsfargo",
)

BRANDS = ("paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "dropbox")

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "digit_ratio",
    "subdomain_count",
    "is_ip",
    "is_https",
    "query_param_count",
    "has_punycode",
    "suspicious_token_count",
    "hostname_entropy",
    "brand_in_subdomain",
    "shortener_like",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip(hostname: str) -> int:
    return int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname)))


def extract_features(url: str) -> dict[str, float]:
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = raw.lower()

    extracted = tldextract.extract(hostname)
    registrable = extracted.top_domain_under_public_suffix
    subdomain = extracted.subdomain
    subdomain_count = float(len([part for part in subdomain.split(".") if part]))

    brand_in_subdomain = 0
    for brand in BRANDS:
        if brand in hostname and brand not in registrable:
            brand_in_subdomain = 1
            break

    return {
        "url_length": float(len(raw)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "dot_count": float(full.count(".")),
        "hyphen_count": float(full.count("-")),
        "at_count": float(full.count("@")),
        "digit_ratio": float(sum(ch.isdigit() for ch in raw) / max(len(raw), 1)),
        "subdomain_count": float(subdomain_count),
        "is_ip": float(_is_ip(hostname)),
        "is_https": float(parsed.scheme == "https"),
        "query_param_count": float(query.count("=")),
        "has_punycode": float("xn--" in hostname),
        "suspicious_token_count": float(sum(token in full for token in SUSPICIOUS_TOKENS)),
        "hostname_entropy": _entropy(hostname),
        "brand_in_subdomain": float(brand_in_subdomain),
        "shortener_like": float(hostname in {"bit.ly", "tinyurl.com", "t.co", "goo.gl"}),
    }


def to_row(url: str) -> list[float]:
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]
