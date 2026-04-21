"""
Domain classification rules for Security X-Ray.
Maps registered domains to categories and known providers.
"""
from pathlib import Path
import json
import logging

logger = logging.getLogger("security_xray.classifier")

_CLASSIFICATION_PATH = Path(__file__).parent.parent / "data" / "domain_classifications.json"


def _load_known_domains() -> dict[str, dict]:
    """Load domain->classification mappings from data/domain_classifications.json."""
    try:
        raw = json.loads(_CLASSIFICATION_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("domain_classifications.json root must be an object")
        cleaned: dict[str, dict] = {}
        for domain, meta in raw.items():
            if not isinstance(meta, dict):
                continue
            category = meta.get("category")
            provider = meta.get("provider")
            if isinstance(domain, str) and isinstance(category, str):
                cleaned[domain.lower()] = {"category": category, "provider": provider}
        return cleaned
    except FileNotFoundError:
        logger.warning("Classification file not found at %s", _CLASSIFICATION_PATH)
        return {}
    except Exception as exc:
        logger.warning("Could not load classification file %s: %s", _CLASSIFICATION_PATH, exc)
        return {}


# Known third-party domain patterns loaded from data file.
KNOWN_DOMAINS: dict[str, dict] = _load_known_domains()
 
# Heuristic keyword patterns (fallback)
# If isn't in KNOWN_DOMAINS. Checked in order.
HEURISTIC_PATTERNS: list[dict] = [
    {"keywords": ["analytics", "tracking", "tracker", "telemetry", "metric", "stat", "insight", "beacon"],
     "category": "analytics",  "provider": None},
    {"keywords": ["ads", "adserver", "adtech", "advert", "ad-", "-ad.", "banner", "bidder", "dsp", "ssp", "rtb"],
     "category": "advertising", "provider": None},
    {"keywords": ["cdn", "cache", "edge", "delivery"],
     "category": "cdn",         "provider": None},
    {"keywords": ["social", "share", "like", "follow", "tweet", "facebook", "instagram", "linkedin", "tiktok"],
     "category": "social",      "provider": None},
    {"keywords": ["chat", "support", "helpdesk", "crm", "intercom", "zendesk", "livechat"],
     "category": "support",     "provider": None},
    {"keywords": ["captcha", "recaptcha", "hcaptcha", "sentry", "bugsnag", "error", "waf"],
     "category": "security",    "provider": None},
    {"keywords": ["cookie", "consent", "cmp", "gdpr", "privacy"],
     "category": "consent",     "provider": None},
    {"keywords": ["payment", "pay", "stripe", "checkout", "billing"],
     "category": "payments",    "provider": None},
    {"keywords": ["font", "typeface", "icon", "svg", "webfont"],
     "category": "fonts",       "provider": None},
    {"keywords": ["test", "experiment", "optimize", "variant", "abtesting", "split"],
     "category": "ab_testing",  "provider": None},
    {"keywords": ["tag", "tagmanager", "tms", "container", "ensighten"],
     "category": "tag_manager", "provider": None},
]
 
VALID_CATEGORIES = {
    "analytics", "advertising", "cdn", "social", "support",
    "ab_testing", "tag_manager", "security", "consent", "payments", "fonts", "unknown"
}
 
 
def classify_domain(registrable_domain: str) -> dict:
    """
    Return {"category": str, "provider": str | None} for a registrable domain.
    Checks the known-domain table first, then keyword heuristics.
    """
    d = registrable_domain.lower()
 
    # 1. Exact match in known table
    if d in KNOWN_DOMAINS:
        return KNOWN_DOMAINS[d]
 
    # 2. Suffix / subdomain match :  "cdn.segment.io" → "segment.io"
    for known, meta in KNOWN_DOMAINS.items():
        if d.endswith("." + known) or d == known:
            return meta
 
    # 3. Heuristic keyword scan
    for rule in HEURISTIC_PATTERNS:
        if any(kw in d for kw in rule["keywords"]):
            return {"category": rule["category"], "provider": rule["provider"]}
 
    return {"category": "unknown", "provider": None}