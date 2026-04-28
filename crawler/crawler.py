"""
Core Crawler
Fetches pages, extracts script/iframe/link resources, classifies third-party origins
"""
 
from __future__ import annotations
 
import json
import logging
import re
import time
from pathlib import Path
import urllib.robotparser
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse
 
import requests
import tldextract
from bs4 import BeautifulSoup
 
from .classifiers import classify_domain
 
logger = logging.getLogger("security_xray.crawler")

#Aliases

_ALIASES_PATH = Path(__file__).parent.parent / "data" / "aliases.json"
 
def _load_aliases() -> dict[str, str]:
    try:
        with open(_ALIASES_PATH) as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except FileNotFoundError:
        logger.warning("aliases.json not found at %s — no alias resolution will occur", _ALIASES_PATH)
        return {}
    except Exception as e:
        logger.warning("Could not load aliases.json: %s", e)
        return {}
 
DOMAIN_ALIASES: dict[str, str] = _load_aliases()

# Constants
 
DEFAULT_TIMEOUT = 15 # seconds per request
DEFAULT_RATE_LIMIT = 1.2 # seconds between requests to the same host
MAX_RESPONSE_SIZE = 5_000_000 # 5 MB skip unusually large pages
USER_AGENT = (
    "SecurityXRayCrawler/1.0 "
    "(academic security research; "
    "https://github.com/a-man23/Security-X-Ray; "
    "+dmh313@scarletmail.rutgers.edu)"
)
 
RESOURCE_TAGS = {
    # tag: list of attributes that hold a URL
    "script":   ["src"],
    "iframe":   ["src"],
    "img":      ["src", "data-src"],
    "link":     ["href"],   # rel=stylesheet, preload, etc.
    "source":   ["src"],
}
 
 
# Helpers

def registrable_domain(url: str) -> str:
    """Return the registrable domain (eTLD+1) for a URL: 'sub.example.co.uk' → 'example.co.uk'."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return ext.domain.lower() or urlparse(url).netloc.lower()
 
 
def normalize_url(base: str, raw: str) -> Optional[str]:
    """Resolve a possibly-relative URL against a base page URL. Returns None for non-HTTP(S)."""
    try:
        joined = urljoin(base, raw.strip())
        parsed = urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        # Drop fragments
        return parsed._replace(fragment="").geturl()
    except Exception:
        return None
 
 
def is_internal_link(page_url: str, link_url: str, site_domain: str) -> bool:
    """True if link_url belongs to the same registrable domain as the target site."""
    return registrable_domain(link_url) == site_domain
 
 
# Robots.txt
 
class RobotsCache:
    def __init__(self, session: requests.Session, timeout: int = DEFAULT_TIMEOUT):
        self._cache: dict[str, urllib.robotparser.RobotFileParser] = {}
        self._session = session
        self._timeout = timeout
 
    def _fetch_robots(self, base_url: str) -> urllib.robotparser.RobotFileParser:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        deny_all = urllib.robotparser.RobotFileParser()
        deny_all.parse(["User-agent: *", "Disallow: /"])
        try:
            resp = self._session.get(robots_url, timeout=self._timeout, allow_redirects=True)
            status = resp.status_code

            # Follow Google guidance: treat most 4xx as "no robots restrictions".
            if 200 <= status < 300:
                rp.parse(resp.text.splitlines())
                logger.debug("Loaded robots.txt from %s", robots_url)
                return rp
            if 300 <= status < 400:
                # requests follows redirects, but keep a defensive fallback.
                logger.warning("Unexpected robots redirect response for %s (%s)", robots_url, status)
                return deny_all
            if status == 429 or 500 <= status < 600:
                # Service unavailable / rate limited: fail closed to avoid violating robots intent.
                logger.warning("robots.txt unavailable for %s (%s), denying crawl", robots_url, status)
                return deny_all
            if 400 <= status < 500:
                logger.debug("No robots.txt restrictions for %s (status %s)", robots_url, status)
                return rp
            logger.warning("Unhandled robots.txt status for %s (%s), denying crawl", robots_url, status)
            return deny_all
        except Exception as e:
            logger.warning("Could not fetch robots.txt for %s: %s", base_url, e)
            return deny_all
 
    def allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        key = f"{parsed.scheme}://{parsed.netloc}"
        if key not in self._cache:
            self._cache[key] = self._fetch_robots(url)
        return self._cache[key].can_fetch(USER_AGENT, url)
 
 
# Resource extractor 
 
def extract_resources(page_url: str, html: str) -> list[dict]:
    """
    Parse HTML and return a list of resource dicts found on the page.
    Each dict has: {url, tag, attribute, raw_src}
    """
    soup = BeautifulSoup(html, "html.parser")
    resources: list[dict] = []
    seen: set[str] = set()
 
    for tag_name, attrs in RESOURCE_TAGS.items():
        for element in soup.find_all(tag_name):
            for attr in attrs:
                raw = element.get(attr)
                if not raw or raw.startswith("data:"):
                    continue
                resolved = normalize_url(page_url, raw)
                if not resolved or resolved in seen:
                    continue
                seen.add(resolved)
                resources.append({
                    "url": resolved,
                    "tag": tag_name,
                    "attribute": attr,
                    "raw_src": raw,
                })
 
    return resources
 
 
def extract_internal_links(page_url: str, html: str, site_domain: str) -> list[str]:
    """Extract <a href> links that stay within the same site."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    seen: set[str] = set()
 
    for a in soup.find_all("a", href=True):
        resolved = normalize_url(page_url, a["href"])
        if not resolved or resolved in seen:
            continue
        if is_internal_link(page_url, resolved, site_domain):
            seen.add(resolved)
            links.append(resolved)
 
    return links
 
 
# Per-domain rate limit
 
class RateLimiter:
    def __init__(self, delay: float = DEFAULT_RATE_LIMIT):
        self._last_request: dict[str, float] = defaultdict(float)
        self._delay = delay
 
    def wait(self, host: str):
        elapsed = time.monotonic() - self._last_request[host]
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request[host] = time.monotonic()
 
 
# Main crawler 
 
class SiteCrawler:
    """
    Crawls a single site up to `max_depth` link levels, extracts all external
    resources, classifies them, and returns a structured result dict.
    """
 
    def __init__(
        self,
        rate_limiter: RateLimiter,
        robots_cache: RobotsCache,
        timeout: int = DEFAULT_TIMEOUT,
        max_pages_per_site: int = 20,
        max_internal_links_per_page: int = 30,
    ):
        self._rl = rate_limiter
        self._robots = robots_cache
        self._timeout = timeout
        self._max_pages = max_pages_per_site
        self._max_internal_links_per_page = max_internal_links_per_page
 
    def crawl(self, start_url: str, max_depth: int) -> dict:
        """
        Crawl start_url to max_depth and return a full site report dict.
        """
        site_domain = registrable_domain(start_url)
        crawled_at = datetime.now(timezone.utc).isoformat()
 
        pages: list[dict] = []
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]  # (url, depth)
        queued: set[str] = {start_url}
 
        # Aggregated across all pages
        resource_index: dict[str, dict] = {}  # resource_url → aggregated info
 
        while queue and len(visited) < self._max_pages:
            url, depth = queue.pop(0)
            queued.discard(url)
            if url in visited:
                continue
 
            host = urlparse(url).netloc
            self._rl.wait(host)
 
            if not self._robots.allowed(url):
                logger.info("Blocked by robots.txt: %s", url)
                visited.add(url)
                pages.append({
                    "url": url,
                    "depth": depth,
                    "status": "blocked_by_robots",
                    "resources": [],
                    "internal_links_found": [],
                })
                continue
 
            page_result = self._fetch_page(url, depth, site_domain)
            visited.add(url)
            pages.append(page_result)
 
            # Queue internal links if we haven't hit max depth
            if depth < max_depth:
                links = page_result.get("internal_links_found", [])
                for link in links[: self._max_internal_links_per_page]:
                    if link not in visited and link not in queued:
                        queue.append((link, depth + 1))
                        queued.add(link)
 
            # Merge resources into index
            for res in page_result.get("resources", []):
                rurl = res["url"]
                if rurl not in resource_index:
                    resource_index[rurl] = {
                        **res,
                        "seen_on_pages": [url],
                    }
                else:
                    if url not in resource_index[rurl]["seen_on_pages"]:
                        resource_index[rurl]["seen_on_pages"].append(url)
 
        resources_list = list(resource_index.values())
 
        # Build summary
        summary = self._build_summary(site_domain, resources_list)
 
        return {
            "crawl_metadata": {
                "target_url": start_url,
                "site_domain": site_domain,
                "crawled_at": crawled_at,
                "max_depth": max_depth,
                "max_internal_links_per_page": self._max_internal_links_per_page,
                "pages_crawled": len(visited),
                "pages_blocked_by_robots": sum(
                    1 for p in pages if p.get("status") == "blocked_by_robots"
                ),
            },
            "summary": summary,
            "resources": resources_list,
            "pages": pages,
        }
 
    def _fetch_page(self, url: str, depth: int, site_domain: str) -> dict:
        """Fetch a single page and return a page-level result dict."""
        try:
            session = requests.Session()
            session.headers["User-Agent"] = USER_AGENT
            resp = self._get_with_checked_redirects(session, url)
            if resp is None:
                return {
                    "url": url,
                    "depth": depth,
                    "status": "blocked_by_robots",
                    "resources": [],
                    "internal_links_found": [],
                }
            # Guard against huge pages
            content = b""
            for chunk in resp.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > MAX_RESPONSE_SIZE:
                    logger.warning("Page too large, truncating: %s", url)
                    break
 
            resp_url = resp.url  # after redirects
            html = content.decode("utf-8", errors="replace")
            content_type = resp.headers.get("content-type", "")
 
            if "html" not in content_type.lower():
                return {
                    "url": url,
                    "final_url": resp_url,
                    "depth": depth,
                    "status": "non_html",
                    "http_status": resp.status_code,
                    "resources": [],
                    "internal_links_found": [],
                }
 
            raw_resources = extract_resources(resp_url, html)
            classified = [self._classify_resource(r, site_domain) for r in raw_resources]
            internal_links = extract_internal_links(resp_url, html, site_domain)
 
            # Collect response security headers
            security_headers = self._extract_security_headers(resp.headers)
 
            return {
                "url": url,
                "final_url": resp_url,
                "depth": depth,
                "status": "ok",
                "http_status": resp.status_code,
                "security_headers": security_headers,
                "resources": classified,
                "internal_links_found": internal_links,
            }
 
        except requests.exceptions.Timeout:
            logger.warning("Timeout: %s", url)
            return {"url": url, "depth": depth, "status": "timeout", "resources": [], "internal_links_found": []}
        except requests.exceptions.TooManyRedirects:
            logger.warning("Too many redirects: %s", url)
            return {"url": url, "depth": depth, "status": "too_many_redirects", "resources": [], "internal_links_found": []}
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error for %s: %s", url, e)
            return {"url": url, "depth": depth, "status": "connection_error", "error": str(e), "resources": [], "internal_links_found": []}
        except Exception as e:
            logger.error("Unexpected error for %s: %s", url, e, exc_info=True)
            return {"url": url, "depth": depth, "status": "error", "error": str(e), "resources": [], "internal_links_found": []}

    def _get_with_checked_redirects(self, session: requests.Session, url: str, max_redirects: int = 5) -> Optional[requests.Response]:
        """
        Fetch URL with manual redirect handling so every hop is checked against robots.txt.
        Returns None when robots policy blocks any URL in the chain.
        """
        current_url = url
        redirect_hops = 0

        while True:
            if not self._robots.allowed(current_url):
                logger.info("Blocked by robots.txt: %s", current_url)
                return None

            host = urlparse(current_url).netloc
            self._rl.wait(host)
            resp = session.get(
                current_url,
                timeout=self._timeout,
                allow_redirects=False,
                stream=True,
            )

            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("location")
                if not location:
                    return resp
                redirect_hops += 1
                if redirect_hops > max_redirects:
                    raise requests.exceptions.TooManyRedirects(f"Exceeded {max_redirects} redirects for {url}")
                current_url = urljoin(current_url, location)
                continue

            return resp
 
    def _classify_resource(self, resource: dict, site_domain: str) -> dict:
        """party classification and category."""
        res_domain = registrable_domain(resource["url"])
        is_first_party = (res_domain == site_domain)
       
        # Check if this domain is a known alias for the target site
        alias_parent = DOMAIN_ALIASES.get(res_domain)
        is_owned_cdn = (alias_parent == site_domain)
        is_first_party = (res_domain == site_domain) or is_owned_cdn

        if is_first_party:
            party = "first-party"
            category = "first-party"
            provider = None
        else:
            party = "third-party"
            classification = classify_domain(res_domain)
            category = classification["category"]
            provider = classification["provider"]
 
        result = {
            **resource,
            "registrable_domain": res_domain,
            "party": party,
            "category": category,
            "provider": provider,
        }
 
        # Only add the field when relevant — keeps JSON clean
        if is_owned_cdn:
            result["owned_cdn"] = res_domain
 
        return result
 
    def _extract_security_headers(self, headers) -> dict:
        """Extract relevant security-related response headers."""
        relevant = [
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "permissions-policy",
            "referrer-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ]
        return {h: headers.get(h) for h in relevant if headers.get(h)}
 
    def _build_summary(self, site_domain: str, resources: list[dict]) -> dict:
        """Compute aggregate statistics from the full resource list."""
        third_party = [r for r in resources if r["party"] == "third-party"]
        first_party = [r for r in resources if r["party"] == "first-party"]
 
        # Count by category
        by_category: dict[str, int] = defaultdict(int)
        for r in third_party:
            by_category[r["category"]] += 1
 
        # Count by provider
        by_provider: dict[str, int] = defaultdict(int)
        for r in third_party:
            if r["provider"]:
                by_provider[r["provider"]] += 1
 
        # Unique third-party domains
        third_party_domains = sorted({r["registrable_domain"] for r in third_party})
 
        # Scripts specifically (highest privilege)
        third_party_scripts = [r for r in third_party if r["tag"] == "script"]
        domain_risk_scores = self._compute_domain_risk_scores(third_party)
        risk_indicators = self._risk_indicators(resources)
        risk_score = self._compute_risk_score(
            third_party=third_party,
            third_party_scripts=third_party_scripts,
            by_category=by_category,
            risk_indicators=risk_indicators,
        )
 
        return {
            "total_resources": len(resources),
            "first_party_count": len(first_party),
            "third_party_count": len(third_party),
            "third_party_script_count": len(third_party_scripts),
            "unique_third_party_domains": len(third_party_domains),
            "third_party_domains": third_party_domains,
            "by_category": dict(by_category),
            "by_provider": dict(sorted(by_provider.items(), key=lambda x: -x[1])),
            "domain_risk_scores": domain_risk_scores,
            "risk_indicators": risk_indicators,
            "risk_score": risk_score,
        }

    def _risk_tier(self, score: int) -> str:
        """Map numeric risk score to a human-readable tier."""
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    def _compute_risk_score(
        self,
        third_party: list[dict],
        third_party_scripts: list[dict],
        by_category: dict[str, int],
        risk_indicators: list[dict],
    ) -> dict:
        """
        Compute a deterministic risk score from crawl evidence.
        Score is 0-100 and intended as a prioritization signal, not a verdict.
        """
        components: list[dict] = []
        indicator_codes = {f.get("code") for f in risk_indicators}
        unique_third_party_domains = len({r["registrable_domain"] for r in third_party if r.get("registrable_domain")})
        unknown_scripts = [r for r in third_party_scripts if r.get("category") == "unknown"]
        advertising_scripts = [r for r in third_party_scripts if r.get("category") == "advertising"]

        def add_component(code: str, points: int, evidence: str):
            if points <= 0:
                return
            components.append({"code": code, "points": points, "evidence": evidence})

        # Script volume is the main attack-surface factor.
        script_count = len(third_party_scripts)
        if script_count > 20:
            add_component("THIRD_PARTY_SCRIPT_VOLUME", 30, f"{script_count} third-party scripts")
        elif script_count > 10:
            add_component("THIRD_PARTY_SCRIPT_VOLUME", 20, f"{script_count} third-party scripts")
        elif script_count > 5:
            add_component("THIRD_PARTY_SCRIPT_VOLUME", 10, f"{script_count} third-party scripts")

        # Unknown scripts represent classification blind spots.
        if unknown_scripts:
            add_component(
                "UNKNOWN_SCRIPT_PRESENCE",
                min(20, len(unknown_scripts) * 3),
                f"{len(unknown_scripts)} unknown third-party scripts",
            )

        # Advertising/tracking scripts can be high-risk in data-sensitive contexts.
        if advertising_scripts:
            add_component(
                "AD_TRACKING_SCRIPT_PRESENCE",
                min(16, len(advertising_scripts) * 2),
                f"{len(advertising_scripts)} advertising/tracking scripts",
            )

        # Broad third-party domain footprint generally increases supply-chain risk.
        if unique_third_party_domains > 25:
            add_component("DOMAIN_FOOTPRINT_SIZE", 15, f"{unique_third_party_domains} unique third-party domains")
        elif unique_third_party_domains > 15:
            add_component("DOMAIN_FOOTPRINT_SIZE", 10, f"{unique_third_party_domains} unique third-party domains")
        elif unique_third_party_domains > 8:
            add_component("DOMAIN_FOOTPRINT_SIZE", 5, f"{unique_third_party_domains} unique third-party domains")

        # Category-specific weighting for common risky classes.
        tag_manager_count = by_category.get("tag_manager", 0)
        if tag_manager_count:
            add_component(
                "TAG_MANAGER_DEPENDENCY",
                min(12, tag_manager_count * 3),
                f"{tag_manager_count} tag manager resources",
            )

        # Promote existing heuristic alerts directly into score context.
        if "MANY_THIRD_PARTY_SCRIPTS" in indicator_codes:
            add_component("HEURISTIC_ALERT_MANY_SCRIPTS", 8, "many third-party scripts heuristic triggered")
        if "ADVERTISING_SCRIPTS" in indicator_codes:
            add_component("HEURISTIC_ALERT_ADVERTISING", 6, "advertising scripts heuristic triggered")

        score = min(100, sum(c["points"] for c in components))
        return {
            "version": 1,
            "score": score,
            "tier": self._risk_tier(score),
            "components": sorted(components, key=lambda c: -c["points"]),
            "note": "Heuristic score for prioritization; not a definitive security assessment.",
        }

    def _compute_domain_risk_scores(self, third_party: list[dict]) -> list[dict]:
        """Compute per-domain risk scores for third-party domains on a site."""
        by_domain: dict[str, list[dict]] = defaultdict(list)
        for r in third_party:
            domain = r.get("registrable_domain")
            if not domain:
                continue
            by_domain[domain].append(r)

        scored_domains: list[dict] = []
        for domain, rows in by_domain.items():
            script_rows = [r for r in rows if r.get("tag") == "script"]
            unknown_script_rows = [r for r in script_rows if r.get("category") == "unknown"]
            ad_script_rows = [r for r in script_rows if r.get("category") == "advertising"]
            tag_manager_rows = [r for r in rows if r.get("category") == "tag_manager"]

            category_counts: dict[str, int] = defaultdict(int)
            provider_counts: dict[str, int] = defaultdict(int)
            for r in rows:
                category_counts[r.get("category") or "unknown"] += 1
                provider = r.get("provider")
                if provider:
                    provider_counts[provider] += 1
            primary_category = max(category_counts.items(), key=lambda item: item[1])[0]
            primary_provider = max(provider_counts.items(), key=lambda item: item[1])[0] if provider_counts else None

            components: list[dict] = []

            def add_component(code: str, points: int, evidence: str):
                if points <= 0:
                    return
                components.append({"code": code, "points": points, "evidence": evidence})

            # Domain-local scoring factors.
            if script_rows:
                add_component(
                    "SCRIPT_REFERENCES",
                    min(35, len(script_rows) * 7),
                    f"{len(script_rows)} script references",
                )
            if unknown_script_rows:
                add_component(
                    "UNKNOWN_SCRIPT_CONTENT",
                    min(18, len(unknown_script_rows) * 6),
                    f"{len(unknown_script_rows)} unknown-category scripts",
                )
            if ad_script_rows:
                add_component(
                    "AD_TRACKING_SCRIPT_CONTENT",
                    min(18, len(ad_script_rows) * 5),
                    f"{len(ad_script_rows)} advertising scripts",
                )
            if tag_manager_rows:
                add_component(
                    "TAG_MANAGER_CONTENT",
                    min(12, len(tag_manager_rows) * 4),
                    f"{len(tag_manager_rows)} tag-manager resources",
                )
            if len(rows) >= 5:
                add_component("HIGH_REFERENCE_COUNT", 8, f"{len(rows)} total references")
            elif len(rows) >= 3:
                add_component("ELEVATED_REFERENCE_COUNT", 4, f"{len(rows)} total references")

            score = min(100, sum(c["points"] for c in components))
            scored_domains.append(
                {
                    "domain": domain,
                    "score": score,
                    "tier": self._risk_tier(score),
                    "primary_category": primary_category,
                    "provider": primary_provider,
                    "total_references": len(rows),
                    "script_references": len(script_rows),
                    "components": sorted(components, key=lambda c: -c["points"]),
                    "examples": [r.get("url") for r in rows if r.get("url")][:3],
                }
            )

        return sorted(
            scored_domains,
            key=lambda row: (-row["score"], -row["script_references"], -row["total_references"], row["domain"]),
        )
 
    def _risk_indicators(self, resources: list[dict]) -> list[dict]:
        """
        Flag notable patterns that warrant manual review.
        Returns a list of {level, code, description} dicts.
        """
        flags: list[dict] = []
        third_party_scripts = [r for r in resources if r["party"] == "third-party" and r["tag"] == "script"]
        advertising_scripts = [r for r in third_party_scripts if r["category"] == "advertising"]
        unknown_scripts = [r for r in third_party_scripts if r["category"] == "unknown"]
 
        if len(third_party_scripts) > 20:
            flags.append({
                "level": "high",
                "code": "MANY_THIRD_PARTY_SCRIPTS",
                "description": f"{len(third_party_scripts)} third-party <script> tags loaded — high attack surface.",
                "affected_count": len(third_party_scripts),
            })
        elif len(third_party_scripts) > 10:
            flags.append({
                "level": "medium",
                "code": "ELEVATED_THIRD_PARTY_SCRIPTS",
                "description": f"{len(third_party_scripts)} third-party <script> tags loaded.",
                "affected_count": len(third_party_scripts),
            })
 
        if advertising_scripts:
            flags.append({
                "level": "medium",
                "code": "ADVERTISING_SCRIPTS",
                "description": f"{len(advertising_scripts)} advertising/tracking script(s) present — potential data exfiltration.",
                "affected_count": len(advertising_scripts),
                "examples": [r["url"] for r in advertising_scripts[:3]],
            })
 
        if unknown_scripts:
            flags.append({
                "level": "info",
                "code": "UNCLASSIFIED_SCRIPTS",
                "description": f"{len(unknown_scripts)} third-party script(s) with unknown category — review manually.",
                "affected_count": len(unknown_scripts),
                "examples": [r["url"] for r in unknown_scripts[:5]],
            })
 
        inline_scripts = [r for r in resources if r.get("tag") == "script" and not r.get("url")]
        # (inline scripts don't have src — already not counted in resources, but flag if CSP missing)
 
        return flags