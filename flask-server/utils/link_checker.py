"""Defensive URL analysis. Remote page fetching is opt-in and SSRF guarded."""
import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse, urljoin

import requests
from utils.trusted_senders import is_trusted_domain
from utils.dl_engine import predict_url, predict_page

logger = logging.getLogger(__name__)
MAX_REDIRECTS = 4
MAX_PAGE_BYTES = 512_000
FETCH_ENABLED = __import__('os').environ.get('PHISHGUARD_ENABLE_PAGE_FETCH', 'false').lower() == 'true'
BRANDS = ("hdfc", "icici", "sbi", "axis", "kotak", "paytm", "phonepe", "amazon", "flipkart", "google", "apple", "microsoft", "paypal", "netflix", "uber", "ola", "zomato", "swiggy", "irctc", "jio", "airtel", "uidai", "epfo", "npci")


def _validate_public_http_url(value: str):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("URL is invalid or too long")
    p = urlparse(value.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are accepted")
    if p.username or p.password:
        raise ValueError("URLs containing credentials are rejected")
    host = p.hostname.rstrip('.').lower()
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local hostnames are not fetchable")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, p.port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(a[4][0]) for a in answers}
        except socket.gaierror as exc:
            raise ValueError("Hostname could not be resolved") from exc
    if not addresses or any(not a.is_global for a in addresses):
        raise ValueError("Private, loopback, link-local and reserved destinations are blocked")
    return p


def _fetch_public_page(start_url: str):
    current = start_url
    chain = []
    session = requests.Session()
    session.trust_env = False  # do not inherit proxy settings from the host
    headers = {"User-Agent": "PhishGuardSecurityScanner/2.1", "Accept": "text/html,application/xhtml+xml", "Accept-Encoding": "identity"}
    for _ in range(MAX_REDIRECTS + 1):
        _validate_public_http_url(current)
        response = session.get(current, headers=headers, timeout=(3, 5), allow_redirects=False, stream=True, verify=True)
        chain.append(current)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ValueError("Redirect without a Location header")
            current = urljoin(current, location)
            continue
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            response.close()
            raise ValueError("Destination did not return an HTML page")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > MAX_PAGE_BYTES:
            response.close()
            raise ValueError("Page exceeds maximum inspection size")
        chunks, total = [], 0
        for chunk in response.iter_content(16_384):
            total += len(chunk)
            if total > MAX_PAGE_BYTES:
                break
            chunks.append(chunk)
        response.close()
        return current, chain, b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
    raise ValueError("Too many redirects")


def check_link_safety(url: str) -> dict:
    report = {"url": str(url)[:2048], "verdict": "SUSPICIOUS", "reasons": [], "redirect_chain": [], "url_score": None, "page_score": None, "is_trusted": False}
    try:
        parsed = _validate_public_http_url(url)
    except ValueError as exc:
        report["reasons"].append(str(exc))
        return report
    host = parsed.hostname.lower().rstrip('.')
    report["is_trusted"] = is_trusted_domain(host)

    # Trusted domains are a weak positive signal, never an unconditional SAFE verdict.
    model_result = predict_url(url)
    report["url_score"] = model_result.get("score")
    report["reasons"].append(model_result.get("reason", "URL model unavailable"))
    verdict = model_result.get("verdict", "SUSPICIOUS")
    if verdict == "DANGEROUS":
        report["verdict"] = "DANGEROUS"
    elif verdict == "SUSPICIOUS":
        report["verdict"] = "SUSPICIOUS"
    else:
        report["verdict"] = "SAFE" if report["is_trusted"] else "SUSPICIOUS"
        if not report["is_trusted"]:
            report["reasons"].append("Unverified domain; model SAFE output is not proof of legitimacy")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        report["verdict"] = "SUSPICIOUS"
        report["reasons"].append("URL uses a literal IPv4 address")
    if any(brand in host for brand in BRANDS) and not report["is_trusted"]:
        report["verdict"] = "SUSPICIOUS"
        report["reasons"].append("Domain contains a known brand name but is not on the trusted-domain list")

    if FETCH_ENABLED and report["verdict"] != "DANGEROUS":
        try:
            final_url, chain, html = _fetch_public_page(url)
            report["redirect_chain"] = chain
            final_host = urlparse(final_url).hostname or ""
            if final_host.lower() != host and not is_trusted_domain(final_host):
                report["verdict"] = "SUSPICIOUS"
                report["reasons"].append("Redirected to a different, unverified domain")
            if not final_url.lower().startswith("https://"):
                report["verdict"] = "SUSPICIOUS"
                report["reasons"].append("Final page does not use HTTPS")
            title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title_text = re.sub(r"<[^>]+>", " ", title.group(1)).lower() if title else ""
            for brand in BRANDS:
                if brand in title_text and not is_trusted_domain(final_host):
                    report["verdict"] = "DANGEROUS"
                    report["reasons"].append("Page title appears to impersonate a known brand")
                    break
            page_text = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
            page_text = re.sub(r"<[^>]+>", " ", page_text)
            page_result = predict_page(re.sub(r"\s+", " ", page_text)[:12000])
            report["page_score"] = page_result.get("score")
            if page_result.get("verdict") == "DANGEROUS":
                report["verdict"] = "DANGEROUS"
                report["reasons"].append(page_result.get("reason", "Page model flagged content"))
            elif page_result.get("verdict") == "SUSPICIOUS" and report["verdict"] != "DANGEROUS":
                report["verdict"] = "SUSPICIOUS"
                report["reasons"].append(page_result.get("reason", "Page model flagged content"))
        except Exception as exc:
            logger.info("Page inspection skipped: %s", type(exc).__name__)
            report["reasons"].append("Live page inspection unavailable; URL-only result used")
    elif not FETCH_ENABLED:
        report["reasons"].append("Live page fetching is disabled by default for server-side request safety")
    return report
