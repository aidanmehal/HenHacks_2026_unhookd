"""
link.py — Rule-based security heuristics for URL / link analysis.

Each check function inspects one dimension of the URL and returns a list of
flag identifier strings.  Flags are later weighted and summed by scoring.py.

Design principles:
  - Each check is a pure function: (url) → List[str]
  - No side effects, no network calls (future: DNS/WHOIS lookups in separate layer)
  - Returning an empty list means "no issues detected" for that check
  - All logic is STUBBED — replace TODO sections with real implementations
"""

import re
from urllib.parse import urlparse
from typing import List


# ---------------------------------------------------------------------------
# Known-bad lists (stubbed — replace with real threat-intel feeds)
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_DOMAINS: List[str] = [
    # TODO: Populate from a threat-intelligence feed (e.g. PhishTank, URLhaus)
    "evil-example.com",
    "phish-test.net",
]

SUSPICIOUS_TLDS: List[str] = [
    # TODO: Expand based on current abuse statistics
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
]

URL_SHORTENERS: List[str] = [
    # TODO: Keep this list up to date
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
]


# ---------------------------------------------------------------------------
# Individual heuristic checks
# ---------------------------------------------------------------------------

def check_https(url: str) -> List[str]:
    """
    Verify whether the URL uses an encrypted HTTPS connection.

    Args:
        url: Full URL string.

    Returns:
        ["no_https"] if the scheme is HTTP (or missing), else [].
    """
    flags: List[str] = []

    # TODO: Also flag non-standard schemes (ftp://, data://, javascript:)
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        flags.append("no_https")

    return flags


def check_known_malicious_domain(url: str) -> List[str]:
    """
    Match the URL's hostname against a list of known-bad domains.

    Args:
        url: Full URL string.

    Returns:
        ["known_malicious_domain"] if matched, else [].

    TODO:
        - Replace static list with an async lookup against PhishTank / Google
          Safe Browsing API.
        - Add sub-domain traversal (evil.legit-looking.evil-example.com should
          still match evil-example.com).
    """
    flags: List[str] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # TODO: Use a proper suffix-list library (e.g. tldextract) for reliable
    #       registered-domain extraction
    for bad_domain in KNOWN_MALICIOUS_DOMAINS:
        if hostname == bad_domain or hostname.endswith("." + bad_domain):
            flags.append("known_malicious_domain")
            break

    return flags


def check_suspicious_tld(url: str) -> List[str]:
    """
    Flag URLs whose top-level domain appears in the high-abuse TLD list.

    Args:
        url: Full URL string.

    Returns:
        ["suspicious_tld"] if TLD is in the watchlist, else [].
    """
    flags: List[str] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # TODO: Use tldextract for accurate TLD parsing
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append("suspicious_tld")
            break

    return flags


def check_ip_address_url(url: str) -> List[str]:
    """
    Detect URLs that use a raw IP address instead of a domain name.
    Legitimate services almost never use bare IPs in clickable links.

    Args:
        url: Full URL string.

    Returns:
        ["ip_address_url"] if hostname is an IPv4/IPv6 address, else [].
    """
    flags: List[str] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Basic IPv4 pattern — TODO: add IPv6 and encoded IP variants
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ipv4_pattern.match(hostname):
        flags.append("ip_address_url")

    return flags


def check_url_shortener(url: str) -> List[str]:
    """
    Flag common URL-shortener domains that hide the final destination.

    Args:
        url: Full URL string.

    Returns:
        ["url_shortener"] if the domain is a known shortener, else [].
    """
    flags: List[str] = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if hostname in URL_SHORTENERS:
        flags.append("url_shortener")

    return flags


def check_subdomain_depth(url: str) -> List[str]:
    """
    Flag URLs with an unusually large number of subdomains, which is a
    common tactic to make phishing URLs appear legitimate at a glance
    (e.g. paypal.com.evil-domain.com).

    Args:
        url: Full URL string.

    Returns:
        ["excessive_subdomains"] if subdomain depth exceeds threshold, else [].

    TODO:
        - Use tldextract to count *real* subdomains (excluding the registered
          domain and public suffix).
        - Tune the depth threshold based on empirical data.
    """
    flags: List[str] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Rough heuristic: more than 3 dot-separated labels is suspicious
    # TODO: This will produce false positives — replace with tldextract logic
    labels = hostname.split(".")
    if len(labels) > 4:
        flags.append("excessive_subdomains")

    return flags


def check_file_extension(url: str) -> List[str]:
    """
    Detect links pointing directly at potentially dangerous file types.

    Args:
        url: Full URL string.

    Returns:
        ["suspicious_file_extension"] if the path ends with a risky extension.

    TODO:
        - Also inspect Content-Type header at download time (requires network
          call — keep out of this pure-function module).
    """
    flags: List[str] = []

    DANGEROUS_EXTENSIONS = [
        ".exe", ".bat", ".ps1", ".vbs", ".js", ".msi",
        ".apk", ".dmg", ".sh", ".cmd", ".scr",
    ]

    parsed = urlparse(url)
    path = parsed.path.lower()

    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext):
            flags.append("suspicious_file_extension")
            break

    return flags


# ---------------------------------------------------------------------------
# Aggregator — called by the API layer
# ---------------------------------------------------------------------------

def analyze_link(url: str) -> List[str]:
    """
    Run all link heuristic checks and return a deduplicated flag list.

    This is the single entry point called by the API route handler.
    The returned flags are passed to scoring.calculate_link_score().

    Args:
        url: The URL string to analyse.

    Returns:
        Deduplicated list of flag identifier strings.
    """
    all_flags: List[str] = []

    all_flags.extend(check_https(url))
    all_flags.extend(check_known_malicious_domain(url))
    all_flags.extend(check_suspicious_tld(url))
    all_flags.extend(check_ip_address_url(url))
    all_flags.extend(check_url_shortener(url))
    all_flags.extend(check_subdomain_depth(url))
    all_flags.extend(check_file_extension(url))

    # Deduplicate while preserving insertion order
    seen = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    return unique_flags
