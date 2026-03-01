"""
email.py — Rule-based phishing heuristics for email analysis.

Each check function inspects one dimension of the email and returns a list of
flag identifier strings. These flags are later passed to the AI layer as
guideline signals.

Design principles:
  - Each check is a pure function: (input) → List[str]
  - No side effects, no I/O, no external calls
  - Returning an empty list means "no issues detected" for that check
  - All logic is STUBBED — replace TODO sections with real implementations
"""

import re
from typing import List
from urllib.parse import urlparse


FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"}
BRAND_KEYWORDS = {
    "paypal": ("paypal", "paypa1", "paypol"),
    "microsoft": ("microsoft", "micros0ft", "rnicrosoft"),
    "google": ("google", "goog1e", "g00gle"),
    "apple": ("apple", "app1e"),
    "amazon": ("amazon", "amaz0n"),
    "bank": ("bank",),
}


def _extract_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower()


def _registered_domain(hostname: str) -> str:
    labels = [label for label in hostname.split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname



# Individual heuristic checks


def check_sender_domain(sender: str) -> List[str]:
    """
    Inspect the sender's email address for suspicious domain patterns.

    Checks performed (TODO — all stubbed):
      - Common lookalike domain substitutions (e.g. paypa1.com, micros0ft.com)
      - Hyphenated brand impersonation (e.g. amazon-support.com)
      - Free email provider sending as a corporation
      - Domain age (future: integrase WHOIS lookup)

    Args:
        sender: Raw sender address string (e.g. "support@amaz0n.com").

    Returns:
        List of flag identifier strings.
    """
    flags: List[str] = []

    domain = _extract_domain(sender)
    if not domain:
        return flags

    if domain in FREE_EMAIL_PROVIDERS:
        flags.append("free_email_provider_sender")

    if any(char.isdigit() for char in domain) or domain.count("-") >= 2:
        flags.append("suspicious_sender_domain")

    for canonical, variants in BRAND_KEYWORDS.items():
        if any(variant in domain for variant in variants) and canonical not in domain:
            flags.append("domain_spoofing")
            break

    if any(part in domain for part in ("secure", "verify", "update", "login")) and domain in FREE_EMAIL_PROVIDERS:
        if "free_email_provider_sender" not in flags:
            flags.append("free_email_provider_sender")

    return flags


def check_subject_urgency(subject: str) -> List[str]:
    """
    Detect urgency and fear-based language in the email subject.

    Args:
        subject: The email subject line string.

    Returns:
        List of flag identifier strings.
    """
    flags: List[str] = []

    # TODO: Build a comprehensive urgency-word corpus
    # TODO: Weight patterns (e.g. ALL CAPS is stronger signal than title case)
    URGENCY_PATTERNS = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\baction required\b",
        r"\bact now\b",
        r"\bfinal notice\b",
        r"\bsecurity alert\b",
        r"\baccount (suspended|locked|compromised)\b",
        r"\bverify (your|account)\b",
        r"\bconfirm (your|account)\b",
    ]

    subject_lower = subject.lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, subject_lower):
            flags.append("urgent_language")
            break  # Don't double-count the same signal

    return flags


def check_body_content(body: str) -> List[str]:
    """
    Scan the email body for high-risk content patterns.

    Checks performed (TODO — mostly stubbed):
      - Password / credential request phrases
      - Financial / wire-transfer request phrases
      - Excessive punctuation (spam indicator)
      - Mismatch between displayed link text and actual href (requires HTML)

    Args:
        body: Plain-text body of the email.

    Returns:
        List of flag identifier strings.
    """
    flags: List[str] = []
    body_lower = body.lower()

    # TODO: Replace simple substring checks with regex + NLP intent detection

    password_patterns = [
        "enter your password",
        "confirm your password",
        "reset password",
        "verify your password",
        "log in to keep your account active",
        "sign in to avoid suspension",
    ]
    if any(phrase in body_lower for phrase in password_patterns):
        flags.append("password_request")

    financial_patterns = [
        "wire transfer",
        "send money",
        "gift card",
        "bank account",
        "invoice attached",
        "payment overdue",
        "outstanding balance",
        "crypto wallet",
    ]
    if any(phrase in body_lower for phrase in financial_patterns):
        flags.append("financial_request")

    # --- Excessive exclamation marks ---
    if body.count("!") > 5:
        flags.append("many_exclamation_marks")

    if "click the link below" in body_lower or "use the secure link" in body_lower:
        flags.append("contains_suspicious_links")

    # TODO: Parse HTML body to detect link-text / href mismatches
    # TODO: Detect base64-encoded or obfuscated content

    return flags


def check_links_in_email(sender: str, links: List[str]) -> List[str]:
    """
    Quick-scan links extracted from the email for obvious red flags.
    Deep link analysis is deferred to /analyze/link.

    Args:
        links: List of URL strings found in the email.

    Returns:
        List of flag identifier strings.
    """
    flags: List[str] = []
    sender_domain = _registered_domain(_extract_domain(sender))

    if links:
        for link in links:
            parsed = urlparse(link)
            hostname = (parsed.hostname or "").lower()
            if link.startswith("http://") or any(short in hostname for short in ("bit.ly", "tinyurl.com", "t.co")):
                flags.append("contains_suspicious_links")
            if sender_domain and hostname and _registered_domain(hostname) != sender_domain:
                flags.append("link_domain_mismatch")
            if "@" in parsed.netloc:
                flags.append("link_domain_mismatch")
            if flags:
                # these are coarse indicators; once present, stop scanning
                break

    return flags



# Aggregator — called by the API layer


def analyze_email(sender: str, subject: str, body: str, links: List[str]) -> List[str]:
    """
    Run all email heuristic checks and return a deduplicated flag list.

    This is the single entry point called by the API route handler.
    The returned flags are converted into prompt guidance for the AI layer.

    Args:
        sender:  Sender email address.
        subject: Email subject line.
        body:    Plain-text email body.
        links:   URLs extracted from the email.

    Returns:
        Deduplicated list of flag identifier strings.
    """
    all_flags: List[str] = []

    all_flags.extend(check_sender_domain(sender))
    all_flags.extend(check_subject_urgency(subject))
    all_flags.extend(check_body_content(body))
    all_flags.extend(check_links_in_email(sender, links))

    # Deduplicate while preserving insertion order
    seen = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    return unique_flags
