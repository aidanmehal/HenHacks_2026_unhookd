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

    # TODO: Parse the domain portion from the sender address
    # TODO: Compare against a list of known free-email providers
    # TODO: Run lookalike-domain check (Levenshtein / regex patterns)
    # TODO: Flag if the display name mentions a brand but the domain does not

    # --- PLACEHOLDER LOGIC (remove once real checks are added) ---
    if "@" in sender:
        domain = sender.split("@")[-1].lower()
        if any(free in domain for free in ["gmail", "yahoo", "hotmail", "outlook"]):
            flags.append("free_email_provider_sender")
    # --- END PLACEHOLDER ---

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

    # --- Password request detection (stubbed) ---
    if any(phrase in body_lower for phrase in ["enter your password", "confirm your password", "reset password"]):
        flags.append("password_request")

    # --- Financial request detection (stubbed) ---
    if any(phrase in body_lower for phrase in ["wire transfer", "send money", "gift card", "bank account"]):
        flags.append("financial_request")

    # --- Excessive exclamation marks ---
    if body.count("!") > 5:
        flags.append("many_exclamation_marks")

    # TODO: Parse HTML body to detect link-text / href mismatches
    # TODO: Detect base64-encoded or obfuscated content

    return flags


def check_links_in_email(links: List[str]) -> List[str]:
    """
    Quick-scan links extracted from the email for obvious red flags.
    Deep link analysis is deferred to /analyze/link.

    Args:
        links: List of URL strings found in the email.

    Returns:
        List of flag identifier strings.
    """
    flags: List[str] = []

    # TODO: Detect link domain mismatches vs sender domain
    # TODO: Flag IP-address URLs (e.g. http://192.168.1.1/login)
    # TODO: Detect URL shorteners that obscure the real destination

    if links:
        # Placeholder: flag if any link lacks HTTPS as a simple signal
        for link in links:
            if link.startswith("http://"):
                flags.append("contains_suspicious_links")
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
    all_flags.extend(check_links_in_email(links))

    # Deduplicate while preserving insertion order
    seen = set()
    unique_flags = []
    for flag in all_flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    return unique_flags
