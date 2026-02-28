"""
scoring.py — Risk score calculation utilities for unhookd.

Converts a list of weighted flag signals into a normalised 0–100 risk score.
Keeping scoring logic here (separate from detection logic) makes it easy to
tune weights without touching the heuristic rules.
"""

from typing import Dict, List


# ---------------------------------------------------------------------------
# Flag weight registry
# Maps flag identifiers to their numeric severity contribution (0–100 scale).
# ---------------------------------------------------------------------------

EMAIL_FLAG_WEIGHTS: Dict[str, int] = {
    # Sender / domain signals
    "suspicious_sender_domain": 30,
    "domain_spoofing": 35,
    "free_email_provider_sender": 10,

    # Content signals
    "urgent_language": 20,
    "password_request": 30,
    "financial_request": 25,
    "mismatched_display_name": 20,
    "many_exclamation_marks": 5,

    # Link signals
    "contains_suspicious_links": 25,
    "link_domain_mismatch": 30,

    # TODO: Add more granular weights as heuristics are implemented
}

LINK_FLAG_WEIGHTS: Dict[str, int] = {
    "no_https": 20,
    "known_malicious_domain": 80,
    "suspicious_tld": 25,
    "ip_address_url": 30,
    "url_shortener": 15,
    "excessive_subdomains": 20,
    "suspicious_file_extension": 35,

    # TODO: Integrate threat-intelligence feeds for real-world scores
}


# ---------------------------------------------------------------------------
# Score calculation helpers
# ---------------------------------------------------------------------------

def calculate_score(flags: List[str], weight_map: Dict[str, int]) -> int:
    """
    Aggregate flag weights into a single clamped risk score.

    Algorithm:
        1. Look up each flag in the provided weight map.
        2. Sum all matching weights.
        3. Clamp the result to [0, 100].

    Args:
        flags:       List of flag identifiers detected by the analysis layer.
        weight_map:  Mapping of flag identifier → severity weight.

    Returns:
        An integer risk score between 0 and 100 (inclusive).

    TODO:
        - Consider multiplicative compounding for highly correlated flags.
        - Normalise by total possible weight so scores are more comparable
          across analyses with different flag counts.
    """
    total: int = 0

    for flag in flags:
        weight = weight_map.get(flag, 0)
        if weight == 0:
            # Unrecognised flag — log for visibility but don't crash
            # TODO: Replace print with proper structured logging
            print(f"[scoring] Unknown flag '{flag}' — defaulting to weight 0")
        total += weight

    # Clamp to valid range
    return min(max(total, 0), 100)


def calculate_email_score(flags: List[str]) -> int:
    """
    Convenience wrapper: calculate risk score for an email analysis result.

    Args:
        flags: Flag identifiers produced by the email heuristic checks.

    Returns:
        Clamped integer risk score (0–100).
    """
    return calculate_score(flags, EMAIL_FLAG_WEIGHTS)


def calculate_link_score(flags: List[str]) -> int:
    """
    Convenience wrapper: calculate risk score for a link analysis result.

    Args:
        flags: Flag identifiers produced by the link heuristic checks.

    Returns:
        Clamped integer risk score (0–100).
    """
    return calculate_score(flags, LINK_FLAG_WEIGHTS)
