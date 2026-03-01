"""
download.py — Heuristics for analysing downloadable files / download URLs.

This module provides a lightweight wrapper around link analysis but also
inspects filename and content-type hints that are commonly associated with
dangerous downloads.

Design: keep functions pure and side-effect free; network checks belong in a
separate runtime layer.
"""
from typing import List, Optional
from urllib.parse import urlparse
from backend.analysis.link import analyze_link


def analyze_download(url: str, filename: Optional[str] = None, content_type: Optional[str] = None) -> List[str]:
    """
    Analyse a download by running URL heuristics and simple filename/mime checks.

    Returns a deduplicated list of flag identifiers suitable for AI guidance.
    """
    flags: List[str] = []

    # Use link analysis for URL-based checks
    flags.extend(analyze_link(url))

    # Filename-based checks (if provided)
    if filename:
        lower = filename.lower()
        # Reuse the same suspicious extensions as link.check_file_extension
        for ext in [
            ".exe", ".bat", ".ps1", ".vbs", ".js", ".msi",
            ".apk", ".dmg", ".sh", ".cmd", ".scr",
        ]:
            if lower.endswith(ext):
                flags.append("suspicious_file_extension")
                break

    # Content-type hints (simple heuristics)
    if content_type:
        ct = content_type.lower()
        if any(binary in ct for binary in ["application/x-msdownload", "application/octet-stream", "application/x-msdos-program"]):
            flags.append("suspicious_file_extension")

    # Deduplicate while preserving order
    seen = set()
    unique_flags = []
    for flag in flags:
        if flag not in seen:
            seen.add(flag)
            unique_flags.append(flag)

    return unique_flags
