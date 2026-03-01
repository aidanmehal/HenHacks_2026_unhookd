"""
gemini.py — Gemini API integration for AI-generated explanations and tips.

Gemini is the final decision-maker for severity classification.
The deterministic analysis modules remain guideline generators only:
they surface hints that are passed into the model, but Gemini returns the
final severity, the displayed flags, and the explanation shown to users.
"""

import os
from pathlib import Path
from typing import List, Tuple, Optional
from functools import lru_cache
import logging
import json
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs) -> bool:
        return False

try:
    from google import genai
except ImportError:
    genai = None

# Load .env from the same directory as this file (optional)
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# Logger
logger = logging.getLogger("unhookd.ai.gemini")

# Initialise client if API key available; otherwise run in offline stub mode
_GEMINI_KEY = os.environ.get("GEMINI_API_KEY")
_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_GEMINI_TIMEOUT_SECONDS = float(os.environ.get("GEMINI_TIMEOUT_SECONDS", "20"))
if _GEMINI_KEY and genai is not None:
    try:
        client = genai.Client(api_key=_GEMINI_KEY)
    except Exception as e:
        logger.exception("Failed to initialise Gemini client: %s", e)
        client = None
elif _GEMINI_KEY and genai is None:
    logger.warning("GEMINI_API_KEY is set but google-genai is not installed — running with AI fallback mode")
    client = None
else:
    logger.warning("GEMINI_API_KEY not set — running with AI stubs")
    client = None

_MODEL_EXECUTOR = ThreadPoolExecutor(max_workers=4)

# Prompt builders


def _build_email_prompt(sender: str, subject: str, body: str, links: List[str], guideline_flags: List[str]) -> str:
    """
    Construct the prompt sent to Gemini for email explanations.

    Passes the raw email content plus heuristic guideline hints.

    Args:
    Returns:
        A formatted prompt string ready to send to the Gemini API.
    """
    flag_list = ", ".join(guideline_flags) if guideline_flags else "none"
    joined_links = ", ".join(links) if links else "none"
    return (
        "You are a cautious cybersecurity assistant.\n"
        "Classify the phishing risk of the email below.\n"
        "Use the heuristic guideline signals as hints only; you must make the final decision.\n"
        "Evaluate sender trust, urgency, credential requests, financial requests, social engineering, and suspicious links.\n"
        "Respond ONLY with valid JSON using this exact schema:\n"
        "{\n"
        "  \"severity\": \"no_risk|low|medium|high|critical\",\n"
        "  \"flags\": [\"short human-readable phrases\"],\n"
        "  \"ai_explanation\": \"2-3 sentence plain-English explanation\",\n"
        "  \"education_tip\": \"one short actionable safety tip\"\n"
        "}\n"
        "Keep the tone calm and specific. Do not include markdown.\n"
        f"Sender: {sender}\n"
        f"Subject: {subject}\n"
        f"Body: {body}\n"
        f"Links: {joined_links}\n"
        f"Guideline signals: {flag_list}\n"
    )


def _build_link_prompt(url: str, guideline_flags: List[str]) -> str:
    """
    Construct the prompt sent to Gemini for link explanations.

    Args:
    Returns:
        A formatted prompt string ready to send to the Gemini API.
    """
    flag_list = ", ".join(guideline_flags) if guideline_flags else "none"
    return (
        "You are a cautious cybersecurity assistant.\n"
        "Classify the security risk of the URL below.\n"
        "Use the heuristic guideline signals as hints only; you must make the final decision.\n"
        "Respond ONLY with valid JSON using this exact schema:\n"
        "{\n"
        "  \"severity\": \"no_risk|low|medium|high|critical\",\n"
        "  \"flags\": [\"short human-readable phrases\"],\n"
        "  \"ai_explanation\": \"1-2 sentence plain-English explanation\"\n"
        "}\n"
        "Keep the tone calm and specific. Do not include markdown.\n"
        f"URL: {url}\n"
        f"Guideline signals: {flag_list}\n"
    )


def _build_download_prompt(
    url: str,
    filename: Optional[str],
    content_type: Optional[str],
    guideline_flags: List[str],
) -> str:
    """
    Construct the prompt sent to Gemini for download explanations.

    Args:
    """
    flag_list = ", ".join(guideline_flags) if guideline_flags else "none"
    return (
        "You are a cautious cybersecurity assistant.\n"
        "Classify the security risk of the download below.\n"
        "Use the heuristic guideline signals as hints only; you must make the final decision.\n"
        "Respond ONLY with valid JSON using this exact schema:\n"
        "{\n"
        "  \"severity\": \"no_risk|low|medium|high|critical\",\n"
        "  \"flags\": [\"short human-readable phrases\"],\n"
        "  \"ai_explanation\": \"2 sentence explanation\",\n"
        "  \"education_tip\": \"one short actionable safety tip\"\n"
        "}\n"
        "Keep the tone calm and specific. Do not include markdown.\n"
        f"URL: {url}\n"
        f"Filename: {filename or 'none'}\n"
        f"Content-Type: {content_type or 'none'}\n"
        f"Guideline signals: {flag_list}\n"
    )



# Public API functions
 

def _cache_key(flags: List[str]) -> Tuple[str, ...]:
    # deterministic ordering for cache key
    return tuple(sorted(flags))


@lru_cache(maxsize=256)
def _generate_from_model_cached(model: str, prompt: str, flags_key: Tuple[str, ...]) -> str:
    """Internal cached wrapper around model generation."""
    if client is None:
        raise RuntimeError("Gemini client not configured")
    response = client.models.generate_content(
        model=model,
        contents=prompt,
    )
    return response.text


def _extract_json_payload(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise ValueError("Model response did not contain valid JSON")


def _normalize_severity(value: Optional[str]) -> str:
    candidate = (value or "").strip().lower()
    if candidate in {"no_risk", "low", "medium", "high", "critical"}:
        return candidate
    if candidate in {"none", "none_detected", "safe", "no risk", "no-risk", "no_risk_detected"}:
        return "no_risk"
    if candidate in {"critical", "severe"}:
        return "critical"
    if candidate in {"very high", "very_high"}:
        return "critical"
    if candidate in {"moderate", "med"}:
        return "medium"
    if candidate in {"minor", "minimal"}:
        return "low"
    return "medium"


def _normalize_flags(value: object, default_flags: List[str]) -> List[str]:
    if isinstance(value, list):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        if cleaned:
            return cleaned[:5]
    return default_flags


def _infer_fallback_severity(default_flags: List[str]) -> str:
    if not default_flags:
        return "no_risk"

    critical_signal_flags = {
        "Password requested",
        "Financial request",
        "Known malicious domain",
        "Known malicious download source",
    }
    high_signal_flags = {
        "IP address in URL",
        "Suspicious file extension",
        "Direct request for account password",
        "Direct credential request",
    }
    medium_signal_flags = {
        "Suspicious sender domain",
        "Domain spoofing",
        "Contains suspicious links",
        "Link/domain mismatch",
        "Unencrypted (no HTTPS)",
        "Suspicious top-level domain",
        "URL shortener",
        "Excessive subdomains",
        "Urgent language",
    }

    if any(flag in critical_signal_flags for flag in default_flags):
        return "critical"
    if any(flag in high_signal_flags for flag in default_flags):
        return "high"
    if any(flag in medium_signal_flags for flag in default_flags) or len(default_flags) >= 3:
        return "medium"
    return "low"


def _offline_decision(default_flags: List[str], include_tip: bool) -> dict:
    severity = _infer_fallback_severity(default_flags)
    if default_flags:
        joined_flags = ", ".join(default_flags[:3])
        explanation = f"This result is based on local phishing checks. Detected signals include {joined_flags}."
    else:
        explanation = "This result is based on local phishing checks and no major risk signals were detected."

    result = {
        "severity": severity,
        "flags": default_flags or ["AI review unavailable"],
        "ai_explanation": explanation,
    }
    if include_tip:
        result["education_tip"] = "Verify unusual messages, links, and downloads through a trusted channel before interacting."
    return result


def _run_ai_decision(prompt: str, guideline_flags: List[str], include_tip: bool) -> dict:
    flags_key = _cache_key(guideline_flags)
    try:
        if client is None:
            raise RuntimeError("Gemini is unavailable for live analysis")

        model = _GEMINI_MODEL
        future = _MODEL_EXECUTOR.submit(_generate_from_model_cached, model, prompt, flags_key)
        text = future.result(timeout=_GEMINI_TIMEOUT_SECONDS)
        payload = _extract_json_payload(text)

        result = {
            "severity": _normalize_severity(payload.get("severity")),
            "flags": _normalize_flags(payload.get("flags"), guideline_flags),
            "ai_explanation": str(payload.get("ai_explanation", "")).strip() or "No explanation available.",
        }
        if include_tip:
            result["education_tip"] = str(payload.get("education_tip", "")).strip() or "Use caution and verify through a trusted channel."
        return result
    except FutureTimeoutError:
        logger.warning("Gemini decision generation exceeded %.1fs", _GEMINI_TIMEOUT_SECONDS)
        raise RuntimeError(f"Gemini took longer than {_GEMINI_TIMEOUT_SECONDS:.1f}s")
    except Exception as e:
        logger.exception("Gemini decision generation failed: %s", e)
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError("Gemini live analysis failed") from e


def analyze_email_with_ai(
    sender: str,
    subject: str,
    body: str,
    links: List[str],
    guideline_flags: List[str],
) -> dict:
    """Return the AI-decided email severity, flags, explanation, and tip."""
    prompt = _build_email_prompt(sender, subject, body, links, guideline_flags)
    return _run_ai_decision(prompt, guideline_flags, include_tip=True)


def analyze_link_with_ai(url: str, guideline_flags: List[str]) -> dict:
    """Return the AI-decided link severity, flags, and explanation."""
    prompt = _build_link_prompt(url, guideline_flags)
    return _run_ai_decision(prompt, guideline_flags, include_tip=False)


def analyze_download_with_ai(
    url: str,
    filename: Optional[str],
    content_type: Optional[str],
    guideline_flags: List[str],
) -> dict:
    """Return the AI-decided download severity, flags, explanation, and tip."""
    prompt = _build_download_prompt(url, filename, content_type, guideline_flags)
    return _run_ai_decision(prompt, guideline_flags, include_tip=True)
