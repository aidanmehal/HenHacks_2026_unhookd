"""
gemini.py — Gemini API integration for AI-generated explanations and tips.

IMPORTANT DESIGN CONSTRAINT:
  - Gemini is ONLY used to explain and educate — it does NOT make risk decisions.
  - Risk scores are determined entirely by the deterministic heuristics in
    analysis/email.py and analysis/link.py plus the weights in utils/scoring.py.
  - Only sanitised metadata (flags list + risk score) is sent to the API.
    Raw email body or URL content is NEVER forwarded to the model.

All functions are STUBBED. Replace the TODO sections with real API calls once
a Gemini API key is available (loaded from environment variables — never
hardcoded).
"""

import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from google import genai

# Load .env from the same directory as this file
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

# Prompt builders (stubbed)


def _build_email_prompt(risk_score: int, flags: List[str]) -> str:
    """
    Construct the prompt sent to Gemini for email explanations.

    Only passes the risk score and flag names — no raw email content.

    Args:
        risk_score: The computed 0–100 risk score.
        flags:      List of flag identifier strings detected.

    Returns:
        A formatted prompt string ready to send to the Gemini API.

    TODO:
        - Tune prompt to request concise, non-alarmist language.
        - Add few-shot examples for formatting consistency.
        - Localise output language based on user preference (future).
    """
    flag_list = ", ".join(flags) if flags else "none"
    return (
        f"A security scan gave this email a risk score of {risk_score}/100. "
        f"The following issues were detected: {flag_list}. "
        f"In 2–3 sentences, explain what these signals mean to a non-technical "
        f"user without being alarmist. Then provide one actionable tip to help "
        f"them stay safer in the future."
    )


def _build_link_prompt(risk_score: int, flags: List[str]) -> str:
    """
    Construct the prompt sent to Gemini for link explanations.

    Args:
        risk_score: The computed 0–100 risk score.
        flags:      List of flag identifier strings detected.

    Returns:
        A formatted prompt string ready to send to the Gemini API.

    TODO: Same tuning notes as _build_email_prompt.
    """
    flag_list = ", ".join(flags) if flags else "none"
    return (
        f"A security scan gave this link a risk score of {risk_score}/100. "
        f"The following issues were detected: {flag_list}. "
        f"In 1–2 sentences, explain what this means to a non-technical user."
    )



# Public API functions
 

def get_email_explanation(risk_score: int, flags: List[str]) -> dict:
    """
    Request a plain-English explanation and educational tip from Gemini.

    Args:
        risk_score: The computed email risk score (0–100).
        flags:      Flags detected by the email heuristics.

    Returns:
        A dict with keys:
            "ai_explanation" — Gemini-generated summary (str)
            "education_tip"  — Gemini-generated advice (str)

    TODO:
        1. Load GEMINI_API_KEY from environment: os.environ["GEMINI_API_KEY"]
        2. Initialise the google-generativeai client.
        3. Call model.generate_content(_build_email_prompt(risk_score, flags)).
        4. Parse response.text and split into explanation + tip.
        5. Add error handling / retry logic for API failures.
        6. Add response caching keyed on (frozenset(flags), risk_score) to
           reduce redundant API calls for identical inputs.
    """
    # --- STUB: return placeholder values until Gemini is integrated ---
    prompt = _build_email_prompt(risk_score, flags)  # built but not sent yet

    return {
        "ai_explanation": (
            "This email shows some characteristics that are common in phishing "
            "attempts, but always verify directly with the sender before acting."
        ),
        "education_tip": (
            "When in doubt, navigate directly to the company's website instead of "
            "clicking links in the email."
        ),
    }


def get_link_explanation(risk_score: int, flags: List[str]) -> dict:
    """
    Request a plain-English explanation from Gemini for a scanned link.

    Args:
        risk_score: The computed link risk score (0–100).
        flags:      Flags detected by the link heuristics.

    Returns:
        A dict with key:
            "ai_explanation" — Gemini-generated summary (str)

    TODO: Same implementation steps as get_email_explanation, minus the tip.
    """
    # --- STUB: return placeholder value until Gemini is integrated ---
    prompt = _build_link_prompt(risk_score, flags)  # built but not sent yet

    return {
        "ai_explanation": (
            "This link has some characteristics that may indicate it is unsafe. "
            "Consider verifying the destination before proceeding."
        ),
    }
