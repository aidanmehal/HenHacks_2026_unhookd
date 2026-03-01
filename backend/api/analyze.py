"""
analyze.py — FastAPI route handlers for the unhookd analysis endpoints.

Endpoints:
    POST /analyze/email  — Accepts email metadata; returns risk assessment.
    POST /analyze/link   — Accepts a URL; returns risk assessment.

Each handler follows the same pipeline:
    1. Validate the incoming request body (Pydantic handles this automatically).
    2. Run deterministic heuristic checks via the analysis/ modules.
    3. Convert heuristic flags into human-readable guideline signals.
    4. Ask Gemini for the final severity, display flags, and explanation.
    5. Return a structured JSON response.

No user data is stored at any point in this pipeline.
"""

from fastapi import APIRouter
from backend.models.schemas import (
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    LinkAnalysisRequest,
    LinkAnalysisResponse,
)
from backend.analysis.email import analyze_email
from backend.analysis.link import analyze_link
from backend.analysis.download import analyze_download
from backend.ai.gemini import analyze_email_with_ai, analyze_link_with_ai
from backend.ai.gemini import analyze_download_with_ai
from backend.models.schemas import DownloadAnalysisRequest, DownloadAnalysisResponse



# Router — mounted at /analyze in main.py


router = APIRouter(prefix="/analyze", tags=["Analysis"])


# Human-readable mapping for internal flag IDs -> display labels
FLAG_DISPLAY_LABELS = {
    # Email flags
    "suspicious_sender_domain": "Suspicious sender domain",
    "domain_spoofing": "Domain spoofing",
    "free_email_provider_sender": "Free email provider",
    "urgent_language": "Urgent language",
    "password_request": "Password requested",
    "financial_request": "Financial request",
    "mismatched_display_name": "Mismatched display name",
    "many_exclamation_marks": "Excessive punctuation",

    # Link / download flags
    "contains_suspicious_links": "Contains suspicious links",
    "link_domain_mismatch": "Link/domain mismatch",
    "no_https": "Unencrypted (no HTTPS)",
    "known_malicious_domain": "Known malicious domain",
    "suspicious_tld": "Suspicious top-level domain",
    "ip_address_url": "IP address in URL",
    "url_shortener": "URL shortener",
    "excessive_subdomains": "Excessive subdomains",
    "suspicious_file_extension": "Suspicious file extension",
}



# Email analysis endpoint


@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    """
    Analyse an email for phishing indicators and return a risk assessment.

    Pipeline:
        1. Run rule-based heuristics on sender, subject, body, and links.
        2. Convert heuristic flags into prompt guidelines.
        3. Gemini returns the final severity, flags, explanation, and tip.
        4. Return structured JSON response.

    Args:
        request: Validated EmailAnalysisRequest payload from the client.

    Returns:
        EmailAnalysisResponse with severity, flags, ai_explanation,
        and education_tip fields.

    TODO:
        - Add rate limiting to prevent abuse.
        - Consider async execution of heuristic checks for performance.
    """
    # Step 1: Run heuristic checks → get list of flag identifiers
    guideline_flags = analyze_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        links=request.links,
    )
    prompt_guidelines = [FLAG_DISPLAY_LABELS.get(flag, flag.replace("_", " ").title()) for flag in guideline_flags]
    ai_result = analyze_email_with_ai(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        links=request.links,
        guideline_flags=prompt_guidelines,
    )

    return EmailAnalysisResponse(
        severity=ai_result["severity"],
        flags=ai_result["flags"],
        ai_explanation=ai_result["ai_explanation"],
        education_tip=ai_result["education_tip"],
    )



# Link analysis endpoint


@router.post("/link", response_model=LinkAnalysisResponse)
async def analyze_link_endpoint(request: LinkAnalysisRequest) -> LinkAnalysisResponse:
    """
    Analyse a URL for security risks and return a risk assessment.

    Pipeline:
        1. Run rule-based heuristics against the URL structure.
        2. Convert heuristic flags into prompt guidelines.
        3. Gemini returns the final severity, flags, and explanation.
        4. Return structured JSON response.

    Args:
        request: Validated LinkAnalysisRequest payload from the client.

    Returns:
        LinkAnalysisResponse with severity, flags, and ai_explanation.

    TODO:
        - Add async DNS / WHOIS / Safe Browsing lookups.
        - Cache results per URL hash (TTL-based) to avoid redundant processing.
    """
    # Step 1: Run heuristic checks → get list of flag identifiers
    guideline_flags = analyze_link(url=str(request.url))
    prompt_guidelines = [FLAG_DISPLAY_LABELS.get(flag, flag.replace("_", " ").title()) for flag in guideline_flags]
    ai_result = analyze_link_with_ai(url=str(request.url), guideline_flags=prompt_guidelines)

    return LinkAnalysisResponse(
        severity=ai_result["severity"],
        flags=ai_result["flags"],
        ai_explanation=ai_result["ai_explanation"],
    )



@router.post("/download", response_model=DownloadAnalysisResponse)
async def analyze_download_endpoint(request: DownloadAnalysisRequest) -> DownloadAnalysisResponse:
    """
    Analyse a download URL and return a risk assessment.

    This endpoint inspects the URL plus optional filename / content-type hints
    and returns Gemini-decided severity, detected flags, explanation, and
    an education tip.
    """
    guideline_flags = analyze_download(url=str(request.url), filename=request.filename, content_type=request.content_type)
    prompt_guidelines = [FLAG_DISPLAY_LABELS.get(flag, flag.replace("_", " ").title()) for flag in guideline_flags]
    ai_result = analyze_download_with_ai(
        url=str(request.url),
        filename=request.filename,
        content_type=request.content_type,
        guideline_flags=prompt_guidelines,
    )

    return DownloadAnalysisResponse(
        severity=ai_result["severity"],
        flags=ai_result["flags"],
        ai_explanation=ai_result.get("ai_explanation", ""),
        education_tip=ai_result.get("education_tip", ""),
    )
