"""
analyze.py — FastAPI route handlers for the unhookd analysis endpoints.

Endpoints:
    POST /analyze/email  — Accepts email metadata; returns risk assessment.
    POST /analyze/link   — Accepts a URL; returns risk assessment.

Each handler follows the same pipeline:
    1. Validate the incoming request body (Pydantic handles this automatically).
    2. Run deterministic heuristic checks via the analysis/ modules.
    3. Calculate a numeric risk score via utils/scoring.py.
    4. Fetch AI-generated explanation / tip from ai/gemini.py.
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
from backend.utils.scoring import calculate_email_score, calculate_link_score
from backend.ai.gemini import get_email_explanation, get_link_explanation


# ---------------------------------------------------------------------------
# Router — mounted at /analyze in main.py
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/analyze", tags=["Analysis"])


# ---------------------------------------------------------------------------
# Email analysis endpoint
# ---------------------------------------------------------------------------

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    """
    Analyse an email for phishing indicators and return a risk assessment.

    Pipeline:
        1. Run rule-based heuristics on sender, subject, body, and links.
        2. Compute weighted risk score from detected flags.
        3. Fetch Gemini explanation and educational tip (currently stubbed).
        4. Return structured JSON response.

    Args:
        request: Validated EmailAnalysisRequest payload from the client.

    Returns:
        EmailAnalysisResponse with risk_score, flags, ai_explanation,
        and education_tip fields.

    TODO:
        - Add rate limiting to prevent abuse.
        - Consider async execution of heuristic checks for performance.
    """
    # Step 1: Run heuristic checks → get list of flag identifiers
    flags = analyze_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        links=request.links,
    )

    # Step 2: Translate flags to a numeric risk score (0–100)
    risk_score = calculate_email_score(flags)

    # Step 3: Request AI explanation (stubbed — returns placeholders for now)
    ai_result = get_email_explanation(risk_score=risk_score, flags=flags)

    # Step 4: Convert internal flag IDs to human-readable labels
    # TODO: Build a proper flag_id → display_label mapping dictionary
    human_readable_flags = [flag.replace("_", " ").title() for flag in flags]

    return EmailAnalysisResponse(
        risk_score=risk_score,
        flags=human_readable_flags,
        ai_explanation=ai_result["ai_explanation"],
        education_tip=ai_result["education_tip"],
    )


# ---------------------------------------------------------------------------
# Link analysis endpoint
# ---------------------------------------------------------------------------

@router.post("/link", response_model=LinkAnalysisResponse)
async def analyze_link_endpoint(request: LinkAnalysisRequest) -> LinkAnalysisResponse:
    """
    Analyse a URL for security risks and return a risk assessment.

    Pipeline:
        1. Run rule-based heuristics against the URL structure.
        2. Compute weighted risk score from detected flags.
        3. Fetch Gemini explanation (currently stubbed).
        4. Return structured JSON response.

    Args:
        request: Validated LinkAnalysisRequest payload from the client.

    Returns:
        LinkAnalysisResponse with risk_score, flags, and ai_explanation.

    TODO:
        - Add async DNS / WHOIS / Safe Browsing lookups.
        - Cache results per URL hash (TTL-based) to avoid redundant processing.
    """
    # Step 1: Run heuristic checks → get list of flag identifiers
    flags = analyze_link(url=request.url)

    # Step 2: Translate flags to a numeric risk score (0–100)
    risk_score = calculate_link_score(flags)

    # Step 3: Request AI explanation (stubbed — returns placeholder for now)
    ai_result = get_link_explanation(risk_score=risk_score, flags=flags)

    # Step 4: Convert internal flag IDs to human-readable labels
    # TODO: Build a proper flag_id → display_label mapping dictionary
    human_readable_flags = [flag.replace("_", " ").title() for flag in flags]

    return LinkAnalysisResponse(
        risk_score=risk_score,
        flags=human_readable_flags,
        ai_explanation=ai_result["ai_explanation"],
    )
