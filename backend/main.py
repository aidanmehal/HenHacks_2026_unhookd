"""
main.py — FastAPI application entry point for the unhookd backend.

Run locally with:
    uvicorn backend.main:app --reload --port 8000

The extension's background.js should point its fetch() calls at:
    http://localhost:8000/analyze/email
    http://localhost:8000/analyze/link
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.analyze import router as analyze_router


# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="unhookd API",
    description=(
        "Real-time phishing and malicious-link detection backend. "
        "Combines deterministic heuristics with Gemini-powered explanations."
    ),
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# CORS — allow the Chrome extension origin during development
# ---------------------------------------------------------------------------

# TODO: Restrict allowed origins to the published extension ID in production.
#       Chrome extension origins look like: chrome-extension://<id>
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Permissive during dev — tighten for prod
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(analyze_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """
    Simple liveness probe.
    Returns 200 OK with status "ok" when the server is running.
    """
    return {"status": "ok", "service": "unhookd"}
