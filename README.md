# unhookd

A real-time phishing and malicious-link detection tool built for **HenHacks 2026**  Security & Safety category.

unhookd is a Chrome extension that analyses email content and web links as you browse, giving you an immediate, plain-English risk assessment without storing any of your data.

---

## Overview

The extension sends email metadata or URLs to the backend, which analyzes them using deterministic heuristics and optionally generates plain-English explanations via Gemini. All risk classification is rule-based—AI is used only for explanations and tips. No user data is stored.

**Architecture:**

```
Content Script (content.js)
   ↓ extracts email / detects links / monitors downloads
Background Service Worker (background.js)
   ↓ relays to backend
FastAPI Backend (Python)
   ├── analysis/email.py       → phishing heuristics
   ├── analysis/link.py        → URL/domain checks
   ├── analysis/download.py    → file safety checks
   └── ai/gemini.py            → explanations & tips
   ↓
JSON response with severity, flags, explanation
```

---

## Project Structure

```
backend/
  main.py              # FastAPI entry point, CORS config
  api/analyze.py       # /analyze/email, /analyze/link, /analyze/download routes
  analysis/
    email.py           # Email heuristics (sender, subject, urgency, requests)
    link.py            # Link heuristics (HTTPS, domains, IP addresses, TLDs)
    download.py        # Download safety checks
  ai/gemini.py         # Gemini API integration
  models/schemas.py    # Pydantic request/response models
  tests/test_api.py    # API tests

extension/
  manifest.json        # Manifest V3 config
  background.js        # Service Worker (API relay)
  content.js           # Content script (extraction)
  popup.html/js        # Extension popup UI
  sidebar/             # Side panel UI (Manifest V3)
  images/              # Icons and assets
  styles.css

homepage/             # Landing page
pytest.ini
README.md
LICENSE
```

---

## API Endpoints

### `POST /analyze/email`

**Request:**
```json
{
  "sender": "support@example.com",
  "subject": "Urgent: Verify your account now!",
  "body": "Click here to confirm your password...",
  "links": ["http://phishing-site.xyz/verify"]
}
```

**Response:**
```json
{
  "severity": "high",
  "flags": ["Urgent language", "Suspicious sender domain", "Password requested"],
  "ai_explanation": "This email exhibits phishing characteristics...",
  "education_tip": "Verify through the official website instead of clicking links."
}
```

Severity levels: `no_risk`, `low`, `medium`, `high`, `critical`

---

### `POST /analyze/link`

**Request:**
```json
{
  "url": "http://192.168.1.1/login.exe"
}
```

**Response:**
```json
{
  "severity": "critical",
  "flags": ["No HTTPS", "IP address in URL", "Suspicious file extension"],
  "ai_explanation": "IP-based URLs bypass reputation checks. .exe suggests malware.",
  "education_tip": "Never download executables from unfamiliar links."
}
```

---

### `POST /analyze/download`

**Request:**
```json
{
  "filename": "Invoice_2024.exe",
  "size": 2097152,
  "content_type": "application/octet-stream"
}
```

**Response:**
```json
{
  "severity": "high",
  "flags": ["Executable disguised as document"],
  "ai_explanation": "Files claiming to be documents but with .exe extensions are common malware vectors.",
  "education_tip": "Verify file types. An invoice should be .pdf or .xlsx, not .exe."
}
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- Chrome or Chromium browser
- pip and venv (included with Python)
- Optional: Google Gemini API key (for AI explanations)

### Backend Setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

pip install fastapi uvicorn pydantic google-generativeai

# Optional: enable AI explanations
set GOOGLE_GEMINI_API_KEY=your-key  # Windows
# export GOOGLE_GEMINI_API_KEY=your-key  # macOS/Linux

uvicorn backend.main:app --reload --port 8000
```

API: [http://localhost:8000](http://localhost:8000)  
Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### Extension Installation

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked** and select the `extension/` folder
4. Ensure the backend is running before using the extension

---

## Implementation Status

This is an MVP built for HenHacks 2026. Core infrastructure is complete; analysis heuristics are partially implemented with TODO comments.

| Component | Status | Notes |
|---|---|---|
| API structure | ✓ | FastAPI routes, Pydantic validation, CORS |
| Email analysis | ⚠ | Basic checks implemented; TODO: NLP enhancements |
| Link analysis | ⚠ | Domain/protocol checks; TODO: threat feeds |
| Download analysis | ⚠ | File heuristics stubbed |
| Extension UI | ✓ | Popup, sidebar, tab switching |
| Gemini integration | ⚠ | Structure ready; TODO: real API calls, key handling |
| Tests | ⚠ | Basic tests present; TODO: expand coverage |

## Privacy

- No user data, emails, or URLs are stored
- Backend is stateless; each request is independent
- Only sanitized flag metadata sent to external services
- All scoring is deterministic—AI used only for explanations

## License

MIT – see [LICENSE](LICENSE) for details
