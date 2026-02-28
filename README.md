# unhookd

A real-time phishing and malicious-link detection tool built for **HenHacks 2026**  Security & Safety category.

unhookd is a Chrome extension that analyses email content and web links as you browse, giving you an immediate, plain-English risk assessment without storing any of your data.

---

## How It Works

```
Chrome Extension (content.js)
        |
        | extracts email text / detects hovered links
        v
Background Service Worker (background.js)
        |
        | POST /analyze/email  or  POST /analyze/link
        v
FastAPI Backend (Python)
        |
        |-- analysis/email.py   rule-based phishing heuristics
        |-- analysis/link.py    URL safety heuristics
        |-- utils/scoring.py    weighted flag  0-100 risk score
        |-- ai/gemini.py        Gemini API (explanation + tip only)
        v
JSON response    background.js    popup.html
```

AI (Gemini) is used **only** to explain risk factors in plain English and generate educational tips.  
All scoring decisions are made by deterministic heuristics  never by the AI model.  
No email content or URLs are stored anywhere.

---

## Project Structure

```
unhookd/
 backend/
    main.py                # FastAPI app entry point
    api/
       analyze.py         # /analyze/email  and  /analyze/link  routes
    analysis/
       email.py           # Email phishing heuristics
       link.py            # Link & download heuristics
    ai/
       gemini.py          # Gemini explanation logic
    models/
       schemas.py         # Pydantic request/response models
    utils/
        scoring.py         # Risk score calculation

 extension/
    manifest.json          # Manifest V3 config
    background.js          # Service worker  API relay
    content.js             # Email + link extraction
    popup.html             # Popup UI layout
    popup.js               # Popup render logic
    styles.css             # Popup styles

 .gitignore
 README.md
```

---

## API Endpoints

### `POST /analyze/email`

**Request**
```json
{
  "sender":  "support@suspicious-domain.com",
  "subject": "Urgent: Verify your account now!",
  "body":    "Please confirm your password immediately...",
  "links":   ["http://click-here-now.xyz/verify"]
}
```

**Response**
```json
{
  "risk_score":      72,
  "flags":           ["Urgent Language", "Suspicious Sender Domain"],
  "ai_explanation":  "This email shows characteristics common in phishing attempts...",
  "education_tip":   "Navigate directly to the company website instead of clicking links."
}
```

---

### `POST /analyze/link`

**Request**
```json
{
  "url": "http://192.168.1.1/login.exe"
}
```

**Response**
```json
{
  "risk_score":     85,
  "flags":          ["No Https", "Ip Address Url", "Suspicious File Extension"],
  "ai_explanation": "This link has characteristics that may indicate it is unsafe..."
}
```

---

## Getting Started

### Backend

**Requirements:** Python 3.11+

```bash
# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# Install dependencies
pip install fastapi uvicorn pydantic

# Run the development server
uvicorn backend.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the `extension/` folder
4. The unhookd icon will appear in your toolbar

Make sure the backend is running before using the extension.

---

## Development Status

This is a hackathon MVP skeleton. All heuristic logic is stubbed with `TODO` comments marking where real implementations should go. The Gemini integration is also stubbed  no API keys are included or required to run the skeleton.

### Key TODO areas

| File | What to implement |
|---|---|
| `analysis/email.py` | Real phishing heuristics, NLP intent detection |
| `analysis/link.py`  | DNS/WHOIS lookups, threat-intel feed integration |
| `utils/scoring.py`  | Weight tuning, compounding logic |
| `ai/gemini.py`      | Real Gemini API calls (key via environment variable) |
| `content.js`        | Platform-specific DOM selectors for Gmail / Outlook Web |
| `popup.js`          | Scan now button, result history |

---

## Privacy

- No user data, email content, or URLs are stored.
- The backend is stateless  each request is independent.
- Only sanitised flag metadata (not raw content) is sent to the Gemini API.

---

## License

MIT  see LICENSE
