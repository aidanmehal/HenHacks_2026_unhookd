/**
 * background.js — Service worker for the unhookd Chrome extension.
 *
 * Responsibilities:
 *   1. Receive analysis requests forwarded by content.js.
 *   2. Send those requests to the unhookd backend API.
 *   3. Receive the JSON risk-assessment response.
 *   4. Cache the latest result and forward it to the popup UI.
 *
 * All backend communication happens here so that:
 *   - content.js stays lightweight and focused on extraction.
 *   - API base URLs are managed in one place.
 *   - Responses can be cached to avoid redundant API calls.
 *
 * Manifest V3 note: service workers are ephemeral — do not rely on
 * in-memory state persisting between events. Use chrome.storage.session
 * for transient state (TODO).
 */

"use strict";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Base URL of the unhookd FastAPI backend. Change for production. */
const API_BASE_URL = "http://localhost:8000";


// ---------------------------------------------------------------------------
// Message handler — listens to messages from content.js
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  /**
   * Message contract (from content.js):
   *   { type: "ANALYZE_EMAIL", payload: { sender, subject, body, links } }
   *   { type: "ANALYZE_LINK",  payload: { url } }
   *
   * Responds via sendResponse() with the raw API JSON or an error object.
   *
   * NOTE: returning `true` from the listener is required to keep the
   * message channel open for async sendResponse calls.
   */

  if (message.type === "ANALYZE_EMAIL") {
    handleEmailAnalysis(message.payload)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err  => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }

  if (message.type === "ANALYZE_LINK") {
    handleLinkAnalysis(message.payload)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err  => sendResponse({ success: false, error: err.message }));
    return true;
  }

  // Unknown message type — ignore silently
  return false;
});


// ---------------------------------------------------------------------------
// API call helpers
// ---------------------------------------------------------------------------

/**
 * Send email metadata to the backend and return the risk assessment.
 *
 * @param {Object} payload
 * @param {string} payload.sender   - Sender email address.
 * @param {string} payload.subject  - Email subject.
 * @param {string} payload.body     - Email body (plain text).
 * @param {string[]} payload.links  - URLs extracted from the email.
 * @returns {Promise<Object>}        Parsed JSON from /analyze/email.
 *
 * TODO: Add request timeout (AbortController).
 * TODO: Add retry logic for transient network errors.
 */
async function handleEmailAnalysis({ sender, subject, body, links = [] }) {
  const response = await fetch(`${API_BASE_URL}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sender, subject, body, links }),
  });

  if (!response.ok) {
    throw new Error(`Backend error: ${response.status} ${response.statusText}`);
  }

  const result = await response.json();

  // Cache the latest email result for the popup to read on open
  // TODO: Use chrome.storage.session once Chrome 102+ is a safe minimum target
  await chrome.storage.local.set({ latestEmailResult: result });

  return result;
}

/**
 * Send a URL to the backend and return the link risk assessment.
 *
 * @param {Object} payload
 * @param {string} payload.url  - The URL to analyse.
 * @returns {Promise<Object>}    Parsed JSON from /analyze/link.
 *
 * TODO: Debounce rapid link-hover events to avoid flooding the API.
 */
async function handleLinkAnalysis({ url }) {
  const response = await fetch(`${API_BASE_URL}/analyze/link`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error(`Backend error: ${response.status} ${response.statusText}`);
  }

  const result = await response.json();

  // Cache the latest link result for the popup to read on open
  await chrome.storage.local.set({ latestLinkResult: result });

  return result;
}
