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

// 
// Configuration
// 

/** Base URL of the unhookd FastAPI backend. Change for production. */
const API_BASE_URL = "http://localhost:8000";


function buildFallbackResult(kind, error, context = {}) {
  const message = error instanceof Error ? error.message : String(error || "Unknown error");
  const explanation = `The ${kind} scan could not reach the backend, so no live analysis was completed. ${message}`;

  if (kind === "email") {
    return {
      severity: "medium",
      flags: ["Backend unavailable"],
      ai_explanation: explanation,
      education_tip: "Check that the API server is running on http://localhost:8000, then reload the extension page.",
      ...context,
    };
  }

  return {
    severity: "medium",
    flags: ["Backend unavailable"],
    ai_explanation: explanation,
    ...context,
  };
}


// 
// Message handler — listens to messages from content.js
// 

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

  if (message.action === "closeSidebar") {
    // Handle sidebar close request
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.sidePanel.setOptions({ tabId: tabs[0].id, path: "" }, () => {
          if (chrome.runtime.lastError) {
            console.error("[unhookd] Error closing sidebar:", chrome.runtime.lastError);
          }
          sendResponse({ success: true });
        });
      }
    });
    return true;
  }

  // Unknown message type — ignore silently
  return false;
});


// 
// API call helpers
// 

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
// Helper: fetch with timeout and simple retry
async function fetchWithRetry(url, options = {}, { timeout = 5000, retries = 1 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const combined = { ...options, signal: controller.signal };
      const res = await fetch(url, combined);
      clearTimeout(id);
      if (!res.ok) throw new Error(`Backend error: ${res.status} ${res.statusText}`);
      return await res.json();
    } catch (err) {
      clearTimeout(id);
      if (err.name === 'AbortError') {
        if (attempt === retries) throw new Error('Request timed out');
      } else {
        if (attempt === retries) throw err;
      }
      // backoff before retrying
      await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempt)));
    }
  }
}

async function handleEmailAnalysis({ sender, subject, body, links = [] }) {
  let result;

  try {
    result = await fetchWithRetry(`${API_BASE_URL}/analyze/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, subject, body, links }),
    }, { timeout: 7000, retries: 1 });
  } catch (error) {
    result = buildFallbackResult("email", error);
  }

  await chrome.storage.local.set({ latestEmailResult: result });

  return result;
}

/**
 * Send a URL to the backend and return the link risk assessment.
 *
 * @param {Object} payload
 * @param {string} payload.url  - The URL to analyse.
 * @returns {Promise<Object>}    Parsed JSON from /analyze/link.
 */

async function _doHandleLinkAnalysis({ url }) {
  let result;

  try {
    result = await fetchWithRetry(`${API_BASE_URL}/analyze/link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    }, { timeout: 5000, retries: 1 });
  } catch (error) {
    result = buildFallbackResult("link", error);
  }

  await chrome.storage.local.set({
    latestLinkResult: result,
    latestLinkUrl: url,
  });

  return result;
}

const handleLinkAnalysis = _doHandleLinkAnalysis;
