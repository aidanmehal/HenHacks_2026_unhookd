/**
 * content.js — Content script injected into every page by the unhookd extension.
 *
 * Responsibilities:
 *   1. EMAIL ANALYSIS: Detect when the user is reading an email and extract
 *      the sender, subject, body, and links from the DOM in real time.
 *   2. LINK ANALYSIS:  Detect when the user hovers over or clicks a link and
 *      forward the URL to the background service worker for analysis.
 *
 * Key design rules:
 *   - No backend calls from this file — always relay through background.js.
 *   - Extract only visible text / metadata — no raw HTML stored or sent.
 *   - Operations must be non-blocking so they don't interfere with the page.
 *   - Platform-agnostic: selectors are intentionally generic and should work
 *     across multiple email clients (Gmail, Outlook Web, etc.).
 *
 * TODO: Add platform-specific selector sets for Gmail, Outlook Web, etc.
 */

"use strict";

// 
// Constants
// 

/**
 * Minimum content length (chars) required before triggering an email analysis.
 * Avoids premature analysis before the DOM is fully populated.
 */
const MIN_BODY_LENGTH = 50;

/**
 * Debounce delay (ms) for DOM-mutation-triggered email extraction.
 * Prevents excessive analysis calls while the user types or the page loads.
 */
const EMAIL_DEBOUNCE_MS = 800;

/**
 * Debounce delay (ms) for link-hover analysis.
 * A hover must last this long before triggering an analysis request.
 */
const LINK_HOVER_DEBOUNCE_MS = 400;


// 
// Utility: simple debounce
// 

/**
 * Returns a debounced version of `fn` that waits `delay` ms after the last
 * call before executing.
 *
 * @param {Function} fn
 * @param {number}   delay - Milliseconds.
 * @returns {Function}
 */
function debounce(fn, delay) {
  let timerId = null;
  return (...args) => {
    clearTimeout(timerId);
    timerId = setTimeout(() => fn(...args), delay);
  };
}


// 
// Email extraction helpers (platform-agnostic stubs)
// 

/**
 * Attempt to extract email metadata from the current page's DOM.
 *
 * Returns null if the page doesn't appear to contain a readable email.
 * All selectors are STUBBED — replace with real, tested selectors per client.
 *
 * @returns {{ sender: string, subject: string, body: string, links: string[] } | null}
 *
 * TODO: Add Gmail-specific selectors (data-message-id containers).
 * TODO: Add Outlook Web-specific selectors.
 * TODO: Detect which email client is active and use the correct extractor.
 */
function extractEmailFromDOM() {
  // --- STUB selectors: replace with client-specific, validated selectors ---

  const senderEl  = document.querySelector("[data-sender], .sender, .from-address");
  const subjectEl = document.querySelector("[data-subject], .subject, h1.email-subject");
  const bodyEl    = document.querySelector("[data-body], .email-body, .message-body, article");

  // If we can't find the basics, this page probably isn't an email view
  if (!bodyEl) return null;

  const bodyText = bodyEl.innerText || bodyEl.textContent || "";
  if (bodyText.trim().length < MIN_BODY_LENGTH) return null;

  // Extract all hrefs from the email body region
  const linkEls = bodyEl.querySelectorAll("a[href]");
  const links   = Array.from(linkEls)
    .map(a => a.href)
    .filter(href => href.startsWith("http")); // Exclude mailto:, tel:, etc.

  return {
    sender:  senderEl?.innerText?.trim()  ?? "",
    subject: subjectEl?.innerText?.trim() ?? document.title ?? "",
    body:    bodyText.trim(),
    links,
  };
}

/**
 * Trigger a one-shot scan for the current page.
 *
 * This is used by popup.js so the extension can be tested on ordinary pages
 * without waiting for hover events or client-specific email selectors.
 *
 * Returns:
 *   - email scan if the page looks like an email view
 *   - link scan using the current page URL if it is http(s)
 */
function scanCurrentPageNow() {
  const emailData = extractEmailFromDOM();
  if (emailData) {
    chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", payload: emailData }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[unhookd] Background not responding:", chrome.runtime.lastError.message);
        return;
      }

      if (response?.success) {
        console.debug("[unhookd] Email analysis complete:", response.data);
      } else {
        console.warn("[unhookd] Email analysis failed:", response?.error);
      }
    });
  }

  const pageUrl = window.location.href;
  if (pageUrl && pageUrl.startsWith("http")) {
    chrome.runtime.sendMessage({ type: "ANALYZE_LINK", payload: { url: pageUrl } }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[unhookd] Background not responding:", chrome.runtime.lastError.message);
        return;
      }

      if (response?.success) {
        console.debug("[unhookd] Link analysis complete:", response.data);
      } else {
        console.warn("[unhookd] Link analysis failed:", response?.error);
      }
    });
  }

  return {
    attemptedEmail: Boolean(emailData),
    attemptedLink: Boolean(pageUrl && pageUrl.startsWith("http")),
    scannedUrl: pageUrl && pageUrl.startsWith("http") ? pageUrl : null,
  };
}


// 
// Email analysis trigger
// 

/**
 * Extract email content and forward it to background.js for analysis.
 * Silently does nothing if no email content is found on the page.
 *
 * TODO: Add result.data handling — e.g. show an inline badge on the email.
 */
function triggerEmailAnalysis() {
  const emailData = extractEmailFromDOM();
  if (!emailData) return;

  chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", payload: emailData }, (response) => {
    if (chrome.runtime.lastError) {
      // Service worker may be inactive — this is expected occasionally in MV3
      console.warn("[unhookd] Background not responding:", chrome.runtime.lastError.message);
      return;
    }

    if (response?.success) {
      // TODO: Optionally surface a subtle inline risk indicator on the email UI
      console.debug("[unhookd] Email analysis complete:", response.data);
    } else {
      console.warn("[unhookd] Email analysis failed:", response?.error);
    }
  });
}

const debouncedEmailAnalysis = debounce(triggerEmailAnalysis, EMAIL_DEBOUNCE_MS);


// 
// Link analysis trigger
// 

/**
 * Per-link hover timeout handles, keyed by element reference.
 * Allows clearing the timeout if the user moves the mouse off quickly.
 * @type {WeakMap<HTMLElement, ReturnType<typeof setTimeout>>}
 */
const linkHoverTimers = new WeakMap();

/**
 * Handle a mouseenter event on an <a> element.
 * Starts a debounce timer — if the hover persists, sends the URL for analysis.
 *
 * @param {MouseEvent} event
 */
function onLinkMouseEnter(event) {
  const anchor = event.currentTarget;
  const url    = anchor.href;

  if (!url || !url.startsWith("http")) return; // Skip non-http links

  const timer = setTimeout(() => {
    chrome.runtime.sendMessage({ type: "ANALYZE_LINK", payload: { url } }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[unhookd] Background not responding:", chrome.runtime.lastError.message);
        return;
      }

      if (response?.success) {
        // TODO: Show a tooltip / inline badge near the link with the risk score
        console.debug("[unhookd] Link analysis complete:", response.data);
      } else {
        console.warn("[unhookd] Link analysis failed:", response?.error);
      }
    });
  }, LINK_HOVER_DEBOUNCE_MS);

  linkHoverTimers.set(anchor, timer);
}

/**
 * Handle a mouseleave event on an <a> element.
 * Clears the pending analysis timer if the user moved off before it fired.
 *
 * @param {MouseEvent} event
 */
function onLinkMouseLeave(event) {
  const anchor = event.currentTarget;
  const timer  = linkHoverTimers.get(anchor);
  if (timer !== undefined) {
    clearTimeout(timer);
    linkHoverTimers.delete(anchor);
  }
}

/**
 * Attach hover listeners to all <a> elements currently in the DOM.
 * Called once on load and again whenever new nodes are added (MutationObserver).
 *
 * TODO: Use event delegation on document.body instead of per-element listeners
 *       to avoid repeated addEventListener calls on the same element.
 */
function attachLinkListeners() {
  const anchors = document.querySelectorAll("a[href]");
  anchors.forEach(anchor => {
    // Guard: avoid attaching the same listeners twice
    if (anchor.dataset.unhookdListening) return;
    anchor.dataset.unhookdListening = "true";

    anchor.addEventListener("mouseenter", onLinkMouseEnter);
    anchor.addEventListener("mouseleave", onLinkMouseLeave);
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "SCAN_CURRENT_PAGE") {
    return false;
  }

  try {
    sendResponse({ success: true, data: scanCurrentPageNow() });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }

  return true;
});


// 
// DOM mutation observer — re-run extraction as the page updates dynamically
// 

const observer = new MutationObserver(() => {
  // Re-attach link listeners on newly added anchor elements
  attachLinkListeners();

  // Re-run email extraction in case new email content appeared
  debouncedEmailAnalysis();
});

observer.observe(document.body, {
  childList: true,
  subtree:   true,
});


// 
// Initial run
// 

attachLinkListeners();
debouncedEmailAnalysis();
