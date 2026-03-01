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
const MIN_BODY_LENGTH = 20;

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
const EMAIL_REPEAT_SUPPRESSION_MS = 4_000;
const LINK_REPEAT_SUPPRESSION_MS = 2_000;

let lastEmailFingerprint = null;
let lastEmailSentAt = 0;
let emailRetryTimer = null;
let lastLinkUrl = "";
let lastLinkSentAt = 0;
let lastObservedPageUrl = window.location.href;


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


function getTextFromSelectors(selectors) {
  for (const selector of selectors) {
    const el = document.querySelector(selector);
    const text = el?.innerText?.trim() || el?.textContent?.trim() || "";
    if (text) {
      return text;
    }
  }

  return "";
}


function getFirstElement(selectors) {
  for (const selector of selectors) {
    const el = document.querySelector(selector);
    if (el) {
      return el;
    }
  }

  return null;
}


function isVisibleElement(element) {
  if (!element || typeof element.getBoundingClientRect !== "function") {
    return false;
  }

  const style = window.getComputedStyle(element);
  if (style.display === "none" || style.visibility === "hidden") {
    return false;
  }

  const rect = element.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}


function buildEmailFingerprint({ sender = "", subject = "", body = "", links = [] }) {
  return JSON.stringify({
    sender: sender.trim().toLowerCase(),
    subject: subject.trim(),
    body: body.trim().slice(0, 800),
    links: [...links].sort(),
  });
}


function isExtensionContextAvailable() {
  try {
    return Boolean(globalThis.chrome?.runtime?.id);
  } catch (error) {
    return false;
  }
}


function safeSendRuntimeMessage(message, callback = null) {
  if (!isExtensionContextAvailable()) {
    return false;
  }

  try {
    chrome.runtime.sendMessage(message, callback);
    return true;
  } catch (error) {
    console.debug("[unhookd] Extension context invalidated; skipping message.");
    return false;
  }
}


function findBestEmailBodyElement() {
  const candidates = [
    ...document.querySelectorAll(".ii.gt div.a3s.aiL"),
    ...document.querySelectorAll(".ii.gt div.a3s"),
    ...document.querySelectorAll(".ii.gt div[dir='ltr']"),
    ...document.querySelectorAll("div.a3s.aiL"),
    ...document.querySelectorAll("div.a3s"),
    ...document.querySelectorAll("[data-message-id] div[dir='ltr']"),
    ...document.querySelectorAll("[role='main'] div[dir='ltr']"),
    ...document.querySelectorAll("[data-body], .email-body, .message-body, article"),
  ];

  let best = null;
  let bestLength = 0;

  for (const candidate of candidates) {
    if (!isVisibleElement(candidate)) {
      continue;
    }

    const text = (candidate.innerText || candidate.textContent || "").trim();
    if (text.length < MIN_BODY_LENGTH) {
      continue;
    }

    if (text.length > bestLength) {
      best = candidate;
      bestLength = text.length;
    }
  }

  return best;
}


function findSenderText() {
  const selectors = [
    "h3.iw span[email]",
    "span[email]",
    ".gD[email]",
    ".gD",
    "[data-hovercard-id]",
    "[aria-label^='From:']",
    "[data-sender]",
    ".sender",
    ".from-address",
  ];

  for (const selector of selectors) {
    const elements = document.querySelectorAll(selector);
    for (const element of elements) {
      if (!isVisibleElement(element)) {
        continue;
      }

      const text = element.getAttribute?.("email")?.trim()
        || element.innerText?.trim()
        || element.textContent?.trim()
        || "";
      if (text) {
        return text;
      }
    }
  }

  return "";
}


function findSubjectText() {
  const selectors = [
    "h2.hP",
    "h2[data-legacy-thread-id]",
    "h2[data-thread-perm-id]",
    "[role='main'] h2",
    "[data-subject]",
    ".subject",
    "h1.email-subject",
  ];

  for (const selector of selectors) {
    const elements = document.querySelectorAll(selector);
    for (const element of elements) {
      if (!isVisibleElement(element)) {
        continue;
      }

      const text = element.innerText?.trim() || element.textContent?.trim() || "";
      if (text) {
        return text;
      }
    }
  }

  return document.title || "";
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
  const sender = findSenderText();
  const subject = findSubjectText();
  const bodyEl = findBestEmailBodyElement() || getFirstElement([
    "div.a3s",
    "[role='listitem'] div[dir='ltr']",
    "[data-body]",
    ".email-body",
    ".message-body",
    "article",
  ]);

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
    sender:  sender,
    subject: subject || document.title || "",
    body:    bodyText.trim(),
    links,
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
function triggerEmailAnalysis({ force = false } = {}) {
  const emailData = extractEmailFromDOM();
  if (!emailData) {
    if (emailRetryTimer) {
      clearTimeout(emailRetryTimer);
    }
    emailRetryTimer = setTimeout(() => triggerEmailAnalysis({ force: true }), 1500);
    return;
  }

  if (emailRetryTimer) {
    clearTimeout(emailRetryTimer);
    emailRetryTimer = null;
  }

  const fingerprint = buildEmailFingerprint(emailData);
  const now = Date.now();
  if (!force && fingerprint === lastEmailFingerprint && (now - lastEmailSentAt) < EMAIL_REPEAT_SUPPRESSION_MS) {
    return;
  }

  const sent = safeSendRuntimeMessage({ type: "ANALYZE_EMAIL", payload: emailData });

  if (!sent) {
    lastEmailSentAt = 0;
    return;
  }

  lastEmailFingerprint = fingerprint;
  lastEmailSentAt = now;
}

const debouncedEmailAnalysis = debounce(triggerEmailAnalysis, EMAIL_DEBOUNCE_MS);


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "UNHOOKD_SCAN_PAGE") {
    return false;
  }

  const emailDetected = Boolean(extractEmailFromDOM());
  triggerEmailAnalysis();
  triggerCurrentPageLinkAnalysis();
  sendResponse({ started: true, emailDetected });
  return false;
});


// 
// Link analysis trigger
// 

/**
 * Per-link hover timeout handles, keyed by element reference.
 * Allows clearing the timeout if the user moves the mouse off quickly.
 * @type {WeakMap<HTMLElement, ReturnType<typeof setTimeout>>}
 */
const linkHoverTimers = new WeakMap();


function triggerLinkAnalysis(url, { force = false } = {}) {
  if (!url || !url.startsWith("http")) {
    return;
  }

  const normalizedUrl = url.trim();
  const now = Date.now();
  if (!force && normalizedUrl === lastLinkUrl && (now - lastLinkSentAt) < LINK_REPEAT_SUPPRESSION_MS) {
    return;
  }

  const sent = safeSendRuntimeMessage({ type: "ANALYZE_LINK", payload: { url: normalizedUrl } });
  if (!sent) {
    lastLinkSentAt = 0;
    return;
  }

  lastLinkUrl = normalizedUrl;
  lastLinkSentAt = now;
}

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
    triggerLinkAnalysis(url);
  }, LINK_HOVER_DEBOUNCE_MS);

  linkHoverTimers.set(anchor, timer);
}

/**
 * Trigger link analysis immediately when a link is clicked.
 * This is more reliable than hover-only flows on pages with dense dynamic DOMs.
 *
 * @param {MouseEvent} event
 */
function onLinkClick(event) {
  const anchor = event.currentTarget;
  const url = anchor.href;

  if (!url || !url.startsWith("http")) return;

  triggerLinkAnalysis(url, { force: true });
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

function findAnchorFromEventTarget(target) {
  if (!(target instanceof Element)) {
    return null;
  }

  return target.closest("a[href]");
}


function onDelegatedMouseOver(event) {
  const anchor = findAnchorFromEventTarget(event.target);
  if (!anchor) {
    return;
  }

  const related = event.relatedTarget;
  if (related instanceof Node && anchor.contains(related)) {
    return;
  }

  onLinkMouseEnter({ currentTarget: anchor });
}


function onDelegatedMouseOut(event) {
  const anchor = findAnchorFromEventTarget(event.target);
  if (!anchor) {
    return;
  }

  const related = event.relatedTarget;
  if (related instanceof Node && anchor.contains(related)) {
    return;
  }

  onLinkMouseLeave({ currentTarget: anchor });
}


function onDelegatedClick(event) {
  const anchor = findAnchorFromEventTarget(event.target);
  if (!anchor) {
    return;
  }

  onLinkClick({ currentTarget: anchor });
}


function triggerCurrentPageLinkAnalysis({ force = false } = {}) {
  const url = window.location.href;
  const urlChanged = url !== lastObservedPageUrl;
  if (urlChanged) {
    lastObservedPageUrl = url;
  }

  triggerLinkAnalysis(url, { force: force || urlChanged });
}


function patchHistoryForRealtimeLinkAnalysis() {
  const methods = ["pushState", "replaceState"];

  for (const methodName of methods) {
    const original = history[methodName];
    if (typeof original !== "function") {
      continue;
    }

    history[methodName] = function (...args) {
      const result = original.apply(this, args);
      triggerCurrentPageLinkAnalysis({ force: true });
      debouncedEmailAnalysis();
      return result;
    };
  }
}


// 
// DOM mutation observer — re-run extraction as the page updates dynamically
// 

const observer = new MutationObserver(() => {
  // Re-run email extraction in case new email content appeared
  debouncedEmailAnalysis();
  triggerCurrentPageLinkAnalysis();
});

observer.observe(document.body, {
  childList: true,
  subtree:   true,
});


// 
// Initial run
// 

debouncedEmailAnalysis();
patchHistoryForRealtimeLinkAnalysis();
document.addEventListener("mouseover", onDelegatedMouseOver, true);
document.addEventListener("mouseout", onDelegatedMouseOut, true);
document.addEventListener("click", onDelegatedClick, true);
triggerCurrentPageLinkAnalysis({ force: true });

document.addEventListener("click", () => {
  debouncedEmailAnalysis();
}, true);

document.addEventListener("keyup", () => {
  debouncedEmailAnalysis();
}, true);

window.addEventListener("focus", () => {
  debouncedEmailAnalysis();
  triggerCurrentPageLinkAnalysis();
});

window.addEventListener("hashchange", () => {
  triggerCurrentPageLinkAnalysis({ force: true });
  debouncedEmailAnalysis();
});

window.addEventListener("popstate", () => {
  triggerCurrentPageLinkAnalysis({ force: true });
  debouncedEmailAnalysis();
});
