/**
 * popup.js — Logic for the unhookd extension popup UI.
 *
 * Responsibilities:
 *   1. On open, read the latest cached analysis results from chrome.storage.
 *   2. Render severity, flags, AI explanation, and education tip.
 *   3. Handle tab switching between Email and Link result panels.
 *   4. Apply visual risk-level styling based on the returned severity.
 *
 * NOTE: The popup does NOT trigger analysis itself — content.js and
 * background.js handle that in real time.  The popup is a read-only view
 * of the most recently cached results.
 *
 * TODO: Add a "Scan now" button to force a re-analysis of the active tab.
 * TODO: Add a "Clear results" option for privacy-conscious users.
 */

"use strict";


//
// Severity metadata
//

/**
 * Map a severity string to a human-readable label and CSS class.
 *
 * @param {string|null|undefined} severity
 * @returns {{ label: string, cssClass: string }}
 */
function getSeverityMeta(severity) {
  switch ((severity || "").toLowerCase()) {
    case "low":
      return { label: "Low Risk", cssClass: "badge--low" };
    case "medium":
      return { label: "Medium Risk", cssClass: "badge--medium" };
    case "high":
      return { label: "High Risk", cssClass: "badge--high" };
    default:
      return { label: "Unknown", cssClass: "badge--unknown" };
  }
}


// 
// DOM helpers
// 

/**
 * Render severity, risk badge, flag list, and explanation into a panel.
 *
 * @param {Object} params
 * @param {string}        params.severityId    - ID of the severity <span>.
 * @param {string}        params.badgeId        - ID of the badge <span>.
 * @param {string}        params.flagsId        - ID of the flags <ul>.
 * @param {string}        params.explanationId  - ID of the explanation <p>.
 * @param {string|null}   params.tipId          - ID of the tip <p> (email panel only).
 * @param {string|null}   params.urlId          - ID of the scanned URL <p> (link panel only).
 * @param {string|null}   params.urlValue       - Last scanned URL.
 * @param {Object|null}   params.data           - The cached API result object, or null.
 */
function renderPanel({ severityId, badgeId, flagsId, explanationId, tipId = null, urlId = null, urlValue = null, data }) {
  const severityEl    = document.getElementById(severityId);
  const badgeEl       = document.getElementById(badgeId);
  const flagsEl       = document.getElementById(flagsId);
  const explanationEl = document.getElementById(explanationId);
  const tipEl         = tipId ? document.getElementById(tipId) : null;
  const urlEl         = urlId ? document.getElementById(urlId) : null;

  if (!severityEl || !badgeEl || !flagsEl || !explanationEl) {
    console.warn("[unhookd] Popup panel is missing one or more required DOM nodes.");
    return;
  }

  if (!data) {
    // No cached result available — show default "waiting" state
    severityEl.textContent    = "Waiting";
    severityEl.className      = "severity-value severity--unknown";
    badgeEl.textContent       = "No scan yet";
    badgeEl.className         = "risk-badge badge--unknown";
    flagsEl.innerHTML         = '<li class="flag-item flag-item--empty">No data — browse to a page or email to trigger a scan</li>';
    if (explanationEl) explanationEl.textContent = "No scan data available yet.";
    if (tipEl)         tipEl.textContent         = "Visit an email or web page to start scanning.";
    if (urlEl)         urlEl.textContent         = "Hover over a link to scan it";
    return;
  }

  const severity = (data.severity || "unknown").toLowerCase();
  const { label, cssClass } = getSeverityMeta(severity);
  severityEl.textContent = severity.charAt(0).toUpperCase() + severity.slice(1);
  severityEl.className = `severity-value severity--${cssClass.replace("badge--", "")}`;

  // Badge
  badgeEl.textContent = label;
  badgeEl.className   = `risk-badge ${cssClass}`;

  // Flags
  const flags = data.flags ?? [];
  if (flags.length === 0) {
    flagsEl.innerHTML = '<li class="flag-item flag-item--clean">&#x2714; No issues detected</li>';
  } else {
    flagsEl.innerHTML = flags
      .map(flag => `<li class="flag-item">&#x26A0; ${escapeHtml(flag)}</li>`)
      .join("");
  }

  // AI explanation
  if (explanationEl) {
    explanationEl.textContent = data.ai_explanation ?? "No explanation available.";
  }

  // Educational tip (email panel only)
  if (tipEl) {
    tipEl.textContent = data.education_tip ?? "No tip available.";
  }

  if (urlEl) {
    urlEl.textContent = urlValue ?? "Recently scanned link unavailable.";
  }
}

/**
 * Escape a string for safe insertion as HTML text content.
 * Prevents XSS from flag strings returned by the API.
 *
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}


// 
// Tab switching
// 

/**
 * Wire up the Email / Link tab buttons to show/hide the correct panel.
 */
function animatePanel(panel, show) {
  if (show) {
    panel.classList.remove("result-panel--hidden");
    // start from zero to measured height
    panel.style.maxHeight = "0px";
    // force a reflow
    panel.getBoundingClientRect();
    panel.style.maxHeight = panel.scrollHeight + "px";
    panel.addEventListener(
      "transitionend",
      () => {
        panel.style.maxHeight = ""; // reset to auto
      },
      { once: true }
    );
  } else {
    panel.style.maxHeight = panel.scrollHeight + "px";
    // trigger layout
    panel.getBoundingClientRect();
    panel.style.maxHeight = "0px";
    panel.addEventListener(
      "transitionend",
      () => {
        panel.classList.add("result-panel--hidden");
        panel.style.maxHeight = "";
      },
      { once: true }
    );
  }
}

// generic collapsible animator for main content using scale so height remains unchanged
function animateCollapse(el, show, callback) {
  const isMain = el.id === "mainContent";
  if (isMain) {
    if (show) {
      el.classList.remove("collapsed");
    } else {
      el.classList.add("collapsed");
    }
    if (callback) {
      el.addEventListener(
        "transitionend",
        function handler() {
          el.removeEventListener("transitionend", handler);
          callback();
        }
      );
    }
  } else {
    // fallback to previous behaviour for other elements
    if (show) {
      el.classList.remove("result-panel--hidden");
      el.style.maxHeight = "0px";
      el.getBoundingClientRect();
      el.style.maxHeight = el.scrollHeight + "px";
      el.addEventListener(
        "transitionend",
        () => {
          el.style.maxHeight = "";
        },
        { once: true }
      );
    } else {
      el.style.maxHeight = el.scrollHeight + "px";
      el.getBoundingClientRect();
      el.style.maxHeight = "0px";
      el.addEventListener(
        "transitionend",
        () => {
          el.classList.add("result-panel--hidden");
          el.style.maxHeight = "";
        },
        { once: true }
      );
    }
  }
}

function initTabs() {
  const emailTab = document.getElementById("tab-email");
  const linkTab = document.getElementById("tab-link");
  const emailPanel = document.getElementById("panel-email");
  const linkPanel = document.getElementById("panel-link");

  emailTab.addEventListener("click", () => {
    emailTab.classList.add("tab-btn--active");
    emailTab.setAttribute("aria-selected", "true");
    linkTab.classList.remove("tab-btn--active");
    linkTab.setAttribute("aria-selected", "false");

    animatePanel(emailPanel, true);
    animatePanel(linkPanel, false);
  });

  linkTab.addEventListener("click", () => {
    linkTab.classList.add("tab-btn--active");
    linkTab.setAttribute("aria-selected", "true");
    emailTab.classList.remove("tab-btn--active");
    emailTab.setAttribute("aria-selected", "false");

    animatePanel(linkPanel, true);
    animatePanel(emailPanel, false);
  });
}


//
// Rendering orchestration
//

function renderStoredResults(stored) {
  const emailData = stored.latestEmailResult ?? null;
  const linkData  = stored.latestLinkResult  ?? null;
  const linkUrl   = stored.latestLinkUrl ?? null;

  renderPanel({
    severityId:   "email-severity",
    badgeId:      "email-badge",
    flagsId:      "email-flags",
    explanationId: "email-explanation",
    tipId:        "email-tip",
    data:         emailData,
  });

  renderPanel({
    severityId:   "link-severity",
    badgeId:      "link-badge",
    flagsId:      "link-flags",
    explanationId: "link-explanation",
    urlId:        "link-url",
    urlValue:     linkUrl,
    data:         linkData,
  });
}


//
// Initialisation — runs when popup DOM is ready
//

document.addEventListener("DOMContentLoaded", () => {
  // Handle toggle button
  const toggleBtn = document.getElementById("toggleBtn");
  const mainContent = document.getElementById("mainContent");
  let isExpanded = false;

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      isExpanded = !isExpanded;
      if (isExpanded) {
        toggleBtn.textContent = "STOP";
        toggleBtn.classList.add("stop-state");
        document.body.classList.add("expanded");
        mainContent.classList.add("fixed-height");
        animateCollapse(mainContent, true);
        document.body.classList.add("button-hidden");
      } else {
        toggleBtn.textContent = "GO PHISH";
        toggleBtn.classList.remove("stop-state");
        animateCollapse(mainContent, false);
        mainContent.classList.remove("fixed-height");
        document.body.classList.remove("expanded");
        document.body.classList.remove("button-hidden");
      }
    });
  }

  initTabs();

  // Read the latest cached results written by background.js
  chrome.storage.local.get(["latestEmailResult", "latestLinkResult", "latestLinkUrl"], renderStoredResults);

  // Keep the popup in sync if a scan finishes while it is open.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;

    if (!changes.latestEmailResult && !changes.latestLinkResult && !changes.latestLinkUrl) {
      return;
    }

    chrome.storage.local.get(["latestEmailResult", "latestLinkResult", "latestLinkUrl"], renderStoredResults);
  });
});
