/**
 * popup.js — Logic for the unhookd extension popup UI.
 *
 * Responsibilities:
 *   1. On open, read the latest cached analysis results from chrome.storage.
 *   2. Render risk score, flags, AI explanation, and education tip.
 *   3. Handle tab switching between Email and Link result panels.
 *   4. Apply visual risk-level styling based on the score.
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
// Risk level thresholds
// 

/**
 * Map a 0–100 risk score to a human-readable risk level and CSS class.
 *
 * @param {number} score
 * @returns {{ label: string, cssClass: string }}
 */
function getRiskLevel(score) {
  if (score === null || score === undefined) {
    return { label: "Unknown",  cssClass: "badge--unknown" };
  }
  if (score <= 20) return { label: "Low Risk",      cssClass: "badge--low"    };
  if (score <= 50) return { label: "Moderate Risk", cssClass: "badge--medium" };
  if (score <= 75) return { label: "High Risk",     cssClass: "badge--high"   };
  return               { label: "Critical Risk",  cssClass: "badge--critical" };
}


// 
// DOM helpers
// 

/**
 * Render a score, risk badge, flag list, and explanation into a panel.
 *
 * @param {Object} params
 * @param {string}        params.scoreId       - ID of the score <span>.
 * @param {string}        params.badgeId        - ID of the badge <span>.
 * @param {string}        params.flagsId        - ID of the flags <ul>.
 * @param {string}        params.explanationId  - ID of the explanation <p>.
 * @param {string|null}   params.tipId          - ID of the tip <p> (email panel only).
 * @param {Object|null}   params.data           - The cached API result object, or null.
 */
function renderPanel({ scoreId, badgeId, flagsId, explanationId, tipId = null, data }) {
  const scoreEl       = document.getElementById(scoreId);
  const badgeEl       = document.getElementById(badgeId);
  const flagsEl       = document.getElementById(flagsId);
  const explanationEl = document.getElementById(explanationId);
  const tipEl         = tipId ? document.getElementById(tipId) : null;

  if (!data) {
    // No cached result available — show default "waiting" state
    scoreEl.textContent       = "--";
    badgeEl.textContent       = "No scan yet";
    badgeEl.className         = "risk-badge badge--unknown";
    flagsEl.innerHTML         = '<li class="flag-item flag-item--empty">No data — browse to a page or email to trigger a scan</li>';
    if (explanationEl) explanationEl.textContent = "No scan data available yet.";
    if (tipEl)         tipEl.textContent         = "Visit an email or web page to start scanning.";
    return;
  }

  // Score
  const score = data.risk_score ?? 0;
  scoreEl.textContent = score;

  // Apply colour-coded class to score value
  const { label, cssClass } = getRiskLevel(score);
  scoreEl.className = `score-value score--${cssClass.replace("badge--", "")}`;

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
function initTabs() {
  const emailTab  = document.getElementById("tab-email");
  const linkTab   = document.getElementById("tab-link");
  const emailPanel = document.getElementById("panel-email");
  const linkPanel  = document.getElementById("panel-link");

  emailTab.addEventListener("click", () => {
    emailTab.classList.add("tab-btn--active");
    emailTab.setAttribute("aria-selected", "true");
    linkTab.classList.remove("tab-btn--active");
    linkTab.setAttribute("aria-selected", "false");

    emailPanel.classList.remove("result-panel--hidden");
    linkPanel.classList.add("result-panel--hidden");
  });

  linkTab.addEventListener("click", () => {
    linkTab.classList.add("tab-btn--active");
    linkTab.setAttribute("aria-selected", "true");
    emailTab.classList.remove("tab-btn--active");
    emailTab.setAttribute("aria-selected", "false");

    linkPanel.classList.remove("result-panel--hidden");
    emailPanel.classList.add("result-panel--hidden");
  });
}


// 
// Initialisation — runs when popup DOM is ready
// 



// 
// Floating button handlers
// 

document.addEventListener("DOMContentLoaded", () => {
  // Handle floating Start button click
  const floatingStartBtn = document.getElementById("floatingStartBtn");
  const stopBtn = document.getElementById("stopBtn");
  const mainContent = document.getElementById("mainContent");

  if (floatingStartBtn) {
    floatingStartBtn.addEventListener("click", () => {
      mainContent.style.display = "block";
      floatingStartBtn.style.display = "none";
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", () => {
      mainContent.style.display = "none";
      floatingStartBtn.style.display = "block";
    });
  }

  initTabs();

  // Read the latest cached results written by background.js
  chrome.storage.local.get(["latestEmailResult", "latestLinkResult"], (stored) => {
    const emailData = stored.latestEmailResult ?? null;
    const linkData  = stored.latestLinkResult  ?? null;

    // Render email panel
    renderPanel({
      scoreId:      "email-score",
      badgeId:      "email-badge",
      flagsId:      "email-flags",
      explanationId: "email-explanation",
      tipId:        "email-tip",
      data:         emailData,
    });

    // Render link panel — also show the scanned URL if available
    // TODO: Store the scanned URL alongside the result in background.js
    renderPanel({
      scoreId:      "link-score",
      badgeId:      "link-badge",
      flagsId:      "link-flags",
      explanationId: "link-explanation",
      data:         linkData,
    });
  });
});
