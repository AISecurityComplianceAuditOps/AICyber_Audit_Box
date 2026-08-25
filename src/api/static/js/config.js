// ── GLOBAL STATE & UTILITY HELPERS ──
var API_BASE = window.location.origin + "/api";

var activeSessionId = null;
var currentUser = null;
var selectedRole = "auditor";
var selectedAnalysisMode = "Deep";
var selectedScopeControlIds = [];
var findingsList = [];

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showToast(msg, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; z-index: 99999;
        background: ${type === 'error' ? '#ef4444' : (type === 'warning' ? '#f59e0b' : '#10b981')};
        color: #fff; padding: 12px 20px; border-radius: 10px; font-weight: 600;
        font-size: 0.88rem; box-shadow: 0 10px 25px rgba(0,0,0,0.3); transition: all 0.3s ease;
    `;
    toast.innerText = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// Sentry error tracking — no-op unless both the vendored SDK file and a DSN are
// present (see qa/monitoring/README.md). Never loaded from a CDN: this app is
// offline-first, so the SDK must be vendored locally like llama-server.exe/GGUF models.
function initSentryIfConfigured() {
    if (typeof window.Sentry === "undefined" || !window.SENTRY_DSN) return;
    window.Sentry.init({ dsn: window.SENTRY_DSN, tracesSampleRate: 0.1 });
}
initSentryIfConfigured();

function isFindingCompliant(f) {
    const polRaw = String(f.policy_present || "No").trim().toLowerCase();
    const evRaw = String(f.evidence_present || "No").trim().toLowerCase();
    const isPolCompliant = (polRaw === "yes" || polRaw === "compliant" || polRaw === "true");
    const isEvCompliant = (evRaw === "yes" || evRaw === "compliant" || evRaw === "true");
    if (!isPolCompliant || !isEvCompliant) return false;

    const s = (f.status || "").toUpperCase();
    return s === "COMPLIANT" || s === "ACCEPTED" || s === "PASS" || s === "SUCCESS";
}
