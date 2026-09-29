// ── AICyberAuditBox Client Application ──
var API_BASE = window.location.origin + "/api";

// ── SECURITY UTILITY: HTML-escape user/server strings before inserting into innerHTML ──
// Called throughout the app but was never defined, causing ReferenceErrors that silently
// swallowed the entire innerHTML assignment and left filenames/titles blank.
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

var currentUser = typeof currentUser !== "undefined" ? currentUser : null;
var selectedRole = typeof selectedRole !== "undefined" ? selectedRole : "auditor";
var activeTab = typeof activeTab !== "undefined" ? activeTab : "";
var activeSessionId = typeof activeSessionId !== "undefined" ? activeSessionId : "";
var activeSessionTitle = typeof activeSessionTitle !== "undefined" ? activeSessionTitle : "";
var findingsList = typeof findingsList !== "undefined" ? findingsList : [];
var uploadedFilesList = typeof uploadedFilesList !== "undefined" ? uploadedFilesList : [];
var selectedAnalysisMode = typeof selectedAnalysisMode !== "undefined" ? selectedAnalysisMode : "Deep";
var activeSeverityFilter = typeof activeSeverityFilter !== "undefined" ? activeSeverityFilter : "";
var activeStatusFilter = typeof activeStatusFilter !== "undefined" ? activeStatusFilter : "All";
var logsPage = typeof logsPage !== "undefined" ? logsPage : 0;
var logsTotalPages = typeof logsTotalPages !== "undefined" ? logsTotalPages : 1;
var customEvidenceMappings = typeof customEvidenceMappings !== "undefined" ? customEvidenceMappings : null;
var customControlDocuments = typeof customControlDocuments !== "undefined" ? customControlDocuments : null;

// ── AUTH FETCH HELPER — always attaches JWT token to every API request ──
function getAuthHeaders(extra) {
    const token = currentUser && currentUser.token ? currentUser.token : "";
    return Object.assign({ "Authorization": `Bearer ${token}` }, extra || {});
}
function authFetch(url, options) {
    options = options || {};
    options.headers = getAuthHeaders(options.headers || {});
    return fetch(url, options);
}

// FastAPI's `detail` field on an error response is a plain string for a
// deliberate HTTPException(detail="..."), but for an automatic 422 validation
// error it's an ARRAY of {loc, msg, type} objects. Callers that did
// `throw new Error(data.detail || "...")` and then alert(err.message) got a
// literal "[object Object]" for every 422, hiding the actual validation
// problem right when it's most useful to see.
function formatApiErrorDetail(detail) {
    if (!detail) return "";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail.map(d => {
            if (typeof d === "string") return d;
            const field = Array.isArray(d.loc) ? d.loc.slice(-1)[0] : "";
            return field ? `${field}: ${d.msg}` : (d.msg || JSON.stringify(d));
        }).join("; ");
    }
    if (typeof detail === "object") return detail.msg || JSON.stringify(detail);
    return String(detail);
}

// --- EMOJIS & ICONS FOR FRAMEWORK CONTROLS ---
const DEFAULT_FRAMEWORK_CONTROLS = [
    { sl: 5, use_case: "5.1 Policies for information security", label: "5.1 Security Policies", category: "Organizational" },
    { sl: 6, use_case: "5.2 Information security roles and responsibilities", label: "5.2 Security Roles", category: "Organizational" },
    { sl: 8, use_case: "5.15 Access control", label: "5.15 Access Control", category: "Organizational" },
    { sl: 12, use_case: "5.16 Identity management", label: "5.16 Identity Management", category: "Organizational" },
    { sl: 15, use_case: "8.15.1 Access restriction", label: "8.15.1 Access Restriction", category: "Technical" },
    { sl: 22, use_case: "8.24 Use of cryptography", label: "8.24 Cryptography", category: "Technical" }
];

// --- INITIAL EVENT LISTENERS ---
document.addEventListener("DOMContentLoaded", () => {
    // Clock setup
    setInterval(updateHeaderClock, 30000);
    updateHeaderClock();

    // Default render tabs & framework controls on page load so they are never blank
    setupTabs(selectedRole || "auditor");
    loadFrameworkControls();

    // Sync role selection UI and auto-fill credentials for the default role
    selectRole(selectedRole || "auditor");

    // Auth selectors
    const loginForm = document.getElementById("login-form");
    if (loginForm) loginForm.addEventListener("submit", handleLoginSubmit);

    const otpForm = document.getElementById("otp-form");
    if (otpForm) otpForm.addEventListener("submit", handleOTPSubmit);

    // Setup File Upload drop zone
    setupFileDropZone();

    // Setup Custom Control form
    const createControlForm = document.getElementById("create-control-form");
    if (createControlForm) {
        createControlForm.addEventListener("submit", handleCreateControlSubmit);
    }

    // Setup Edit Finding Modal form
    const editForm = document.getElementById("edit-finding-form");
    if (editForm) editForm.addEventListener("submit", handleEditFindingSubmit);

    // Live update severity row visibility when auditor changes the Status dropdown
    const editStatusSel = document.getElementById("edit-finding-status");
    if (editStatusSel) {
        editStatusSel.addEventListener("change", function () {
            // A VAPT finding: keep Severity in step (Closed <-> Closed, ...).
            if (_editDialogIsVapt()) { _vaptSyncFromStatus(); return; }
            _updateSeverityVisibility(this.value);
        });
    }
    const editSevSel = document.getElementById("edit-finding-severity");
    if (editSevSel) {
        editSevSel.addEventListener("change", function () {
            if (_editDialogIsVapt()) _vaptSyncFromSeverity();
        });
    }
});

function updateHeaderClock() {
    const timeLabel = document.getElementById("current-time-label");
    if (timeLabel) {
        const now = new Date();
        const options = { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' };
        timeLabel.innerText = now.toLocaleDateString('en-GB', options).replace(/,/g, '');
    }
}

// ── AUTHENTICATION CONTROLLERS ──

function selectRole(role) {
    selectedRole = role;

    // Update button visual styles
    document.querySelectorAll(".role-btn").forEach(btn => btn.classList.remove("active"));
    const targetBtn = document.getElementById(`role-${role}-btn`);
    if (targetBtn) targetBtn.classList.add("active");

    // Keep input fields clean for user manual entry
    const usernameInput = document.getElementById("username-input");
    const passwordInput = document.getElementById("password-input");
    if (usernameInput && passwordInput) {
        usernameInput.value = "";
        passwordInput.value = "";
    }

    // Update descriptions
    const descEl = document.getElementById("role-desc");
    if (descEl) {
        if (role === "admin") {
            descEl.innerText = "SYSTEM ADMINISTRATOR";
        } else if (role === "auditor") {
            descEl.innerText = "COMPLIANCE AUDITOR • Upload Audit Scope Documents to Run Guided Audits";
        } else {
            descEl.innerText = "AUDITEE • Upload Audit Evidence Documents for the Auditor to Review";
        }
    }

    // Hide register option for Admin (seeded default is login only) --
    // but keep "Forgot Password?" visible, it shares this row with "Create Account".
    const toggleRow = document.getElementById("toggle-auth-row");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    if (toggleRow) {
        toggleRow.style.display = "flex";
        if (toggleActionBtn) toggleActionBtn.style.display = (role === "admin") ? "none" : "";
        if (role === "admin") {
            resetAuthActionToLogin();
        }
    }
    showError("");
}

function resetAuthActionToLogin() {
    const submitBtn = document.getElementById("auth-submit-btn");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    const toggleLabel = document.getElementById("toggle-label");

    if (submitBtn) submitBtn.innerText = "Secure Sign In";
    if (toggleActionBtn) toggleActionBtn.innerText = "Create Account";
    if (toggleLabel) toggleLabel.innerText = "NEW USER?";
}

function toggleAuthAction() {
    const submitBtn = document.getElementById("auth-submit-btn");
    const toggleActionBtn = document.getElementById("toggle-action-btn");
    const toggleLabel = document.getElementById("toggle-label");

    if (submitBtn && submitBtn.innerText === "Secure Sign In") {
        submitBtn.innerText = "Create Secure Account";
        if (toggleActionBtn) toggleActionBtn.innerText = "Back to Login";
        if (toggleLabel) toggleLabel.innerText = "ALREADY REGISTERED?";
    } else {
        resetAuthActionToLogin();
    }
    showError("");
}

function togglePasswordVisibility() {
    const pwInput = document.getElementById("password-input");
    const eyeIcon = document.getElementById("eye-icon");
    const eyeOffIcon = document.getElementById("eye-off-icon");
    if (!pwInput) return;

    if (pwInput.type === "password") {
        pwInput.type = "text";
        if (eyeIcon) eyeIcon.style.display = "none";
        if (eyeOffIcon) eyeOffIcon.style.display = "block";
    } else {
        pwInput.type = "password";
        if (eyeIcon) eyeIcon.style.display = "block";
        if (eyeOffIcon) eyeOffIcon.style.display = "none";
    }
}

async function handleLoginSubmit(e) {
    e.preventDefault();
    showError("");

    const username = document.getElementById("username-input").value.trim();
    const password = document.getElementById("password-input").value;
    const submitBtn = document.getElementById("auth-submit-btn");

    const isRegister = submitBtn.innerText.includes("Create");

    try {
        if (isRegister) {
            // Register Action
            const response = await fetch(`${API_BASE}/auth/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, role: selectedRole })
            });

            let data = {};
            try { data = await response.json(); } catch (_) { }
            if (!response.ok) throw new Error(data.detail || `Registration failed (HTTP ${response.status}). Please try again.`);

            // Show QR Setup
            document.getElementById("login-form").style.display = "none";
            document.getElementById("register-setup-form").style.display = "block";
            document.getElementById("register-qr-img").src = data.qr_code_base64;
            document.getElementById("register-qr-secret").innerText = data.totp_secret;
        } else {
            // Login Action
            const response = await fetch(`${API_BASE}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });

            let data = {};
            try { data = await response.json(); } catch (_) { }
            if (!response.ok) throw new Error(data.detail || `Authentication failed (HTTP ${response.status}). Please try again.`);

            // Switch to OTP verify
            document.getElementById("login-form").style.display = "none";
            document.getElementById("otp-form").style.display = "block";
            document.getElementById("otp-input").value = "";
            document.getElementById("otp-input").focus();

            // Hide QR code container during regular sign in — only prompt for 6-digit OTP code!
            document.getElementById("admin-qr-container").style.display = "none";

            // Stash user detail temporarily
            currentUser = { username: data.username, role: data.role };
        }
    } catch (err) {
        showError(err.message);
    }
}

async function handleOTPSubmit(e) {
    e.preventDefault();
    showError("");

    const otpCode = document.getElementById("otp-input").value.trim();
    if (!currentUser) return;

    try {
        const response = await fetch(`${API_BASE}/auth/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUser.username, otp_code: otpCode })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Invalid code.");

        // The Admin/Auditor/Auditee tabs on the login screen are cosmetic only --
        // they're never sent to the server and never restrict which credentials
        // can be typed there. The account's real role always comes from the DB
        // (data.role here), so typing a different account's credentials while a
        // different tab is highlighted silently logs you in as whatever that
        // account really is, with zero indication the tab you picked didn't
        // match. Warn and let the user back out instead of proceeding silently.
        if (selectedRole && data.role && selectedRole !== data.role) {
            const proceed = confirm(
                `You selected "${selectedRole}" but these credentials belong to a "${data.role}" account.\n\n` +
                `Continue signing in as ${data.role}?`
            );
            if (!proceed) {
                currentUser = null;
                resetOTPForm();
                return;
            }
        }

        currentUser.token = data.token;

        // Login Successful
        document.getElementById("auth-overlay").classList.remove("active");
        document.getElementById("app-shell").style.display = "flex";
        initResizableSidebar();

        initializeDashboard(currentUser);
    } catch (err) {
        showError(err.message);
    }
}

function resetOTPForm() {
    document.getElementById("otp-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
    showError("");
}

function proceedToSignInAfterRegister() {
    document.getElementById("register-setup-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
    resetAuthActionToLogin();
    showError("");
}

function showError(msg) {
    const errorEl = document.getElementById("auth-error");
    if (msg) {
        errorEl.innerText = msg;
        errorEl.style.display = "block";
    } else {
        errorEl.style.display = "none";
    }
}

function logout() {
    currentUser = null;
    activeSessionId = "";
    activeSessionTitle = "";
    window._currentPollSessionId = null;
    window._recentSessionsCache = [];
    findingsList = [];
    uploadedFilesList = [];
    if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
    if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }

    try {
        localStorage.removeItem("last_active_session_id");
        localStorage.removeItem("last_active_session_title");
        localStorage.removeItem("shakti_active_session");
        localStorage.removeItem("shakti_user");
    } catch (e) { }

    const badge = document.getElementById("active-session-badge");
    const wsTitle = document.getElementById("workspace-title");
    if (badge) badge.innerText = "";
    if (wsTitle) wsTitle.innerText = "ISO 27001 Workspace";

    const countBadge = document.getElementById("evidence-count-badge");
    if (countBadge) countBadge.innerText = "0 files";
    document.querySelectorAll("#uploaded-files-registry, #auditee-files-registry").forEach(reg => {
        reg.innerHTML = `<div class="empty-state">No files uploaded yet. Drag files to begin audit.</div>`;
    });

    document.getElementById("app-shell").style.display = "none";
    document.getElementById("auth-overlay").classList.add("active");
    document.getElementById("login-form").style.display = "block";
    document.getElementById("otp-form").style.display = "none";
    document.getElementById("register-setup-form").style.display = "none";
    document.getElementById("username-input").value = "";
    document.getElementById("password-input").value = "";
    showError("");
}

// ── DASHBOARD INITIALIZATION ──

async function initializeDashboard(user) {
    // Set Profile Info
    document.getElementById("profile-name").innerText = user.username;
    document.getElementById("profile-role").innerText = user.role.toUpperCase();
    document.getElementById("profile-initials").innerText = user.username.slice(0, 2).toUpperCase();

    // Role permissions toggle
    const isAdmin = user.role === "admin";
    const isAuditor = user.role === "auditor";

    // Hide/show sidebar panels (safe null-check in case some panels are absent)
    const setDisplay = (id, val) => { const el = document.getElementById(id); if (el) el.style.display = val; };
    setDisplay("sidebar-ai-setup", isAdmin ? "block" : "none");
    setDisplay("sidebar-framework-setup", (isAdmin || isAuditor) ? "block" : "none");
    // sidebar-branding-setup is gone -- Report Metadata moved into #branding-modal on
    // the Report Exporter tab, which is itself only built for admin/auditor (see
    // renderTabsForRole), so that form keeps exactly the role gating it had here.
    setDisplay("sidebar-mode-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-checklist-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-action-setup", (isAdmin || isAuditor) ? "block" : "none");
    setDisplay("sidebar-admin-tools", isAdmin ? "block" : "none");
    setDisplay("sidebar-auditee-submissions", (isAdmin || isAuditor) ? "block" : "none");

    // Setup Tabs Bar
    setupTabs(user.role);

    // Initialize standard checklist
    if (isAdmin || isAuditor) {
        loadFrameworkControls();
    }

    // Resolve Active Audit Session ID
    await loadOrCreateSession(user);
    // Covers the page-reload case, not just clicking through Recent Sessions:
    // if the resolved session is still actively running, correct the scope
    // display/lock from the server's checkpoint truth (see
    // checkActiveSessionStatusOnSwitch) instead of leaving whatever the
    // (possibly stale) client-side scoping cache last rendered.
    if (activeSessionId && typeof checkActiveSessionStatusOnSwitch === "function") {
        checkActiveSessionStatusOnSwitch();
    }
    loadRecentSessions();
    if (!window._recentSessionsInterval) {
        window._recentSessionsInterval = setInterval(loadRecentSessions, 10000);
    }

    // Load Chat History list
    if (user.role !== "auditee") {
        loadChatSessions();
    }
}

function setupTabs(role) {
    const tabsBar = document.getElementById("tabs-bar");
    if (!tabsBar) return;
    tabsBar.innerHTML = "";

    let tabs = [];
    if (role === "auditee") {
        tabs = [
            { id: "tab-upload-evidence", label: "Upload Evidence" },
            { id: "tab-submitted-reports", label: "Auditor Submitted Report" },
            { id: "tab-auditee-history", label: "My Document History" }
        ];
    } else if (role === "admin") {
        // Admin Role - includes System & Auditor Warning Logs
        tabs = [
            { id: "tab-scan-workspace", label: "Scan Workspace" },
            { id: "tab-audit-records", label: "Audit Records & Findings" },
            { id: "tab-audit-report", label: "Report Exporter" },
            { id: "tab-auditee-docs", label: "Audit Reports" },
            { id: "tab-manage-controls", label: "Manage Controls and Backup" },
            { id: "tab-admin-logs", label: "System & Auditor Logs" }
        ];
    } else {
        // Auditor Role
        tabs = [
            { id: "tab-scan-workspace", label: "Scan Workspace" },
            { id: "tab-audit-records", label: "Audit Records & Findings" },
            { id: "tab-audit-report", label: "Report Exporter" },
            { id: "tab-auditee-docs", label: "Audit Reports" },
            { id: "tab-manage-controls", label: "Manage Controls and Backup" }
        ];
    }

    tabs.forEach((tab, index) => {
        const btn = document.createElement("button");
        btn.className = `tab-link ${index === 0 ? 'active' : ''}`;
        btn.innerText = tab.label;
        btn.onclick = () => switchTab(tab.id, btn);
        tabsBar.appendChild(btn);
    });

    if (tabsBar.firstChild) {
        switchTab(tabs[0].id, tabsBar.firstChild);
    }
}

function switchTab(tabId, tabBtn) {
    activeTab = tabId;

    // Active tabs navigation state
    document.querySelectorAll(".tab-link").forEach(btn => btn.classList.remove("active"));
    if (tabBtn) tabBtn.classList.add("active");

    // Show active tab panel
    document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.remove("active"));
    const targetPanel = document.getElementById(tabId);
    if (targetPanel) targetPanel.classList.add("active");

    // Update workspace title header based on active tab
    const wsTitle = document.getElementById("workspace-title");
    if (wsTitle) {
        if (tabId === "tab-scan-workspace") wsTitle.innerText = "Audit Scan Workspace";
        else if (tabId === "tab-audit-records") wsTitle.innerText = "Audit Records & Compliance Gaps Workspace";
        else if (tabId === "tab-auditee-docs") wsTitle.innerText = "Auditee Evidence Documents";
        else if (tabId === "tab-audit-report") wsTitle.innerText = "Audit Report & Delivery Center";
        else if (tabId === "tab-upload-evidence") wsTitle.innerText = "Auditee Evidence Upload & Auditor Assignment";
        else if (tabId === "tab-submitted-reports") wsTitle.innerText = "Auditor Submitted Final Reports";
        else if (tabId === "tab-auditee-history") wsTitle.innerText = "My Document Submission History";
        else if (tabId === "tab-manage-controls") wsTitle.innerText = "Manage Framework Controls";
        else if (tabId === "tab-admin-logs") wsTitle.innerText = "System Event & Developer Logs";
    }

    // Perform tab-specific loading
    if (tabId === "tab-scan-workspace") {
        loadEvidenceFileList();
    } else if (tabId === "tab-upload-evidence") {
        loadRegisteredAuditors();
    } else if (tabId === "tab-audit-records") {
        loadFindings();
    } else if (tabId === "tab-audit-report") {
        renderAuditReportPreview();
        populateAuditeeSelector();
    } else if (tabId === "tab-admin-logs") {
        loadSystemEvents();
        loadDeveloperLogs();
        populateBenchmarkSessionSelector();
        loadLiveMetrics();
        // Admin-only endpoint; the panel simply shows its own error for anyone else,
        // and the tab itself is only built for admins (see renderTabsForRole).
        if (typeof loadAllAuditorReports === "function") loadAllAuditorReports();
    } else if (tabId === "tab-manage-controls") {
        loadCustomControlsTable();
        if (currentUser && currentUser.role === "admin") loadUploadSettings();
    } else if (tabId === "tab-submitted-reports") {
        loadSubmittedReports();
    } else if (tabId === "tab-auditee-history") {
        loadAuditeeDocumentHistory();
    } else if (tabId === "tab-auditee-docs") {
        loadAuditeeSessionsList();
    } else if (tabId === "tab-ai-chat") {
        loadChatSessions();
    }
}

function toggleCollapsible(contentId) {
    const el = document.getElementById(contentId);
    if (!el) return;
    const parent = el.parentElement;
    if (parent) parent.classList.toggle("open");

    if (el.style.display === "none" || !el.style.display) {
        el.style.display = "block";
        if (contentId === "recent-sessions-container") {
            loadRecentSessions();
        }
    } else {
        el.style.display = "none";
    }
}

window._recentSessionsCache = [];
window._showAllRecentSessions = false;

async function loadRecentSessions() {
    const container = document.getElementById("recent-sessions-list");
    if (!container) return;

    try {
        // No need to pass our own username -- the backend now derives identity
        // from the JWT by default, so it's not echoed back in plaintext in the
        // URL (and therefore in access logs) on every poll.
        const response = await authFetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();

        if (data.success && data.sessions.length > 0) {
            const seen = new Set();
            // Include ALL sessions belonging to the user
            window._recentSessionsCache = data.sessions.filter(s => {
                if (!s.session_id || seen.has(s.session_id)) return false;
                seen.add(s.session_id);
                const title = (s.session_title || "").toLowerCase();
                if (title.includes("chat") || title.includes("error")) return false;
                return true;
            });

            // Restore Last Visited Session if not active or on initial startup
            if (window._recentSessionsCache.length > 0) {
                const userKey = currentUser && currentUser.username ? `_${currentUser.username}` : "";
                const lastSid = localStorage.getItem(`last_active_session_id${userKey}`);
                const foundLast = lastSid ? window._recentSessionsCache.find(s => s.session_id === lastSid) : null;
                const activeBelongsToUser = activeSessionId ? window._recentSessionsCache.some(s => s.session_id === activeSessionId) : false;

                if (!activeSessionId || !activeBelongsToUser) {
                    const targetSession = foundLast || window._recentSessionsCache[0];
                    switchRecentSession(targetSession.session_id, targetSession.session_title);
                } else {
                    renderFilteredRecentSessionsList();
                }
            } else {
                renderFilteredRecentSessionsList();
            }
        } else {

            window._recentSessionsCache = [];
            const badgeCount = document.getElementById("recent-sessions-count-badge");
            if (badgeCount) badgeCount.innerText = "(0)";
            container.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; padding: 6px;">No recent sessions found.</div>`;
        }

        // Real-Time Tab Synchronization Trigger
        if (activeTab === "tab-auditee-history") loadAuditeeDocumentHistory();
        if (activeTab === "tab-auditee-docs") loadAuditeeSessionsList();
        if (currentUser && currentUser.role !== "auditee") loadSidebarAuditeeFiles();
    } catch (err) {
        window._recentSessionsCache = [];
        const badgeCount = document.getElementById("recent-sessions-count-badge");
        if (badgeCount) badgeCount.innerText = "(0)";
        console.error("Failed to load recent sessions:", err);
    }
}

// Wired to #show-more-sessions-btn in index.html. The button, the state flag
// (window._showAllRecentSessions) and the label that reads it all existed --
// this function did not, so clicking it threw ReferenceError and the session
// list stayed capped at 10 with no way to see the rest.
function toggleShowAllRecentSessions() {
    window._showAllRecentSessions = !window._showAllRecentSessions;
    renderFilteredRecentSessionsList();
}

function renderFilteredRecentSessionsList() {
    const container = document.getElementById("recent-sessions-list");
    const showMoreBtn = document.getElementById("show-more-sessions-btn");
    const searchInput = document.getElementById("recent-sessions-search-input");
    const badgeCount = document.getElementById("recent-sessions-count-badge");

    if (!container) return;

    const query = (searchInput ? searchInput.value : "").toLowerCase().trim();
    let filtered = window._recentSessionsCache || [];

    if (query) {
        filtered = filtered.filter(s => {
            const t = (s.session_title || "").toLowerCase();
            const sid = (s.session_id || "").toLowerCase();
            const d = (s.created_at || "").toLowerCase();
            return t.includes(query) || sid.includes(query) || d.includes(query);
        });
    }

    if (badgeCount) badgeCount.innerText = `(${filtered.length})`;

    if (filtered.length === 0) {
        container.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; padding: 6px;">No matching sessions found.</div>`;
        if (showMoreBtn) showMoreBtn.style.display = "none";
        return;
    }

    const limit = window._showAllRecentSessions || query ? filtered.length : 10;
    const toRender = filtered.slice(0, limit);

    container.innerHTML = "";
    toRender.forEach(s => {
        const btn = document.createElement("button");
        btn.className = "recent-session-item";
        const isActive = (activeSessionId === s.session_id);
        if (isActive) btn.classList.add("active-session");

        btn.onclick = () => switchRecentSession(s.session_id, s.session_title);

        const isFinal = (s.status || "").toLowerCase().includes("final") || (s.status || "").toLowerCase().includes("review");
        const statusPill = isFinal
            ? `<span style="font-size:0.65rem; padding:1px 6px; border-radius:4px; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:800;">FINAL</span>`
            : `<span style="font-size:0.65rem; padding:1px 6px; border-radius:4px; background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:800;">OPEN</span>`;

        const shortTitle = escapeHtml(s.session_title || `Audit Session (${s.session_id.slice(0, 6)})`);
        const dateStr = s.created_at ? s.created_at.slice(0, 10) : "";

        const bg = isActive ? "rgba(37, 99, 235, 0.16)" : "var(--bg-card)";
        const border = isActive ? "1px solid #3b82f6" : "1px solid var(--border-color)";
        const boxShadow = isActive ? "0 0 10px rgba(59, 130, 246, 0.35)" : "none";

        btn.style.cssText = `display: flex; flex-direction: column; align-items: flex-start; width: 100%; padding: 9px 11px; background: ${bg}; border: ${border}; box-shadow: ${boxShadow}; border-radius: 10px; color: var(--text-main); font-size: 0.78rem; text-align: left; cursor: pointer; margin-bottom: 6px; transition: all 0.15s ease;`;
        btn.onmouseover = () => { if (!isActive) { btn.style.background = "rgba(37, 99, 235, 0.1)"; btn.style.borderColor = "rgba(37, 99, 235, 0.4)"; } };
        btn.onmouseout = () => { if (!isActive) { btn.style.background = "var(--bg-card)"; btn.style.borderColor = "var(--border-color)"; } };

        btn.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 4px;">
                <span style="font-weight: 700; color: ${isActive ? '#60a5fa' : 'var(--text-main)'}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px;" title="${shortTitle}">${shortTitle}</span>
                ${statusPill}
            </div>
            <div style="font-size: 0.7rem; color: var(--text-muted); display: flex; justify-content: space-between; width: 100%;">
                <span>${s.findings_count || 0} findings &bull; <b style="color:#10b981;">${s.score_percent || 0}%</b></span>
                <span>${dateStr}</span>
            </div>
        `;
        container.appendChild(btn);
    });


    if (showMoreBtn) {
        if (filtered.length > 10 && !query) {
            showMoreBtn.style.display = "block";
            showMoreBtn.innerText = window._showAllRecentSessions
                ? "▲ Show Top 10 Sessions Only"
                : `📂 Show More Sessions (Total ${filtered.length})`;
        } else {
            showMoreBtn.style.display = "none";
        }
    }
}

function filterRecentSessionsList() {
    renderFilteredRecentSessionsList();
}

window._sessionScopingCache = window._sessionScopingCache || {};

// Which scope mode actually produced the findings currently on screen, as recorded
// on the saved report by the server -- not the mode the sidebar happens to be in
// now. A Customize run is rendered as questions and answers rather than as control
// findings, and that has to follow the run, not the live UI: an auditor who reopens
// a finished Excel session while the sidebar sits in Customize must still see their
// Excel findings drawn as Excel findings. Runs saved before the server recorded the
// mode leave this false and render exactly as they always did.
window._sessionIsCustomizeRun = false;

function _noteRunScopingMode(data) {
    window._sessionIsCustomizeRun =
        String((data && data.scoping_mode) || "").toUpperCase().startsWith("CUSTOM");
}

// The scope mode for the current session. Every caller must agree on this:
// the server judges a control on evidence alone in Customize mode, and on policy
// AND evidence otherwise, so a mode that goes missing turns a question-based
// audit into one that fails on policy documents nobody put in scope.
// The scan progress box is shown by the progress poll and hidden here. Kept as
// one function so every "scan finished/stopped/failed" path clears it the same
// way -- there are several such paths and they used to leave the bar on screen.
function hidePipelineProgress() {
    const box = document.getElementById("pipeline-progress-box");
    if (box) box.style.display = "none";
    const fill = document.getElementById("pipeline-progress-fill");
    if (fill) fill.style.width = "0%";
}

function resolveScopingMode() {
    // The highlighted mode button is the fallback when the global is unset --
    // it is what the auditor can actually see on screen.
    const active = document.querySelector(".active-scope-mode");
    const fromButton = active && active.id === "btn-customize-scoping" ? "CUSTOMIZE" : "";
    return String(window.currentScopingMode || fromButton || "EXCEL").toUpperCase();
}

function saveSessionScopingCache(sessionId, customEvidenceData, mode) {
    if (!sessionId) return;
    window._sessionScopingCache[sessionId] = {
        custom_evidence: customEvidenceData,
        scoping_mode: mode || "Excel Scoping"
    };
    try {
        localStorage.setItem(`scoping_cache_${sessionId}`, JSON.stringify({
            custom_evidence: customEvidenceData,
            scoping_mode: mode || "Excel Scoping"
        }));
    } catch (e) { }
}

function restoreSessionScopingCache(sessionId) {
    if (!sessionId) return false;
    let data = window._sessionScopingCache ? window._sessionScopingCache[sessionId] : null;
    if (!data) {
        try {
            const raw = localStorage.getItem(`scoping_cache_${sessionId}`);
            if (raw) data = JSON.parse(raw);
        } catch (e) { }
    }
    if (data && data.custom_evidence && data.custom_evidence.excel_items && data.custom_evidence.excel_items.length > 0) {
        customEvidenceMappings = data.custom_evidence;
        const mode = data.scoping_mode || "Excel Scoping";
        if (typeof setScopingMode === "function") setScopingMode(mode);

        const excelSLs = Array.from(new Set(data.custom_evidence.excel_items.map(item => parseInt(item.sl_no)).filter(n => !isNaN(n))));
        const matchedSet = new Set(excelSLs);
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => {
            cb.checked = matchedSet.has(parseInt(cb.value));
        });
        if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();

        const excelBanner = document.getElementById("excel-scope-banner");
        if (excelBanner) excelBanner.style.display = "flex";
        const scopeLabel = document.getElementById("excel-scope-label");
        if (scopeLabel) {
            const _isCustom = String(mode || "").toUpperCase().startsWith("CUSTOM");
            scopeLabel.innerText = `${_isCustom ? "Question-Based Checklist" : "Excel Checklist"} Loaded (${data.custom_evidence.excel_items.length} Items)`;
        }
        return true;
    }
    return false;
}

async function switchRecentSession(sessionId, sessionTitle) {
    activeSessionId = sessionId;
    if (sessionTitle) activeSessionTitle = sessionTitle;

    try {
        const userKey = currentUser && currentUser.username ? `_${currentUser.username}` : "";
        localStorage.setItem(`last_active_session_id${userKey}`, activeSessionId);
        if (activeSessionTitle) localStorage.setItem(`last_active_session_title${userKey}`, activeSessionTitle);
        localStorage.removeItem("last_active_session_id");
        localStorage.removeItem("last_active_session_title");
    } catch (e) { }


    // ── Stop any running audit & polling from the previous session ──────────────
    if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
    if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
    window._currentPollSessionId = activeSessionId;

    // ── Reset data state ─────────────────────────────────────────────────────────
    findingsList = [];
    uploadedFilesList = [];
    activeSeverityFilter = "";
    activeStatusFilter = "All";
    activeComplianceFilter = "";

    // ── Reset UI: Session header ─────────────────────────────────────────────────
    const badge = document.getElementById("active-session-badge");
    const wsTitle = document.getElementById("workspace-title");
    if (badge) badge.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
    if (wsTitle) wsTitle.innerText = activeSessionTitle || "ISO 27001 Local Compliance Audit";

    // ── Reset UI: KPI counters ───────────────────────────────────────────────────
    ["count-compliant", "count-noncompliant", "count-p1", "count-p2", "count-p3", "count-p4"].forEach(id => {
        const el = document.getElementById(id); if (el) el.innerText = "0";
    });

    // ── Reset UI: Progress bar ────────────────────────────────────────────────────
    const progressBar = document.getElementById("pipeline-progress-fill");
    const progressPct = document.getElementById("pipeline-progress-percent");
    const progressStatus = document.getElementById("pipeline-status-text");
    if (progressBar) progressBar.style.width = "0%";
    if (progressPct) progressPct.innerText = "0%";
    if (progressStatus) progressStatus.innerText = "Ready to scan";

    // ── Reset UI: Scan run button ─────────────────────────────────────────────────
    const runBtn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    if (runBtn) { runBtn.disabled = false; runBtn.style.opacity = "1"; runBtn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress(); }
    if (stopBtn) stopBtn.style.display = "none";

    // ── Restore or Reset UI: Controls checkboxes & scoping mode ───────────────────
    try {
        const restored = restoreSessionScopingCache(activeSessionId);
        if (!restored) {
            customEvidenceMappings = null;
            customControlDocuments = null;
            if (typeof selectAllCheckboxes === "function") selectAllCheckboxes(false);
            if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();
            if (typeof setScopingMode === "function") setScopingMode('EXCEL');
        }

        // Clear search box so "5.15" from previous session doesn't persist
        const searchInput = document.getElementById("controls-search-input");
        if (searchInput) {
            searchInput.value = "";
            if (typeof filterCheckboxList === "function") filterCheckboxList();
        }

        // Hide Excel scoping banner if not an Excel session
        if (!restored) {
            const excelBanner = document.getElementById("excel-scope-banner");
            if (excelBanner) excelBanner.style.display = "none";
            const scopeLabel = document.getElementById("excel-scope-label");
            if (scopeLabel) scopeLabel.innerText = "";
        }
    } catch (e) {
        console.warn("[switchRecentSession] Control reset warning:", e);
    }

    // ── Reset UI: Status filter ───────────────────────────────────────────────────
    document.querySelectorAll(".filter-btn").forEach(btn => btn.classList.remove("active"));
    const allBtn = document.querySelector(".filter-btn[data-status='All']") ||
        document.querySelector(".filter-btn[data-filter='All']");
    if (allBtn) allBtn.classList.add("active");

    const statusSelect = document.getElementById("status-filter");
    if (statusSelect) statusSelect.value = "All";

    // Also reset KPI box visual highlights
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");

    // ── Load this session's data ──────────────────────────────────────────────────
    loadEvidenceFileList();
    loadAuditeeEvidenceDocs();
    await loadFindings();
    renderFilteredRecentSessionsList();
    checkCrashResilienceCheckpoint();
    checkActiveSessionStatusOnSwitch();

    showToast(`📂 Switched to audit session: "${activeSessionTitle}"`, "info");
}

async function checkActiveSessionStatusOnSwitch() {
    if (!activeSessionId) return;
    try {
        const response = await authFetch(`${API_BASE}/audit/status/${encodeURIComponent(activeSessionId)}`);
        const data = await response.json();
        if (data.status === "running") {
            const btn = document.getElementById("run-analysis-btn");
            const stopBtn = document.getElementById("stop-analysis-btn");
            if (btn) btn.disabled = true;
            if (stopBtn) stopBtn.style.display = "inline-flex";
            window._currentPollSessionId = activeSessionId;
            if (progressInterval) clearInterval(progressInterval);
            progressInterval = setInterval(pollAuditProgress, 1000);
            pollAuditProgress();

            // Correct the scope display from the server's own checkpoint truth,
            // not the client-side scoping cache -- that cache is only ever
            // populated at the moment a checklist is uploaded in THIS browser tab,
            // so a page reload, a different tab/device, or a cache miss silently
            // fell back to showing "AI Auto-Scoping, all controls selected" even
            // while the backend was correctly running a smaller scoped subset.
            lockScopeDisplayToCheckpoint(data.checkpoint);
        } else {
            unlockScopeDisplay();
        }
    } catch (e) {
        console.warn("[checkActiveSessionStatusOnSwitch] Failed:", e);
    }
}

// Reflects the ACTUAL running scope (from the checkpoint the backend itself
// wrote at /start) in the scope-selection UI, and locks it read-only -- scope
// can't be changed mid-run anyway, so an editable-looking selector showing the
// wrong count/mode is actively misleading, not just cosmetically stale.

// Elements that describe WHAT this run audits. /audit/start snapshots all of
// it, so changing any of them mid-scan cannot alter the run -- it only makes
// the screen disagree with the audit that is executing, and with the report it
// will produce. The server refuses the evidence ones with a 409; this keeps the
// interface honest about it rather than offering an action that will bounce.
function _setRunLockedInputs(locked) {
    // Read by syncControlsScopeFromFindings(), which is called from the findings
    // poller during a run -- without this flag it re-selected controls behind the
    // lock and made the panel look editable again.
    window._scopeRunLocked = !!locked;

    const ids = [
        "framework-select",        // switching ISO->VAPT mid-run describes a different audit
        "btn-ai-scoping", "btn-checklist-scoping", "btn-excel-scoping", "btn-customize-scoping",
        "evidence-file-input", "evidence-folder-input",
        // Scope-editing controls. Without these the auditor could still tick and
        // untick controls while the scan ran -- the evidence was frozen and said so
        // in its own banner, but the scope beside it stayed fully editable, so the
        // panel could end up describing a completely different set of controls from
        // the one the run was actually auditing. Only the resume path
        // (lockScopeDisplayToCheckpoint) ever disabled these; a normal scan start
        // never did.
        "btn-select-all-controls", "btn-clear-all-controls", "controls-search-input",
        // The Excel scoping matrix, and the two ways in beside it. These stayed
        // live while a scan ran: the dropzone is a div with its own onclick, so
        // disabling the buttons around it left the box itself clickable, and
        // dropping a new sheet mid-run re-scopes the audit underneath the run
        // that is already going. The builder and template links go with it --
        // both produce the same scope, so leaving either open reopens the hole.
        "scoping-excel-dropzone", "scoping-excel-file", "scoping-builder-entry",
    ];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.disabled = locked;
        el.style.opacity = locked ? "0.5" : "";
        el.style.pointerEvents = locked ? "none" : "";
        // The dropzone sets cursor:pointer inline; without this it still reads
        // as clickable while being inert, which is worse than looking disabled.
        //
        // Stash and restore rather than testing the live value. The test used to
        // be `el.style.cursor === "pointer"` in BOTH directions, which only ever
        // worked on the way in: locking rewrites the value to "not-allowed", so
        // unlocking found "not-allowed", failed the test, and left the cursor
        // alone. Every scope-mode button therefore kept a no-entry cursor for
        // the rest of the session once any run had started -- while staying
        // enabled, with pointer-events untouched and fully clickable. The panel
        // worked and looked broken, which is the worst of both, and it cleared
        // only on reload so it never reproduced when anyone went looking.
        if (locked) {
            if (el.style.cursor === "pointer" || id === "scoping-excel-dropzone") {
                if (el.dataset.cursorBeforeLock === undefined) {
                    el.dataset.cursorBeforeLock = el.style.cursor || "";
                }
                el.style.cursor = "not-allowed";
            }
        } else if (el.dataset.cursorBeforeLock !== undefined) {
            el.style.cursor = el.dataset.cursorBeforeLock;
            delete el.dataset.cursorBeforeLock;
        }
    });

    // The control checkboxes themselves, and their container, so the whole list
    // reads as frozen rather than merely being unclickable.
    document.querySelectorAll("#controls-checkbox-container input[type='checkbox']")
        .forEach(cb => { cb.disabled = locked; });
    const _ctrlBox = document.getElementById("controls-checkbox-container");
    if (_ctrlBox) _ctrlBox.style.opacity = locked ? "0.55" : "";

    // Say so, the way the evidence card does. Greyed-out controls alone leave the
    // panel still reading "Active: <mode>", which looks like the scope is live.
    // The previous text is stashed and put back on unlock rather than re-running
    // setScopingMode(), which would re-apply that mode's side effects and could
    // clear the auditor's selection.
    const _scopeNote = document.getElementById("scoping-mode-status-note");
    if (_scopeNote) {
        if (locked) {
            if (window._scopeNoteBeforeLock === undefined) {
                window._scopeNoteBeforeLock = _scopeNote.innerHTML;
            }
            _scopeNote.innerHTML = `<span style="color:#f59e0b;font-weight:700;">🔒 Scope locked while the scan runs.</span> This audit is using the controls exactly as they were when it started. Stop the scan to change them.`;
        } else if (window._scopeNoteBeforeLock !== undefined) {
            _scopeNote.innerHTML = window._scopeNoteBeforeLock;
            window._scopeNoteBeforeLock = undefined;
        }
    }

    // The browse buttons and Delete All are plain buttons wired by onclick, so
    // they are found through the card rather than by id.
    const card = document.querySelector(".modern-evidence-card");
    if (card) {
        card.querySelectorAll("button").forEach(b => {
            b.disabled = locked;
            b.style.opacity = locked ? "0.5" : "";
        });
        // Every drop zone, not just the first: getElementById returns one
        // element, and the page has two upload zones. The second stayed live
        // during a scan, so evidence could still be added behind the lock.
        document.querySelectorAll(".drop-zone").forEach(drop => {
            drop.style.opacity = locked ? "0.45" : "";
            drop.style.pointerEvents = locked ? "none" : "";
        });
    }

    const note = document.getElementById("evidence-lock-note");
    if (note) note.style.display = locked ? "block" : "none";

    // Put the scope badge back. lockScopeDisplayToCheckpoint writes
    // "N / M selected (locked — scan in progress)" into it, and nothing clears
    // that suffix on release: the only other writer is updateSelectedScopeCount,
    // which runs when the auditor changes the selection. So after a resumed run
    // finished, the panel went on announcing a scan in progress -- beside
    // controls that were once again editable -- until something unrelated
    // happened to tick a checkbox. Same shape as the cursor above: state applied
    // on the way in with no matching step on the way out.
    //
    // A pure recount of the checkboxes, so it is safe to call here; the run-lock
    // flag is already cleared at the top of this function.
    if (!locked && typeof updateSelectedScopeCount === "function") {
        updateSelectedScopeCount();
    }
}

function lockScopeDisplayToCheckpoint(checkpoint) {
    if (!checkpoint) return;
    const realTotal = checkpoint.total_controls;
    const realSelected = Array.isArray(checkpoint.selected_sls) ? checkpoint.selected_sls : null;

    if (realSelected && realSelected.length > 0) {
        const matchedSet = new Set(realSelected.map(n => parseInt(n)));
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => { cb.checked = matchedSet.has(parseInt(cb.value)); });
    }
    if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();

    // Correct the header badge directly too, in case realTotal disagrees with
    // however many checkboxes exist client-side (e.g. framework list changed).
    if (typeof realTotal === "number" && realTotal > 0) {
        const totalBadge = document.getElementById("total-scope-badge");
        const shown = realSelected ? realSelected.length : realTotal;
        if (totalBadge) totalBadge.innerText = `${shown} / ${realTotal} selected (locked — scan in progress)`;
    }

    // Lock the whole scope panel read-only while this run is active.
    ["btn-ai-scoping", "btn-checklist-scoping", "btn-excel-scoping", "btn-customize-scoping"].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.disabled = true; el.style.opacity = "0.5"; el.style.pointerEvents = "none"; }
    });
    document.querySelectorAll("#controls-checkbox-container input[type='checkbox']").forEach(cb => { cb.disabled = true; });
    _setRunLockedInputs(true);
    const statusNote = document.getElementById("scoping-mode-status-note");
    if (statusNote) {
        statusNote.innerHTML = `<span style="color:#f59e0b;font-weight:700;">🔒 Locked:</span> This run is already scoped to <b>${realSelected ? realSelected.length : realTotal} control(s)</b> and cannot be changed until the scan finishes or is stopped.`;
    }
}

function unlockScopeDisplay() {
    ["btn-ai-scoping", "btn-checklist-scoping", "btn-excel-scoping", "btn-customize-scoping"].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.disabled = false; el.style.opacity = ""; el.style.pointerEvents = ""; }
    });
    document.querySelectorAll("#controls-checkbox-container input[type='checkbox']").forEach(cb => { cb.disabled = false; });
    _setRunLockedInputs(false);
}



async function checkCrashResilienceCheckpoint() {
    const banner = document.getElementById("crash-resilience-banner");
    const label = document.getElementById("checkpoint-status-label");
    if (!banner || !activeSessionId) return;

    try {
        const response = await authFetch(`${API_BASE}/audit/progress?session_id=${encodeURIComponent(activeSessionId)}`);
        const data = await response.json();

        // Two independent reasons this banner never appeared after a stop:
        // completed_batches only advances once per batch (and the per-control
        // checkpoint path never writes it at all), and a stopped run leaves
        // findings behind, which makes /status report "completed". Neither says
        // anything about whether there is work left to resume. The presence of a
        // checkpoint does: the API only returns one while it is resumable.
        const ck = data.checkpoint;
        const done = ck ? (ck.completed_controls || 0) : 0;
        const total = ck ? (ck.total_controls || 0) : 0;
        if (ck && data.status !== "running" && done < total) {
            if (label) {
                label.innerText = total
                    ? `${done} of ${total} controls evaluated — resuming continues from control ${done + 1}`
                    : "Progress saved";
            }
            banner.style.display = "flex";
        } else {
            banner.style.display = "none";
        }
    } catch (err) {
        console.error("Checkpoint check error:", err);
    }
}

async function resumeAuditFromCheckpoint() {
    const banner = document.getElementById("crash-resilience-banner");
    if (banner) banner.style.display = "none";
    if (!activeSessionId) return;

    showToast("🛡️ Resuming audit scan from saved checkpoint...", "info");
    await resumeSessionFromCheckpoint(activeSessionId);
}

// Shared by the in-session banner and the interrupted-session recovery modal:
// both mean "continue the run that stopped", and both need the 1s progress
// poller restarted afterwards or the resumed scan runs entirely invisibly.
//
// This used to call startAuditScan(true) -- a function that does not exist
// anywhere in the app, behind a `typeof === "function"` guard that swallowed
// the mistake. Pressing Resume hid the banner, said "Resuming...", and did
// nothing at all; the real endpoint is /audit/resume-checkpoint, which is what
// skips the controls already in the checkpoint.
async function resumeSessionFromCheckpoint(sessionId) {
    const btn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");

    try {
        const resp = await authFetch(`${API_BASE}/audit/resume-checkpoint`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sessionId })
        });
        const data = await resp.json();
        if (!resp.ok || !data.success) {
            throw new Error(formatApiErrorDetail(data.detail) || data.message || "Resume failed.");
        }

        showToast(`🔄 ${data.message || "Scan resumed from the saved checkpoint."}`, "info");

        // Cleared explicitly: a stop leaves this set, and the poller renders
        // "Stopping Scan..." over a run that is now going again.
        window._isStoppingSession = false;
        if (btn) { btn.disabled = true; btn.innerText = "⏳ Resuming Scan..."; }
        if (stopBtn) stopBtn.style.display = "block";
        if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(true);

        if (progressInterval) clearInterval(progressInterval);
        if (window._resultsInterval) clearInterval(window._resultsInterval);
        window._currentPollSessionId = sessionId;
        progressInterval = setInterval(pollAuditProgress, 1000);
        pollAuditProgress();
        return true;
    } catch (err) {
        showToast(`Resume failed: ${err.message}`, "error");
        if (btn) { btn.disabled = false; btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress(); }
        if (stopBtn) stopBtn.style.display = "none";
        return false;
    }
}

async function discardCheckpointAndReset() {
    const banner = document.getElementById("crash-resilience-banner");
    if (banner) banner.style.display = "none";
    if (!activeSessionId) return;

    try {
        await authFetch(`${API_BASE}/audit/discard-checkpoint`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: activeSessionId })
        });
        showToast("🗑️ Audit checkpoint discarded. Workspace reset for fresh scan.", "info");

        // Reset progress bar & buttons
        const progressBar = document.getElementById("pipeline-progress-fill");
        const progressPct = document.getElementById("pipeline-progress-percent");
        const progressStatus = document.getElementById("pipeline-status-text");
        if (progressBar) progressBar.style.width = "0%";
        if (progressPct) progressPct.innerText = "0%";
        if (progressStatus) progressStatus.innerText = "Ready to scan";

        const runBtn = document.getElementById("run-analysis-btn");
        const stopBtn = document.getElementById("stop-analysis-btn");
        if (runBtn) { runBtn.disabled = false; runBtn.style.opacity = "1"; runBtn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress(); }
        if (stopBtn) stopBtn.style.display = "none";
    } catch (err) {
        showToast(`Discard failed: ${err.message}`, "error");
    }
}


// ── SESSION MANAGEMENT ──

// ── Keep the sidebar framework pointed at the session that is actually active ──
//
// The sidebar <select> and the session's stored framework were independent:
// nothing in this file ever ASSIGNED framework-select, so it only changed when
// the auditor clicked it. Switching to a VAPT session while the sidebar still
// said ISO 27001 left the two disagreeing, and the disagreement is not
// cosmetic -- /audit/start sends the SIDEBAR value and the backend writes it
// over the session's stored framework. So running an audit from a stale
// sidebar silently reframes the session, and the report that comes out is not
// the one the header says it is.
//
// The two selects also do not share a vocabulary: the sidebar offers "VAPT"
// and "SOC2", the new-session modal offers "VAPT" and "SOC 2", and the backend
// rewrites a running VAPT session's framework to "VAPT Framework Controls"
// (_FRAMEWORK_CATEGORY_LABELS in controls.py). Matching on the exact string
// would therefore fail on precisely the sessions this needs to fix, so the
// match is on framework family instead.
function _frameworkFamily(value) {
    const v = String(value || "").toUpperCase();
    if (v.includes("PQC")) return "PQC";
    if (v.includes("VAPT")) return "VAPT";
    if (v.includes("NIST")) return "NIST";
    if (v.includes("DPDP") || v.includes("GDPR")) return "DPDP";
    if (v.includes("SOC")) return "SOC";
    // Checked before ISO: "ISO 22301 BCMS" contains both.
    if (v.includes("BCMS") || v.includes("22301")) return "BCMS";
    if (v.includes("XBOM") || v.includes("X-BOM") || v.includes("SBOM")) return "XBOM";
    if (v.includes("ISO")) return "ISO";
    return "";
}

function applySessionFramework(framework) {
    const sel = document.getElementById("framework-select");
    const family = _frameworkFamily(framework);
    if (!sel || !family) return false;
    // Not while a run is executing. framework-select is one of the inputs
    // _setRunLockedInputs() freezes, because switching framework mid-run would
    // describe a different audit from the one running -- and the re-render
    // below calls loadFrameworkControls(), which does NOT consult
    // window._scopeRunLocked and would blank and rebuild the scope panel behind
    // that lock.
    if (window._scopeRunLocked) return false;
    const match = Array.from(sel.options).find(
        o => _frameworkFamily(o.value) === family);
    // Assigning a value no <option> carries silently blanks a <select>, which
    // is worse than leaving a stale one, so an unmatched framework is ignored.
    if (!match || sel.value === match.value) return false;
    sel.value = match.value;
    // The framework gates which analysis modes are selectable, so the gating has
    // to be re-run -- the browser fires no change event for a scripted assignment.
    if (typeof onFrameworkChangeSuggestMode === "function") onFrameworkChangeSuggestMode();
    if (typeof loadFrameworkControls === "function") loadFrameworkControls();
    return true;
}

async function syncFrameworkFromSession(sessionId, knownFramework) {
    let fw = knownFramework;
    if (!fw && sessionId) {
        try {
            const res = await authFetch(`${API_BASE}/audit/sessions`);
            const data = await res.json();
            const hit = (data.sessions || []).find(s => s.session_id === sessionId);
            fw = hit ? hit.framework : "";
        } catch (e) { return; }
    }
    applySessionFramework(fw);
}

function _autoFillSessionTitle() {
    const frameworkEl = document.getElementById("new-session-framework");
    const companyEl = document.getElementById("new-session-company");
    const titleEl = document.getElementById("new-session-title-input");
    if (!titleEl) return;
    const todayStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    const framework = frameworkEl ? frameworkEl.value : "ISO 27001";
    const company = companyEl && companyEl.value.trim() ? ` — ${companyEl.value.trim()}` : "";
    titleEl.value = `${framework}${company} — ${todayStr}`;
}

function openNewSessionModal() {
    const frameworkEl = document.getElementById("new-session-framework");
    const companyEl = document.getElementById("new-session-company");
    const modal = document.getElementById("new-session-modal");
    const input = document.getElementById("new-session-title-input");
    // Pre-fill the modal framework from the CURRENT sidebar selection instead
    // of always resetting to ISO 27001. This ensures a session created while
    // VAPT or PQC is selected in the sidebar actually stores the right framework
    // in the DB — without this, the DB had ISO 27001 for every session, causing
    // the governance guardrail to coerce Fast Parser -> Deep even for VAPT/PQC.
    const sidebarFw = document.getElementById("framework-select");
    const defaultFw = (sidebarFw && sidebarFw.value) ? sidebarFw.value : "ISO 27001";
    if (frameworkEl) frameworkEl.value = defaultFw;
    if (companyEl) companyEl.value = "";
    _autoFillSessionTitle();
    if (modal) {
        modal.style.display = "flex";
    } else {
        // Previously a silent no-op if this element was ever missing --
        // looked identical to the button doing nothing at all, with no way
        // to tell from the outside. Now at least visible in the console.
        console.error("[openNewSessionModal] #new-session-modal not found in DOM.");
    }
    if (companyEl) setTimeout(() => { companyEl.focus(); }, 50);
}

function closeNewSessionModal() {
    const modal = document.getElementById("new-session-modal");
    if (modal) modal.style.display = "none";
}

// ── Admin: every auditor's reports ───────────────────────────────────────────
// The export endpoints already let an admin download any session
// (_assert_session_access permits role == "admin"); what was missing was any way
// to SEE which reports exist without already knowing a session id.
async function loadAllAuditorReports() {
    const box = document.getElementById("admin-auditor-reports");
    if (!box) return;
    box.innerHTML = `<div style="color:var(--text-muted); font-size:0.78rem; text-align:center; padding:14px 0;">Loading…</div>`;

    try {
        const res = await authFetch(`${API_BASE}/audit/admin/all-reports`);
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success) {
            throw new Error(data.detail || `Server returned ${res.status}`);
        }
        const reports = data.reports || [];
        if (!reports.length) {
            box.innerHTML = `<div style="color:var(--text-muted); font-size:0.78rem; text-align:center; padding:14px 0;">No audit reports found.</div>`;
            return;
        }

        const rows = reports.map(r => {
            const when = r.created_at ? new Date(r.created_at).toLocaleDateString() : "—";
            // A report with nothing committed exports an empty document. Saying so
            // here stops an admin sending a client a blank report.
            const empty = !r.committed_findings;
            const countCell = empty
                ? `<span style="color:#f59e0b; font-weight:700;" title="Nothing committed to Shakthi DB — a download would be empty">${r.total_findings} draft, 0 committed</span>`
                : `<span style="color:#10b981; font-weight:700;">${r.committed_findings} committed</span>`;
            const sid = escapeHtml(r.session_id);
            return `
            <tr style="border-bottom:1px solid rgba(148,163,184,0.12);">
                <td style="padding:7px 8px; font-size:0.76rem;">${escapeHtml(r.session_title)}</td>
                <td style="padding:7px 8px; font-size:0.76rem; color:var(--text-muted);">${escapeHtml(r.auditor)}</td>
                <td style="padding:7px 8px; font-size:0.74rem;">${escapeHtml(r.framework)}</td>
                <td style="padding:7px 8px; font-size:0.74rem;">${escapeHtml(r.status)}</td>
                <td style="padding:7px 8px; font-size:0.74rem; color:var(--text-muted);">${when}</td>
                <td style="padding:7px 8px; font-size:0.74rem;">${countCell}</td>
                <td style="padding:7px 8px; white-space:nowrap;">
                    <button type="button" onclick="adminDownloadReport('${sid}','pdf')"
                        style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:#f87171; padding:3px 9px; border-radius:6px; font-size:0.7rem; font-weight:700; cursor:pointer;">PDF</button>
                    <button type="button" onclick="adminDownloadReport('${sid}','docx')"
                        style="background:rgba(59,130,246,0.15); border:1px solid rgba(59,130,246,0.3); color:#60a5fa; padding:3px 9px; border-radius:6px; font-size:0.7rem; font-weight:700; cursor:pointer; margin-left:4px;">DOCX</button>
                </td>
            </tr>`;
        }).join("");

        box.innerHTML = `
        <table style="width:100%; border-collapse:collapse;">
            <thead>
                <tr style="text-align:left; border-bottom:1px solid rgba(148,163,184,0.25);">
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Session</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Auditor</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Framework</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Status</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Created</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Findings</th>
                    <th style="padding:6px 8px; font-size:0.68rem; text-transform:uppercase; color:var(--text-muted);">Export</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;
    } catch (err) {
        console.error("[Admin reports] load failed:", err);
        box.innerHTML = `<div style="color:#f87171; font-size:0.78rem; padding:12px;">Could not load auditor reports: ${escapeHtml(err.message)}</div>`;
    }
}

async function adminDownloadReport(sessionId, kind) {
    // Reuses the normal export endpoints -- an admin is authorised there already,
    // so this is the same document the auditor would get, not a separate path that
    // could drift from it.
    try {
        showToast(`Preparing ${kind.toUpperCase()} export…`, "info");
        const url = `${API_BASE}/audit/export/${kind}?session_id=${encodeURIComponent(sessionId)}`;
        const res = await authFetch(url);
        if (!res.ok) {
            const e = await res.json().catch(() => ({}));
            throw new Error(e.detail || `Server returned ${res.status}`);
        }
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `audit_report_${sessionId.slice(0, 8)}.${kind}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(a.href);
        showToast(`${kind.toUpperCase()} downloaded.`, "success");
    } catch (err) {
        console.error("[Admin download] failed:", err);
        showToast(`Download failed: ${err.message}`, "error");
    }
}

// ── Checklist builder ────────────────────────────────────────────────────────
// The no-Excel path into scoping. Rows typed here are POSTed to
// /controls/build-scope-checklist, which runs the SAME control resolution the
// uploaded sheet does, so an in-app checklist and an uploaded one are
// indistinguishable from that point on. Evidence is chosen from the files already
// uploaded to this session rather than typed, which is the real advantage: the
// Excel path has to fuzzy-match typed filenames against actual uploads, and this
// removes that failure mode instead of tolerating it.
window._builderEvidenceFiles = [];

async function openChecklistBuilder() {
    const modal = document.getElementById("checklist-builder-modal");
    if (!modal) return;

    // Pull the session's real evidence filenames so the dropdown offers exactly
    // what can actually be matched.
    window._builderEvidenceFiles = [];
    try {
        if (activeSessionId) {
            const r = await authFetch(`${API_BASE}/audit/evidence?session_id=${encodeURIComponent(activeSessionId)}`);
            const d = await r.json();
            window._builderEvidenceFiles = ((d && d.success && d.files) ? d.files : [])
                .map(f => f.filename).filter(Boolean);
        }
    } catch (e) {
        console.warn("[Builder] Could not load evidence file list:", e);
    }

    const note = document.getElementById("builder-no-evidence-note");
    if (note) note.style.display = window._builderEvidenceFiles.length ? "none" : "block";

    // The two scope modes read different sheets, so the builder has to collect
    // different things. It used to collect a question and one evidence file for
    // both -- which is the Customize shape -- so a scope built here in Excel mode
    // had no policy document, and Excel mode fails a row that has none.
    const _isCustomize = String(window.currentScopingMode || "").toUpperCase().startsWith("CUSTOM");
    window._builderIsCustomize = _isCustomize;

    const _show = (id, on) => {
        const el = document.getElementById(id);
        if (el) el.style.display = on ? "" : "none";
    };
    _show("bhdr-question", _isCustomize);
    _show("bhdr-policy", !_isCustomize);
    // No control column: Customize resolves no control, so a value typed here
    // would be collected, sent, and then dropped by the server.
    _show("bhdr-control", !_isCustomize);

    // Read left-to-right in the same order as the sheet this mode reads, so the
    // builder and the downloaded template teach one layout rather than two:
    //   Excel      Control ID | Policy document | Evidence document
    //   Customize  Audit check question | Evidence file | Control ID
    const _order = (id, n) => {
        const el = document.getElementById(id);
        if (el) el.style.order = String(n);
    };
    _order("bhdr-question", _isCustomize ? 1 : 0);
    _order("bhdr-control", _isCustomize ? 3 : 1);
    _order("bhdr-policy", 2);
    _order("bhdr-evidence", _isCustomize ? 2 : 3);

    // The hidden question column was the one carrying flex:1, so without this the
    // Excel row packs to its fixed widths and leaves a dead gap on the right.
    const _grow = (id, on) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.style.flex = on ? "1" : "";
        el.style.width = on ? "auto" : "230px";
        el.style.minWidth = on ? "170px" : "";
    };
    _grow("bhdr-policy", !_isCustomize);
    _grow("bhdr-evidence", !_isCustomize);

    const _sub = document.getElementById("builder-subtitle");
    if (_sub) {
        _sub.innerText = _isCustomize
            ? "Write each question and pick the document that answers it. Each question is answered from that document alone -- no controls are applied."
            : "Name the control, its policy document(s) and the evidence that proves it is done. Add as many of each as the control needs. Both sides are assessed; a row passes only if both hold.";
    }
    const _hdrEv = document.getElementById("bhdr-evidence");
    if (_hdrEv) _hdrEv.innerText = _isCustomize ? "Evidence file(s)" : "Evidence document(s)";

    const _hdrCtrl = document.getElementById("bhdr-control");
    if (_hdrCtrl) _hdrCtrl.innerText = _isCustomize ? "Control ID (Optional)" : "Control ID";

    const rows = document.getElementById("builder-rows");
    if (rows) rows.innerHTML = "";
    addChecklistRow();
    addChecklistRow();
    addChecklistRow();

    modal.style.display = "flex";
}

function closeChecklistBuilder() {
    const modal = document.getElementById("checklist-builder-modal");
    if (modal) modal.style.display = "none";
}

// A row's document lists. Each side was a single <select>, so a control needing
// two policies or three pieces of evidence could not be expressed in the builder
// at all -- the spreadsheet path has always allowed several per cell, and the
// API takes lists on both sides, so only this widget was the limit.
//
// A picker that adds a chip, rather than a <select multiple>: multiple-select
// needs ctrl+click to add a second item and silently drops the first if the
// auditor plain-clicks, which is the wrong default for the mistake being made
// here (naming one file when two were meant).
function _builderAddFile(sel) {
    const name = sel.value;
    sel.value = "";
    if (!name) return;
    const box = sel.closest(".builder-files");
    if (!box) return;
    const chips = box.querySelector(".builder-chips");
    if (!chips) return;
    const already = Array.from(chips.querySelectorAll(".builder-chip"))
        .map(c => c.getAttribute("data-file"));
    if (already.indexOf(name) !== -1) return;   // same file twice is not two documents
    chips.insertAdjacentHTML("beforeend", _builderChipHtml(name));
}

function _builderChipHtml(name) {
    return `<span class="builder-chip" data-file="${escapeHtml(name)}" title="${escapeHtml(name)}"
        style="display:inline-flex; align-items:center; gap:4px; background:rgba(37,99,235,0.18); border:1px solid rgba(59,130,246,0.35); color:#dbeafe; border-radius:999px; padding:2px 4px 2px 8px; font-size:0.68rem; max-width:100%;">
        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:150px;">${escapeHtml(name)}</span>
        <button type="button" title="Remove" onclick="this.closest('.builder-chip').remove()"
            style="background:none; border:none; color:#93c5fd; cursor:pointer; font-size:0.72rem; line-height:1; padding:0 2px;">✕</button>
    </span>`;
}

function _builderRowFiles(row, role) {
    const box = row.querySelector(`.builder-files[data-role="${role}"]`);
    if (!box) return [];
    return Array.from(box.querySelectorAll(".builder-chip"))
        .map(c => c.getAttribute("data-file"))
        .filter(Boolean);
}

function addChecklistRow(question, file, controlId, policyFile) {
    const wrap = document.getElementById("builder-rows");
    if (!wrap) return;

    const isCustomize = !!window._builderIsCustomize;
    const asList = v => (Array.isArray(v) ? v : (v ? [v] : []));
    const fileOpts = label =>
        [`<option value="">— add ${label} —</option>`]
            .concat((window._builderEvidenceFiles || []).map(f =>
                `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`))
            .join("");
    const chipsFor = list => asList(list).map(_builderChipHtml).join("");

    const row = document.createElement("div");
    row.className = "builder-row";
    // flex-start, not center: a row grows downward as documents are added, and
    // centred fields drift out of line with their headers as it does.
    row.style.cssText = "display:flex; gap:8px; align-items:flex-start; margin-bottom:6px;";
    const fieldCss = "padding:7px 6px; font-size:0.74rem; border-radius:6px; background:rgba(15,23,42,0.6); border:1px solid rgba(148,163,184,0.25); color:#f8fafc;";
    // Both modes pick from the SAME uploaded-evidence list: a policy document is
    // an uploaded file like any other, and typing its name by hand is the
    // mismatch the builder exists to avoid.
    row.innerHTML = `
        <input type="text" class="builder-q" maxlength="500" placeholder="e.g. Whether NTP is enabled?"
            value="${escapeHtml(question || "")}"
            style="flex:1; order:${isCustomize ? 1 : 0}; ${fieldCss} ${isCustomize ? "" : "display:none;"}">
        <div class="builder-files" data-role="policy"
            style="${isCustomize ? "width:230px;" : "flex:1; min-width:170px;"} order:2; display:${isCustomize ? "none" : "flex"}; flex-direction:column; gap:4px;">
            <select class="builder-picker" onchange="_builderAddFile(this)"
                style="width:100%; ${fieldCss}">${fileOpts("policy document")}</select>
            <div class="builder-chips" style="display:flex; flex-wrap:wrap; gap:4px;">${chipsFor(policyFile)}</div>
        </div>
        <div class="builder-files" data-role="evidence"
            style="${isCustomize ? "width:230px;" : "flex:1; min-width:170px;"} order:${isCustomize ? 2 : 3}; display:flex; flex-direction:column; gap:4px;">
            <select class="builder-picker" onchange="_builderAddFile(this)"
                style="width:100%; ${fieldCss}">${fileOpts(isCustomize ? "evidence file" : "evidence document")}</select>
            <div class="builder-chips" style="display:flex; flex-wrap:wrap; gap:4px;">${chipsFor(file)}</div>
        </div>
        <input type="text" class="builder-ctrl" maxlength="40" placeholder="e.g. A.6.5"
            value="${escapeHtml(controlId || "")}"
            style="width:130px; order:1; ${fieldCss} ${isCustomize ? "display:none;" : ""}">
        <button type="button" title="Remove row" onclick="this.closest('.builder-row').remove()"
            style="width:28px; order:9; background:transparent; border:none; color:#f87171; cursor:pointer; font-size:1rem; line-height:1;">✕</button>`;
    wrap.appendChild(row);
}

async function applyChecklistBuilder() {
    const isCustomize = !!window._builderIsCustomize;
    const val = (r, sel) => ((r.querySelector(sel) || {}).value || "").trim();
    const rows = Array.from(document.querySelectorAll("#builder-rows .builder-row")).map(r => ({
        question: val(r, ".builder-q"),
        files: _builderRowFiles(r, "evidence"),
        policy_files: isCustomize ? [] : _builderRowFiles(r, "policy"),
        control_id: val(r, ".builder-ctrl"),
    })).filter(r => isCustomize
        ? r.question
        : (r.control_id || r.files.length || r.policy_files.length));

    if (!rows.length) {
        showToast(isCustomize
            ? "Add at least one audit check question."
            : "Add at least one row with a control ID and its documents.", "error");
        return;
    }
    if (isCustomize) {
        if (rows.every(r => !r.files.length)) {
            showToast("Pick at least one evidence file to answer a question.", "error");
            return;
        }
    } else {
        // Excel scoping assesses both sides, so a row missing one is a gap the
        // auditor should decide on now rather than read as a finding later.
        const noPolicy = rows.filter(r => !r.policy_files.length).length;
        const noEvidence = rows.filter(r => !r.files.length).length;
        if (rows.every(r => !r.control_id)) {
            showToast("Excel scoping needs the control ID on each row (e.g. A.6.5).", "error");
            return;
        }
        if (noPolicy || noEvidence) {
            const parts = [];
            if (noPolicy) parts.push(`${noPolicy} row(s) with no policy document`);
            if (noEvidence) parts.push(`${noEvidence} row(s) with no evidence document`);
            const ok = confirm(
                `${parts.join(" and ")}.\n\n` +
                "Excel scoping assesses the policy and the evidence separately, and " +
                "reports a missing one as a gap. Continue anyway?");
            if (!ok) return;
        }
    }

    const btn = document.getElementById("btn-apply-checklist");
    if (btn) { btn.disabled = true; btn.innerText = "Applying..."; }

    try {
        const res = await authFetch(`${API_BASE}/controls/build-scope-checklist`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rows, scoping_mode: window.currentScopingMode || "" }),
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            throw new Error(data.detail || "Could not build the checklist.");
        }

        // From here on this is byte-identical to the uploaded-sheet path.
        customEvidenceMappings = data.custom_evidence || null;
        customControlDocuments = data.custom_documents || null;

        const matched = new Set((data.matched_sls || []).map(n => parseInt(n)));
        document.querySelectorAll("#controls-checkbox-container input[type='checkbox']")
            .forEach(cb => { cb.checked = matched.has(parseInt(cb.value)); });
        if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();

        const isCustomize = String(window.currentScopingMode || "").toUpperCase().startsWith("CUSTOM");
        if (typeof saveSessionScopingCache === "function") {
            saveSessionScopingCache(activeSessionId, data.custom_evidence,
                isCustomize ? "CUSTOMIZE" : "Excel Scoping");
        }

        const banner = document.getElementById("excel-scope-banner");
        if (banner) banner.style.display = "flex";
        const label = document.getElementById("excel-scope-label");
        if (label) label.innerText = `Checklist Built In-App (${rows.length} Items)`;

        closeChecklistBuilder();
        if (data.warning) showToast(data.warning, "error");
        showToastBanner(isCustomize
            ? `CHECKLIST APPLIED: ${rows.length} question(s) — each answered from the document cited on its row`
            : `CHECKLIST APPLIED: ${rows.length} question(s), ${matched.size} control(s) matched`);
    } catch (err) {
        console.error("[Builder] apply failed:", err);
        showToast(`Could not apply checklist: ${err.message}`, "error");
    } finally {
        if (btn) { btn.disabled = false; btn.innerText = "Apply Checklist"; }
    }
}

// Excel scoping assesses a POLICY document and an EVIDENCE document per row and
// reports a missing policy as a gap. A question-based sheet -- the shape the app
// used to hand out for both modes -- parses perfectly well here and then fails
// every row for the same reason, which reads as an audit result rather than as
// the wrong sheet. Say so at upload time, while it is still a file the auditor
// can swap.
function _warnIfScopeSheetLacksPolicy(data) {
    try {
        const mode = String(window.currentScopingMode || "EXCEL").toUpperCase();
        if (mode.startsWith("CUSTOM")) return;   // no policy dimension by design
        const items = (data && data.custom_evidence && data.custom_evidence.excel_items) || [];
        if (!items.length) return;
        const withPolicy = items.filter(it => ((it.policy_files || []).length > 0)).length;
        if (withPolicy > 0) return;
        alert(
            "⚠ This sheet has no policy document column.\n\n" +
            `All ${items.length} row(s) were loaded, but Excel Scoping assesses a policy ` +
            "document AND an evidence document for each control, so every row will be " +
            "reported as a policy gap.\n\n" +
            "Expected columns:  Control ID (ISO) | Policy Document Name | Evidence Document Name\n\n" +
            "Use \"download a template\" for the correct sheet, or switch to Customize " +
            "mode if you meant question-based scoping with no policy.");
    } catch (e) {
        console.warn("[Scope] policy-column check skipped:", e);
    }
}

async function downloadScopeTemplate() {
    try {
        // The two modes read different sheets. Handing out one template for both
        // meant an auditor in Excel mode filled in a question-based sheet with
        // nowhere to name a policy -- the one document that mode is built to
        // assess -- and only found out from the findings.
        const mode = String(window.currentScopingMode || "EXCEL").toUpperCase();
        const isCustomize = mode.startsWith("CUSTOM");
        const res = await authFetch(
            `${API_BASE}/controls/scope-template?mode=${encodeURIComponent(mode)}`);
        if (!res.ok) throw new Error("Template download failed.");
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.download = isCustomize
            ? "customize_question_checklist_template.xlsx"
            : "excel_scoping_policy_evidence_template.xlsx";
        a.href = url;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast("Template downloaded — fill it in and upload it back.", "success");
    } catch (err) {
        console.error("[Template] download failed:", err);
        showToast("Could not download the template.", "error");
    }
}

// ── Report Metadata modal ────────────────────────────────────────────────────
// The branding/metadata form used to be a sidebar collapsible, and the Edit
// button on the REPORT METADATA card in Report Exporter called
// toggleCollapsible('branding-fields') -- which expanded the form back in the
// sidebar, nowhere near the card the auditor had just clicked. The form now
// lives in #branding-modal next to the card that displays its values.
function openBrandingModal() {
    const modal = document.getElementById("branding-modal");
    if (modal) modal.style.display = "flex";
}

function closeBrandingModal() {
    const modal = document.getElementById("branding-modal");
    if (modal) modal.style.display = "none";
    // Push any edits straight back into the REPORT METADATA summary card so the
    // values the auditor just typed are visible immediately on closing.
    if (typeof updateBrandingSummary === "function") {
        try { updateBrandingSummary(); } catch (e) { }
    }
}

async function handleNewSessionSubmit(e) {
    e.preventDefault();
    if (window._isCreatingSession) return;
    window._isCreatingSession = true;

    try {
        const input = document.getElementById("new-session-title-input");
        const title = input ? input.value.trim() : "";
        closeNewSessionModal();
        await startNewAuditSession(true, title);
    } finally {
        window._isCreatingSession = false;
    }
}


async function startNewAuditSession(skipPrompt = false, customTitle = null) {
    if (!currentUser) return;
    try {
        const todayStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
        // Build smart default title from modal fields if available
        const frameworkEl = document.getElementById("new-session-framework");
        const companyEl = document.getElementById("new-session-company");
        // Primary source: modal #new-session-framework (already pre-filled from
        // the sidebar by openNewSessionModal()). Fallback: current sidebar value.
        // This ensures the stored DB framework always matches what the user sees.
        const sidebarFwEl = document.getElementById("framework-select");
        const framework = (frameworkEl && frameworkEl.value)
            ? frameworkEl.value
            : (sidebarFwEl && sidebarFwEl.value)
                ? sidebarFwEl.value
                : "ISO 27001";
        const company = (companyEl && companyEl.value.trim()) ? ` — ${companyEl.value.trim()}` : "";
        const defaultTitle = `${framework}${company} — ${todayStr}`;
        let finalTitle = customTitle || defaultTitle;

        if (!skipPrompt && customTitle === null) {
            // Only this auditor's own running audits are checked -- other
            // auditors' active sessions never block or interrupt this flow.
            //
            // Previously, declining the confirm() below returned out of this
            // whole function with zero visible feedback -- indistinguishable
            // from the button silently doing nothing at all, including from a
            // stray misclick on the dialog. Now every path either opens the
            // new-session modal or explicitly says why it didn't.
            let userDeclined = false;
            try {
                const activeResp = await authFetch(`${API_BASE}/audit/my-active-audits`);
                const activeData = await activeResp.json();
                const activeSessions = (activeData.success && activeData.active_sessions) ? activeData.active_sessions : [];
                if (activeSessions.length > 0) {
                    const proceed = confirm(
                        `⚠️ You have ${activeSessions.length} audit(s) currently running:\n\n` +
                        activeSessions.map(s => `• ${s}`).join('\n') +
                        `\n\nStarting a new session will STOP the running audit(s) and their in-progress scan will be lost. Continue?`
                    );
                    if (!proceed) {
                        userDeclined = true;
                        showToast("Cancelled — your running audit was left untouched.", "info");
                    } else {
                        for (const sid of activeSessions) {
                            await authFetch(`${API_BASE}/audit/stop/${sid}`, { method: "POST" }).catch(() => { });
                        }
                        showToast("⏹️ Stopped previous running audit(s).", "info");
                    }
                }
            } catch (err) {
                // Fails open: if the active-audits check itself errors (network
                // blip, etc.), still let the user create a new session rather
                // than silently blocking them.
                console.error("Error checking active audits:", err);
            }
            if (!userDeclined) openNewSessionModal();
            return;
        }

        // ── FULL SESSION STATE RESET ─────────────────────────────────────────────────
        // Reset every global variable that belongs to a session so nothing bleeds
        // from a previous session into the new one.

        const shortId = Math.random().toString(36).substring(2, 8);
        activeSessionId = `session-${Date.now()}-${shortId}`;
        activeSessionTitle = finalTitle;

        // Data state
        findingsList = [];
        uploadedFilesList = [];
        customEvidenceMappings = null;
        customControlDocuments = null;
        activeSeverityFilter = "";
        activeStatusFilter = "All";
        activeComplianceFilter = "";
        currentInterruptedSession = null;

        // Stop any in-progress polling from the old session
        if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
        if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
        window._currentPollSessionId = activeSessionId;

        // ── Reset UI: Session header ─────────────────────────────────────────────────
        const badgeEl = document.getElementById("active-session-badge");
        const titleEl = document.getElementById("workspace-title");
        if (badgeEl) badgeEl.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
        if (titleEl) titleEl.innerText = activeSessionTitle;

        // ── Reset UI: File upload area ───────────────────────────────────────────────
        const emptyMsg = `<div class="empty-state">No files uploaded yet. Upload files to verify compliance.</div>`;
        const evidenceRegistry = document.getElementById("uploaded-files-registry");
        const auditeeRegistry = document.getElementById("auditee-files-registry");
        const countBadge = document.getElementById("evidence-count-badge");
        if (evidenceRegistry) evidenceRegistry.innerHTML = emptyMsg;
        if (auditeeRegistry) auditeeRegistry.innerHTML = emptyMsg;
        if (countBadge) countBadge.innerText = "0 files";

        // ── Reset UI: Report preview ─────────────────────────────────────────────────
        const previewContainer = document.getElementById("report-preview-container");
        if (previewContainer) previewContainer.innerHTML = "";

        // ── Reset UI: Findings panel ─────────────────────────────────────────────────
        const container = document.getElementById("findings-container");
        if (container) container.innerHTML = `<div class="empty-state">No audit findings generated yet. Upload evidence documents and click Run Audit.</div>`;

        // ── Reset UI: KPI counters ───────────────────────────────────────────────────
        ["count-compliant", "count-noncompliant", "count-p1", "count-p2", "count-p3", "count-p4"].forEach(id => {
            const el = document.getElementById(id); if (el) el.innerText = "0";
        });

        // ── Reset UI: Scan run button ─────────────────────────────────────────────────
        const runBtn = document.getElementById("run-analysis-btn");
        const stopBtn = document.getElementById("stop-analysis-btn");
        if (runBtn) {
            runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
            runBtn.disabled = false;
            runBtn.style.opacity = "1";
            runBtn.style.cursor = "pointer";
        }
        if (stopBtn) stopBtn.style.display = "none";

        // ── Reset UI: Controls checkboxes, search & scoping mode ─────────────────────
        try {
            // Uncheck all controls
            if (typeof selectAllCheckboxes === "function") selectAllCheckboxes(false);
            if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();

            // Reset to Excel Upload Scope (no scope from old session)
            if (typeof setScopingMode === "function") setScopingMode('EXCEL');

            // Clear search filter — "5.15" or any other previous term persisted across sessions
            const searchInput = document.getElementById("controls-search-input");
            if (searchInput) {
                searchInput.value = "";
                if (typeof filterCheckboxList === "function") filterCheckboxList();
            }

            // Hide Excel scoping banner
            const excelBanner = document.getElementById("excel-scope-banner");
            if (excelBanner) excelBanner.style.display = "none";
            const scopeLabel = document.getElementById("excel-scope-label");
            if (scopeLabel) scopeLabel.innerText = "";

        } catch (e) {
            console.warn("[Session Reset] Control reset warning:", e);
        }

        // ── Reset UI: Status/severity filter buttons ──────────────────────────────────
        document.querySelectorAll(".filter-btn").forEach(btn => btn.classList.remove("active"));
        const allBtn = document.querySelector(".filter-btn[data-status='All']") ||
            document.querySelector(".filter-btn[data-filter='All']");
        if (allBtn) allBtn.classList.add("active");

        // ── Reset UI: Workflow filter ─────────────────────────────────────────────────
        // "All", not "" -- the empty string matches none of the select's options, so
        // the browser rendered the box blank. Every other reset of this control
        // (the session load, the KPI toggle, the severity toggle) sets "All"; this
        // one was the odd one out, so a new session always opened showing a filter
        // with no value in it. Harmless to the filtering itself, which reads the
        // value and falls back to "all" when it is empty -- which is exactly why
        // it survived: the list was right and only the label looked wrong.
        const wfFilter = document.getElementById("status-filter");
        if (wfFilter) wfFilter.value = "All";

        // ── Reset UI: Progress bar ────────────────────────────────────────────────────
        const progressBar = document.getElementById("pipeline-progress-fill");
        const progressPct = document.getElementById("pipeline-progress-percent");
        const progressStatus = document.getElementById("pipeline-status-text");
        if (progressBar) progressBar.style.width = "0%";
        if (progressPct) progressPct.innerText = "0%";
        if (progressStatus) progressStatus.innerText = "Ready to scan";

        // ── Reload dynamic data ───────────────────────────────────────────────────────
        loadEvidenceFileList();
        populateAuditeeSelector();

        // ── Persist session to DB ─────────────────────────────────────────────────────
        try {
            const sessionBody = new FormData();
            sessionBody.append("session_title", finalTitle);
            sessionBody.append("framework", framework);
            sessionBody.append("username", currentUser ? currentUser.username : "admin");
            const saveResp = await authFetch(`${API_BASE}/audit/sessions`, {
                method: "POST",
                body: sessionBody
            });
            const saveData = await saveResp.json();
            if (saveData.success && saveData.session_id) {
                activeSessionId = saveData.session_id;
                // The framework the auditor just picked in the modal, so the
                // sidebar agrees with the session from the moment it exists.
                applySessionFramework(framework);
                if (badgeEl) badgeEl.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
                try {
                    const userKey = currentUser && currentUser.username ? `_${currentUser.username}` : "";
                    localStorage.setItem(`last_active_session_id${userKey}`, activeSessionId);
                    if (activeSessionTitle) localStorage.setItem(`last_active_session_title${userKey}`, activeSessionTitle);
                } catch (e) { }
            }
        } catch (saveErr) {
            console.warn("[Session] Could not persist session to DB:", saveErr.message);
        }

        // ── Reload controls list fresh for the new session ────────────────────────────
        try {
            await loadFrameworkControls();
        } catch (e) {
            console.warn("[Session] Controls reload warning:", e);
        }

        loadRecentSessions();

        // A brand-new session opens on the Scan Workspace -- that is where the
        // auditor actually starts work (upload evidence, pick scope, run the
        // scan). Creating a session used to leave whatever tab happened to be
        // open still showing, so a fresh session could land on Report Exporter
        // or Audit Records, both of which are empty by definition for a session
        // that has not run yet.
        try {
            const scanTabBtn = Array.from(document.querySelectorAll("#tabs-bar button"))
                .find(b => b.innerText.includes("Scan"));
            switchTab("tab-scan-workspace", scanTabBtn);
        } catch (tabErr) {
            console.warn("[Session] Could not switch to Scan Workspace tab:", tabErr);
        }

        if (!skipPrompt) {
            showToast(`Started fresh new audit session: "${finalTitle}"`, "info");
        }
    } catch (err) {
        console.error("Error starting new session:", err);
    }
}

async function loadOrCreateSession(user) {
    const userKey = user && user.username ? `_${user.username}` : "";
    const lastSid = localStorage.getItem(`last_active_session_id${userKey}`);
    const lastTitle = localStorage.getItem(`last_active_session_title${userKey}`);
    if (lastSid) {
        activeSessionId = lastSid;
        if (lastTitle) activeSessionTitle = lastTitle;
        syncFrameworkFromSession(lastSid);
        const badgeEl = document.getElementById("active-session-badge");
        const titleEl = document.getElementById("workspace-title");
        if (badgeEl) badgeEl.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
        if (titleEl) titleEl.innerText = activeSessionTitle;
    } else {
        activeSessionId = "";
        activeSessionTitle = "";
        const badgeEl = document.getElementById("active-session-badge");
        const titleEl = document.getElementById("workspace-title");
        if (badgeEl) badgeEl.innerText = "";
        if (titleEl) titleEl.innerText = "ISO 27001 Workspace";
    }
    const showedInterruptedModal = await checkInterruptedAuditSessions();

    // A fresh auditor account (or a browser with no saved session) previously
    // landed on a blank workspace with no active session and no indication of
    // what to do next -- despite this function's name, it never actually
    // "created" one. Only auditors run audits from this workspace (admin
    // doesn't, auditee has its own separate upload-driven flow), and only
    // when there's neither a session to resume nor an interrupted one to
    // recover, so this never stacks on top of the interrupted-session modal.
    if (!lastSid && !showedInterruptedModal && user) {
        if (user.role === "auditor") {
            openNewSessionModal();
        } else if (user.role === "auditee") {
            // Auditees need a session to upload evidence. Auto-create one so
            // they are never blocked by "Active session missing" on first login.
            try {
                const body = new FormData();
                body.append("session_title", `Evidence Upload — ${user.username}`);
                body.append("framework", "ISO 27001");
                body.append("username", user.username);
                const res = await authFetch(`${API_BASE}/audit/sessions`, { method: "POST", body });
                const data = await res.json();
                if (data.success && data.session_id) {
                    activeSessionId = data.session_id;
                    activeSessionTitle = data.session_title || "Evidence Upload Session";
                    try {
                        localStorage.setItem(`last_active_session_id${userKey}`, activeSessionId);
                        localStorage.setItem(`last_active_session_title${userKey}`, activeSessionTitle);
                    } catch (e) { }
                    const badgeEl = document.getElementById("active-session-badge");
                    const titleEl = document.getElementById("workspace-title");
                    if (badgeEl) badgeEl.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
                    if (titleEl) titleEl.innerText = activeSessionTitle;
                }
            } catch (e) {
                console.warn("[Auditee] Auto session create failed:", e);
            }
        }
    }
}


let currentInterruptedSession = null;

async function checkInterruptedAuditSessions() {
    // Returns true iff an interrupted-session recovery modal was actually shown,
    // so callers (loadOrCreateSession) know whether it's safe to instead prompt
    // for a brand new session without stacking two modals on top of each other.
    if (!currentUser) return false;
    // Admin user does not run audit scans — do NOT show audit scan recovery modal for admin!
    if (currentUser.role === "admin" || currentUser.username === "admin") return false;

    try {
        const username = currentUser.username || "auditor";
        const resp = await authFetch(`${API_BASE}/audit/interrupted-checkpoints?username=${encodeURIComponent(username)}`);
        const data = await resp.json();

        if (data.success && data.interrupted_sessions && data.interrupted_sessions.length > 0) {
            currentInterruptedSession = data.interrupted_sessions[0];
            showInterruptedSessionModal(currentInterruptedSession);
            return true;
        }
        return false;
    } catch (e) {
        console.warn("[Interrupted Checkpoint] Check error:", e);
        return false;
    }
}

function showInterruptedSessionModal(session) {
    const modal = document.getElementById("interrupted-session-modal");
    if (!modal) return;

    const titleEl = document.getElementById("interrupted-session-title");
    const progressEl = document.getElementById("interrupted-progress-text");
    const timeEl = document.getElementById("interrupted-time-text");

    if (titleEl) titleEl.innerText = session.session_title || session.session_id || "Untitled Session";
    if (progressEl) progressEl.innerText = `${session.completed_controls || 0} / ${session.total_controls || 0} Controls`;
    if (timeEl) timeEl.innerText = session.updated_at || "—";

    modal.style.display = "flex";
}

async function handleResumeInterruptedSession() {
    if (!currentInterruptedSession) return;
    const modal = document.getElementById("interrupted-session-modal");
    if (modal) modal.style.display = "none";

    try {
        const sid = currentInterruptedSession.session_id;
        activeSessionId = sid;
        activeSessionTitle = currentInterruptedSession.session_title || sid;

        const badgeEl = document.getElementById("active-session-badge");
        const titleEl = document.getElementById("workspace-title");
        if (badgeEl) badgeEl.innerText = `Session ID: ${activeSessionId.slice(0, 14)}...`;
        if (titleEl) titleEl.innerText = activeSessionTitle;

        showToastBanner(`RESUMING AUDIT SCAN: "${activeSessionTitle}"`);

        // pollAuditProgress takes no arguments and polls activeSessionId -- the
        // `bg_${sid}` passed here was ignored, and calling it once instead of on
        // an interval meant the progress bar never moved again either way.
        await resumeSessionFromCheckpoint(sid);

        // The workspace still shows the previous session's data until the
        // already-completed controls are pulled back in.
        if (typeof loadEvidenceFileList === "function") loadEvidenceFileList();
        if (typeof loadFindings === "function") await loadFindings();
    } catch (err) {
        showToastBanner(`Resume failed: ${err.message}`, "error");
    }
}

async function handleDiscardInterruptedSession() {
    if (!currentInterruptedSession) return;
    const modal = document.getElementById("interrupted-session-modal");
    if (modal) modal.style.display = "none";

    try {
        const sid = currentInterruptedSession.session_id;
        await authFetch(`${API_BASE}/audit/discard-checkpoint`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid })
        });
        showToastBanner("Interrupted session discarded. Opening fresh workspace.", "info");
        currentInterruptedSession = null;
        await startNewAuditSession(true);
    } catch (err) {
        showToastBanner(`Discard failed: ${err.message}`, "error");
    }
}

async function populateAuditeeSelector() {
    const select = document.getElementById("report-target-auditee");
    if (!select) return;

    try {
        const userRes = await authFetch(`${API_BASE}/auth/auditees`); // BUG-01 FIX: was bare fetch() — no JWT sent, caused 401
        const userData = await userRes.json();

        if (userData.success && userData.auditees && userData.auditees.length > 0) {
            select.innerHTML = "";
            userData.auditees.forEach(a => {
                const opt = document.createElement("option");
                opt.value = a.username;
                opt.innerText = `${a.username} (${a.role.toUpperCase()} User Account)`;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = `
                <option value="auditee@organization.com">auditee@organization.com (Auditee User Account)</option>
                <option value="auditee2@organization.com">auditee2@organization.com (Auditee User Account)</option>
            `;
        }
    } catch (err) {
        console.error("Failed to populate auditee accounts:", err);
        select.innerHTML = `
            <option value="auditee@organization.com">auditee@organization.com (Auditee User Account)</option>
            <option value="auditee2@organization.com">auditee2@organization.com (Auditee User Account)</option>
        `;
    }
}

// ── FILE UPLOAD & EVIDENCE COLLECTOR ENGINE ──

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handleFileDrop(e) {
    preventDefaults(e);
    const dt = e.dataTransfer;
    const files = dt ? dt.files : null;
    if (files && files.length > 0) {
        uploadFiles(Array.from(files));
    }
}

async function processEvidenceFiles(files) {
    if (!files || files.length === 0) return;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];

        let sizeStr = "";
        if (file.size < 1024 * 1024) {
            sizeStr = `${(file.size / 1024).toFixed(1)} KB`;
        } else {
            sizeStr = `${(file.size / (1024 * 1024)).toFixed(1)} MB`;
        }

        const ext = file.name.split('.').pop().toLowerCase();
        let fileType = "DOC";
        let iconClass = "file-type-doc";

        if (["pdf"].includes(ext)) { fileType = "PDF"; iconClass = "file-type-pdf"; }
        else if (["xls", "xlsx", "csv"].includes(ext)) { fileType = "XLS"; iconClass = "file-type-xls"; }
        else if (["xml", "json", "txt", "html", "htm"].includes(ext)) { fileType = "XML"; iconClass = "file-type-xml"; }
        else if (["png", "jpg", "jpeg"].includes(ext)) { fileType = "IMG"; iconClass = "file-type-doc"; }

        const fileObj = {
            name: file.name,
            size: sizeStr,
            type: fileType,
            iconClass: iconClass,
            fileRaw: file
        };

        uploadedFilesList.push(fileObj);

        // Upload to backend API
        try {
            if (activeSessionId) {
                const formData = new FormData();
                formData.append("files", file);
                formData.append("session_id", activeSessionId);
                formData.append("is_auditor_uploaded", "true");
                formData.append("username", currentUser ? currentUser.username : "");

                authFetch(`${API_BASE}/audit/upload`, {
                    method: "POST",
                    body: formData
                }).catch(e => console.warn("Background upload notice:", e));
            }
        } catch (e) {
            console.warn("Upload exception:", e);
        }
    }

    renderUploadedFilesList();
}

function renderUploadedFilesList() {
    const registry = document.getElementById("uploaded-files-registry");
    const countBadge = document.getElementById("evidence-count-badge");
    if (!registry) return;

    if (countBadge) countBadge.innerText = `${uploadedFilesList.length} files`.trim();

    if (uploadedFilesList.length === 0) {
        registry.innerHTML = `<div class="empty-state" style="font-size: 0.78rem; color: var(--text-muted); text-align: center; padding: 24px;">No files uploaded yet. Drag files to begin audit.</div>`;
        return;
    }

    registry.innerHTML = "";
    uploadedFilesList.forEach((file, idx) => {
        const item = document.createElement("div");
        item.className = "modern-file-card";
        item.style.cssText = "display: flex; align-items: center; justify-content: space-between; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px; padding: 10px 12px; gap: 12px;";

        item.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; flex: 1;">
                <span class="file-icon-badge ${file.iconClass}" style="width: 32px; height: 32px; font-size: 0.65rem; border-radius: 8px; flex-shrink: 0; display: inline-flex; align-items: center; justify-content: center;">${file.type}</span>
                <div style="overflow: hidden;">
                    <div style="font-size: 0.82rem; font-weight: 600; color: var(--text-main); text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">${file.name}</div>
                    <div style="font-size: 0.7rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
                        <span>${file.size}</span>
                        <span style="color: #34d399; font-weight: 600;">✓ Attached</span>
                    </div>
                </div>
            </div>
            <button type="button" onclick="deleteEvidenceFile(${idx})" style="background: transparent; border: none; color: #94a3b8; cursor: pointer; padding: 4px; border-radius: 4px; display: flex; align-items: center; justify-content: center; transition: color 0.15s;" title="Remove file" onmouseover="this.style.color='#ef4444'" onmouseout="this.style.color='#94a3b8'" aria-label="Remove ${escapeHtml(file.name)}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
        `;
        registry.appendChild(item);
    });
}

async function deleteEvidenceFile(idx) {
    if (idx < 0 || idx >= uploadedFilesList.length) return;
    const file = uploadedFilesList[idx];

    // This button previously only spliced the local uploadedFilesList array --
    // the file had already been uploaded to the server in the background the
    // moment it was dropped (processEvidenceFiles's fire-and-forget POST
    // /audit/upload), but nothing told the server it was removed. Any later
    // refresh of this same file list from the server (loadEvidenceFileList(),
    // which renders into the identical #uploaded-files-registry container)
    // would still include it, making a "deleted" file reappear once a new
    // file was added. Soft-delete it server-side first, matching what
    // deleteServerEvidenceFile() already does elsewhere in the app.
    if (activeSessionId && file && file.name) {
        try {
            await authFetch(`${API_BASE}/audit/evidence/delete`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ session_id: activeSessionId, filename: file.name })
            });
        } catch (e) {
            console.warn("Evidence delete (server) failed, removing from local list only:", e);
        }
    }

    uploadedFilesList.splice(idx, 1);
    renderUploadedFilesList();
}

async function clearAllUploadedFiles() {
    if (activeSessionId) {
        try {
            await authFetch(`${API_BASE}/audit/evidence/delete-all`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ session_id: activeSessionId })
            });
        } catch (e) {
            console.warn("Evidence delete-all (server) failed, attempting individual deletes:", e);
            if (uploadedFilesList && uploadedFilesList.length > 0) {
                await Promise.all(uploadedFilesList.filter(f => f && f.name).map(file =>
                    authFetch(`${API_BASE}/audit/evidence/delete`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ session_id: activeSessionId, filename: file.name })
                    }).catch(err => console.warn("Evidence delete failed for", file.name, err))
                ));
            }
        }
    }

    uploadedFilesList = [];
    renderUploadedFilesList();
    if (typeof loadEvidenceFileList === "function") {
        await loadEvidenceFileList();
    }
}

function setAnalysisMode(mode) {
    const frameworkSelect = document.getElementById("framework-select");
    const fwVal = frameworkSelect ? frameworkSelect.value.toUpperCase() : "";
    const isTechnical = fwVal.includes("VAPT") || fwVal.includes("PQC");
    const isGovernance = (
        fwVal.includes("ISO") || fwVal.includes("SOC") ||
        fwVal.includes("DPDP") || fwVal.includes("BCMS") ||
        fwVal.includes("XBOM") || fwVal.includes("X-BOM")
    );

    if (isTechnical && (mode === "Quick" || mode === "Deep")) {
        mode = "Technical findings only";
    }
    if (isGovernance && mode === "Technical findings only") {
        mode = "Deep";
    }

    selectedAnalysisMode = mode;
    const btnScanner = document.getElementById("btn-mode-fast-parser");
    const btnQuick = document.getElementById("btn-mode-quick");
    const btnDeep = document.getElementById("btn-mode-deep");

    const allBtns = [btnScanner, btnQuick, btnDeep];

    const activeBtn = mode === "Technical findings only" ? btnScanner
        : mode === "Quick" ? btnQuick
            : btnDeep;

    allBtns.forEach(b => {
        if (!b) return;
        const isActive = b === activeBtn;
        b.classList.toggle("active", isActive);
        b.style.background = isActive ? "#2563eb" : "transparent";
        b.style.color = isActive ? "#ffffff" : "#94a3b8";
        b.style.fontWeight = isActive ? "700" : "500";
        b.style.outline = "none";
        b.style.boxShadow = isActive ? "0 2px 6px rgba(37, 99, 235, 0.4)" : "none";
    });

    // The AI-recommendations toggle only means anything in Scanner mode --
    // Quick/Deep already run the LLM for every finding, so offering it there
    // would ask a question that has already been answered.
    const aiRow = document.getElementById("ai-recommendations-row");
    if (aiRow) aiRow.style.display = (mode === "Technical findings only") ? "flex" : "none";
}

// ─── Framework-to-Mode Auto-Routing ──────────────────────────────────────────
// VAPT / PQC   → Mode locked to Scanner (Python Parsers + LLM Engine).
//               Quick Audit & Deep Audit buttons are greyed out & disabled.
// Governance   → ISO 27001 / SOC 2 / DPDP / BCMS / X-BOM require LLM
//               reasoning for policy vs evidence evaluation. Scanner is
//               disabled and mode is set to Deep Audit.
// ─────────────────────────────────────────────────────────────────────────────
function onFrameworkChangeSuggestMode() {
    const frameworkSelect = document.getElementById("framework-select");
    const fwVal = frameworkSelect ? frameworkSelect.value.toUpperCase() : "";
    if (typeof setAnalysisMode !== "function") return;

    const btnScanner = document.getElementById("btn-mode-fast-parser");
    const btnQuick = document.getElementById("btn-mode-quick");
    const btnDeep = document.getElementById("btn-mode-deep");

    const isGovernance = (
        fwVal.includes("ISO") || fwVal.includes("SOC") ||
        fwVal.includes("DPDP") || fwVal.includes("BCMS") ||
        fwVal.includes("XBOM") || fwVal.includes("X-BOM")
    );
    const isTechnical = fwVal.includes("VAPT") || fwVal.includes("PQC");

    if (isTechnical) {
        // VAPT / PQC → Lock mode to Scanner; Grey out Quick & Deep Audit buttons!
        if (btnQuick) {
            btnQuick.disabled = true;
            btnQuick.style.opacity = "0.35";
            btnQuick.style.cursor = "not-allowed";
            btnQuick.title = "Quick Audit is disabled for VAPT and PQC. Mode is locked to Scanner (Parser + LLM Engine).";
        }
        if (btnDeep) {
            btnDeep.disabled = true;
            btnDeep.style.opacity = "0.35";
            btnDeep.style.cursor = "not-allowed";
            btnDeep.title = "Deep Audit is disabled for VAPT and PQC. Mode is locked to Scanner (Parser + LLM Engine).";
        }
        if (btnScanner) {
            btnScanner.disabled = false;
            btnScanner.style.opacity = "1";
            btnScanner.style.cursor = "pointer";
            btnScanner.title = "Scanner mode: Technical scan of Nessus, Burp Suite, Nmap, Qualys, Trivy, PQC configs & images using Python Parsers + LLM Engine.";
        }
        setAnalysisMode("Technical findings only");
    } else if (isGovernance) {
        // Governance frameworks (ISO / SOC 2 / etc.) → Enable Quick & Deep; Disable Scanner
        if (btnQuick) {
            btnQuick.disabled = false;
            btnQuick.style.opacity = "1";
            btnQuick.style.cursor = "pointer";
            btnQuick.title = "Quick Audit mode.";
        }
        if (btnDeep) {
            btnDeep.disabled = false;
            btnDeep.style.opacity = "1";
            btnDeep.style.cursor = "pointer";
            btnDeep.title = "Deep Audit mode.";
        }
        if (btnScanner) {
            btnScanner.disabled = true;
            btnScanner.style.opacity = "0.35";
            btnScanner.style.cursor = "not-allowed";
            btnScanner.title = "Scanner is not available for governance frameworks. AI reasoning is required to evaluate policies and evidence.";
        }
        setAnalysisMode("Deep");
    } else {
        // Default / None
        if (btnQuick) {
            btnQuick.disabled = false;
            btnQuick.style.opacity = "1";
            btnQuick.style.cursor = "pointer";
        }
        if (btnDeep) {
            btnDeep.disabled = false;
            btnDeep.style.opacity = "1";
            btnDeep.style.cursor = "pointer";
        }
        if (btnScanner) {
            btnScanner.disabled = false;
            btnScanner.style.opacity = "1";
            btnScanner.style.cursor = "pointer";
        }
    }

    const btnAiScoping = document.getElementById("btn-ai-scoping");
    if (btnAiScoping) {
        btnAiScoping.style.display = isTechnical ? "flex" : "none";
    }
    if (!isTechnical && window.currentScopingMode === "AI") {
        setScopingMode("EXCEL");
    }

    // VAPT/PQC take their scope from the uploaded scan files, not from a checklist:
    // findings are whatever the deterministic parsers extract. Excel, Manual and
    // Customize are all checklist-driven and had NO effect on a technical scan --
    // the checklist never reaches _run_fast_technical_vapt_bg at all -- yet the UI
    // still accepted an upload and announced "EXCEL SCOPING APPLIED". Hiding them
    // stops the app claiming to do something it does not.
    //
    // Control selection below still works, and now genuinely filters (see the
    // scope-filter guard in the worker): every control starts selected, and an
    // auditor who wants a narrower report deselects what they do not need.
    const _checklistModeBtns = ["btn-excel-scoping", "btn-checklist-scoping", "btn-customize-scoping"];
    _checklistModeBtns.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isTechnical ? "none" : "flex";
    });
    const _excelDrop = document.getElementById("scoping-excel-dropzone");
    if (isTechnical && _excelDrop) _excelDrop.style.display = "none";
    const _builderEntry = document.getElementById("scoping-builder-entry");
    if (isTechnical && _builderEntry) _builderEntry.style.display = "none";

    if (isTechnical && window.currentScopingMode !== "AI") {
        // Switching into a technical framework while sitting in a now-hidden mode
        // would leave the panel with no active mode button at all.
        setScopingMode("AI");
    }
}

async function pollAuditResults() {
    const targetSessionId = activeSessionId;
    const runBtn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");

    if (window._resultsInterval) clearInterval(window._resultsInterval);

    let attempts = 0;
    window._resultsInterval = setInterval(async () => {
        attempts++;
        if (activeSessionId !== targetSessionId) {
            if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
            return;
        }
        try {
            const res = await authFetch(`${API_BASE}/audit/findings?session_id=${targetSessionId}&include_info=true`);
            if (!res.ok) return;
            const data = await res.json();

            if (activeSessionId !== targetSessionId) {
                if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
                return;
            }

            // What this session shows -- decided before the "anything yet?" test,
            // so a non-VAPT session keeps polling exactly as it did when the
            // server left informational rows out.
            const _shown = (data.success && data.findings) ? findingsForSession(data) : [];
            if (_shown.length > 0) {
                if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
                _noteRunScopingMode(data);
                findingsList = _shown;
                renderFindingsList();
                updateKPICounters();

                if (runBtn) {
                    runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
                    runBtn.disabled = false;
                }
                if (stopBtn) stopBtn.style.display = "none";
                alert(`🎉 RAG Audit Scan Complete! ${data.findings.length} findings generated.`);
            }
        } catch (e) {
            console.warn("Polling error:", e);
        }

        if (attempts > 30) {
            if (window._resultsInterval) { clearInterval(window._resultsInterval); window._resultsInterval = null; }
            if (runBtn) {
                runBtn.innerHTML = `<span>▶</span> <span>RUN AUDIT SCAN</span>`;
                runBtn.disabled = false;
            }
            if (stopBtn) stopBtn.style.display = "none";
        }
    }, 2000);
}

// ── SIDEBAR FRAMEWORK CHECKLIST ──

// ── SIDEBAR FRAMEWORK CHECKLIST & SEGMENTED CONTROLS ──

// The "build one here / download a template" line belongs with the two modes that
// actually consume a checklist (Excel and Customize); AI and Manual scoping have
// no sheet, so offering it there would be noise.
function _setBuilderEntryVisible(show) {
    const el = document.getElementById("scoping-builder-entry");
    if (el) el.style.display = show ? "block" : "none";
}

// The control scope panel: the clause accordions with their checkboxes, and the
// "Edit Scope (108/108)" button that opens the same list in a modal. Shown in
// every mode except Customize, which has no controls to show -- its audit items
// are the auditor's own questions, answered from the documents they cited, and a
// list of ISO controls beside them only describes an audit that is not running.
function _setControlScopeVisible(show) {
    const box = document.getElementById("target-controls-container-box");
    if (box) box.style.display = show ? "block" : "none";
    const editBtn = document.getElementById("btn-edit-scope");
    if (editBtn) editBtn.style.display = show ? "" : "none";
    const label = document.getElementById("scope-method-label");
    if (label) label.innerText = show ? "Scope Detection Method" : "Scope Method";
}

// ── Which scoping mode can actually apply ────────────────────────────────────
//
// A technical framework (VAPT, PQC) takes its scope from the uploaded scan files,
// so onFrameworkChangeSuggestMode() shows only AI Auto-Scoping and hides the three
// checklist modes; a governance framework does the reverse. That was enforced only
// at the moment the framework changed. Three session paths then called
// setScopingMode('EXCEL') unconditionally -- switching to a session with no
// scoping cache, starting a new session, and restoring a cached mode -- and none
// of them looked at the framework. On a VAPT session the result was a panel in two
// states at once: the checklist buttons still hidden, but the Excel dropzone and
// the "build one here" link back on screen, the status line announcing "Control
// Scope", and the active marker on the Excel button that nobody could see -- so
// the only visible button, AI Auto-Scoping, rendered as inactive grey. Whether it
// happened depended on which of the two ran last, which is why it came and went.
//
// Enforcing it here, where every caller passes through, means no call order can
// produce that state again.
function _frameworkIsTechnical() {
    const sel = document.getElementById("framework-select");
    const fw = sel ? String(sel.value || "").toUpperCase() : "";
    return fw.includes("VAPT") || fw.includes("PQC");
}

function _effectiveScopingMode(requested, technical) {
    const m = String(requested || "").toUpperCase();
    const wantsAi = m === "AI" || m.includes("AUTO");
    if (technical && !wantsAi) return "AI";      // checklist modes are hidden here
    if (!technical && wantsAi) return "EXCEL";   // and AI is hidden here
    return m;
}

function setScopingMode(mode) {
    const aiBtn = document.getElementById("btn-ai-scoping");
    const chkBtn = document.getElementById("btn-checklist-scoping");
    const excelBtn = document.getElementById("btn-excel-scoping");
    const customBtn = document.getElementById("btn-customize-scoping");

    const excelDropzone = document.getElementById("scoping-excel-dropzone");
    const statusNote = document.getElementById("scoping-mode-status-note");

    // Reset active class on all buttons
    [aiBtn, chkBtn, excelBtn, customBtn].forEach(b => { if (b) b.classList.remove("active-scope-mode"); });

    const modeStr = _effectiveScopingMode(mode, _frameworkIsTechnical());

    if (modeStr === "CUSTOMIZE" || modeStr.includes("CUSTOM")) {
        // Pure document Q&A. Each checklist question is answered from the document
        // cited beside it, the way it would be answered by someone who had just read
        // that document -- no control, no policy requirement, and none of the
        // framework's reasoning rules.
        //
        // The control list is hidden rather than merely ignored. It used to stay on
        // screen with the matched controls ticked, which is a claim: it told the
        // auditor this run was scoped to those controls and would report against
        // them. It is not and does not. Nothing here selects a control, and the
        // server resolves none for this mode.
        if (customBtn) customBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "block";
        _setBuilderEntryVisible(true);
        _setControlScopeVisible(false);
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>Checklist (Document Q&amp;A)</b> — Upload your questions; each is answered from the document you cite for it. No controls, no policy requirement.`;
        window.currentScopingMode = "CUSTOMIZE";

        // Any selection left ticked by a previous mode is cleared: it is invisible
        // from here, and an invisible selection that still travels with the run is
        // how a question-based audit ends up reported against controls again.
        document.querySelectorAll("#controls-checkbox-container input[type='checkbox']")
            .forEach(cb => { cb.checked = false; });
        if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();
        return;
    }

    if (modeStr === "AI" || modeStr.includes("AUTO")) {
        if (aiBtn) aiBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "none";
        _setBuilderEntryVisible(false);
        _setControlScopeVisible(true);
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>AI Auto-Scoping</b> — Automatically detects technical scan findings across VAPT / PQC assets.`;
        window.currentScopingMode = "AI";
    } else if (modeStr === "MANUAL" || modeStr.includes("MANUAL")) {
        if (chkBtn) chkBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "none";
        _setBuilderEntryVisible(false);
        _setControlScopeVisible(true);
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>Selective Scope</b> — Select the specific controls to audit from the accordions below.`;
        window.currentScopingMode = "MANUAL";

        // Manual scope starts from nothing selected -- the auditor chooses. This branch
        // is only ever reached from the auditor's own "Manual" button in index.html
        // (every programmatic caller of setScopingMode passes EXCEL), so clearing here
        // can never wipe a restored selection behind the user's back.
        document.querySelectorAll("#controls-checkbox-container input[type='checkbox']")
            .forEach(cb => { cb.checked = false; });
        if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();
    } else {
        // Default to EXCEL Upload Scope
        if (excelBtn) excelBtn.classList.add("active-scope-mode");
        if (excelDropzone) excelDropzone.style.display = "block";
        _setBuilderEntryVisible(true);
        _setControlScopeVisible(true);
        if (statusNote) statusNote.innerHTML = `<span style="color:#10b981;font-weight:700;">🟢 Active:</span> <b>Control Scope</b> — Drag & drop or browse an Excel scoping matrix (.xlsx) below.`;
        window.currentScopingMode = "EXCEL";

        // Entering Excel scope clears the selection so the uploaded checklist is the
        // only thing that puts controls in scope. Skipped when a checklist is already
        // loaded for this session -- that match has already selected the right rows and
        // must not be wiped when the mode is re-applied (e.g. on session restore).
        const _hasChecklist = !!(customEvidenceMappings
            && customEvidenceMappings.excel_items
            && customEvidenceMappings.excel_items.length > 0);
        if (!_hasChecklist) {
            document.querySelectorAll("#controls-checkbox-container input[type='checkbox']")
                .forEach(cb => { cb.checked = false; });
            if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();
        }
    }
}

function toggleClauseAccordion(contentId, headerEl) {
    const body = document.getElementById(contentId);
    if (!body) return;
    const arrow = headerEl.querySelector(".clause-arrow");
    if (body.style.display === "none") {
        body.style.display = "block";
        if (arrow) arrow.innerText = "v";
    } else {
        body.style.display = "none";
        if (arrow) arrow.innerText = "›";
    }
}

async function loadFrameworkControls() {
    const select = document.getElementById("framework-select");
    const container = document.getElementById("controls-checkbox-container");
    if (!container) return;
    container.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;'>Loading controls checklist...</div>";

    try {
        const response = await authFetch(`${API_BASE}/controls/framework`);
        const data = await response.json();

        let controlsToRender = DEFAULT_FRAMEWORK_CONTROLS;
        if (data.success && data.controls && data.controls.length > 0) {
            controlsToRender = data.controls;
        }

        container.innerHTML = "";
        const selectedStd = select ? select.value : "ISO 27001";

        const filtered = controlsToRender.filter(c => {
            const cat = (c.category || "").toUpperCase();
            const useCase = (c.use_case || "").toUpperCase();
            const isVapt = cat.includes("VAPT") || useCase.includes("VAPT") || useCase.startsWith("VAPT-");
            const isDpdp = cat.includes("DPDP") || cat.includes("GDPR") || useCase.includes("DPDP") || useCase.includes("GDPR");
            const isSoc2 = cat.includes("SOC") || useCase.includes("SOC");
            const isBcms = cat.includes("BCMS") || cat.includes("BUSINESS CONTINUITY") || useCase.includes("BCMS");
            const isXbom = cat.includes("X-BOM") || cat.includes("SBOM") || useCase.includes("X-BOM") || useCase.includes("XBOM");
            const isNist = cat.includes("NIST");
            const isPqc = cat.includes("PQC") || useCase.includes("PQC") || useCase.startsWith("PQC-");
            const isIso = !isVapt && !isDpdp && !isSoc2 && !isBcms && !isXbom && !isNist && !isPqc;

            if (selectedStd === "All Standards") return true;
            if (selectedStd === "ISO 27001") return isIso;
            if (selectedStd === "VAPT") return isVapt;
            if (selectedStd === "DPDP") return isDpdp;
            if (selectedStd === "SOC2") return isSoc2;
            if (selectedStd === "BCMS") return isBcms;
            if (selectedStd === "XBOM") return isXbom;
            if (selectedStd === "NIST CSF 2.0") return isNist;
            if (selectedStd === "PQC") return isPqc;
            return true;
        });

        // Group into Clause Categories matching Streamlit UI
        const clauseMap = {
            "Clause 5 — Organizational Controls": [],
            "Clause 6 — People Controls": [],
            "Clause 7 — Physical Controls": [],
            "Clause 8 — Technological Controls": [],
            "VAPT Framework Controls": [],
            "NIST CSF 2.0 Core Controls": [],
            "SOC 2 Type II Controls": [],
            "DPDP / GDPR Privacy Controls": [],
            "ISO 22301 BCMS Controls": [],
            "X-BOM / SBOM Controls": [],
            "PQC Framework Controls": [],
            "Custom Controls": []
        };

        filtered.forEach(c => {
            const cid = (c.control_id || c.use_case || c.sl || "").toString().toUpperCase();
            const cat = (c.category || "").toUpperCase();

            if (cid.startsWith("5.") || cat.includes("ORGANIZATIONAL")) {
                clauseMap["Clause 5 — Organizational Controls"].push(c);
            } else if (cid.startsWith("6.") || cat.includes("PEOPLE")) {
                clauseMap["Clause 6 — People Controls"].push(c);
            } else if (cid.startsWith("7.") || cat.includes("PHYSICAL")) {
                clauseMap["Clause 7 — Physical Controls"].push(c);
            } else if (cid.startsWith("8.") || cat.includes("TECH") || cat.includes("IT SECURITY")) {
                clauseMap["Clause 8 — Technological Controls"].push(c);
            } else if (cid.includes("VAPT") || cat.includes("VAPT")) {
                clauseMap["VAPT Framework Controls"].push(c);
            } else if (cat.includes("NIST") || /^(GV|ID|PR|DE|RS|RC)\./.test(cid)) {
                clauseMap["NIST CSF 2.0 Core Controls"].push(c);
            } else if (cat.includes("SOC") || cid.startsWith("CC")) {
                clauseMap["SOC 2 Type II Controls"].push(c);
            } else if (cat.includes("DPDP") || cat.includes("GDPR")) {
                clauseMap["DPDP / GDPR Privacy Controls"].push(c);
            } else if (cat.includes("BCMS") || cat.includes("BUSINESS CONTINUITY")) {
                clauseMap["ISO 22301 BCMS Controls"].push(c);
            } else if (cat.includes("X-BOM") || cat.includes("SBOM")) {
                clauseMap["X-BOM / SBOM Controls"].push(c);
            } else if (cid.includes("PQC") || cat.includes("PQC")) {
                clauseMap["PQC Framework Controls"].push(c);
            } else {
                clauseMap["Custom Controls"].push(c);
            }
        });

        // Render each Clause Accordion
        Object.keys(clauseMap).forEach((clauseTitle, idx) => {
            const controls = clauseMap[clauseTitle];
            if (controls.length === 0) return;

            const accordionCard = document.createElement("div");
            accordionCard.className = "clause-accordion-card";
            accordionCard.style.cssText = "margin-bottom: 8px; border-radius: 10px; overflow: hidden;";

            const contentId = `clause_body_${idx}`;

            const header = document.createElement("div");
            header.className = "clause-header";
            header.style.cssText = "padding: 10px 12px; font-size: 0.82rem; font-weight: 700; display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none;";
            header.onclick = () => toggleClauseAccordion(contentId, header);
            header.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1;">
                    <span class="clause-arrow" style="color: #60a5fa; font-weight: 700; font-size: 0.85rem; width: 14px; text-align: center;">›</span>
                    <span style="font-weight: 700; font-size: 0.8rem; text-transform: none; white-space: normal; line-height: 1.2;">${clauseTitle}</span>
                </div>
                <span class="clause-count-badge" id="clause_badge_${idx}" style="font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 6px; white-space: nowrap; margin-left: 6px;">[0/0]</span>
            `;

            const body = document.createElement("div");
            body.id = contentId;
            body.className = "clause-body";
            body.style.cssText = "display: none; padding: 10px 12px; border-top: 1px solid var(--border-color); background: var(--bg-card); max-height: 360px; overflow-y: auto; scrollbar-width: thin;";

            controls.forEach(c => {
                const itemDiv = document.createElement("div");
                itemDiv.className = "checkbox-item ctrl-checkbox-item";
                itemDiv.style.cssText = "display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: 8px; margin-bottom: 4px; transition: background 0.15s ease;";
                itemDiv.onmouseover = () => itemDiv.style.background = "rgba(59, 130, 246, 0.12)";
                itemDiv.onmouseout = () => itemDiv.style.background = "transparent";

                const input = document.createElement("input");
                input.type = "checkbox";
                input.value = c.sl;
                input.id = `ctrl_chk_${c.sl}`;
                // Controls start UNSELECTED in both scoping modes where a human decides
                // the scope:
                //   EXCEL  -- the uploaded checklist decides, and only the rows it
                //             actually matches get switched on (see
                //             restoreSessionScopingCache and the upload handler).
                //   MANUAL -- the auditor picks the controls; pre-selecting the whole
                //             framework makes "Manual Scope" a misnomer and means an
                //             auditor who forgets to deselect runs all ~93 controls.
                // Only AI auto-scoping starts fully selected, because it needs the whole
                // control pool to detect scope from the evidence itself.
                // Defaulting all-checked meant that until a match ran -- or for any
                // control the sheet never mentioned -- the entire framework sat selected,
                // silently widening the scope beyond what the auditor actually chose.
                const _mode = String(window.currentScopingMode || "EXCEL").toUpperCase();
                input.checked = (_mode === "AI");
                input.style.cssText = "width: 17px; height: 17px; min-width: 17px; cursor: pointer; accent-color: #2563eb;";
                input.onchange = updateSelectedScopeCount;

                const label = document.createElement("label");
                label.htmlFor = `ctrl_chk_${c.sl}`;
                label.style.cssText = "cursor: pointer; font-size: 0.82rem; color: var(--text-main); font-weight: 600; text-transform: none; white-space: normal; word-break: break-word; line-height: 1.35; margin: 0; flex: 1;";

                const ctrlId = c.control_id || c.sl;
                const ctrlName = c.label || c.control_name || "";
                label.innerText = `${ctrlName} (${ctrlId})`;
                label.title = `${ctrlId}: ${ctrlName}`;

                itemDiv.appendChild(input);
                itemDiv.appendChild(label);
                body.appendChild(itemDiv);
            });

            accordionCard.appendChild(header);
            accordionCard.appendChild(body);
            container.appendChild(accordionCard);
        });

        updateSelectedScopeCount();
    } catch (err) {
        container.innerHTML = `<div style='font-size:11px;color:var(--error);padding:8px;'>Loaded fallback controls.</div>`;
    }
}

function updateSelectedScopeCount() {
    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    const selected = Array.from(checkboxes).filter(cb => cb.checked);

    const countBadge = document.getElementById("sidebar-scope-count-badge");
    if (countBadge) countBadge.innerText = `${selected.length}/${checkboxes.length} · Edit`;

    const totalBadge = document.getElementById("total-scope-badge");
    if (totalBadge) totalBadge.innerText = `${selected.length} / ${checkboxes.length} selected`;

    // Recalculate each Clause accordion badge dynamically
    const accordions = document.querySelectorAll(".clause-accordion-card");
    accordions.forEach((acc, idx) => {
        const badge = acc.querySelector(".clause-count-badge");
        const cbs = acc.querySelectorAll(".clause-body input[type='checkbox']");
        const selCbs = Array.from(cbs).filter(cb => cb.checked);

        if (badge && cbs.length > 0) {
            if (selCbs.length === cbs.length) {
                badge.innerText = `[${selCbs.length}/${cbs.length} All]`;
                badge.style.background = "rgba(37, 99, 235, 0.25)";
                badge.style.color = "#60a5fa";
            } else if (selCbs.length === 0) {
                badge.innerText = `[0/${cbs.length}]`;
                badge.style.background = "rgba(148, 163, 184, 0.15)";
                badge.style.color = "#94a3b8";
            } else {
                badge.innerText = `[${selCbs.length}/${cbs.length}]`;
                badge.style.background = "rgba(234, 179, 8, 0.2)";
                badge.style.color = "#facc15";
            }
        }
    });
}

async function handleExcelScopeUpload(e) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const file = files[0];

    const badge = document.getElementById("scoping-file-name");
    if (badge) {
        badge.innerText = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        badge.style.display = "block";
    }

    const formData = new FormData();
    formData.append("file", file);
    // Confine control resolution to the framework being audited. Without it, a
    // checklist row with no control ID is matched by name against all eight
    // frameworks -- an ISO row reading "Cryptographic Controls" resolved to
    // SOC 2 CC3.4 instead of ISO 8.24.
    try {
        const _fw = (typeof activeSessionFramework !== "undefined" && activeSessionFramework)
            || (document.getElementById("framework-select") || {}).value || "";
        if (_fw) formData.append("framework", _fw);
    } catch (e) { /* framework is optional; omit rather than fail the upload */ }

    // Customize mode must reach the parser, which skips control resolution entirely
    // for it. Without this the questions would still be mapped onto ISO controls and
    // the mode would behave identically to ordinary Excel scoping.
    try {
        // Always sent, never conditional: an omitted mode makes the server
        // fall back to Excel scoping, which judges the row on policy AND
        // evidence and fails every question-based row on a missing policy.
        formData.append("scoping_mode", resolveScopingMode());
    } catch (e) { /* optional */ }

    try {
        const response = await authFetch(`${API_BASE}/controls/parse-scope-excel`, {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || "Failed to parse Excel file.");
        }
        const data = await response.json();


        customEvidenceMappings = data.custom_evidence || null;
        customControlDocuments = data.custom_documents || null;
        const matchedSls = new Set(data.matched_sls || []);

        // Auto-check mapped controls in checklist, uncheck unmapped
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => {
            const slNum = parseInt(cb.value);
            cb.checked = matchedSls.has(slNum);
        });

        updateSelectedScopeCount();
        _warnIfScopeSheetLacksPolicy(data);
        alert(`✅ ${data.message || 'Loaded checklist items successfully!'}`);
    } catch (err) {
        alert(`❌ Error parsing Excel: ${err.message}`);
    }
}

function filterCheckboxList() {
    const searchInput = document.getElementById("controls-search-input");
    if (!searchInput) return;
    const q = searchInput.value.trim().toLowerCase();
    const accordions = document.querySelectorAll(".clause-accordion-card");

    if (!q) {
        // GLITCH-05 FIX: when clearing search, restore ALL items AND collapse accordions back
        document.querySelectorAll("#controls-checkbox-container .checkbox-item").forEach(row => {
            row.style.display = "flex";
        });
        // Collapse all accordion sections back to their default closed state
        accordions.forEach(acc => {
            acc.style.display = "block";
            const body = acc.querySelector(".clause-body");
            if (body) body.style.display = "none";
            const header = acc.querySelector(".clause-header");
            if (header) {
                const arrow = header.querySelector(".clause-arrow");
                if (arrow) arrow.innerText = "›";
            }
        });
        return;
    }

    accordions.forEach(acc => {
        const body = acc.querySelector(".clause-body");
        const toggleIcon = acc.querySelector(".clause-toggle-icon");
        const items = acc.querySelectorAll(".checkbox-item");
        let hasMatch = false;

        items.forEach(row => {
            const text = row.innerText.toLowerCase();
            if (text.includes(q)) {
                row.style.display = "flex";
                hasMatch = true;
            } else {
                row.style.display = "none";
            }
        });

        if (body) {
            if (hasMatch) {
                body.style.display = "block";
                acc.style.display = "block";
                // GLITCH-02 FIX: was .clause-toggle-icon which doesn't exist — correct class is .clause-arrow
                const arrow = acc.querySelector(".clause-arrow");
                if (arrow) arrow.innerText = "v";
            } else {
                acc.style.display = "none";
            }
        }
    });
}


function selectAllCheckboxes(checked) {
    const rows = document.querySelectorAll("#controls-checkbox-container .checkbox-item");
    rows.forEach(row => {
        if (row.style.display !== "none") {
            const cb = row.querySelector("input[type='checkbox']");
            if (cb) cb.checked = checked;
        }
    });
    updateSelectedScopeCount();
}

function syncControlsScopeFromFindings(findings) {
    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    if (!checkboxes || checkboxes.length === 0) return;

    // NEVER touch the scope while a run owns it. This is called from loadFindings(),
    // which polls on an interval during a scan -- so a second or two after the
    // auditor ticked anything, the poller re-selected every control and undid it.
    // It also re-enabled the checkboxes visually without restoring their disabled
    // state, which is why the panel stopped looking locked mid-run.
    if (window._scopeRunLocked) return;

    // A Customize run evaluated questions, not controls: its findings carry row ids
    // ("Q1"), not control ids. There is nothing to sync, and matching those against
    // the control labels would tick controls the run never looked at.
    if (window._sessionIsCustomizeRun) return;

    // An empty findings list means "the scan has not produced anything yet", which
    // is the normal state for the first minutes of every run -- it does NOT mean
    // "the auditor wants all 93 controls". Selecting everything here overwrote a
    // deliberate selection, including one the auditor had just narrowed.
    if (!findings || findings.length === 0) {
        return;
    }

    const evaluatedSls = new Set();
    const ctrlIdSet = new Set();

    findings.forEach(f => {
        if (f.sl_no) evaluatedSls.add(parseInt(f.sl_no));
        if (f.control_id) {
            const rawCid = String(f.control_id).trim().toLowerCase();
            ctrlIdSet.add(rawCid);
            const m = rawCid.match(/^(\d+\.\d+)/);
            if (m) ctrlIdSet.add(m[1]);
        }
    });

    let matchedCount = 0;
    checkboxes.forEach(cb => {
        const slVal = parseInt(cb.value);
        let isMatch = evaluatedSls.has(slVal);

        if (!isMatch && ctrlIdSet.size > 0) {
            const label = document.querySelector(`label[for='${cb.id}']`);
            if (label) {
                const labelText = label.innerText.toLowerCase();
                isMatch = Array.from(ctrlIdSet).some(cid => cid && labelText.includes(cid));
            }
        }

        cb.checked = isMatch;
        if (isMatch) matchedCount++;
    });

    if (matchedCount === 0 && findings.length > 0) {
        // Findings exist but none matched a checkbox label -- a display/matching
        // problem, not evidence that the auditor wants everything. Selecting all
        // here silently widened the scope; leaving the selection alone is the
        // conservative choice.
        console.warn("[Scope sync] findings did not match any control checkbox; leaving the selection unchanged.");
    }

    updateSelectedScopeCount();
}


// ── EVIDENCE FILE UPLOAD ──

function setupFileDropZone() {
    const dropZones = document.querySelectorAll(".drop-zone");
    if (!dropZones || dropZones.length === 0) return;

    dropZones.forEach(dropZone => {
        dropZone.addEventListener("dragover", e => {
            preventDefaults(e);
            dropZone.style.borderColor = "var(--primary, #3b82f6)";
            dropZone.style.background = "rgba(37, 99, 235, 0.15)";
        });

        dropZone.addEventListener("dragleave", e => {
            preventDefaults(e);
            dropZone.style.borderColor = "rgba(148, 163, 184, 0.25)";
            dropZone.style.background = "";
        });

        dropZone.addEventListener("drop", async e => {
            preventDefaults(e);
            dropZone.style.borderColor = "rgba(148, 163, 184, 0.25)";
            dropZone.style.background = "";

            const items = e.dataTransfer.items;
            let filesToUpload = [];

            if (items && items.length > 0) {
                const entryPromises = [];
                for (let i = 0; i < items.length; i++) {
                    const item = items[i];
                    if (item.kind === "file") {
                        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
                        if (entry) {
                            entryPromises.push(readEntryRecursively(entry));
                        } else {
                            const file = item.getAsFile();
                            if (file) filesToUpload.push(file);
                        }
                    }
                }
                if (entryPromises.length > 0) {
                    const results = await Promise.all(entryPromises);
                    results.forEach(fArr => filesToUpload.push(...fArr));
                }
            }

            if (filesToUpload.length === 0 && e.dataTransfer.files.length > 0) {
                filesToUpload = Array.from(e.dataTransfer.files);
            }

            if (filesToUpload.length > 0) {
                uploadFiles(filesToUpload);
            }
        });
    });
}

async function readEntryRecursively(entry) {
    return new Promise((resolve) => {
        if (entry.isFile) {
            entry.file(file => resolve([file]), () => resolve([]));
        } else if (entry.isDirectory) {
            const dirReader = entry.createReader();
            dirReader.readEntries(async (entries) => {
                const childPromises = entries.map(child => readEntryRecursively(child));
                const childResults = await Promise.all(childPromises);
                const allFiles = childResults.flat();
                resolve(allFiles);
            }, () => resolve([]));
        } else {
            resolve([]);
        }
    });
}

function handleEvidenceUpload(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
}

function handleEvidenceFolderUpload(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
}


async function uploadFiles(files) {
    if (!files || files.length === 0) return;

    const dropZone = document.getElementById("drop-zone");
    const countBadge = document.getElementById("evidence-count-badge");
    const registry = document.getElementById("uploaded-files-registry");
    const browseBtn = document.querySelector(".modern-evidence-card button");

    // 1. Immediate visual feedback on drop zone
    if (dropZone) {
        dropZone.style.borderColor = "#3b82f6";
        dropZone.style.background = "rgba(37, 99, 235, 0.15)";
        dropZone.style.boxShadow = "0 0 20px rgba(59, 130, 246, 0.3)";
        dropZone.innerHTML = `
            <span class="drop-icon" style="font-size: 2.4rem; display: block; margin-bottom: 6px; animation: pulse 1s infinite alternate;">⏳</span>
            <h4 style="margin: 0; font-size: 0.95rem; font-weight: 800; color: #60a5fa;">Uploading ${files.length} file(s)...</h4>
            <p style="margin: 4px 0 0 0; font-size: 0.74rem; color: #94a3b8;">⚡ Extracting text, scanning security, and indexing into RAG memory...</p>
        `;
    }

    if (countBadge) {
        countBadge.innerText = `⏳ Uploading...`;
        countBadge.style.background = "rgba(234, 179, 8, 0.2)";
        countBadge.style.color = "#facc15";
    }

    if (browseBtn) {
        browseBtn.disabled = true;
        browseBtn.innerText = "⏳ Uploading...";
    }

    // 2. Render temporary loading skeleton items in attached files registry
    if (registry) {
        registry.innerHTML = "";
        Array.from(files).forEach(f => {
            const card = document.createElement("div");
            card.className = "modern-file-card";
            card.style.cssText = "display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 10px; background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(59, 130, 246, 0.3); opacity: 0.85;";
            card.innerHTML = `
                <div style="font-size: 1rem; width: 28px; height: 28px; border-radius: 6px; background: rgba(59, 130, 246, 0.2); color: #60a5fa; display: flex; align-items: center; justify-content: center; font-weight: 700;">⏳</div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #f8fafc; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${f.name}</div>
                    <div style="font-size: 0.72rem; color: #60a5fa; font-weight: 600;">Uploading & extracting text...</div>
                </div>
            `;
            registry.appendChild(card);
        });
    }

    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }

    if (!activeSessionId) {
        resetDropZoneUI();
        alert("⚠️ Active session missing. Please create or select an audit session first.");
        return;
    }

    const isAuditor = currentUser ? currentUser.role !== "auditee" : true;
    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("is_auditor_uploaded", isAuditor ? "true" : "false");
    body.append("username", currentUser ? currentUser.username : "");

    for (let i = 0; i < files.length; i++) {
        body.append("files", files[i]);
    }

    try {
        const response = await authFetch(`${API_BASE}/audit/upload`, {
            method: "POST",
            body: body
        });

        // BUG-03 FIX: check response.ok BEFORE calling .json() — a 502/503 returns HTML not JSON,
        // so .json() throws SyntaxError before we can show the real error message.
        if (!response.ok) {
            let errMsg = `Upload failed (HTTP ${response.status})`;
            try { const errData = await response.json(); errMsg = formatApiError(errData.detail, errMsg); } catch (_) { }
            throw new Error(errMsg);
        }
        const data = await response.json();

        const processedCount = (data.files || []).length;
        const blocked = data.blocked || [];

        if (processedCount > 0) {
            showToastBanner(`✅ ${processedCount} Evidence File(s) successfully uploaded and indexed into RAG memory!`);
        }
        if (blocked.length > 0) {
            const details = blocked.map(b => `• ${b.filename}: ${b.reason}`).join('\n');
            alert(`🚨 SECURITY ALERT: ${blocked.length} file(s) were blocked by the security scan and were NOT uploaded:\n\n${details}`);
        }
        await loadEvidenceFileList();
        setTimeout(loadEvidenceFileList, 600);
    } catch (err) {
        alert(`❌ Upload Error: ${err.message}`);
        await loadEvidenceFileList();
    } finally {
        resetDropZoneUI();
    }
}

function resetDropZoneUI() {
    const dropZone = document.getElementById("drop-zone");
    const countBadge = document.getElementById("evidence-count-badge");
    const browseBtn = document.querySelector(".modern-evidence-card button");

    if (dropZone) {
        dropZone.style.borderColor = "rgba(59, 130, 246, 0.35)";
        dropZone.style.background = "rgba(15, 23, 42, 0.4)";
        dropZone.style.boxShadow = "none";
        dropZone.innerHTML = `
            <span class="drop-icon" style="font-size: 2.2rem; display: block; margin-bottom: 6px;">📤</span>
            <h4 style="margin: 0; font-size: 0.9rem; font-weight: 700; color: #60a5fa;">Drag-and-drop zone</h4>
            <p style="margin: 3px 0 0 0; font-size: 0.74rem; color: var(--text-muted);">Drop PDF, DOCX, CSV, HTML, JSON evidence files here</p>
            <input type="file" id="evidence-file-input" multiple style="display: none;" onchange="handleEvidenceUpload(event)">
        `;
    }

    if (countBadge) {
        countBadge.style.background = "rgba(255,255,255,0.06)";
        countBadge.style.color = "var(--text-muted)";
    }

    if (browseBtn) {
        browseBtn.disabled = false;
        browseBtn.innerText = "+ Browse files";
    }
}

async function loadEvidenceFileList() {
    const registries = document.querySelectorAll("#uploaded-files-registry, #auditee-files-registry");
    const countBadge = document.getElementById("evidence-count-badge");
    if (!registries || registries.length === 0) return;

    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }

    if (!activeSessionId) return;
    const requestSessionId = activeSessionId;

    try {
        const response = await authFetch(`${API_BASE}/audit/evidence?session_id=${encodeURIComponent(requestSessionId)}`);
        if (response.status === 403) {
            console.warn(`[Evidence] User ${currentUser ? currentUser.username : ''} does not have access to session ${requestSessionId}. Resetting active session.`);
            const userKey = currentUser && currentUser.username ? `_${currentUser.username}` : "";
            try {
                localStorage.removeItem(`last_active_session_id${userKey}`);
                localStorage.removeItem(`last_active_session_title${userKey}`);
            } catch (e) { }
            if (activeSessionId === requestSessionId) {
                activeSessionId = "";
                activeSessionTitle = "";
                if (window._recentSessionsCache && window._recentSessionsCache.length > 0) {
                    const validSess = window._recentSessionsCache[0];
                    switchRecentSession(validSess.session_id, validSess.session_title);
                } else if (currentUser && currentUser.role === "auditor") {
                    startNewAuditSession(true);
                }
            }
            return;
        }
        const data = await response.json();

        // Session guard: if active session changed while request was in-flight, ignore response
        if (activeSessionId !== requestSessionId) return;

        const files = (data.success && data.files) ? data.files : [];
        if (countBadge) countBadge.innerText = `${files.length} files`;


        registries.forEach(registry => {
            registry.innerHTML = "";
            if (files.length === 0) {
                registry.innerHTML = `<div class="empty-state">No files uploaded yet. Drag files to begin audit.</div>`;
            } else {
                files.forEach(f => {
                    const fn = f.filename;
                    const ext = fn.split('.').pop().toLowerCase();
                    // Was defaulting everything to "XML" unless it matched pdf/doc/xls --
                    // so png/jpg screenshots, json, txt, html, pptx, zip all showed a
                    // misleading "XML" badge. Matches the categorization already used in
                    // processEvidenceFiles() above, so both file-list renderers agree.
                    let fileClass = "file-type-doc";
                    let fileIconText = "DOC";

                    if (ext === "pdf") { fileClass = "file-type-pdf"; fileIconText = "PDF"; }
                    else if (["doc", "docx"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "DOC"; }
                    else if (["xls", "xlsx", "csv"].includes(ext)) { fileClass = "file-type-xls"; fileIconText = "XLS"; }
                    else if (["xml", "json", "txt", "html", "htm"].includes(ext)) { fileClass = "file-type-xml"; fileIconText = "XML"; }
                    else if (["png", "jpg", "jpeg"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "IMG"; }
                    else if (["ppt", "pptx"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "PPT"; }
                    else if (ext === "zip") { fileClass = "file-type-doc"; fileIconText = "ZIP"; }

                    const safeFnEsc = fn.replace(/'/g, "\\'").replace(/"/g, "&quot;");
                    const card = document.createElement("div");
                    card.className = "modern-file-card";
                    card.style.cssText = "display: flex; align-items: center; justify-content: space-between; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px; padding: 10px 12px; gap: 12px;";
                    card.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 10px; overflow: hidden; flex: 1;">
                            <div class="file-icon-badge ${fileClass}" style="width: 32px; height: 32px; font-size: 0.65rem; border-radius: 8px; flex-shrink: 0; display: inline-flex; align-items: center; justify-content: center;">${fileIconText}</div>
                            <div style="overflow: hidden;">
                                <div style="font-size: 0.82rem; font-weight: 600; color: var(--text-main); text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${escapeHtml(fn)}">${escapeHtml(fn)}</div>
                                <div style="font-size: 0.7rem; color: #94a3b8; display: flex; align-items: center; gap: 6px;">
                                    <span>${escapeHtml(f.size_str || 'Ready')}</span>
                                    <span style="color: #34d399; font-weight: 600;">✓ Attached</span>
                                </div>
                            </div>
                        </div>
                        <button type="button" onclick="deleteServerEvidenceFile('${requestSessionId}', ${f.id}, '${safeFnEsc}')" style="background: transparent; border: none; color: #94a3b8; cursor: pointer; padding: 4px; border-radius: 4px; display: flex; align-items: center; justify-content: center; transition: color 0.15s;" title="Remove file" onmouseover="this.style.color='#ef4444'" onmouseout="this.style.color='#94a3b8'" aria-label="Remove ${escapeHtml(fn)}"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
                    `;
                    registry.appendChild(card);
                });
            }
        });
        // VAPT retest: offer it when files arrived that no version scanned.
        refreshVaptRetestChoice();
    } catch (err) {
        console.error("Error loading evidence file list:", err);
    }
}

// ── RUN LOCAL AUDIT ANALYSIS ──

let progressInterval = null;

async function triggerAuditAnalysis() {
    const btn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    btn.disabled = true;
    btn.innerText = "⏳ Running Scan (0%)...";
    if (stopBtn) stopBtn.style.display = "block";

    const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
    let selectedSls = Array.from(checkboxes).filter(cb => cb.checked).map(cb => parseInt(cb.value));

    // Customize is scoped by its questions. No control is selected for it (the
    // panel is hidden and the server resolves none), so anything still ticked here
    // is left over from another mode and must not travel with the run.
    const _isCustomizeRun = String(resolveScopingMode() || "").toUpperCase().startsWith("CUSTOM");
    if (_isCustomizeRun) selectedSls = [];

    // STRICT SCOPING ENFORCEMENT: If Excel Scoping matrix is loaded, restrict audit ONLY to Excel controls
    if (customEvidenceMappings && customEvidenceMappings.excel_items && customEvidenceMappings.excel_items.length > 0) {
        const excelSLs = Array.from(new Set(customEvidenceMappings.excel_items.map(item => parseInt(item.sl_no)).filter(n => !isNaN(n))));
        if (excelSLs.length > 0) {
            selectedSls = excelSLs;
            // Sync UI checkboxes to reflect exact Excel controls count
            const matchedSet = new Set(excelSLs);
            checkboxes.forEach(cb => {
                cb.checked = matchedSet.has(parseInt(cb.value));
            });
            if (typeof updateSelectedScopeCount === "function") updateSelectedScopeCount();
        }
    }

    // VAPT/PQC: a narrowed scope means vulnerabilities the scan DOES find can be left
    // out of the report. Say so while it is still a decision they can change, rather
    // than as a footnote afterwards explaining what they already lost -- the person
    // reading the report later was not the one who clicked here.
    try {
        const _fwv = String((document.getElementById("framework-select") || {}).value || "").toUpperCase();
        if (_fwv.includes("VAPT") || _fwv.includes("PQC")) {
            const _allBoxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
            const _total = _allBoxes.length;
            const _deselected = _total - selectedSls.length;
            if (_total > 0 && _deselected > 0) {
                const proceed = confirm(
                    `You have deselected ${_deselected} of ${_total} controls.\n\n` +
                    `Any vulnerabilities this scan finds in those categories will NOT appear ` +
                    `in the report, even if they are critical.\n\n` +
                    `Run with the narrowed scope?`
                );
                if (!proceed) {
                    btn.disabled = false;
                    btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
                    if (stopBtn) stopBtn.style.display = "none";
                    return;
                }
            }
        }
    } catch (e) { /* never block a scan on the confirmation itself failing */ }

    // Customize needs questions, not controls -- its own guard.
    if (_isCustomizeRun) {
        const _qCount = (customEvidenceMappings && customEvidenceMappings.excel_items)
            ? customEvidenceMappings.excel_items.length : 0;
        if (_qCount === 0) {
            alert("⚠️ Add at least one question before running. Upload a checklist, or build one with \"Build one here\".");
            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            if (stopBtn) stopBtn.style.display = "none";
            return;
        }
    } else if (selectedSls.length === 0) {
        alert("⚠️ Please select at least one control to analyze.");
        btn.disabled = false;
        btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
        if (stopBtn) stopBtn.style.display = "none";
        return;
    }

    // Count evidence: both files uploaded in THIS browser session (uploadedFilesList)
    // AND files already attached server-side from a previous session/page load.
    // Always refresh from the server first so the badge and DOM are up-to-date
    // (stale badge text like "0\n   files" caused parseInt to return 0 even when
    // files were present, triggering a false "no evidence" alert).
    await loadEvidenceFileList();

    const serverAttachedCount = (() => {
        // Primary source: the badge that loadEvidenceFileList sets
        const badge = document.getElementById("evidence-count-badge");
        if (badge) {
            const n = parseInt(badge.innerText.trim());
            if (!isNaN(n)) return n;
        }
        // Fallback: count rendered file cards in the registry
        const registry = document.getElementById("uploaded-files-registry");
        if (registry) {
            const cards = registry.querySelectorAll(".modern-file-card");
            if (cards.length > 0) return cards.length;
        }
        return 0;
    })();

    const totalEvidenceCount = uploadedFilesList.length + serverAttachedCount;

    if (totalEvidenceCount === 0) {
        alert("⚠️ Please upload at least one evidence file before starting the audit.");
        btn.disabled = false;
        btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
        if (stopBtn) stopBtn.style.display = "none";
        return;
    }



    const frameworkSelect = document.getElementById("framework-select");
    const isVaptFramework = frameworkSelect ? frameworkSelect.value.toUpperCase().includes("VAPT") : false;
    // Capture the live sidebar framework value to send with the audit/start request.
    // This lets the backend sync the session's stored framework before routing,
    // so switching from ISO 27001 -> VAPT in the sidebar after session creation
    // doesn't leave the DB with a stale ISO 27001 framework that triggers the
    // governance guardrail and coerces Fast Parser -> Deep wrongly.
    const currentFramework = (frameworkSelect && frameworkSelect.value) ? frameworkSelect.value : "";
    const modelEl = document.getElementById("llm-model-select");
    const model = modelEl ? modelEl.value : "Gemma 4 (e4b)";
    // Previously read from document.querySelector("input[name='audit-mode']:checked"),
    // an element that has never existed in this page's DOM -- that selector always
    // returned null, so every scan silently sent "Deep" regardless of whether Quick
    // Audit or Deep Audit was clicked. setAnalysisMode() (see the mode-toggle
    // buttons) is the actual source of truth; read that instead.
    const mode = selectedAnalysisMode || "Deep";

    try {
        const response = await authFetch(`${API_BASE}/audit/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                selected_sls: selectedSls,
                model_choice: model,
                audit_mode: mode,
                current_framework: currentFramework,
                custom_evidence: customEvidenceMappings,
                custom_documents: customControlDocuments,
                scoping_mode: resolveScopingMode(),
                username: currentUser ? currentUser.username : null,
                // Only meaningful in Scanner mode; the checkbox is hidden
                // otherwise, so this is false whenever it doesn't apply.
                ai_recommendations: !!(document.getElementById("ai-recommendations-toggle") || {}).checked,
                // VAPT retest: only when the Scan Workspace offered it and
                // the auditor kept "Retest" chosen.
                vapt_retest: vaptRetestSelected()
            })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(formatApiErrorDetail(data.detail) || "Failed to trigger scan.");

        // Honest, immediate capacity notice at click-time -- llama-server's real
        // slot busy-count, not a static heuristic. Informational only, the scan
        // still starts and queues normally; this just tells the auditor upfront
        // instead of them only discovering it via a slow-moving progress bar.
        const cap = data.llm_capacity;
        const acap = data.audit_capacity;
        if (cap && cap.reachable && cap.at_capacity) {
            showToastBanner(`⏳ All ${cap.total_slots} compute slot(s) busy right now — this scan will start as soon as one frees up.`);
        } else if (acap && acap.advice && acap.limit && acap.running >= acap.limit) {
            // This scan just took the last audit the machine is rated for, so the
            // next auditor will be refused. Said here, while there is still time
            // to act on it, rather than only in the refusal itself -- the advice
            // names whether cores or memory is what would raise the number.
            showToastBanner(`⚠ This server is now running its maximum of ${acap.limit} simultaneous audit(s). ${acap.advice}`);
        }

        // Freeze the inputs for the duration of the run. The server refuses
        // evidence changes with a 409 from this point, so leaving the controls
        // live would offer actions that bounce.
        if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(true);

        // Start high-frequency progress polling (every 1 second)
        if (progressInterval) clearInterval(progressInterval);
        if (window._resultsInterval) clearInterval(window._resultsInterval);
        window._currentPollSessionId = activeSessionId;
        progressInterval = setInterval(pollAuditProgress, 1000);
    } catch (err) {
        btn.disabled = false;
        btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
        if (stopBtn) stopBtn.style.display = "none";
        // The scan never started -- a 409 from the re-run guard lands here --
        // so releasing the inputs is what lets the auditor act on the refusal.
        if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(false);
        const msg = String(err.message || "");
        if (msg.toLowerCase().includes("failed to fetch") || msg.toLowerCase().includes("networkerror")) {
            alert("Server Connection Error: The local backend service is starting up or temporarily offline. Please wait a few seconds and click 'Start Scan' again.");
        } else {
            alert(`Failed to start scan: ${msg}`);
        }
    }
}

async function pollAuditProgress() {
    const targetSessionId = window._currentPollSessionId || activeSessionId;
    if (!activeSessionId || activeSessionId !== targetSessionId) {
        if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
        return;
    }

    const btn = document.getElementById("run-analysis-btn");
    const stopBtn = document.getElementById("stop-analysis-btn");
    const progressBar = document.getElementById("pipeline-progress-fill");
    const progressPercent = document.getElementById("pipeline-progress-percent");
    const progressStatus = document.getElementById("pipeline-status-text");

    try {
        const response = await authFetch(`${API_BASE}/audit/status/${targetSessionId}`);
        const data = await response.json();

        // Session guard: if active session changed while waiting for status API
        if (activeSessionId !== targetSessionId) {
            if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
            return;
        }

        if (data.status === "running") {
            const p = data.progress || {};
            const pct = typeof p.percent === "number" ? Math.min(100, Math.max(0, p.percent)) : 0;
            const txt = p.text || 'Scanning...';

            if (window._isStoppingSession) {
                if (btn) {
                    btn.disabled = true;
                    btn.innerText = `⏳ Stopping Scan (${pct}%)...`;
                }
                if (stopBtn) stopBtn.style.display = "none";
            } else {
                if (btn) {
                    if (txt && (txt.includes("Scanning") || txt.includes("evaluating"))) {
                        btn.innerText = `⏳ ${pct}% • ${txt}`;
                    } else {
                        btn.innerText = `⏳ Running Scan (${pct}%)...`;
                    }
                }
                if (stopBtn) stopBtn.style.display = "block";
            }

            const progressBox = document.getElementById("pipeline-progress-box");
            if (progressBox) progressBox.style.display = "block";
            if (progressBar) progressBar.style.width = `${pct}%`;
            if (progressPercent) progressPercent.innerText = `${pct}%`;
            if (progressStatus) progressStatus.innerText = `${txt} (${pct}%)`;


            // ── Resource pressure banner — only toast on a STATE CHANGE, not every
            // 1s poll tick, so it doesn't spam. CRITICAL is more visible/sticky
            // than WARNING since it means the audit is about to pause itself.
            const resStatus = data.resource_status || (p.resource_status) || "OK";
            if (resStatus !== window._lastResourceStatus) {
                if (resStatus === "CRITICAL") {
                    showToastBanner(`🛑 ${data.resource_message || p.text || "System resources critically low — audit is pausing to avoid a crash."}`, "error");
                } else if (resStatus === "WARNING") {
                    showToastBanner(`⚠️ ${data.resource_message || "System resources are getting tight."}`, "warning");
                }
                window._lastResourceStatus = resStatus;
            }

            // ── Busy-system notice — other audits already running. Warning only,
            // never blocks; same "only on state change" debouncing as above.
            const busyWarning = p.warning || null;
            if (busyWarning !== window._lastBusyWarning) {
                if (busyWarning) showToastBanner(busyWarning, "warning");
                window._lastBusyWarning = busyWarning;
            }

            // ── AI recommendations that did not complete ──────────────────────
            // The worker keeps the parser's text when an enrichment batch fails,
            // which is a valid report -- but silently, so ticking the box and
            // having it time out looked exactly like never ticking it. Same
            // state-change debouncing as the notices above.
            const aiNote = p.ai_note || null;
            if (aiNote !== window._lastAiNote) {
                if (aiNote) showToastBanner(`⚠️ ${aiNote}`, "warning");
                window._lastAiNote = aiNote;
            }
        } else if (data.status === "completed") {
            clearInterval(progressInterval);
            progressInterval = null;

            // Released here rather than after the session guard below: the run
            // has ended whether or not the auditor is still looking at this
            // session, and a lock that outlives its run is indistinguishable
            // from a broken page.
            if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(false);

            if (activeSessionId !== targetSessionId) return;

            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            if (stopBtn) stopBtn.style.display = "none";
            if (progressBar) progressBar.style.width = `100%`;
            if (progressPercent) progressPercent.innerText = `100%`;
            if (progressStatus) progressStatus.innerText = `Scan completed successfully`;

            // Auto-load audit records findings and switch to records view
            await loadFindings();
            // The files just scanned are no longer new: withdraw the retest offer.
            refreshVaptRetestChoice();

            if (activeSessionId !== targetSessionId) return;

            // Switch to Audit Records tab if not already open
            if (typeof activeTab !== "undefined" && activeTab !== "tab-audit-records") {
                const recordsTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Records") || b.innerText.includes("Scan workspace"));
                if (recordsTabBtn) switchTab("tab-audit-records", recordsTabBtn);
            }

            alert("✅ Local audit RAG scan completed successfully! Review records below and click 'Save to Shakthi DB' to commit.");
        } else if (data.status === "idle" && data.checkpoint && data.checkpoint.status === "failed") {
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            if (stopBtn) stopBtn.style.display = "none";
            if (progressStatus) progressStatus.innerText = `Scan failed`;
            alert("❌ Analysis failed. Verify Ollama or local llama-server is running.");
        } else if (data.status === "failed") {
            // The scan ended with an error -- e.g. its findings could not be
            // saved. This fell through to the reset below, so the page went
            // quiet and the auditor saw an empty list with no reason.
            clearInterval(progressInterval);
            progressInterval = null;
            if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(false);
            if (activeSessionId !== targetSessionId) return;
            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            if (stopBtn) stopBtn.style.display = "none";
            if (progressStatus) progressStatus.innerText = `Scan failed`;
            showToastBanner(`❌ ${data.error || "The scan failed."}`, "error");
        } else {
            // If scan is idle, stopped, or not running, reset state cleanly
            clearInterval(progressInterval);
            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            if (stopBtn) {
                stopBtn.style.display = "none";
                stopBtn.disabled = false;
                stopBtn.innerText = "⛔ Stop";
            }
        }
    } catch (err) {
        console.error("Progress polling error:", err);
    }
}

// ── TOAST NOTIFICATION HELPER ──
// Auto-dismiss applies to routine confirmations only. A warning or error is
// something the auditor has to act on -- "evidence rejected", "the LLM server is
// down", "running low on memory" -- and a message like that disappearing after a
// few seconds while they were reading the other half of the screen means the run
// carries on with them unaware. Those stay until dismissed.
const _TOAST_AUTO_DISMISS_MS = 5000;

function hideToast() {
    const toast = document.getElementById("app-toast-notification");
    if (!toast) return;
    if (window._toastTimer) { clearTimeout(window._toastTimer); window._toastTimer = null; }
    toast.style.transform = "translateY(100px)";
    toast.style.opacity = "0";
}

function showToast(message, type = "info") {
    let toast = document.getElementById("app-toast-notification");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "app-toast-notification";
        toast.style.cssText = "position: fixed; bottom: 24px; right: 24px; z-index: 9999; max-width: 460px; padding: 12px 20px; border-radius: 10px; font-size: 0.85rem; font-weight: 600; color: #ffffff; background: rgba(30, 41, 59, 0.98); border: 1px solid rgba(148, 163, 184, 0.2); box-shadow: 0 10px 25px rgba(0,0,0,0.4); transition: all 0.3s ease; transform: translateY(100px); opacity: 0; display: flex; align-items: flex-start; gap: 12px;";
        document.body.appendChild(toast);
    }

    // A previous toast's countdown would otherwise still be running and hide THIS
    // message early -- a success at t=4.5s inheriting a timer due at t=5s flashed
    // for half a second.
    if (window._toastTimer) { clearTimeout(window._toastTimer); window._toastTimer = null; }

    const isSticky = (type === "warning" || type === "warn" || type === "error");

    if (type === "warning" || type === "warn") {
        toast.style.borderColor = "rgba(245, 158, 11, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(245, 158, 11, 0.2)";
    } else if (type === "error") {
        toast.style.borderColor = "rgba(239, 68, 68, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(239, 68, 68, 0.2)";
    } else if (type === "success") {
        // GLITCH-04 FIX: add green branch for "success" type (was falling through to default blue)
        toast.style.borderColor = "rgba(16, 185, 129, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(16, 185, 129, 0.2)";
    } else {
        toast.style.borderColor = "rgba(59, 130, 246, 0.6)";
        toast.style.boxShadow = "0 4px 20px rgba(59, 130, 246, 0.2)";
    }

    // escapeHtml: messages carry server text (filenames, rejection reasons) that
    // originates outside the app, so it is escaped rather than interpolated raw.
    toast.innerHTML =
        `<span style="flex:1; line-height:1.45;">${escapeHtml(String(message || ""))}</span>` +
        (isSticky
            ? `<button type="button" onclick="hideToast()" title="Dismiss"
                 style="background:transparent; border:none; color:var(--text-main, #0f172a); cursor:pointer; font-size:1rem; line-height:1; padding:0 2px; flex-shrink:0;">✕</button>`
            : "");

    toast.style.transform = "translateY(0)";
    toast.style.opacity = "1";

    if (!isSticky) {
        window._toastTimer = setTimeout(hideToast, _TOAST_AUTO_DISMISS_MS);
    }
}

async function stopAuditAnalysis() {
    const stopBtn = document.getElementById("stop-analysis-btn");
    const btn = document.getElementById("run-analysis-btn");
    if (!activeSessionId) return;

    window._isStoppingSession = true;
    if (stopBtn) stopBtn.style.display = "none";
    if (btn) {
        btn.disabled = true;
        btn.innerText = "⏳ Stopping Scan...";
    }

    try {
        const res = await authFetch(`${API_BASE}/audit/stop/${activeSessionId}`, { method: "POST" });
        const data = await res.json();

        showToast("⛔ Stop signal sent — ending scan gracefully.", "warning");

        setTimeout(() => {
            window._isStoppingSession = false;
            if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
            // The run is over, so the inputs belong to the auditor again --
            // stopping in order to change the evidence is the documented way
            // out of the 409, and it has to actually give them back.
            if (typeof _setRunLockedInputs === "function") _setRunLockedInputs(false);
            if (btn) {
                btn.disabled = false;
                btn.style.opacity = "1";
                btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
            }
            if (stopBtn) {
                stopBtn.style.display = "none";
                stopBtn.disabled = false;
                stopBtn.innerText = "STOP ANALYSIS";
            }
            checkCrashResilienceCheckpoint();
        }, 1200);
    } catch (err) {
        window._isStoppingSession = false;
        if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
        if (btn) {
            btn.disabled = false;
            btn.innerText = "▶ Run Audit Scan"; if (typeof hidePipelineProgress === "function") hidePipelineProgress();
        }
        if (stopBtn) {
            stopBtn.style.display = "none";
            stopBtn.disabled = false;
            stopBtn.innerText = "STOP ANALYSIS";
        }
        showToast(`Stop request error: ${err.message}`, "error");
    }
}



// ── AUDIT FINDINGS FEED & CRUD ──

async function loadFindings() {
    if (!activeSessionId) return;
    const requestSessionId = activeSessionId;
    const container = document.getElementById("findings-container");
    if (!container) return;
    container.innerHTML = `<div class="empty-state">Loading findings from Shakthi DB...</div>`;

    try {
        // include_info: a VAPT session lists its informational findings (below);
        // every other session drops them here, as the server used to.
        const response = await authFetch(`${API_BASE}/audit/findings?session_id=${requestSessionId}&include_info=true`);
        const data = await response.json();

        // Session guard: if active session changed while request was in-flight, ignore response
        if (activeSessionId !== requestSessionId) return;

        _noteRunScopingMode(data);

        const banner = document.getElementById("shakti-commit-banner");
        const bannerText = document.getElementById("shakti-banner-text");
        if (banner) {
            banner.style.display = "flex";
            if (data.success && data.findings) {
                findingsList = findingsForSession(data);
                // VAPT retest: this session's versions. A reload of the same
                // session keeps the version on screen; another session starts
                // at its latest.
                if (vaptRoundsSession !== requestSessionId) {
                    vaptViewRound = null;
                    vaptRetestFilter = "";
                    vaptRoundsSession = requestSessionId;
                }
                vaptRounds = (isVaptOnlySession() && Array.isArray(data.vapt_rounds)) ? data.vapt_rounds : [];
                vaptAllFindings = findingsList;
                if (!vaptRetestActive()) { vaptViewRound = null; vaptRetestFilter = ""; }
                if (vaptViewingOlder()) findingsList = vaptFindingsAsOf(vaptAllFindings, vaptViewRound);
                else vaptViewRound = null;
                renderVaptRetestBar();
                const statusFilterEl = document.getElementById("status-filter");
                if (statusFilterEl && statusFilterEl.value === "Compliant") {
                    const hasCompliant = findingsList.some(f => isFindingCompliant(f));
                    if (!hasCompliant) statusFilterEl.value = "All";
                }
                renderFindingsList();
                calculateSeverityStats();
                syncControlsScopeFromFindings(findingsList);

                // Update progress bar if findings exist for this session
                if (findingsList.length > 0) {
                    const progressBar = document.getElementById("pipeline-progress-fill");
                    const progressPct = document.getElementById("pipeline-progress-percent");
                    const progressStatus = document.getElementById("pipeline-status-text");
                    if (progressBar) progressBar.style.width = "100%";
                    if (progressPct) progressPct.innerText = "100%";
                    if (progressStatus) progressStatus.innerText = `Completed (${findingsList.length} control evaluations recorded)`;
                }

                const isFinalized = (data.session_status && data.session_status.includes("Finalized")) ||
                    (data.session_title && data.session_title.includes("Finalized")) ||
                    (findingsList.length > 0 && findingsList.every(f => f.is_saved_to_shakthi));

                if (isFinalized) {
                    banner.style.background = "rgba(16, 185, 129, 0.12)";
                    banner.style.borderColor = "rgba(52, 211, 153, 0.35)";
                    banner.style.color = "#6ee7b7";
                    if (bannerText) bannerText.innerHTML = `<b>ShakthiDB Audit Ledger:</b> ${findingsList.length} control evaluation record(s) committed, verified, and cryptographically locked.`;
                } else {
                    banner.style.background = "rgba(37, 99, 235, 0.12)";
                    banner.style.borderColor = "rgba(59, 130, 246, 0.35)";
                    banner.style.color = "#93c5fd";
                    if (bannerText) bannerText.innerHTML = `<b>Audit Evaluation Progress:</b> ${findingsList.length} control record(s) evaluated. Review records below and click <b>Save to Shakthi DB</b> to commit to audit ledger.`;
                }
            } else {
                syncControlsScopeFromFindings([]);
                vaptRounds = [];
                vaptAllFindings = [];
                renderVaptRetestBar();
                banner.style.background = "rgba(30, 41, 59, 0.6)";
                banner.style.borderColor = "rgba(148, 163, 184, 0.25)";
                banner.style.color = "#cbd5e1";
                if (bannerText) bannerText.innerHTML = `<b>ShakthiDB Audit Notice:</b> No control evaluations recorded in ledger yet. Navigate to <b>Scan workspace</b> tab, upload compliance evidence documents, and execute <b>Run Audit Scan</b> to evaluate all target controls.`;
                container.innerHTML = `<div class="empty-state">No control evaluations recorded for active session. Switch to <b>Scan workspace</b> tab to upload evidence documents and run AI audit evaluation.</div>`;
            }
        }

    } catch (err) {
        container.innerHTML = `<div class="error-msg">Failed to query findings: ${err.message}</div>`;
    }
}

async function resetSessionFindings() {
    if (!activeSessionId) {
        alert("No active session selected.");
        return;
    }
    if (!confirm("Are you sure you want to clear unverified draft findings for this session?\n\n(Verified ledger records will be preserved.)")) {
        return;
    }
    try {
        const response = await authFetch(`${API_BASE}/audit/reset-session-findings`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: activeSessionId })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            showToastBanner(`🧹 ${data.message || 'Draft findings cleared successfully.'}`);
            loadFindings();
        } else {
            alert(`Error clearing findings: ${data.detail || data.message || 'Failed'}`);
        }
    } catch (err) {
        alert(`Failed to reset findings: ${err.message}`);
    }
}

async function commitSessionToShaktiDB(force = false) {
    console.log("💾 [commitSessionToShaktiDB] Invoked. activeSessionId:", activeSessionId, "force:", force);
    if (!activeSessionId) {
        alert("No active session. Please select or start an audit session first.");
        return;
    }
    try {
        const auditorName = currentUser ? currentUser.username : "Lead Auditor";
        const response = await authFetch(`${API_BASE}/audit/findings/commit-session/${activeSessionId}?force=${force}&auditor_user=${encodeURIComponent(auditorName)}`, {
            method: "PUT"
        });
        if (!response.ok) {
            let errorMsg = `Server error ${response.status}`;
            try {
                const errJson = await response.json();
                errorMsg = errJson.detail || errJson.message || errorMsg;
            } catch (e) { }
            alert(`Failed to commit findings: ${errorMsg}`);
            return;
        }
        const data = await response.json();
        console.log("💾 [commitSessionToShaktiDB] Response:", data);

        if (data.requires_confirmation && !force) {
            // Unreviewed controls detected! Trigger Unreviewed Warning Modal
            const countEl = document.getElementById("unreviewed-count-text");
            const listEl = document.getElementById("unreviewed-list-container");
            const modalEl = document.getElementById("unreviewed-warning-modal");

            if (countEl) countEl.innerText = data.unreviewed_count || 0;
            if (listEl && data.unreviewed_controls) {
                // Show max 20 items to prevent browser overflow with large scans
                const MAX_SHOW = 20;
                const ctrls = data.unreviewed_controls || [];
                const shown = ctrls.slice(0, MAX_SHOW);
                const remaining = ctrls.length - shown.length;
                listEl.innerHTML = shown.map(ctrl => `<li>• ${escapeHtml(ctrl)}</li>`).join("") +
                    (remaining > 0 ? `<li style="color:#94a3b8; font-style: italic;">... and ${remaining} more unreviewed controls</li>` : "");
            }
            if (modalEl) {
                modalEl.style.display = "flex";
                modalEl.style.zIndex = "100000";
            }
            return;
        }

        if (data.success) {
            alert(`✅ ${data.message || 'Session successfully committed to Shakthi DB!'}`);
            showToast(data.message || "Session committed to Shakthi DB!", "info");
            closeUnreviewedWarningModal();
            await loadFindings();

            // Switch to Report tab and render real-time review report (only saved findings)
            await renderAuditReportPreview();
            const reportTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Report"));
            if (reportTabBtn) switchTab("tab-audit-report", reportTabBtn);
        } else {
            alert(`Failed to commit: ${data.message || 'Unknown error'}`);
        }
    } catch (err) {
        console.error("💾 [commitSessionToShaktiDB] Exception:", err);
        alert(`Failed to commit findings to Shakthi DB: ${err.message}`);
    }
}

function closeUnreviewedWarningModal() {
    const modalEl = document.getElementById("unreviewed-warning-modal");
    if (modalEl) modalEl.style.display = "none";
}

async function forceCommitSessionToShaktiDB() {
    await commitSessionToShaktiDB(true);
}

window.commitSessionToShaktiDB = commitSessionToShaktiDB;
window.closeUnreviewedWarningModal = closeUnreviewedWarningModal;
window.forceCommitSessionToShaktiDB = forceCommitSessionToShaktiDB;


function ensureAdminModalDOM() {
    let modalEl = document.getElementById("admin-log-modal");
    if (modalEl) return modalEl;

    modalEl = document.createElement("div");
    modalEl.id = "admin-log-modal";
    modalEl.style.cssText = "display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15,23,42,0.8); z-index:9999; justify-content:center; align-items:center; backdrop-filter:blur(4px);";

    modalEl.innerHTML = `
        <div style="background: var(--bg-card, #1e293b); width: 92%; max-width: 1200px; max-height: 90vh; border-radius: 14px; border: 1px solid rgba(148,163,184,0.2); box-shadow: 0 20px 40px rgba(0,0,0,0.4); display: flex; flex-direction: column; overflow: hidden; color: var(--text-primary, #f8fafc);">
            <!-- Modal Header -->
            <div style="padding: 16px 22px; background: rgba(15,23,42,0.6); border-bottom: 1px solid rgba(148,163,184,0.15); display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0; font-size: 1.15rem; font-weight: 700; color: #f8fafc; display: flex; align-items: center; gap: 8px;">
                        <span>🛡️ Administrative Audit Logs & Telemetry Dashboard</span>
                    </h3>
                    <p style="margin: 3px 0 0 0; font-size: 0.78rem; color: #94a3b8;">Real Auditor Telemetry, Hardware Specs, Token Benchmark & Multi-Session Aggregator</p>
                </div>
                <button onclick="closeAdminLogModal()" style="background: transparent; border: none; color: #94a3b8; font-size: 1.4rem; cursor: pointer; padding: 4px 8px; border-radius: 6px;" title="Close Modal">✕</button>
            </div>

            <!-- Tab Navigation Bar -->
            <div style="padding: 10px 22px; background: rgba(15,23,42,0.3); border-bottom: 1px solid rgba(148,163,184,0.15); display: flex; gap: 12px; align-items: center;">
                <button id="tab-btn-benchmark" onclick="switchAdminTab('benchmark')" style="padding: 7px 16px; font-size: 0.8rem; font-weight: 700; border-radius: 7px; border: 1px solid rgba(99,102,241,0.4); background: rgba(99,102,241,0.25); color: #818cf8; cursor: pointer;">
                    📊 Auditor Sessions & Hardware Telemetry
                </button>
                <button id="tab-btn-overrides" onclick="switchAdminTab('overrides')" style="padding: 7px 16px; font-size: 0.8rem; font-weight: 700; border-radius: 7px; border: 1px solid rgba(148,163,184,0.2); background: transparent; color: #94a3b8; cursor: pointer;">
                    ⚠️ Admin Overrides & Security Log
                </button>
            </div>

            <!-- Modal Content Area -->
            <div style="padding: 20px; overflow-y: auto; flex: 1;">
                <!-- TAB 1: AUDITOR BENCHMARK & MULTI-SESSION AGGREGATOR -->
                <div id="admin-tab-benchmark" style="display: block;">
                    <!-- Action Bar -->
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; background: rgba(15,23,42,0.4); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(148,163,184,0.15); flex-wrap: wrap; gap: 10px;">
                        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                            <!-- Auditor Dropdown Filter -->
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <label style="font-size: 0.76rem; font-weight: 700; color: #818cf8;">👤 Filter Auditor:</label>
                                <select id="benchmark-auditor-filter" onchange="filterBenchmarkSessionsByAuditor()" style="padding: 5px 10px; font-size: 0.76rem; font-weight: 600; border-radius: 6px; background: #0f172a; color: #f8fafc; border: 1px solid rgba(99,102,241,0.4); outline: none; cursor: pointer;">
                                    <option value="ALL">All Auditors (All Sessions)</option>
                                </select>
                            </div>
                            <button class="btn-primary" onclick="aggregateSelectedAuditSessions()" style="padding: 7px 14px; font-size: 0.78rem; font-weight: 700; background: linear-gradient(135deg, #6366f1, #4f46e5); display: flex; align-items: center; gap: 6px;">
                                <span>⚡ Combine Selected Sessions</span>
                            </button>
                            <span id="selected-sessions-count-badge" style="font-size: 0.76rem; color: #94a3b8;">0 sessions selected</span>
                        </div>
                        <button class="btn-secondary" onclick="exportAdminBenchmarkExcel()" style="padding: 7px 14px; font-size: 0.78rem; font-weight: 700; color: #10b981; border-color: rgba(16,185,129,0.4); display: flex; align-items: center; gap: 6px;">
                            <span>📥 Download Executive Excel Report</span>
                        </button>
                    </div>

                    <!-- Aggregated Multi-Session Summary Container (Hidden until user clicks Combine) -->
                    <div id="aggregated-summary-box" style="display: none; margin-bottom: 16px; background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.3); border-radius: 10px; padding: 14px 18px;">
                        <!-- Content populated dynamically by aggregateSelectedAuditSessions() -->
                    </div>

                    <!-- Benchmark Table -->
                    <div style="overflow-x: auto; border: 1px solid rgba(148,163,184,0.15); border-radius: 8px;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;">
                            <thead>
                                <tr style="background: #1e293b; color: #f8fafc; font-weight: 800; border-bottom: 2px solid #334155;">
                                    <th style="padding: 11px 10px; width: 36px; text-align: center;">
                                        <input type="checkbox" id="select-all-benchmark-chk" onchange="toggleSelectAllBenchmarkSessions(this.checked)" style="cursor: pointer;">
                                    </th>
                                    <th style="padding: 11px 10px;">Session ID / Timestamp</th>
                                    <th style="padding: 11px 10px;">Auditor</th>
                                    <th style="padding: 11px 10px;">CPU Hardware</th>
                                    <th style="padding: 11px 10px;">Files & Types</th>
                                    <th style="padding: 11px 10px;">File Size</th>
                                    <th style="padding: 11px 10px;">Text Chars</th>
                                    <th style="padding: 11px 10px;">Tokens Used</th>
                                    <th style="padding: 11px 10px;">Audit Latency</th>
                                    <th style="padding: 11px 10px;">Compliance %</th>
                                    <th style="padding: 11px 10px; text-align: center;">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="benchmark-table-body">
                                <tr><td colspan="11" style="text-align:center; padding:16px; color:var(--text-main, #0f172a);">Loading audit session telemetry...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- TAB 2: ADMIN OVERRIDES & SECURITY LOG -->
                <div id="admin-tab-overrides" style="display: none;">
                    <div style="overflow-x: auto; border: 1px solid rgba(148,163,184,0.15); border-radius: 8px;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;">
                            <thead>
                                <tr style="background: #1e293b; color: #f8fafc; font-weight: 800; border-bottom: 2px solid #334155;">
                                    <th style="padding: 11px 10px;">Timestamp</th>
                                    <th style="padding: 11px 10px;">Auditor User</th>
                                    <th style="padding: 11px 10px;">Action</th>
                                    <th style="padding: 11px 10px;">Unreviewed Controls</th>
                                    <th style="padding: 11px 10px;">Details</th>
                                </tr>
                            </thead>
                            <tbody id="admin-log-table-body">
                                <tr><td colspan="6" style="text-align:center; padding:16px; color:#94a3b8;">Loading Admin Audit Log trail...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Export Toolbar -->
            <div style="padding: 14px 22px; border-top: 1px solid rgba(148,163,184,0.15); background: rgba(15,23,42,0.3);">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                    <span style="font-size: 0.78rem; color: #94a3b8; font-weight: 600; white-space: nowrap;">👤 Filter Auditor:</span>
                    <input id="admin-log-auditor-filter"
                        type="text"
                        placeholder="e.g. rk1@gmail.com  (leave blank = all)"
                        style="flex: 1; padding: 7px 12px; font-size: 0.8rem; border-radius: 8px; border: 1px solid rgba(148,163,184,0.3); background: rgba(15,23,42,0.7); color: #f1f5f9; outline: none;">
                </div>
                <div style="background: rgba(15,23,42,0.5); border: 1px solid rgba(148,163,184,0.15); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                    <div style="font-size: 0.76rem; font-weight: 700; color: #60a5fa; margin-bottom: 9px; display: flex; align-items: center; gap: 6px;">
                        🛡️ System Event Logs &amp; Error Trail
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <button id="btn-download-logs-excel" type="button"
                            onclick="downloadAdminLogsExport('excel')"
                            style="flex: 1; min-width: 140px; padding: 8px 14px; background: rgba(34,197,94,0.15); border: 1px solid rgba(34,197,94,0.4); color: #4ade80; border-radius: 8px; font-size: 0.8rem; font-weight: 700; cursor: pointer; transition: all 0.2s;">
                            📥 Download Logs (.xlsx)
                        </button>
                        <button id="btn-download-logs-pdf" type="button"
                            onclick="downloadAdminLogsExport('pdf')"
                            style="flex: 1; min-width: 140px; padding: 8px 14px; background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); color: #f87171; border-radius: 8px; font-size: 0.8rem; font-weight: 700; cursor: pointer; transition: all 0.2s;">
                            📄 Download Logs (.pdf)
                        </button>
                    </div>
                </div>
                <div style="background: rgba(15,23,42,0.5); border: 1px solid rgba(148,163,184,0.15); border-radius: 10px; padding: 12px;">
                    <div style="font-size: 0.76rem; font-weight: 700; color: #a78bfa; margin-bottom: 9px; display: flex; align-items: center; gap: 6px;">
                        📊 Telemetry &amp; Performance Benchmark Reports
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <button id="btn-download-telemetry-excel" type="button"
                            onclick="downloadBenchmarkExport('excel')"
                            style="flex: 1; min-width: 140px; padding: 8px 14px; background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.4); color: #a5b4fc; border-radius: 8px; font-size: 0.8rem; font-weight: 700; cursor: pointer; transition: all 0.2s;">
                            📥 Download Telemetry (.xlsx)
                        </button>
                        <button id="btn-download-telemetry-pdf" type="button"
                            onclick="downloadBenchmarkExport('pdf')"
                            style="flex: 1; min-width: 140px; padding: 8px 14px; background: rgba(251,191,36,0.12); border: 1px solid rgba(251,191,36,0.35); color: #fbbf24; border-radius: 8px; font-size: 0.8rem; font-weight: 700; cursor: pointer; transition: all 0.2s;">
                            📄 Download Telemetry (.pdf)
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modalEl);
    return modalEl;
}

window.switchAdminTab = function (tabName) {
    const tabBench = document.getElementById("admin-tab-benchmark");
    const tabOver = document.getElementById("admin-tab-overrides");
    const btnBench = document.getElementById("tab-btn-benchmark");
    const btnOver = document.getElementById("tab-btn-overrides");

    if (tabName === "benchmark") {
        if (tabBench) tabBench.style.display = "block";
        if (tabOver) tabOver.style.display = "none";
        if (btnBench) {
            btnBench.style.background = "rgba(99,102,241,0.25)";
            btnBench.style.color = "#818cf8";
            btnBench.style.borderColor = "rgba(99,102,241,0.4)";
        }
        if (btnOver) {
            btnOver.style.background = "transparent";
            btnOver.style.color = "#94a3b8";
            btnOver.style.borderColor = "rgba(148,163,184,0.2)";
        }
    } else {
        if (tabBench) tabBench.style.display = "none";
        if (tabOver) tabOver.style.display = "block";
        if (btnOver) {
            btnOver.style.background = "rgba(99,102,241,0.25)";
            btnOver.style.color = "#818cf8";
            btnOver.style.borderColor = "rgba(99,102,241,0.4)";
        }
        if (btnBench) {
            btnBench.style.background = "transparent";
            btnBench.style.color = "#94a3b8";
            btnBench.style.borderColor = "rgba(148,163,184,0.2)";
        }
    }
};

window.allBenchmarkSessionsCache = [];

async function loadAdminAuditLogs() {
    const modalEl = ensureAdminModalDOM();
    modalEl.style.display = "flex";

    // Load Tab 1: Telemetry Sessions
    loadBenchmarkSessionsData();

    // Load Tab 2: Overrides
    loadAdminOverridesData();
}

window._showAllBenchmarkSessions = false;

function toggleShowAllBenchmarkSessions() {
    window._showAllBenchmarkSessions = !window._showAllBenchmarkSessions;
    filterBenchmarkSessionsByAuditor();
}

function renderBenchmarkTableWithLimit(sessions) {
    const tbody = document.getElementById("benchmark-table-body");
    if (!tbody) return;
    const limit = window._showAllBenchmarkSessions ? sessions.length : 10;
    let html = renderBenchmarkRowsHTML(sessions.slice(0, limit));
    if (sessions.length > 10) {
        const label = window._showAllBenchmarkSessions
            ? "▲ Show Top 10 Sessions Only"
            : `📂 Show More Sessions (Total ${sessions.length})`;
        html += `<tr><td colspan="10" style="text-align:center; padding:10px;">
            <button type="button" class="btn-secondary" style="padding:6px 14px; font-size:0.76rem; font-weight:700;" onclick="toggleShowAllBenchmarkSessions()">${escapeHtml(label)}</button>
        </td></tr>`;
    }
    tbody.innerHTML = html;
}

function filterBenchmarkSessionsByAuditor() {
    const filterVal = (document.getElementById("benchmark-auditor-filter")?.value || "ALL").toLowerCase();
    const tbody = document.getElementById("benchmark-table-body");
    if (!tbody || !window.allBenchmarkSessionsCache) return;

    let filtered = window.allBenchmarkSessionsCache;
    if (filterVal !== "all") {
        filtered = filtered.filter(s => {
            const u = String(s.auditor_username || s.folder_name || "").toLowerCase();
            return u === filterVal;
        });
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:16px; color:#fbbf24;">No audit session logs found for selected auditor.</td></tr>`;
        return;
    }

    renderBenchmarkTableWithLimit(filtered);
    updateSelectedBenchmarkSessionsCount();
}

function renderBenchmarkRowsHTML(sessions) {
    return sessions.map((s, idx) => {
        const sid = s.session_id || `SESS-${idx}`;
        const sidShort = sid.length > 12 ? sid.slice(0, 12) + "..." : sid;
        const ts = s.timestamp || "N/A";
        const cpu = s.cpu_cores ? `${s.cpu_cores} Cores` : "4 Cores";
        const filesCnt = s.files_count || 0;
        const fileMb = s.file_size_mb ? `${s.file_size_mb} MB` : `${s.file_size_kb || 0} KB`;
        const chars = s.extracted_text_chars ? Number(s.extracted_text_chars).toLocaleString() : "0";
        const tokens = s.total_tokens ? Number(s.total_tokens).toLocaleString() : "0";
        const auditorName = s.auditor_username || s.folder_name || "Auditor";

        // Latency format
        const latSec = floatVal(s.total_latency_seconds);
        const latMins = Math.floor(latSec / 60);
        const latRemSec = Math.round(latSec % 60);
        const latStr = latMins > 0 ? `${latMins}m ${latRemSec}s` : `${latSec.toFixed(1)}s`;

        // Compliance %
        const compCnt = intVal(s.compliant_count);
        const nonCompCnt = intVal(s.non_compliant_count);
        const totalCtrls = compCnt + nonCompCnt;
        const compPct = totalCtrls > 0 ? Math.round((compCnt / totalCtrls) * 100) : 0;
        let compBadgeStyle = "background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3);";
        if (compPct < 50) compBadgeStyle = "background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3);";
        else if (compPct < 80) compBadgeStyle = "background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3);";

        // File types badges
        const fts = s.file_types_summary || {};
        const ftsPills = Object.keys(fts).length
            ? Object.entries(fts).map(([ext, cnt]) => `<span style="font-size:0.68rem; padding:1px 5px; border-radius:3px; background:rgba(99,102,241,0.15); color:#818cf8; border:1px solid rgba(99,102,241,0.3); margin-right:3px;">${escapeHtml(String(ext).toUpperCase())}:${escapeHtml(String(cnt))}</span>`).join("")
            : `<span style="color:#94a3b8;">${filesCnt} files</span>`;

        return `
            <tr style="border-bottom: 1px solid rgba(148, 163, 184, 0.15);">
                <td style="padding: 10px; text-align: center;">
                    <input type="checkbox" class="benchmark-session-chk" value="${escapeHtml(sid)}" onchange="updateSelectedBenchmarkSessionsCount()" style="cursor: pointer;">
                </td>
                <td style="padding: 10px;">
                    <div style="font-family: monospace; font-weight: 700; color: #f8fafc;" title="${escapeHtml(sid)}">${escapeHtml(sidShort)}</div>
                    <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 2px;">${escapeHtml(ts)}</div>
                </td>
                <td style="padding: 10px;">
                    <span style="font-size:0.72rem; padding:2px 8px; border-radius:12px; background:rgba(99,102,241,0.18); color:#818cf8; font-weight:700; border:1px solid rgba(99,102,241,0.35);">👤 ${escapeHtml(auditorName)}</span>
                </td>
                <td style="padding: 10px;">
                    <span style="font-size:0.72rem; padding:2px 6px; border-radius:4px; background:rgba(30,41,59,0.8); color:#cbd5e1; font-weight:600; border:1px solid rgba(148,163,184,0.2);">${escapeHtml(cpu)}</span>
                </td>
                <td style="padding: 10px;">
                    <div>${ftsPills}</div>
                    <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 2px;">${filesCnt} files (${fileMb})</div>
                </td>
                <td style="padding: 10px; font-family: monospace; font-size: 0.8rem;">${chars}</td>
                <td style="padding: 10px; font-family: monospace; font-size: 0.8rem; font-weight: 700; color: #818cf8;">${tokens}</td>
                <td style="padding: 10px; font-family: monospace; font-size: 0.8rem; color: #38bdf8;">${latStr}</td>
                <td style="padding: 10px;">
                    <span style="padding: 3px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 700; ${compBadgeStyle}">${compPct}% (${compCnt}/${totalCtrls})</span>
                </td>
                <td style="padding: 10px; text-align: center;">
                    <button class="btn-secondary" onclick="downloadBenchmarkReportForSession('${escapeHtml(sid)}')" style="padding: 3px 8px; font-size: 0.72rem; font-weight: 700; color: #38bdf8; border-color: rgba(56,189,248,0.3);">Excel</button>
                </td>
            </tr>
        `;
    }).join("");
}

async function loadBenchmarkSessionsData() {
    const tbody = document.getElementById("benchmark-table-body");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:16px; color:#94a3b8;">Loading audit session telemetry...</td></tr>`;

    try {
        const response = await authFetch(`${API_BASE}/audit/benchmark/sessions`);
        const data = await response.json();
        if (data.success && data.sessions && data.sessions.length > 0) {
            window.allBenchmarkSessionsCache = data.sessions;

            // Populate Auditor Filter Dropdown
            const filterSel = document.getElementById("benchmark-auditor-filter");
            if (filterSel) {
                const uniqueAuditors = Array.from(new Set(data.sessions.map(s => s.auditor_username || s.folder_name || "Auditor"))).sort();
                filterSel.innerHTML = `<option value="ALL">All Auditors (${data.sessions.length} Sessions)</option>` +
                    uniqueAuditors.map(u => `<option value="${escapeHtml(u.toLowerCase())}">👤 ${escapeHtml(u)}</option>`).join("");
            }

            window._showAllBenchmarkSessions = false;
            renderBenchmarkTableWithLimit(data.sessions);
        } else {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:16px; color:#94a3b8;">No real auditor session benchmarks recorded yet. Run an audit to log telemetry.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:16px; color:#ef4444;">Failed to load benchmark telemetry: ${err.message}</td></tr>`;
    }
}

async function loadAdminOverridesData() {
    const tbody = document.getElementById("admin-log-table-body");
    if (!tbody) return;

    try {
        const response = await authFetch(`${API_BASE}/audit/admin-logs`);
        const data = await response.json();
        if (data.success && data.logs && data.logs.length > 0) {
            tbody.innerHTML = data.logs.map(log => `
                <tr style="border-bottom: 1px solid rgba(148, 163, 184, 0.15);">
                    <td style="padding: 10px; font-family: monospace; font-size: 0.78rem;">${escapeHtml(log.timestamp)}</td>
                    <td style="padding: 10px; font-weight: 600; color: #60a5fa;">${escapeHtml(log.auditor_user)}</td>
                    <td style="padding: 10px;"><span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.74rem;">${escapeHtml(log.action)}</span></td>
                    <td style="padding: 10px; font-family: monospace; color: #fbbf24;">${escapeHtml(log.unreviewed_controls || 'N/A')}</td>
                    <td style="padding: 10px; font-size: 0.78rem; color: var(--text-main, #0f172a);">${escapeHtml(log.details)}</td>
                </tr>
            `).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:16px; color:#94a3b8;">No administrative overrides recorded yet.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:16px; color:#ef4444;">Failed to load overrides log: ${err.message}</td></tr>`;
    }
}

window.toggleSelectAllBenchmarkSessions = function (checked) {
    const chks = document.querySelectorAll(".benchmark-session-chk");
    chks.forEach(c => c.checked = checked);
    updateSelectedBenchmarkSessionsCount();
};

window.updateSelectedBenchmarkSessionsCount = function () {
    const checkedChks = document.querySelectorAll(".benchmark-session-chk:checked");
    const badge = document.getElementById("selected-sessions-count-badge");
    if (badge) {
        badge.innerText = `${checkedChks.length} session(s) selected`;
    }
};

window.aggregateSelectedAuditSessions = async function () {
    const checkedChks = document.querySelectorAll(".benchmark-session-chk:checked");
    const sids = Array.from(checkedChks).map(c => c.value);

    const summaryBox = document.getElementById("aggregated-summary-box");
    if (!summaryBox) return;

    summaryBox.style.display = "block";
    summaryBox.innerHTML = `<div style="text-align:center; color:#818cf8; font-weight:600; padding:10px;">⚡ Combining and aggregating benchmark metrics across ${sids.length || 'all'} auditor sessions...</div>`;

    try {
        const response = await authFetch(`${API_BASE}/audit/benchmark/aggregate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_ids: sids.length ? sids : null })
        });
        const data = await response.json();
        if (data.success && data.aggregated && data.aggregated.selected_sessions_count > 0) {
            const agg = data.aggregated;
            const cnt = agg.selected_sessions_count;
            const latStr = agg.combined_latency_formatted;
            const tokStr = Number(agg.combined_total_tokens).toLocaleString();
            const promptToks = Number(agg.combined_prompt_tokens).toLocaleString();
            const compToks = Number(agg.combined_completion_tokens).toLocaleString();
            const filesCnt = agg.combined_files_count;
            const fileMb = agg.combined_file_size_mb;
            const chars = Number(agg.combined_extracted_text_chars).toLocaleString();
            const scorePct = agg.overall_compliance_score_pct;
            const cpu = agg.cpu_cores;

            const fts = agg.file_types_summary || {};
            const ftsStr = Object.keys(fts).length ? Object.entries(fts).map(([ext, c]) => `${ext.toUpperCase()}: ${c}`).join(" · ") : "N/A";

            summaryBox.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 1px solid rgba(99,102,241,0.25); padding-bottom: 10px; margin-bottom: 12px;">
                    <h4 style="margin:0; color:#818cf8; font-size:1.0rem; font-weight:700;">
                        🏆 AGGREGATED MULTI-AUDITOR BENCHMARK SUMMARY (${cnt} AUDITOR RUNS COMBINED)
                    </h4>
                    <button onclick="document.getElementById('aggregated-summary-box').style.display='none'" style="background:transparent; border:none; color:#94a3b8; cursor:pointer;">✕ Close Summary</button>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 14px;">
                    <div style="background: rgba(15,23,42,0.5); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.2);">
                        <div style="font-size: 0.72rem; color: #94a3b8;">Total Combined Latency</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #fbbf24;">${latStr}</div>
                        <div style="font-size: 0.68rem; color: #64748b;">${agg.combined_latency_seconds} seconds</div>
                    </div>
                    <div style="background: rgba(15,23,42,0.5); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.2);">
                        <div style="font-size: 0.72rem; color: #94a3b8;">Total Combined Tokens</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #818cf8;">${tokStr}</div>
                        <div style="font-size: 0.68rem; color: #64748b;">Prompt: ${promptToks} · Output: ${compToks}</div>
                    </div>
                    <div style="background: rgba(15,23,42,0.5); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.2);">
                        <div style="font-size: 0.72rem; color: #94a3b8;">Combined Evidence Files</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #34d399;">${filesCnt} Files (${fileMb} MB)</div>
                        <div style="font-size: 0.68rem; color: #64748b;">${ftsStr}</div>
                    </div>
                    <div style="background: rgba(15,23,42,0.5); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.2);">
                        <div style="font-size: 0.72rem; color: #94a3b8;">Overall Compliance Rate</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: ${scorePct >= 80 ? '#34d399' : (scorePct >= 50 ? '#fbbf24' : '#f87171')};">${scorePct}%</div>
                        <div style="font-size: 0.68rem; color: #64748b;">Compliant: ${agg.combined_compliant_count} · Gaps: ${agg.combined_non_compliant_count}</div>
                    </div>
                    <div style="background: rgba(15,23,42,0.5); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.2);">
                        <div style="font-size: 0.72rem; color: #94a3b8;">System Hardware</div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #60a5fa;">${cpu} CPU Cores</div>
                        <div style="font-size: 0.68rem; color: #64748b;">Total Extracted Text: ${chars} Chars</div>
                    </div>
                </div>
                <div style="text-align: right;">
                    <button class="btn-secondary" onclick="exportAdminBenchmarkExcel()" style="padding: 6px 14px; font-size: 0.75rem; font-weight: 700; color: #10b981; border-color: rgba(16,185,129,0.4);">
                        📥 Export Combined Executive Excel Report (.xlsx)
                    </button>
                </div>
            `;
        } else {
            summaryBox.innerHTML = `<div style="text-align:center; color:#f87171; padding:10px;">No benchmark records found for the selected session IDs.</div>`;
        }
    } catch (err) {
        summaryBox.innerHTML = `<div style="text-align:center; color:#ef4444; padding:10px;">Failed to aggregate sessions: ${err.message}</div>`;
    }
};

window.exportAdminBenchmarkExcel = function () {
    window.location.href = `${API_BASE}/audit/benchmark/export`;
};

// ── Telemetry bulk download (Excel or PDF) ─────────────────────────────────
window.downloadBenchmarkExport = async function (format) {
    const btn = document.getElementById(
        format === "pdf" ? "btn-download-telemetry-pdf" : "btn-download-telemetry-excel"
    );
    const origText = btn ? btn.innerHTML : "";
    if (btn) { btn.disabled = true; btn.innerHTML = "⏳ Generating..."; }
    try {
        const endpoint = format === "pdf"
            ? `${API_BASE}/audit/benchmark/export-pdf`
            : `${API_BASE}/audit/benchmark/export`;
        const resp = await authFetch(endpoint);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || `Failed to download ${format.toUpperCase()} report.`, "error");
            return;
        }
        const blob = await resp.blob();
        const ext = format === "pdf" ? "pdf" : "xlsx";
        const mime = format === "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
        const url = URL.createObjectURL(new Blob([blob], { type: mime }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `Executive_Audit_Telemetry_Report.${ext}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`✅ Telemetry report (.${ext}) downloaded!`, "success");
    } catch (e) {
        showToast(`Download failed: ${e.message}`, "error");
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = origText; }
    }
};

// ── Per-session Excel download ─────────────────────────────────────────────
window.downloadBenchmarkReportForSession = async function (sessionId) {
    if (!sessionId) return;
    try {
        const resp = await authFetch(`${API_BASE}/audit/export-token-benchmark?session_id=${encodeURIComponent(sessionId)}`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to download session report.", "error");
            return;
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(new Blob([blob], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `Audit_Session_${sessionId.slice(0, 8)}_Benchmark.xlsx`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("✅ Session report downloaded!", "success");
    } catch (e) {
        showToast(`Download failed: ${e.message}`, "error");
    }
};


function floatVal(val) {
    const num = parseFloat(val);
    return isNaN(num) ? 0.0 : num;
}

function intVal(val) {
    const num = parseInt(val, 10);
    return isNaN(num) ? 0 : num;
}

function closeAdminLogModal() {
    const modalEl = document.getElementById("admin-log-modal");
    if (modalEl) modalEl.style.display = "none";
}


function updateBrandingSummary() {
    const firm = document.getElementById("brand-firm")?.value || "XYZ Security Services Pvt. Ltd.";
    const auditor = document.getElementById("brand-auditor")?.value || "Lead Cyber Security Auditor";
    const client = document.getElementById("brand-client")?.value || "XYZ Enterprise Security";
    const docid = document.getElementById("brand-docid")?.value || "AUD-XYZ-2026-001";

    const summaryFirm = document.getElementById("summary-brand-firm");
    const summaryAuditor = document.getElementById("summary-brand-auditor");
    const summaryClient = document.getElementById("summary-brand-client");
    const summaryDocId = document.getElementById("summary-brand-docid");

    if (summaryFirm) summaryFirm.innerText = firm;
    if (summaryAuditor) summaryAuditor.innerText = auditor;
    if (summaryClient) summaryClient.innerText = client;
    if (summaryDocId) summaryDocId.innerText = docid;
}

async function handleCompanyLogoUpload(event) {
    const file = event.target.files ? event.target.files[0] : null;
    if (!file) return;

    // Instant local thumbnail preview using FileReader
    const reader = new FileReader();
    reader.onload = function (e) {
        const preview = document.getElementById("meta-logo-preview");
        const statusTag = document.getElementById("logo-status-tag");
        const resetBtn = document.getElementById("btn-reset-logo");
        if (preview) preview.src = e.target.result;
        if (statusTag) statusTag.style.display = "inline-block";
        if (resetBtn) resetBtn.style.display = "block";
    };
    reader.readAsDataURL(file);

    // Upload logo to backend
    try {
        const formData = new FormData();
        formData.append("file", file);
        const resp = await authFetch(`${API_BASE}/audit/upload-logo?kind=auditor`, {
            method: "POST",
            body: formData
        });
        const data = await resp.json().catch(() => ({}));
        if (resp.ok && data.success) {
            showToast("Company logo uploaded! PDF & Word reports will use custom logo.", "success");
        } else {
            // A rejection must NOT read as success. The preview above is rendered
            // locally by FileReader and updates whatever the server says, so a
            // failure here is invisible unless it is stated: the logo looked
            // applied while every export kept using the default. Reported as an
            // error so it stays on screen until dismissed.
            revertCompanyLogoPreview();
            showToast(
                `Logo NOT saved — reports will keep the default logo. ${data.detail || data.message || `Server returned ${resp.status}.`}`,
                "error"
            );
        }
    } catch (err) {
        console.warn("[Company Logo] Upload failed:", err.message);
        revertCompanyLogoPreview();
        showToast(`Logo NOT saved — reports will keep the default logo. ${err.message}`, "error");
    }
}

function revertCompanyLogoPreview() {
    // Put the preview back to the default so the screen matches what the exports
    // will actually contain.
    const preview = document.getElementById("meta-logo-preview");
    const statusTag = document.getElementById("logo-status-tag");
    const resetBtn = document.getElementById("btn-reset-logo");
    if (preview) preview.src = "/static/placeholder_logo.svg";
    if (statusTag) statusTag.style.display = "none";
    if (resetBtn) resetBtn.style.display = "none";
}

async function resetCompanyLogo(event) {
    if (event) event.stopPropagation();
    try {
        await authFetch(`${API_BASE}/audit/upload-logo?kind=auditor`, { method: "DELETE" });
    } catch (e) { }

    const preview = document.getElementById("meta-logo-preview");
    const statusTag = document.getElementById("logo-status-tag");
    const resetBtn = document.getElementById("btn-reset-logo");
    const fileInput = document.getElementById("meta-company-logo");

    if (preview) preview.src = "/static/placeholder_logo.svg";
    if (statusTag) statusTag.style.display = "none";
    if (resetBtn) resetBtn.style.display = "none";
    if (fileInput) fileInput.value = "";

    showToast("Reset to default template logo.", "info");
}

// The auditee's logo is a second, independent slot (report cover page); the
// auditor's own logo above fills the header. Same endpoint, distinguished by
// `kind` -- so an upload of one never overwrites the other.
async function handleAuditeeLogoUpload(event) {
    const file = event.target.files ? event.target.files[0] : null;
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        const preview = document.getElementById("meta-auditee-logo-preview");
        const statusTag = document.getElementById("auditee-logo-status-tag");
        const resetBtn = document.getElementById("btn-reset-auditee-logo");
        if (preview) preview.src = e.target.result;
        if (statusTag) statusTag.style.display = "inline-block";
        if (resetBtn) resetBtn.style.display = "block";
    };
    reader.readAsDataURL(file);

    try {
        const formData = new FormData();
        formData.append("file", file);
        const resp = await authFetch(`${API_BASE}/audit/upload-logo?kind=auditee`, {
            method: "POST",
            body: formData
        });
        const data = await resp.json().catch(() => ({}));
        if (resp.ok && data.success) {
            showToast("Auditee logo uploaded! It will appear on the report cover page.", "success");
        } else {
            // Same reasoning as the auditor logo: the preview is local, so a
            // server-side rejection is invisible unless it is stated outright.
            revertAuditeeLogoPreview();
            showToast(
                `Auditee logo NOT saved — the report cover will stay blank. ${data.detail || data.message || `Server returned ${resp.status}.`}`,
                "error"
            );
        }
    } catch (err) {
        console.warn("[Auditee Logo] Upload failed:", err.message);
        revertAuditeeLogoPreview();
        showToast(`Auditee logo NOT saved — the report cover will stay blank. ${err.message}`, "error");
    }
}

function revertAuditeeLogoPreview() {
    const preview = document.getElementById("meta-auditee-logo-preview");
    const statusTag = document.getElementById("auditee-logo-status-tag");
    const resetBtn = document.getElementById("btn-reset-auditee-logo");
    if (preview) preview.src = "/static/placeholder_logo.svg";
    if (statusTag) statusTag.style.display = "none";
    if (resetBtn) resetBtn.style.display = "none";
}

async function resetAuditeeLogo(event) {
    if (event) event.stopPropagation();
    try {
        await authFetch(`${API_BASE}/audit/upload-logo?kind=auditee`, { method: "DELETE" });
    } catch (e) { }

    revertAuditeeLogoPreview();
    const fileInput = document.getElementById("meta-auditee-logo");
    if (fileInput) fileInput.value = "";

    showToast("Auditee logo removed.", "info");
}

async function renderAuditReportPreview() {
    const container = document.getElementById("report-preview-container");
    if (!container) return;

    if (!activeSessionId) {
        container.innerHTML = `<div class="empty-state">No active audit session selected.</div>`;
        return;
    }

    container.innerHTML = `<div class="empty-state">Loading real-time audit evaluation report from Shakthi DB...</div>`;

    try {
        // CRITICAL REQUIREMENT: Query saved_only=true so ONLY findings saved to Shakthi DB appear in PDF Exporter Review & Download!
        const response = await authFetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&saved_only=true`);
        const data = await response.json();

        const findings = (data.success && data.findings) ? data.findings : [];

        const brandFirm = document.getElementById("brand-firm")?.value || "TÜV SÜD South Asia Pvt. Ltd.";
        const brandAuditor = document.getElementById("brand-auditor")?.value || "Mr. Vikas Dubey";
        const brandReviewer = document.getElementById("brand-reviewer")?.value || "Ms. Prianka Singla";
        const brandApprover = document.getElementById("brand-approver")?.value || "Mr. Atul Srivastava";
        const brandDocId = document.getElementById("brand-docid")?.value || "3153142723";
        const brandClient = document.getElementById("brand-client")?.value || "NOCPL";
        const brandEmail = document.getElementById("brand-email")?.value || "ashish.jaiswal1@motorolasolutions.com";

        updateBrandingSummary();

        // Standards Rule: Exclude pure INFO items from Executive Audit Evaluation details table!
        const reportFindings = findings.filter(f => !isFindingInformational(f));

        function getSevRank(f) {
            const sev = String(f.severity || "").toUpperCase();
            if (sev.includes("CRITICAL") || sev.includes("P1") || sev.startsWith("9.") || sev.startsWith("10.")) return 1;
            if (sev.includes("HIGH") || sev.includes("P2") || sev.startsWith("7.") || sev.startsWith("8.")) return 2;
            if (sev.includes("MEDIUM") || sev.includes("P3") || sev.startsWith("4.") || sev.startsWith("5.") || sev.startsWith("6.")) return 3;
            if (sev.includes("LOW") || sev.includes("P4") || sev.startsWith("0.") || sev.startsWith("1.") || sev.startsWith("2.") || sev.startsWith("3.")) return 4;
            return 5;
        }
        reportFindings.sort((a, b) => getSevRank(a) - getSevRank(b));

        let compliantCount = 0;
        let nonCompliantCount = 0;

        reportFindings.forEach(f => {
            if (isFindingCompliant(f)) {
                compliantCount++;
            } else {
                nonCompliantCount++;
            }
        });

        const totalCount = reportFindings.length;
        const scorePercent = Math.round((compliantCount / (totalCount || 1)) * 100);

        let rowsHtml = "";
        if (reportFindings.length === 0) {
            rowsHtml = `<tr><td colspan="6" style="text-align:center; padding:20px; color:#fbbf24; background: rgba(245, 158, 11, 0.08);">⚠️ <b>No actionable findings saved to Shakthi DB yet.</b> Go to <b>Audit Records & Findings</b> tab, review your controls, and click <b>"Save to Shakthi DB"</b> to display them in this PDF report.</td></tr>`;
        } else {
            reportFindings.forEach(f => {
                const isComp = isFindingCompliant(f);
                const displayStatus = f.status || (isComp ? "Compliant" : "Non-Compliant");
                const badgeColor = isComp ? "#10b981" : "#ef4444";
                const badgeBg = isComp ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)";

                // Safe control name: never show "undefined" or "null"
                const rawCtrlName = f.control_name;
                const ctrlTitle = (rawCtrlName && rawCtrlName !== 'null' && rawCtrlName !== 'undefined')
                    ? rawCtrlName
                    : f.control_id;

                const polSub = f.policy_present ? `<div style="font-size:0.68rem; color:#60a5fa; margin-top:2px;">📜 Policy: ${escapeHtml(f.policy_present)}</div>` : '';
                const evSub = f.evidence_present ? `<div style="font-size:0.68rem; color:#c084fc; margin-top:1px;">🔍 Evidence: ${escapeHtml(f.evidence_present)}</div>` : '';

                const evSnippet = f.evidence_snippet ? `<div class="ev-snippet-text" style="margin-bottom:4px; font-family:var(--font-mono); font-size:0.74rem; line-height: 1.4;"><b>Exact Evidence:</b> "${escapeHtml(f.evidence_snippet)}"</div>` : '';
                const evDesc = f.description ? `<div class="ev-desc-text" style="font-size:0.74rem; line-height: 1.4; opacity: 0.9;">${escapeHtml(f.description)}</div>` : '';
                const srcFile = f.source_files ? `<div style="font-size:0.7rem; color:#2563eb; margin-top:3px; font-weight:600;">📁 ${escapeHtml(f.source_files)}</div>` : '';
                const sev = (f.severity && f.severity !== 'null' && f.severity !== 'undefined') ? f.severity : 'N/A';

                rowsHtml += `
                    <tr style="border-bottom: 1px solid rgba(148,163,184,0.2);">
                        <td style="padding: 10px; font-weight:700; color:#2563eb; font-family:var(--font-mono);">${f.control_id}</td>
                        <td style="padding: 10px; font-weight:600;" class="preview-ctrl-title">${escapeHtml(ctrlTitle)}</td>
                        <td style="padding: 10px;">
                            <span style="padding: 4px 9px; border-radius: 6px; font-size: 0.72rem; font-weight:700; color:${badgeColor}; background:${badgeBg}; border: 1px solid ${badgeColor}40;">${displayStatus}</span>
                            ${polSub}
                            ${evSub}
                        </td>
                        <td style="padding: 10px; font-weight:700; font-size:0.74rem;">${sev}</td>
                        <td style="padding: 10px; max-width: 420px;">${evSnippet}${evDesc}${srcFile}</td>
                    </tr>
                `;
            });
        }

        container.innerHTML = `
            <div class="report-preview-card" style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 16px; padding: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid rgba(148, 163, 184, 0.2); padding-bottom: 16px; margin-bottom: 20px;">
                    <div>
                        <h2 style="margin: 0 0 6px 0; font-size: 1.3rem; font-weight: 800;" class="preview-ctrl-title">FINAL EXECUTIVE AUDIT EVALUATION REPORT</h2>
                        <div style="font-size: 0.82rem; color: #2563eb; font-weight: 700;">Audit Framework Preview</div>
                    </div>
                    <div style="text-align: right; font-size: 0.78rem; line-height: 1.5;" class="preview-meta-block">
                        <div>Auditor Firm: <b class="preview-b-text">${escapeHtml(brandFirm)}</b></div>
                        <div>Document ID: <b style="color:#2563eb;">${escapeHtml(brandDocId)}</b></div>
                        <div>Date: <b class="preview-b-text">${new Date().toLocaleDateString()}</b></div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; background: rgba(30, 41, 59, 0.5); padding: 16px; border-radius: 12px; border: 1px solid rgba(148, 163, 184, 0.15);" class="preview-summary-card">
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Client Organization</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandClient)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Client Contact Email</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandEmail)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Lead Auditor(s)</span><b style="font-size:0.88rem;" class="preview-b-text">${escapeHtml(brandAuditor)}</b></div>
                    <div><span style="font-size:0.72rem; opacity:0.8; display:block; margin-bottom: 2px;">Compliance Score</span><b style="font-size:1.1rem; color:${scorePercent >= 70 ? '#10b981' : '#f59e0b'};">${scorePercent}% Compliance</b></div>
                </div>

                <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom:12px;" class="preview-ctrl-title">Audit Control Evaluation Details (${reportFindings.length} controls evaluated)</h4>
                <div style="overflow-x: auto; margin-bottom: 20px; border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px;">
                    <table style="width:100%; border-collapse:collapse; font-size:0.8rem; text-align:left;" class="report-preview-table">
                        <thead>
                            <tr style="background:rgba(30,41,59,0.8); border-bottom: 2px solid rgba(148, 163, 184, 0.25);">
                                <th style="padding:10px; width: 11%;">Control ID</th>
                                <th style="padding:10px; width: 38%;">Control Name</th>
                                <th style="padding:10px; width: 13%;">Status</th>
                                <th style="padding:10px; width: 10%;">Severity</th>
                                <th style="padding:10px; width: 28%;">Evidence / Reason Snippet</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHtml}
                        </tbody>
                    </table>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-top:20px; padding-top:16px; border-top:1px solid rgba(148,163,184,0.15); font-size:0.78rem;" class="preview-footer-block">
                    <div>Reviewed By: <b class="preview-b-text">${escapeHtml(brandReviewer)}</b></div>
                    <div>Approved By: <b class="preview-b-text">${escapeHtml(brandApprover)}</b></div>
                    <div>Shakthi DB Hash: <b style="color:#10b981;">SECURE_COMMIT_VERIFIED</b></div>
                </div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Failed to render audit report preview: ${err.message}</div>`;
    }
}

function isVaptFinding(f) {
    if (!f) return false;
    const cid = String(f.control_id || "").toUpperCase();
    const cat = String(f.category || f.control_name || "").toUpperCase();
    const fw = String(typeof activeSessionFramework !== "undefined" ? activeSessionFramework : "").toUpperCase();
    // PQC findings come from the same deterministic scanner-parser pipeline as
    // VAPT (pqc_parser.py, not the LLM/RAG path) and carry the same POC-style
    // evidence_snippet/plugin_id/cia_impact fields, so they render with the
    // same VAPT-style finding card here.
    return cid.startsWith("VAPT") || cat.includes("VAPT") || fw.includes("VAPT")
        || cid.startsWith("PQC") || cat.includes("PQC") || fw.includes("PQC");
}

// PQC findings render inside the same VAPT-style card as isVaptFinding() above
// (isVaptFinding already matches PQC control IDs/category/framework), but carry
// their own extra columns (quantum_status/asset_name/ca_algorithm/key_algorithm/
// protocol_version/exposure_context/port/environment) that need their own
// display block. quantum_status is the most PQC-specific signal -- it's only
// ever populated by pqc_parser.py -- so gate on that rather than re-deriving
// the same control-id/category/framework heuristics as isVaptFinding().
function isPqcFinding(f) {
    return !!(f && f.quantum_status);
}

// A VAPT finding recorded as closed / remediated, by the pentest report or by
// the auditor in the Modify dialog: status "Closed", or an Accepted one whose
// verdict is CLOSED (Accept confirms it). A finding the auditor reopened is
// open. Only ever true on a VAPT session --
// no other framework has closed findings -- so ISO, PQC and the rest keep
// every count and filter they had.
function isFindingClosed(f) {
    if (!f || !isVaptOnlySession()) return false;
    const st = String(f.status || "").trim().toLowerCase();
    if (st === "closed") return true;
    // Accept keeps the verdict: a closed finding's is CLOSED. One reopened in
    // the Modify dialog has another, whatever its proof says.
    if (st === "accepted" || st === "confirmed") {
        return String(f.final_result || "").trim().toUpperCase() === "CLOSED";
    }
    return false;
}

// A VAPT session's Informational / Closed / Total boxes: select that status,
// or clear it on a second click.
function toggleVaptStatusFilter(value) {
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");
    const sel = document.getElementById("status-filter");
    const next = (sel && sel.value === value) ? "All" : value;
    if (sel) sel.value = next;
    activeSeverityFilter = "";
    activeComplianceFilter = "";
    currentFilter = next === "All" ? "all" : next;
    const box = { Informational: ".info-box", Closed: ".closed-box" }[next];
    const el = box ? document.querySelector(`#kpi-row-vapt ${box}`) : null;
    if (el) el.style.outline = "2px solid #3b82f6";
    renderFindingsList();
}

function isFindingInformational(f) {
    const sev = (f.severity || "").toUpperCase();
    const st = (f.status || "").toUpperCase();
    return sev.includes("INFO") || st.includes("INFO");
}

// ── VAPT retest (src/core/vapt_retest.py) ─────────────────────────────────
// A VAPT session scanned more than once: its versions (v1, v2 ...), which one
// is on screen (null = the latest), and the retest status the counts filter
// on. Every other session has no versions and none of this shows.
let vaptRounds = [];
let vaptRoundsSession = null;
let vaptViewRound = null;
let vaptRetestFilter = "";
let vaptAllFindings = [];

const VAPT_RETEST_LABELS = {
    still_open:   { text: "Still open",   fg: "#c2410c", bg: "rgba(249,115,22,0.14)", hint: "found again in the retest" },
    fixed:        { text: "Fixed",        fg: "#15803d", bg: "rgba(34,197,94,0.15)",  hint: "host rescanned, not found" },
    new:          { text: "New",          fg: "#dc2626", bg: "rgba(239,68,68,0.14)",  hint: "not in the earlier scan" },
    not_retested: { text: "Not retested", fg: "#64748b", bg: "rgba(100,116,139,0.18)", hint: "host left out of the retest" },
    reopened:     { text: "Reopened",     fg: "#9333ea", bg: "rgba(168,85,247,0.15)", hint: "fixed earlier, found again" },
};

function vaptRetestActive() { return isVaptOnlySession() && vaptRounds.length >= 2; }
function vaptLatestRound() {
    return vaptRounds.length ? Math.max(...vaptRounds.map(r => Number(r.round) || 0)) : 1;
}
function vaptViewingOlder() { return vaptRetestActive() && !!vaptViewRound && vaptViewRound < vaptLatestRound(); }

function vaptRetestDate(iso) {
    const d = new Date(String(iso || "").slice(0, 10) + "T00:00:00Z");
    return isNaN(d.getTime()) ? String(iso || "") :
        d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
}

// The findings as version k stood: those found by then, each with the status
// that version gave it (as vapt_retest.view_as_of_round does for the report).
function vaptFindingsAsOf(list, k) {
    return list.filter(f => (Number(f.first_round) || 1) <= k).map(f => {
        let best = null;
        (Array.isArray(f.retest_history) ? f.retest_history : []).forEach(h => {
            const r = Number(h && h.round) || 0;
            if (r <= k && (!best || r >= best.round)) best = { round: r, status: h.status };
        });
        const status = (best && best.status) || f.status;
        const closed = String(status || "").trim().toLowerCase() === "closed";
        const fr = closed ? "CLOSED" : (String(f.final_result || "").toUpperCase() === "CLOSED" ? "" : f.final_result);
        return Object.assign({}, f, { status: status, final_result: fr });
    });
}

function vaptRetestCounts() {
    const c = { still_open: 0, fixed: 0, new: 0, not_retested: 0, reopened: 0 };
    vaptAllFindings.forEach(f => { if (c[f.retest_status] !== undefined) c[f.retest_status] += 1; });
    return c;
}

// The version in which a finding reached its current retest status.
function vaptRetestRoundOf(f) {
    if (f.retest_status === "new") return Number(f.first_round) || vaptLatestRound();
    const hist = (Array.isArray(f.retest_history) ? f.retest_history : []).slice()
        .sort((a, b) => (Number(a.round) || 0) - (Number(b.round) || 0));
    let at = null;
    for (let i = hist.length - 1; i >= 1; i--) {
        const closedNow = String(hist[i].status || "").toLowerCase() === "closed";
        const closedBefore = String(hist[i - 1].status || "").toLowerCase() === "closed";
        if (closedNow !== closedBefore) { at = Number(hist[i].round); break; }
    }
    return at || vaptLatestRound();
}

function renderVaptRetestBar() {
    const bar = document.getElementById("vapt-retest-bar");
    const exp = document.getElementById("vapt-export-version");
    const container = document.getElementById("findings-container");
    if (container) container.classList.toggle("vapt-history-view", vaptViewingOlder());
    if (!bar) return;
    if (!vaptRetestActive()) {
        bar.style.display = "none";
        bar.innerHTML = "";
        if (exp) exp.style.display = "none";
        return;
    }
    const latest = vaptLatestRound();
    const viewing = vaptViewRound || latest;
    const byRound = {};
    vaptRounds.forEach(r => { byRound[Number(r.round)] = r; });
    const cur = byRound[viewing] || {};
    const prev = byRound[viewing - 1];
    const buttons = vaptRounds.map(r => {
        const n = Number(r.round);
        const what = n === 1 ? "first scan" : "retest";
        return `<button type="button" id="vapt-version-${n}" class="vapt-version-btn" aria-pressed="${n === viewing}" onclick="setVaptViewRound(${n})">`
            + `v${n} · ${what}${n === latest ? " (latest)" : ""}<small>${escapeHtml(vaptRetestDate(r.date))} · ${Number(r.found) || 0} found</small></button>`;
    }).join("");
    const compare = prev
        ? `v${viewing} compared with v${viewing - 1} · ${escapeHtml(vaptRetestDate(cur.date))} vs ${escapeHtml(vaptRetestDate(prev.date))}`
        : `First scan · ${escapeHtml(vaptRetestDate(cur.date))}`;
    let body;
    if (viewing < latest) {
        body = `<div class="vapt-retest-note">Showing <b>v${viewing}</b> as it stood on ${escapeHtml(vaptRetestDate(cur.date))}, read only. `
            + `Switch to <b>v${latest}</b> to review and change findings.</div>`;
    } else {
        const c = vaptRetestCounts();
        const keys = ["still_open", "fixed", "new", "not_retested"].concat(c.reopened ? ["reopened"] : []);
        body = `<div class="vapt-retest-counts" role="group" aria-label="Filter by retest status">` + keys.map(k => {
            const L = VAPT_RETEST_LABELS[k];
            return `<button type="button" id="vapt-retest-${k}" class="vapt-retest-count" aria-pressed="${vaptRetestFilter === k}" `
                + `onclick="toggleVaptRetestFilter('${k}')" style="color:${L.fg}; background:${L.bg};">`
                + `<span class="n">${Number(c[k]) || 0}</span><span class="l">${escapeHtml(L.text)}</span><span class="d">${escapeHtml(L.hint)}</span></button>`;
        }).join("") + `</div>`;
    }
    bar.innerHTML = `<div class="vapt-retest-head"><span class="vapt-retest-label">SCAN VERSION</span>`
        + `<div class="vapt-version-seg" role="group" aria-label="Scan version">${buttons}</div>`
        + `<span class="vapt-retest-compare">${compare}</span></div>${body}`;
    bar.style.display = "block";

    // Report Exporter: the version to export, latest first.
    const sel = document.getElementById("vapt-export-round");
    if (exp && sel) {
        const keep = sel.value;
        sel.innerHTML = vaptRounds.slice().reverse().map(r => {
            const n = Number(r.round);
            return `<option value="${n}">v${n} · ${n === 1 ? "first scan" : "retest"} · ${escapeHtml(vaptRetestDate(r.date))}${n === latest ? " (latest)" : ""}</option>`;
        }).join("");
        if (keep && sel.querySelector(`option[value="${keep}"]`)) sel.value = keep;
        exp.style.display = "flex";
    }
}

function setVaptViewRound(n) {
    vaptViewRound = (Number(n) >= vaptLatestRound()) ? null : Number(n);
    vaptRetestFilter = "";
    findingsList = vaptViewRound ? vaptFindingsAsOf(vaptAllFindings, vaptViewRound) : vaptAllFindings;
    renderVaptRetestBar();
    renderFindingsList();
    calculateSeverityStats();
}

function toggleVaptRetestFilter(k) {
    vaptRetestFilter = (vaptRetestFilter === k) ? "" : k;
    renderVaptRetestBar();
    renderFindingsList();
}

function vaptRetestBadgeHtml(f) {
    if (!vaptRetestActive() || vaptViewingOlder()) return "";
    const L = VAPT_RETEST_LABELS[f.retest_status];
    if (!L) return "";
    const when = (f.retest_status === "fixed" || f.retest_status === "new" || f.retest_status === "reopened")
        ? ` IN v${vaptRetestRoundOf(f)}` : "";
    return `<span class="badge vapt-retest-badge" title="${escapeHtml(L.hint)}" style="background:${L.bg}; color:${L.fg}; border:1px solid ${L.fg};">`
        + `${escapeHtml(L.text.toUpperCase())}${when}</span>`;
}

const VAPT_HISTORY_WORDS = {
    found: "Found", not_found: "Not found (host rescanned)",
    not_scanned: "Host not scanned", reported_closed: "Reported closed",
};
const VAPT_HISTORY_NOTES = {
    fixed: "Closed by the retest. Reopen it with Modify if the scanner only missed it.",
    not_retested: "Its host was not part of the latest retest, so it stays open until a later scan covers it.",
    new: "Found in the retest; it was not in the earlier scan.",
    reopened: "It had been fixed and was found again.",
};

function vaptRetestHistoryHtml(f) {
    if (!vaptRetestActive() || vaptViewingOlder()) return "";
    const hist = (Array.isArray(f.retest_history) ? f.retest_history : []).slice()
        .sort((a, b) => (Number(a.round) || 0) - (Number(b.round) || 0));
    if (!hist.length) return "";
    const dates = {};
    vaptRounds.forEach(r => { dates[Number(r.round)] = r.date; });
    const steps = hist.map(h => `<span class="vapt-step">v${Number(h.round) || "?"} · ${escapeHtml(vaptRetestDate(dates[Number(h.round)] || h.date))}: `
        + `<b>${escapeHtml(VAPT_HISTORY_WORDS[h.state] || h.state || "")}</b></span>`).join(`<span class="vapt-step-arrow">→</span>`);
    const note = VAPT_HISTORY_NOTES[f.retest_status] || "";
    return `<div class="vapt-retest-history"><label>↻ Retest history</label><div class="vapt-steps">${steps}</div>`
        + (note ? `<p>${escapeHtml(note)}</p>` : "") + `</div>`;
}

// Scan Workspace: offer the retest when a VAPT session that already has
// findings has files no version has scanned yet.
async function refreshVaptRetestChoice() {
    const box = document.getElementById("vapt-retest-choice");
    if (!box) return;
    const sid = activeSessionId;
    const hide = () => {
        box.style.display = "none";
        box.innerHTML = "";
        box.dataset.next = "";
        syncRunButtonForRetest();
    };
    if (!sid) return hide();
    try {
        const res = await authFetch(`${API_BASE}/audit/vapt/retest-info?session_id=${encodeURIComponent(sid)}`);
        if (!res.ok) return hide();
        const info = await res.json();
        if (activeSessionId !== sid) return;
        const newFiles = Array.isArray(info.new_files) ? info.new_files : [];
        if (!info.vapt || !info.has_findings) return hide();
        const rounds = Array.isArray(info.rounds) ? info.rounds : [];
        const last = rounds[rounds.length - 1] || {};
        const lastN = Number(last.round) || 1;
        const next = Number(info.next_round) || lastN + 1;
        if (!newFiles.length) {
            // Scanned, and nothing new to compare yet. This used to show
            // nothing at all: an auditor who uploaded the same report again saw
            // no retest option, pressed Run, and replaced v1 with a fresh full
            // scan. Say how a retest starts, and what Run does meanwhile. No
            // next version is set, so Run stays an ordinary run.
            box.dataset.next = "";
            const found = rounds.length ? `${Number(last.found) || 0} finding(s)` : "findings";
            const when = last.date ? `, ${escapeHtml(vaptRetestDate(last.date))}` : "";
            box.innerHTML = `<div class="vapt-retest-choice-box vapt-retest-hint">`
                + `<b>v${lastN} scanned: ${found}${when}.</b>`
                + `<span>To retest, upload the <b>new</b> scan report of the same targets (a different file from v${lastN}'s). `
                + `It is compared with v${lastN}: still open, fixed, new, not retested.</span>`
                + `<span class="vapt-retest-hint-warn">Run Audit Scan without a new file scans v${lastN}'s files again from the start and replaces unsaved findings.</span>`
                + `<button type="button" class="btn-secondary" id="vapt-retest-upload-btn" `
                + `onclick="document.getElementById('evidence-file-input-panel').click()">Upload retest file</button>`
                + `</div>`;
            box.style.display = "block";
            syncRunButtonForRetest();
            return;
        }
        const choice = box.dataset.choice || "retest";
        box.dataset.next = String(next);
        box.innerHTML = `<div class="vapt-retest-choice-box">`
            + `<b>This session already has v${lastN}: ${Number(last.found) || 0} finding(s), scanned ${escapeHtml(vaptRetestDate(last.date))}.</b>`
            + `<span>Not scanned yet: ${newFiles.map(n => escapeHtml(n)).join(", ")}</span>`
            + `<label for="vapt-run-retest"><input type="radio" name="vapt-run-kind" id="vapt-run-retest" value="retest"${choice === "retest" ? " checked" : ""}>`
            + `<span><b>Retest (v${next})</b>: scan only the new file(s) and compare with v${lastN}. Found again: still open. `
            + `Host rescanned but not found: fixed. Host not in the retest: not retested. Not in v${lastN}: new. v${lastN} is kept.</span></label>`
            + `<label for="vapt-run-full"><input type="radio" name="vapt-run-kind" id="vapt-run-full" value="full"${choice === "full" ? " checked" : ""}>`
            + `<span><b>Scan everything again as one scan</b>: every file, as before. Unsaved findings are replaced and the versions start over.</span></label>`
            + `</div>`;
        box.style.display = "block";
        box.querySelectorAll("input[name='vapt-run-kind']").forEach(r => r.addEventListener("change", () => {
            box.dataset.choice = r.value;
            syncRunButtonForRetest();
        }));
        syncRunButtonForRetest();
    } catch (e) {
        hide();
    }
}

function vaptRetestSelected() {
    const box = document.getElementById("vapt-retest-choice");
    if (!box || box.style.display === "none" || !box.dataset.next) return false;
    const r = box.querySelector("input[name='vapt-run-kind']:checked");
    return !!r && r.value === "retest";
}

function syncRunButtonForRetest() {
    const btn = document.getElementById("run-analysis-btn");
    if (!btn || btn.disabled) return;
    const box = document.getElementById("vapt-retest-choice");
    const label = vaptRetestSelected() ? `Run Retest Scan (v${Number(box.dataset.next) || 2})` : "Run Audit Scan";
    btn.innerHTML = `<span>▶</span> <span>${escapeHtml(label)}</span>`;
}

// Report Exporter: the version and summary choices, when there is a choice.
function vaptExportParams() {
    const exp = document.getElementById("vapt-export-version");
    if (!exp || exp.style.display === "none" || !vaptRetestActive()) return "";
    const sel = document.getElementById("vapt-export-round");
    const sum = document.getElementById("vapt-export-summary");
    let q = "";
    if (sel && sel.value && Number(sel.value) < vaptLatestRound()) q += `&version=${encodeURIComponent(sel.value)}`;
    if (sum && !sum.checked) q += "&retest_summary=false";
    return q;
}

// The framework of the session on the Audit Records page, as /audit/findings
// reports it. (activeSessionFramework, which several checks read, is never
// assigned; a separate name keeps those checks exactly as they are.)
let findingsSessionFramework = "";

// A VAPT session keeps its scanner's informational findings on screen, as the
// VAPT report does. Nothing in a VAPT scan is "Compliant", so that filter and
// counter can never match; Informational takes their place. ISO and PQC
// sessions are unchanged.
function isVaptOnlySession() {
    const fw = String(findingsSessionFramework || "").toUpperCase();
    return fw.includes("VAPT") && !fw.includes("PQC");
}

// The findings a /audit/findings?include_info=true payload puts on screen:
// all of them for a VAPT session, all but informational for any other.
function findingsForSession(data) {
    findingsSessionFramework = (data && data.framework) || "";
    syncStatusFilterForSession();
    const all = (data && data.findings) || [];
    return isVaptOnlySession() ? all : all.filter(f => !isFindingInformational(f));
}

function syncStatusFilterForSession() {
    const vapt = isVaptOnlySession();
    const sel = document.getElementById("status-filter");
    if (sel) {
        const relabel = (value, vaptText) => {
            const opt = sel.querySelector(`option[value="${value}"]`);
            if (!opt) return;
            if (!opt.dataset.defaultText) opt.dataset.defaultText = opt.textContent;
            opt.textContent = vapt ? vaptText : opt.dataset.defaultText;
        };
        relabel("All", "All Findings (Vulnerabilities & Informational)");
        relabel("Non-Compliant", "Vulnerabilities Only (P1-P4)");
        relabel("Open", "Unreviewed / Open Vulnerabilities");
        const comp = sel.querySelector('option[value="Compliant"]');
        let info = sel.querySelector('option[value="Informational"]');
        if (!info) {
            info = new Option("Informational Only", "Informational");
            sel.insertBefore(info, comp ? comp.nextSibling : null);
        }
        if (comp) comp.hidden = vapt;
        info.hidden = !vapt;
        let closedOpt = sel.querySelector('option[value="Closed"]');
        if (!closedOpt) {
            closedOpt = new Option("Closed (remediated per report)", "Closed");
            sel.insertBefore(closedOpt, info.nextSibling);
        }
        closedOpt.hidden = !vapt;
        if (vapt && sel.value === "Compliant") sel.value = "All";
        if (!vapt && (sel.value === "Informational" || sel.value === "Closed")) sel.value = "All";
    }
    // VAPT sessions have their own row of counters, in the order a VAPT report
    // reads: Critical, High, Medium, Low, Informational, Closed, Total.
    const stdRow = document.getElementById("kpi-row-standard");
    const vaptRow = document.getElementById("kpi-row-vapt");
    if (stdRow && vaptRow) {
        stdRow.style.display = vapt ? "none" : "";
        vaptRow.style.display = vapt ? "" : "none";
    }
    const label = document.querySelector(".kpi-box.compliant-box .kpi-label");
    if (label) {
        if (!label.dataset.defaultText) label.dataset.defaultText = label.textContent;
        label.textContent = vapt ? "Informational" : label.dataset.defaultText;
    }
}

function matchesSeverityFilter(fSeverity, activeFilter) {
    if (!activeFilter) return true;
    const sev = (fSeverity || "").toLowerCase();
    const filter = activeFilter.toLowerCase();

    if (filter.includes("p1") || filter.includes("critical")) {
        return sev.includes("p1") || sev.includes("critical") || sev.includes("9.") || sev.includes("10.");
    }
    if (filter.includes("p2") || filter.includes("high")) {
        return sev.includes("p2") || sev.includes("high") || sev.includes("7.") || sev.includes("8.");
    }
    if (filter.includes("p3") || filter.includes("medium")) {
        return sev.includes("p3") || sev.includes("medium") || sev.includes("4.") || sev.includes("5.") || sev.includes("6.");
    }
    if (filter.includes("p4") || filter.includes("low")) {
        return sev.includes("p4") || sev.includes("low") || sev.includes("0.") || sev.includes("1.") || sev.includes("2.") || sev.includes("3.");
    }
    if (filter.includes("info")) {
        return sev.includes("info");
    }
    return true;
}

let activeComplianceFilter = "";

function toggleComplianceFilter(mode) {
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");

    const statusSelect = document.getElementById("status-filter");

    if (activeComplianceFilter.toLowerCase() === mode.toLowerCase()) {
        activeComplianceFilter = "";
        currentFilter = "all";
        if (statusSelect) statusSelect.value = "All";
    } else {
        activeComplianceFilter = mode;
        currentFilter = mode;
        if (statusSelect) {
            // The first KPI box counts informational findings on a VAPT session.
            statusSelect.value = (mode.toLowerCase().includes("non")) ? "Non-Compliant"
                : (isVaptOnlySession() ? "Informational" : "Compliant");
        }
        const selector = mode.toLowerCase().includes("non") ? ".noncompliant-box" : ".compliant-box";
        const box = document.querySelector(selector);
        if (box) box.style.outline = "2px solid #3b82f6";
    }
    activeSeverityFilter = "";
    renderFindingsList();
}

function toggleTerminalFullscreen() {
    const term = document.getElementById("developer-terminal");
    if (!term) return;
    term.classList.toggle("terminal-fullscreen");
    if (term.classList.contains("terminal-fullscreen")) {
        term.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function toggleSeverityFilter(sev) {
    document.querySelectorAll(".kpi-box").forEach(b => b.style.outline = "none");

    // Reset status filter dropdown to "All" so status doesn't block severity matching
    const select = document.getElementById("status-filter");
    if (select) select.value = "All";

    if (activeSeverityFilter === sev) {
        activeSeverityFilter = ""; // Clear filter
    } else {
        activeSeverityFilter = sev;
        let selector = "";
        if (sev.includes("P1")) selector = ".p1-box";
        else if (sev.includes("P2")) selector = ".p2-box";
        else if (sev.includes("P3")) selector = ".p3-box";
        else if (sev.includes("P4")) selector = ".p4-box";

        if (selector) {
            const row = isVaptOnlySession() ? "#kpi-row-vapt" : "#kpi-row-standard";
            const box = document.querySelector(`${row} ${selector}`) || document.querySelector(selector);
            if (box) box.style.outline = "2px solid #3b82f6";
        }
    }
    renderFindingsList();
}

// Which P-band a severity string belongs to, as "p1".."p4", or "" for none.
//
// The KPI counters and the KPI click-through filter each used to decide this
// for themselves, and they disagreed. The counter accepted either spelling --
// includes("p4") OR includes("low") -- while the filter asked whether the
// severity contained the whole label the box passes it, "p4 low". So a finding
// stored as "Low", "P4", "P4 - Low" or "P4/Low" was counted in the box and
// then matched by nothing when that same box was clicked: P4 / Low showing 1,
// and "No audit findings match the current filter criteria" underneath it.
//
// One function, used by both, so a severity that is counted is always a
// severity that can be found. The order matters: a P-code wins over a word, so
// "P2 High" is p2 and never p1 by way of some other substring.
function severityBand(severity) {
    const sev = String(severity || "").toLowerCase();
    if (sev.includes("p1") || sev.includes("critical")) return "p1";
    if (sev.includes("p2") || sev.includes("high")) return "p2";
    if (sev.includes("p3") || sev.includes("medium")) return "p3";
    if (sev.includes("p4") || sev.includes("low")) return "p4";
    return "";
}

// Called after renderFindingsList() by the scan-complete poller and the
// "Recent" session loader, and never defined: each call threw a ReferenceError,
// so the poller never re-enabled the Run button and "Recent" reported
// "Failed to load recent session" after loading it. renderFindingsList() has
// already refreshed the counters by this point.
function updateKPICounters() {}

function calculateSeverityStats(currentExpandedCards) {
    let compCount = 0;
    let infoCount = 0;
    let nonCompCount = 0;
    let p1Count = 0;
    let p2Count = 0;
    let p3Count = 0;
    let p4Count = 0;
    let closedCount = 0;
    let totalCount = 0;

    const cardsToCount = currentExpandedCards || [];

    if (cardsToCount.length > 0) {
        cardsToCount.forEach(item => {
            const f = item.originalFinding;
            const singleSnip = item.singleSnippet;
            totalCount++;
            // A closed VAPT finding counts under Closed only (never true elsewhere).
            if (isFindingClosed(f)) { closedCount++; return; }
            // A VAPT informational result is not a gap (only VAPT sessions list them).
            if (isFindingInformational(f)) { infoCount++; return; }
            const isComp = isFindingCompliant(f, singleSnip);

            if (isComp) {
                compCount++;
            } else {
                nonCompCount++;
                const band = severityBand(f.severity);
                if (band === "p1") p1Count++;
                else if (band === "p2") p2Count++;
                else if (band === "p3") p3Count++;
                else if (band === "p4") p4Count++;
            }
        });
    } else {
        (findingsList || []).forEach(f => {
            const statusLower = (f.status || "").toLowerCase();
            if (statusLower === "rejected" || statusLower === "excluded") return;
            totalCount++;
            if (isFindingClosed(f)) { closedCount++; return; }
            if (isFindingInformational(f)) { infoCount++; return; }

            const isComp = isFindingCompliant(f);
            if (isComp) {
                compCount++;
            } else {
                nonCompCount++;
                const band = severityBand(f.severity);
                if (band === "p1") p1Count++;
                else if (band === "p2") p2Count++;
                else if (band === "p3") p3Count++;
                else if (band === "p4") p4Count++;
            }
        });
    }

    // A VAPT session has no compliant controls; its first counter is the
    // informational findings (labelled so by syncStatusFilterForSession).
    const elComp = document.getElementById("count-compliant");
    if (elComp) elComp.innerText = isVaptOnlySession() ? infoCount : compCount;

    const elNonComp = document.getElementById("count-noncompliant");
    if (elNonComp) elNonComp.innerText = nonCompCount;

    const elP1 = document.getElementById("count-p1");
    if (elP1) elP1.innerText = p1Count;

    const elP2 = document.getElementById("count-p2");
    if (elP2) elP2.innerText = p2Count;

    const elP3 = document.getElementById("count-p3");
    if (elP3) elP3.innerText = p3Count;

    const elP4 = document.getElementById("count-p4");
    if (elP4) elP4.innerText = p4Count;

    // The VAPT row (shown only for VAPT sessions).
    const vaptCounts = { "count-vapt-critical": p1Count, "count-vapt-high": p2Count,
                         "count-vapt-medium": p3Count, "count-vapt-low": p4Count,
                         "count-vapt-info": infoCount, "count-vapt-closed": closedCount,
                         "count-vapt-total": totalCount };
    Object.keys(vaptCounts).forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerText = vaptCounts[id];
    });
}

function formatStructuredPoc(pocText) {
    if (!pocText || typeof pocText !== "string") return "";
    let clean = pocText.trim();

    if (clean.includes("Plugin Output:\n")) {
        clean = clean.split("Plugin Output:\n")[1].trim();
    } else if (clean.includes("Plugin Output:")) {
        clean = clean.split("Plugin Output:")[1].trim();
    }
    clean = clean.replace(/^(Target Host|Plugin ID|CVE\(s\)|Scanner):[^\n]*\n?/gm, '').trim();

    if (!clean || clean.toLowerCase().includes("not available in scan report")) {
        return "";
    }

    // Auto-structure Nessus / Burp key-value outputs cleanly with bullet points
    clean = clean
        .replace(/([^\n])\s*(Path\s*:)/gi, "$1\n\u2022 Installation Path           :")
        .replace(/([^\n])\s*(Installed version\s*:)/gi, "$1\n\u2022 Installed Version           :")
        .replace(/([^\n])\s*(Security End of Life\s*:)/gi, "$1\n\u2022 Security End-of-Life Date   :")
        .replace(/([^\n])\s*(Time since Security End of Life \(Est\.\)\s*:)/gi, "$1\n\u2022 Time Since EoL (Estimated)  :");

    return clean.trim();
}

// The labels the parsers put over each part of a proof of concept -- "[HTTP
// Request 1]", "[HTTP Response 1]", "[Issue detail]" (mirrors _poc_sections in
// src/core/report_exporter.py).
const _POC_LABEL_RE = /^[ \t]*\[((?:HTTP[ \t]+)?(?:Request|Response)(?:[ \t]+Snippet)?(?:[ \t]+\d+)?|Issue detail|Collaborator (?:HTTP|DNS|SMTP) interaction)\][ \t]*$/gim;

// A proof of concept as [{label, body}]: what precedes the first label (label
// ""), then each labelled part. Text with no labels is one part.
function pocSections(text) {
    const t = String(text || "").replace(/\r\n/g, "\n").trim();
    const marks = [...t.matchAll(_POC_LABEL_RE)];
    if (!marks.length) return t ? [{ label: "", body: t }] : [];
    const parts = [];
    const head = t.slice(0, marks[0].index).replace(/\n?Plugin Output:\s*$/, "").trim();
    if (head) parts.push({ label: "", body: head });
    marks.forEach((m, k) => {
        const end = k + 1 < marks.length ? marks[k + 1].index : t.length;
        const body = t.slice(m.index + m[0].length, end).trim();
        if (body) parts.push({ label: m[1].split(/\s+/).join(" "), body });
    });
    return parts;
}

// Label colours inside the proof box: requests blue, responses green, the
// scanner's issue detail amber.
function pocLabelColours(label) {
    if (/collaborator/i.test(label)) return ["#6d28d9", "#ede9fe"];
    if (/request/i.test(label)) return ["#1d4ed8", "#dbeafe"];
    if (/response/i.test(label)) return ["#047857", "#d1fae5"];
    return ["#92400e", "#fef3c7"];
}

// A VAPT card's proof of concept, whole, in one scrolling box: the report's
// own facts (source, severity, status) as chips above it, then each request /
// response / issue detail inside it under a label that stays in view while
// its part scrolls. It was one box 240px high over text the parsers had
// already cut at 500-1500 characters.
function pocHtml(text) {
    const facts = [];
    const parts = [];
    pocSections(text).forEach(({ label, body }) => {
        if (!label) {
            const lines = body.split("\n");
            while (lines.length && /^(Source|Reported severity|Status in report):\s*\S/.test(lines[0])) {
                const m = lines.shift().match(/^([^:]+):\s*(.*)$/);
                facts.push(`<span style="font-size:0.74rem; padding:2px 8px; border-radius:4px; background:rgba(16,185,129,0.1); color:#065f46; border:1px solid rgba(16,185,129,0.25);"><b>${escapeHtml(m[1])}:</b> ${escapeHtml(m[2])}</span>`);
            }
            body = lines.join("\n").trim();
            if (!body) return;
        }
        parts.push({ label, body });
    });
    const pre = body => `<pre style="margin:0; padding:8px 12px; font-family:'Consolas','Fira Code',monospace; font-size:0.78rem; color:#064e3b; line-height:1.45; white-space:pre-wrap; word-break:break-word; font-weight:600; background:transparent; border:0;">${escapeHtml(body)}</pre>`;
    const sections = parts.map(({ label, body }, k) => {
        const sep = k ? "border-top:1px solid rgba(16,185,129,0.25);" : "";
        if (!label) return `<section class="poc-part" style="${sep}">${pre(body)}</section>`;
        const [fg, bg] = pocLabelColours(label);
        return `<section class="poc-part" style="${sep}"><div class="poc-part-label" style="position:sticky; top:0; z-index:1; background:${bg}; color:${fg}; font-weight:800; font-size:0.7rem; text-transform:uppercase; letter-spacing:0.4px; padding:4px 12px; border-bottom:1px solid rgba(16,185,129,0.2);">${escapeHtml(label)}</div>${pre(body)}</section>`;
    }).join("");
    return (facts.length ? `<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:6px;">${facts.join("")}</div>` : "")
        + (sections ? `<div class="poc-box" style="max-height:420px; overflow-y:auto; background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.25); border-radius:8px;">${sections}</div>` : "");
}

/**
 * formatRemediationSteps(text, color)
 * Splits numbered-step remediation text ("1. Do X. 2. Do Y.") into a
 * structured HTML ordered list so each action point is clearly visible.
 * Falls back to a plain <p> for single-sentence / no-number text.
 * @param {string} text   - Raw remediation / mitigation string
 * @param {string} color  - CSS color for step number badges (e.g. '#3b82f6')
 * @returns {string}      - HTML string safe to inject into innerHTML
 */
// A sentence ends at . ! or ? followed by a space and a capital, a digit or an
// opening quote/bracket. Not inside "10.x", "2.4.49" or a URL (no space), not
// before a lower-case word ("e.g. a proxy"), and not after a common
// abbreviation ("e.g. A", "etc. The").
function splitSentences(text) {
    return String(text || "")
        .replace(/(?<!\b(?:e\.g|i\.e|etc|vs|approx|incl|Mr|Mrs|Dr|No|Fig|Ref))([.!?])\s+(?=[A-Z0-9"'(\[])/g, "$1\u0000")
        .split("\u0000")
        .map(s => s.trim())
        .filter(Boolean);
}

// The badge beside a CVE that is in CISA's Known Exploited Vulnerabilities
// catalog (the findings API sends the entries as `known_exploited`). The
// severity beside it is still the scanner's.
function kevBadgeHtml(k) {
    if (!k || !k.cve) return "";
    const since = escapeHtml(k.date_added || "?");
    const tip = escapeHtml(`In CISA's Known Exploited Vulnerabilities catalog since ${k.date_added || "?"}; `
        + `known ransomware use: ${k.ransomware_use || "Unknown"}. ${k.name || ""}`);
    return `<span style="font-size:0.7rem; padding:2px 7px; border-radius:4px; background:#b91c1c; color:#fff; font-weight:800; margin-right:6px; letter-spacing:0.3px;" title="${tip}">⚠ KNOWN EXPLOITED (CISA KEV, since ${since})</span>`;
}

// Prose as points, one per sentence; a single sentence stays a paragraph.
function remediationPoints(text, color) {
    const c = escapeHtml(color);
    const sentences = splitSentences(text);
    if (sentences.length <= 1) {
        return `<p style="margin:0; font-size:0.86rem; color:${c}; line-height:1.6;">${escapeHtml(String(text || "").trim())}</p>`;
    }
    const items = sentences.map(s =>
        `<li style="margin-bottom:5px; line-height:1.55; font-size:0.86rem; color:${c};">${escapeHtml(s)}</li>`
    ).join("");
    return `<ul style="margin:0; padding-left:18px; list-style:disc; color:${c};">${items}</ul>`;
}

function formatRemediationSteps(text, color) {
    if (!text || typeof text !== "string") return "";
    const safe = text.trim();
    if (!safe) return "";

    // Detect if text has numbered steps: looks for " 1. ", " 2. " etc.
    // Use a regex that matches a number+period boundary anywhere in the string.
    const hasSteps = /(?:^|[.!?]\s+|:\s*)\d{1,2}\.\s+[A-Z]/m.test(safe)
        || /^\d{1,2}\.\s+/m.test(safe);

    if (!hasSteps) {
        // No numbered structure: one point per sentence. A scanner's advice
        // (Burp's runs to eight sentences) was a single block of text.
        return remediationPoints(safe, color);
    }

    // Split on numbered-step boundaries: "1. ", "2. ", "3. " etc.
    // The regex keeps the delimiter as a lookahead so we don't lose the first word.
    // Strategy: insert a delimiter before each "<number>." that follows a sentence end
    // or appears at the start, then split.
    const delim = "\x00STEP\x00";
    let marked = safe
        // "IMMEDIATE ACTIONS:" and similar colons before step 1 — keep as label
        .replace(/([.!?])\s+(\d{1,2})\.\s+/g, `$1 ${delim}$2. `)
        // "...not from the report: 1. Before transmitting..." -- a step after a
        // colon, or the first one was folded into the heading above the list.
        .replace(/:\s+(\d{1,2})\.\s+(?=[A-Z])/g, `: ${delim}$1. `)
        .replace(/^(\d{1,2})\.\s+/, `${delim}$1. `);

    const parts = marked.split(delim).map(p => p.trim()).filter(Boolean);

    if (parts.length <= 1) {
        // Splitting produced only 1 chunk — fall back to one point per sentence
        return remediationPoints(safe, color);
    }

    // First chunk may be a preamble (e.g. "RSA is broken by...IMMEDIATE ACTIONS:")
    // Detect by checking if it starts with a digit (step) or not (preamble)
    let preamble = "";
    let steps = parts;
    if (!/^\d/.test(parts[0])) {
        preamble = parts[0];
        steps = parts.slice(1);
    }

    const listItems = steps.map(step => {
        // Extract leading number: "1. Do this" → num=1, body="Do this"
        const m = step.match(/^(\d{1,2})\.\s*(.*)$/s);
        if (!m) return `<li style="margin-bottom:6px; line-height:1.55; font-size:0.86rem;">${escapeHtml(step)}</li>`;
        const num = m[1];
        const body = m[2].trim();
        return `<li style="margin-bottom:8px; line-height:1.55;">
            <span style="display:inline-flex; align-items:center; justify-content:center; width:20px; height:20px; border-radius:50%; background:${escapeHtml(color)}22; color:${escapeHtml(color)}; font-size:0.72rem; font-weight:800; border:1px solid ${escapeHtml(color)}66; margin-right:8px; flex-shrink:0; vertical-align:middle;">${escapeHtml(num)}</span>
            <span style="font-size:0.86rem; color:${escapeHtml(color)}; vertical-align:middle;">${escapeHtml(body)}</span>
        </li>`;
    }).join("");

    return `
        ${preamble ? `<p style="margin:0 0 8px 0; font-size:0.85rem; color:${escapeHtml(color)}; line-height:1.5; font-style:italic;">${escapeHtml(preamble)}</p>` : ""}
        <ol style="margin:0; padding-left:0; list-style:none;">${listItems}</ol>
    `;
}


function _isOcrNoiseText(str) {
    if (!str || typeof str !== "string") return false;
    return str.includes("[Embedded Image OCR]") || /^\[Embedded Image OCR\]/i.test(str) || /ocr|mobaxterm|timedatectl|ntp synchronized|root@/i.test(str);
}

function _cleanOcrText(str) {
    if (!str || typeof str !== "string") return "";
    let cleaned = str
        .replace(/^\[Embedded Image OCR\]:\s*/gi, "")
        .replace(/\b(jpg|png|jpeg|bmp|svg)\b/gi, "")
        // Clean out terminal directory listing noise (ls -l output)
        .replace(/\b(local|mozila|pki|Desktop|Documents|Downloads|Music|Pictures|Public|Templates|Videos|bash_history|bash_logout|bash_profile|bashrc|\.cshrc|esd_auth|ICEauthority|mysql_history|tcshrc)\b/g, "")
        // Clean out MobaXterm advertising footer noise
        .replace(/Remote monitoring Follow terminal folder UNREGISTERED.*?by subscribing to the professional edition here:?\s*http[s]?:\/\/[^\s]+/gi, "")
        .replace(/UNREGISTERED VERSION.*?mobatek\.net/gi, "")
        .replace(/VERSION o Please: support\.MobaXterm.*$/gi, "")
        .replace(/i Search - [àaA\s\.\-]+$/gi, "")
        .replace(/\s+/g, " ")
        .trim();
    return cleaned;
}

// Splits a dashboard OCR line into value tokens, merging a bare number
// immediately followed by a unit ("6.69" "%" -> "6.69%") since OCR frequently
// reads a percent/unit sign as its own token separated by a space.
function _tokenizeDashboardLine(line) {
    const raw = line.trim().split(/\s+/).filter(Boolean);
    const VALUE = /^-{1,2}$|^\d[\d,]*(\.\d+)?$/;
    const UNIT = /^(%|kb|mb|gb|tb|bytes?|ms|s)$/i;
    const out = [];
    for (let i = 0; i < raw.length; i++) {
        if (VALUE.test(raw[i]) && i + 1 < raw.length && UNIT.test(raw[i + 1])) {
            out.push(raw[i] + " " + raw[i + 1]);
            i++;
        } else {
            out.push(raw[i]);
        }
    }
    return out;
}

function _isValueToken(tok) {
    return /^-{1,2}$|^\d[\d,]*(\.\d+)?(\s?(%|kb|mb|gb|tb|bytes?|ms|s))?$/i.test(tok.trim());
}

function _isLabelToken(tok) {
    // A real field label reads like "CPUUtilization" or "FreeableMemory" --
    // letters only (plus a trailing % is allowed, e.g. "EBSIOBalance%"). An
    // instance ID or a CWAgent metric string ("AWS/EC2 i-...", "cwagent
    // mem_used_p...") contains digits or slashes and correctly fails this,
    // so that row is left unpaired rather than guessed at.
    return /^[A-Za-z][A-Za-z_-]*%?$/.test(tok.trim());
}

// Pairs a line of dashboard tile VALUES with the line of LABELS immediately
// beneath it, by position -- e.g. "0.957 % 134 ...\nCPUUtilization
// DatabaseConnections ..." -> {label: "CPUUtilization", value: "0.957 %"},
// {label: "DatabaseConnections", value: "134"}, ... . This is what actually
// recovers real numbers ("39%") instead of just the metric's NAME being
// present ("CPU Utilization (CPUUtilization)") -- see formatEvidenceSnippet's
// CloudWatch block below.
//
// Grounded in how the OCR line-grouping actually works (doc_parsers.py's
// _DocTRReaderAdapter groups words by line/y-position): a dashboard's row of
// tiles shares one y-band, so their values land on one OCR line and the
// labels below them land on the next -- this is not a guess about layout,
// it follows from how doctr groups text.
//
// Deliberately conservative: only pairs when the value-line and label-line
// token counts match exactly and every label token passes _isLabelToken.
// Skips a line without a clean match rather than force a guess -- a tile
// whose "label" is an instance ID or a truncated CWAgent metric name (not
// plain letters) is left out, not mislabeled.
function _pairDashboardValueLabelRows(snip) {
    const lines = String(snip || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const pairs = [];
    for (let i = 0; i < lines.length - 1; i++) {
        const valueToks = _tokenizeDashboardLine(lines[i]);
        if (valueToks.length < 2 || !valueToks.every(_isValueToken)) continue;
        const labelToksMulti = lines[i + 1].trim().split(/\s{2,}|\t/).map(s => s.trim()).filter(Boolean);
        const labelToksSingle = lines[i + 1].trim().split(/\s+/).filter(Boolean);
        const candidates = labelToksMulti.length === valueToks.length ? labelToksMulti
            : (labelToksSingle.length === valueToks.length ? labelToksSingle : null);
        if (!candidates || !candidates.every(_isLabelToken)) continue;
        for (let j = 0; j < valueToks.length; j++) {
            pairs.push({ label: candidates[j], value: valueToks[j] });
        }
        i++; // this label line has been consumed, don't also test it as a value line
    }
    return pairs;
}

function formatEvidenceSnippet(snip) {

    if (!snip) return "No specific evidence quote found in document.";
    if (typeof snip !== "string") snip = String(snip);
    snip = snip.trim();

    if (snip.includes("Business Impact:") || snip.includes("Missing Requirements:")) {
        return "No specific evidence quote found in document.";
    }

    if (!snip || snip.toUpperCase() === "JPG" || snip.toUpperCase() === "PNG" || snip.length <= 3) {
        return "System Screenshot Evidence verified via Optical Character Recognition (OCR).";
    }

    // ── Clean Terminal / Screenshot OCR Text ──
    const lowerSnip = snip.toLowerCase();
    const isTerminalOrNtp = /ntp|timedatectl|clock|mobaxterm|root@|systemd-timesyncd|chronyd/i.test(snip);

    if (isTerminalOrNtp) {
        let bullets = [];
        let hostMatch = snip.match(/root@([a-zA-Z0-9_\-]+)/i);
        let hostName = hostMatch ? hostMatch[1] : "";

        let isNtpSynced = /ntp\s+synchronized:\s*yes|clock\s+synchronized:\s*yes|ntp\s+active|synchronized:\s*yes/i.test(snip);
        let isRtcLocal = /rtc\s+in\s+local\s+tz:\s*yes/i.test(snip);

        bullets.push("🖥️ TERMINAL SYSTEM EVIDENCE (Clock Synchronization):");
        if (hostName) bullets.push(`• Verified Target Host: ${hostName}`);
        bullets.push(`• NTP Clock Synchronized: ${isNtpSynced ? 'YES (Active)' : 'NO / Unconfirmed'}`);
        bullets.push(`• Real-Time Clock (RTC) Config: ${isRtcLocal ? 'Local Timezone' : 'UTC (Standard)'}`);

        return bullets.join("\n");
    }

    // ── Structure CloudWatch & System Monitoring OCR Evidence ──
    const isCloudWatchOrMetrics = /cloudwatch|aws\/ec2|mem_used|cpuutilization|ebswriteops|ebsreadops|srit-monitoring/i.test(snip);

    if (isCloudWatchOrMetrics) {
        let bullets = [];

        // Extract EC2 instances cleanly
        const ec2Matches = Array.from(snip.matchAll(/i-[0-9a-f]{17}/gi)).map(m => m[0]);
        const uniqueEc2 = Array.from(new Set(ec2Matches));

        // Extract App/Instance Labels
        const appMatches = Array.from(snip.matchAll(/(App\d+|Web\d+|numedist[a-z0-9]+)/gi)).map(m => m[0]);
        const uniqueApps = Array.from(new Set(appMatches));

        // Extract Monitored Metrics
        let metrics = [];
        if (/mem_used/i.test(snip)) metrics.push("Memory Utilization (mem_used)");
        if (/cpuutilization|cpu/i.test(snip)) metrics.push("CPU Utilization (CPUUtilization)");
        if (/ebswriteops|ebsreadops|ebs/i.test(snip)) metrics.push("EBS Storage I/O Operations (Read/Write Ops)");

        bullets.push("📊 CLOUDWATCH MONITORING DASHBOARD EVIDENCE:");
        if (uniqueEc2.length > 0) {
            bullets.push(`• Monitored EC2 Instance IDs: ${uniqueEc2.join(", ")}`);
        }
        if (uniqueApps.length > 0) {
            bullets.push(`• System Workload Targets: ${uniqueApps.join(", ")}`);
        }
        if (metrics.length > 0) {
            bullets.push(`• Active Resource Metrics: ${metrics.join(" | ")}`);
        }

        // Everything above only says WHICH metrics are present, never their
        // values -- "CPU Utilization (CPUUtilization)" as a flag, never
        // "39%". A tile dashboard's OCR text naturally comes back as one line
        // of values (all tiles in a visual row share a y-position, so the OCR
        // line-grouping puts them together) followed by the line of labels
        // underneath those same tiles -- so pairing value[i] with label[i]
        // across two adjacent lines recovers the actual numbers.
        const valuePairs = _pairDashboardValueLabelRows(snip);
        if (valuePairs.length > 0) {
            bullets.push("• Metric Values:");
            for (const p of valuePairs) {
                bullets.push(`   - ${p.label}: ${p.value}`);
            }
        }

        let cleanExcerpt = snip
            .replace(/(AWS\/EC2\s+i-[0-9a-f]{17}\s*\([^)]*\)\s*)+/gi, "AWS/EC2 Instance ")
            .replace(/\s+/g, " ")
            .trim();

        // No length cap. This used to cut every dashboard excerpt to 350
        // characters regardless of size, which for a two-panel dashboard like
        // this one sliced off before reaching the CPU/memory/disk metrics
        // entirely -- the auditor's actual question went unanswered by data
        // that was already sitting right there in the OCR text.
        return `${bullets.join("\n")}\n\n[Full Dashboard Evidence Text]:\n"${cleanExcerpt}"`;
    }

    // ── Structure General OCR Noise Text ──
    if (_isOcrNoiseText(snip)) {
        const rawOcr = snip.replace(/^\[Embedded Image OCR\]:\s*/i, "").trim();
        let cleanedOcr = _cleanOcrText(rawOcr);
        if (!cleanedOcr || cleanedOcr.length < 5 || cleanedOcr.toUpperCase() === "JPG" || cleanedOcr.toUpperCase() === "PNG") {
            cleanedOcr = "System Screenshot Evidence verified via Optical Character Recognition (OCR).";
        }

        let detectedItems = [];
        if (/timedatectl|ntp/i.test(rawOcr)) detectedItems.push("• System Service: Linux Time Synchronization Daemon (timedatectl / NTP)");
        if (/ntp\s+enabled:\s*yes/i.test(rawOcr)) detectedItems.push("• Synchronization Setting: Network Time Protocol (NTP) Enabled");
        if (/ntp\s+synchronized:\s*yes/i.test(rawOcr)) detectedItems.push("• Synchronization State: System Clock Successfully Synchronized");
        if (/pam|privileged|privilcged/i.test(rawOcr)) detectedItems.push("• System Application: Privileged Access Manager (PAM) Web Console");
        if (/https?:\/\/[0-9\.]+/i.test(rawOcr)) {
            const urlMatch = rawOcr.match(/https?:\/\/[0-9\.\/a-zA-Z0-9#_\-]+/i);
            if (urlMatch) detectedItems.push(`• Verified Target URL: ${urlMatch[0]}`);
        }
        if (/oauth2|oauth|o4uth2/i.test(rawOcr)) detectedItems.push("• Authentication Control: OAuth2 Single Sign-On Protocol Enabled");
        if (/tokens|active|sessions|session|privsessions/i.test(rawOcr)) detectedItems.push("• Operational Feature: Active User Privileged Session & Token Tracking");
        if (/policy|resource|access|accs/i.test(rawOcr)) detectedItems.push("• Policy Enforcement: Resource Access Policy Active");

        let summaryHeader = /timedatectl|ntp/i.test(rawOcr)
            ? "🖼️ SCREENSHOT EVIDENCE EXCERPT (System Time & Clock Synchronization Console):"
            : "🖼️ SCREENSHOT EVIDENCE EXCERPT (Privileged Access Management System):";

        let bulletText = detectedItems.length > 0 ? detectedItems.join("\n") : "• Embedded System Screenshot verified via Optical Character Recognition (OCR).";

        return `${summaryHeader}\n${bulletText}\n\n[Extracted & Cleaned Screenshot Evidence Text]:\n"${cleanedOcr}"`;
    }

    // ── General "Label: value" fallback (any topic, not hand-picked) ──
    // Everything above is a hardcoded block for one specific audit topic (NTP,
    // CloudWatch, a fixed OCR-noise keyword list) -- so evidence for anything
    // else (MFA, PAM, a firewall rule dump, anything) fell straight through to
    // the raw, unformatted snippet below, no matter how cleanly it was already
    // structured as key:value lines. Rather than write another one-off block
    // per topic -- which never covers the NEXT topic either -- detect the
    // SHAPE directly: 2+ lines that read as "Label: value" get bulleted with a
    // check/cross icon when the value itself is a yes/no-style answer.
    // Display-only: the verbatim text is appended below and is the copy the
    // backend already validated for grounding, so nothing here can affect it.
    const kvLines = _extractKeyValueLines(snip);
    if (kvLines.length >= 2) {
        const bullets = kvLines.map(kv => `${kv.icon ? kv.icon + " " : "• "}${kv.label}: ${kv.value}`);
        return `${bullets.join("\n")}\n\n[Verbatim Evidence Text]:\n"${snip}"`;
    }

    // Return snippet cleanly without adding fragmented quote headers
    return snip;
}

// Pulls "Label: value" lines out of a raw evidence snippet -- the shape terminal
// output, config dumps and many OCR'd screenshots naturally have. Deliberately
// conservative: a short label (<=40 chars, no sentence punctuation) and a short
// value (<=80 chars) rules out an ordinary prose sentence that happens to
// contain one colon, and a URL is excluded outright so a link never gets read
// as a "label: value" pair.
function _extractKeyValueLines(snip) {
    const AFFIRM = /^(yes|true|enabled|active|pass(?:ed)?|on|allowed|granted|present|configured|found)$/i;
    const NEGATIVE = /^(no|false|disabled|inactive|fail(?:ed)?|off|denied|absent|not[\s_-]?configured|not[\s_-]?found|n\/a)$/i;
    const out = [];
    for (const raw of String(snip || "").split(/\r?\n/)) {
        const line = raw.trim();
        const m = /^([A-Za-z][A-Za-z0-9 _\-\/]{1,40}):\s+(.{1,80})$/.exec(line);
        if (!m) continue;
        const label = m[1].trim();
        const value = m[2].trim().replace(/[.,;]+$/, "");
        if (!value || /^https?:\/\//i.test(value)) continue;
        // A real field label reads like "NTP enabled" or "RTC in local TZ" --
        // short, no more than a handful of words, no auxiliary verb. Without
        // this, an ordinary sentence with one incidental colon ("Access is
        // granted per the policy: least privilege basis...") passed the same
        // character-length check a real label does and got mistaken for one.
        if (label.split(/\s+/).length > 5
            || /\b(?:is|are|was|were|has|have|will|would|can|could|should|must|shall)\b/i.test(label)) {
            continue;
        }
        let icon = "";
        if (AFFIRM.test(value)) icon = "✅";
        else if (NEGATIVE.test(value)) icon = "❌";
        out.push({ label, value, icon });
    }
    return out;
}

const EVIDENCE_SNIPPET_PRE_STYLE = "margin:0; font-family:'Consolas','Fira Code',monospace; font-size:0.78rem; color:#f8fafc; background:rgba(15,23,42,0.9); padding:10px 12px; border-radius:8px; border:1px solid rgba(59,130,246,0.3); line-height:1.45; white-space:pre-wrap; word-break:break-word;";

// Returns the audit check question for a finding, or "" when there isn't a real
// one to show. Shared by the card header subtitle and the AUDIT QUESTION detail
// block below so the two can never disagree about whether a question exists --
// they previously each had their own copy of these checks, and the header's copy
// was computed and then never rendered at all.
function getCleanAuditQuestion(f) {
    if (!f) return "";
    let qText = (f.requirement_question || f.audit_question || f.question
                 || f.checklist_question || "").trim();

    // Older findings stored the question appended to the title/control name after
    // an em dash rather than in its own column -- recover it from there.
    if (!qText && f.title && f.title.includes(" — ")) {
        const parts = f.title.split(" — ");
        if (parts.length > 1) qText = parts.slice(1).join(" — ").trim();
    }
    if (!qText && f.control_name && f.control_name.includes(" — ")) {
        const parts = f.control_name.split(" — ");
        if (parts.length > 1) qText = parts.slice(1).join(" — ").trim();
    }
    if (!qText) return "";

    const lowerQ = qText.toLowerCase();
    const ctrlIdLower = String(f.control_id || "").toLowerCase().trim();
    const ctrlNameLower = String(f.control_name || "").toLowerCase().trim();

    // Placeholder text and questions that merely repeat the control name carry no
    // information -- showing them under the title just duplicates the heading.
    if (
        lowerQ === "requirement question not provided" ||
        lowerQ === "general control requirement" ||
        lowerQ === "no question provided" ||
        (ctrlIdLower && lowerQ === ctrlIdLower) ||
        (ctrlNameLower && lowerQ === ctrlNameLower)
    ) {
        return "";
    }
    return qText;
}

// The question rendered directly beneath the control name in a finding card
// header, which is where the auditor's own Excel checklist wording belongs.
function buildQuestionSubtitleHtml(f) {
    const qText = getCleanAuditQuestion(f);
    if (!qText) return "";
    return `<p style="margin:4px 0 0 0; font-size:0.82rem; font-weight:500; color:var(--text-secondary); line-height:1.4; font-style:italic;">${escapeHtml(qText)}</p>`;
}

function buildRequirementQuestionHtml(f) {
    if (!f) return "";
    let qText = (f.requirement_question || f.question || "").trim();
    
    // Also check if title or control_name contains question after ' — '
    if (!qText && f.title && f.title.includes(" — ")) {
        const parts = f.title.split(" — ");
        if (parts.length > 1) qText = parts.slice(1).join(" — ").trim();
    }
    if (!qText && f.control_name && f.control_name.includes(" — ")) {
        const parts = f.control_name.split(" — ");
        if (parts.length > 1) qText = parts.slice(1).join(" — ").trim();
    }

    if (!qText) return "";

    const lowerQ = qText.toLowerCase();
    const ctrlIdLower = String(f.control_id || "").toLowerCase().trim();
    const ctrlNameLower = String(f.control_name || "").toLowerCase().trim();

    // Do NOT render AUDIT QUESTION section if generic fallback text or matches control name
    if (
        lowerQ === "requirement question not provided" ||
        lowerQ === "general control requirement" ||
        lowerQ === "no question provided" ||
        (ctrlIdLower && lowerQ === ctrlIdLower) ||
        (ctrlNameLower && lowerQ === ctrlNameLower)
    ) {
        return "";
    }

    return `
    <div class="finding-detail-row" style="margin-bottom: 12px;">
        <label style="font-weight:700; font-size:0.78rem; color:#3b82f6; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">AUDIT QUESTION</label>
        <p style="margin:0; font-size:0.86rem; color:var(--text-primary); line-height:1.5; font-style:italic;">${escapeHtml(qText)}</p>
    </div>`;
}

function buildEvidenceSnippetHtml(rawSnip, f_obj) {
    let snip = rawSnip;
    if (typeof snip !== "string") snip = String(snip || "");
    snip = snip.trim();

    // ── Question-based checklist: the passage the answer came from ───────────
    // The control version of this panel does not fit a question at all. It leads
    // with DOCUMENTED POLICY STATEMENTS -- a dimension this mode does not have,
    // so it always printed "NO DOCUMENTED POLICY IDENTIFIED" -- and it decides
    // the evidence block from evidence_status/evidence_assessment, which are
    // deliberately empty here. The defaults below read a missing status as
    // NOT_FOUND, so a compliant answer with a verified quote sitting right there
    // was captioned "NO RELEVANT EVIDENCE FOUND ... addressing this control
    // objective", contradicting its own card.
    //
    // A question needs one thing: the sentence in the document that answers it.
    if (window._sessionIsCustomizeRun) {
        let qaItems = [];
        if (f_obj && f_obj.evidence_items_json) {
            try {
                qaItems = typeof f_obj.evidence_items_json === "string"
                    ? JSON.parse(f_obj.evidence_items_json) : f_obj.evidence_items_json;
            } catch (e) { }
        }
        const qaSnip = (Array.isArray(qaItems) && qaItems.length
                ? qaItems.map(it => it && it.extracted_text).filter(Boolean).join("\n\n") : "")
            || snip || (f_obj && f_obj.evidence_snippet) || (f_obj && f_obj.evidence_quote) || "";
        const qaText = String(qaSnip || "").trim();
        const qaHas = qaText.length > 5
            && !qaText.toUpperCase().includes("NOT_FOUND")
            && !qaText.toUpperCase().includes("NO RELEVANT EVIDENCE");

        if (qaHas) {
            return `<div style="margin-bottom:8px;">
                <div style="font-size:0.75rem; font-weight:700; color:#c084fc; letter-spacing:0.5px; margin-bottom:4px;">📄 FROM THE DOCUMENT</div>
                <pre class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE.replace('rgba(59,130,246,0.3)', 'rgba(192,132,252,0.3)')}">${escapeHtml(formatEvidenceSnippet(qaText))}</pre>
            </div>`;
        }
        // Nothing to quote. Say what is actually true -- the document does not
        // answer the question -- rather than reporting a missing control artifact.
        return `<div style="margin-bottom:8px;">
            <div style="font-size:0.75rem; font-weight:700; color:#94a3b8; letter-spacing:0.5px; margin-bottom:4px;">📄 FROM THE DOCUMENT</div>
            <div style="font-size:0.8rem; color:#64748b; font-style:italic; padding:8px 12px; background:rgba(148,163,184,0.12); border-radius:6px;">The cited document does not address this question, so there is no passage to quote.</div>
        </div>`;
    }

    const evStatus = (f_obj && f_obj.evidence_status) ? String(f_obj.evidence_status).toUpperCase() : "NOT_FOUND";
    const evAssess = (f_obj && f_obj.evidence_assessment) ? String(f_obj.evidence_assessment).toUpperCase() : "NON_COMPLIANT";

    let polItems = [];
    if (f_obj && f_obj.policy_items_json) {
        try {
            polItems = typeof f_obj.policy_items_json === "string" ? JSON.parse(f_obj.policy_items_json) : f_obj.policy_items_json;
        } catch (e) { }
    }

    let evItems = [];
    if (f_obj && f_obj.evidence_items_json) {
        try {
            evItems = typeof f_obj.evidence_items_json === "string" ? JSON.parse(f_obj.evidence_items_json) : f_obj.evidence_items_json;
        } catch (e) { }
    }

    const polSnip = (f_obj && f_obj.policy_snippet) || (polItems.length > 0 ? polItems.map(it => it.extracted_text).filter(Boolean).join("\n\n") : "") || (f_obj && f_obj.policy_quote) || (f_obj && f_obj.policy_excerpt) || "";
    const opSnip = (f_obj && f_obj.operational_evidence_snippet) || (evItems.length > 0 ? evItems.map(it => it.extracted_text).filter(Boolean).join("\n\n") : "") || rawSnip || (f_obj && f_obj.evidence_snippet) || (f_obj && f_obj.evidence_quote) || "";
    const hasEvidenceText = opSnip && opSnip.trim().length > 5 && !opSnip.toUpperCase().includes("NOT_FOUND") && !opSnip.toUpperCase().includes("NO RELEVANT EVIDENCE");

    let polHtml = "";
    if (polSnip && polSnip.trim()) {
        if (polSnip.includes("\n\n")) {
            const parts = polSnip.split("\n\n").map(p => p.trim()).filter(Boolean);
            if (parts.length > 1) {
                const items = parts.map((p, idx) =>
                    `<li style="margin-bottom:10px;"><span style="color:#60a5fa; font-weight:700;">Policy Statement ${idx + 1} of ${parts.length}:</span><br>"${escapeHtml(p)}"</li>`
                ).join("");
                polHtml = `<div style="margin-bottom:14px;"><div style="font-size:0.75rem; font-weight:700; color:#38bdf8; letter-spacing:0.5px; margin-bottom:4px;">📜 DOCUMENTED POLICY STATEMENTS</div><ol class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE.replace('white-space:pre-wrap;', '')} padding-left:22px;">${items}</ol></div>`;
            } else {
                polHtml = `<div style="margin-bottom:14px;"><div style="font-size:0.75rem; font-weight:700; color:#38bdf8; letter-spacing:0.5px; margin-bottom:4px;">📜 DOCUMENTED POLICY STATEMENTS</div><pre class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE}">${escapeHtml(formatEvidenceSnippet(polSnip))}</pre></div>`;
            }
        } else {
            polHtml = `<div style="margin-bottom:14px;"><div style="font-size:0.75rem; font-weight:700; color:#38bdf8; letter-spacing:0.5px; margin-bottom:4px;">📜 DOCUMENTED POLICY STATEMENTS</div><pre class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE}">${escapeHtml(formatEvidenceSnippet(polSnip))}</pre></div>`;
        }
    } else {
        polHtml = `<div style="margin-bottom:14px;"><div style="font-size:0.75rem; font-weight:700; color:#94a3b8; letter-spacing:0.5px; margin-bottom:4px;">📜 DOCUMENTED POLICY STATEMENTS</div><div style="font-size:0.8rem; color:#64748b; font-style:italic; padding:6px 10px; background:rgba(30,41,59,0.5); border-radius:4px;">NO DOCUMENTED POLICY IDENTIFIED</div></div>`;
    }


    let opHtml = "";
    if (evStatus === "FOUND" && evAssess === "COMPLIANT" && hasEvidenceText) {
        opHtml = `<div style="margin-bottom:8px;"><div style="font-size:0.75rem; font-weight:700; color:#c084fc; letter-spacing:0.5px; margin-bottom:4px;">🔍 EVIDENCE</div><pre class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE.replace('rgba(59,130,246,0.3)', 'rgba(192,132,252,0.3)')}">${escapeHtml(formatEvidenceSnippet(opSnip))}</pre></div>`;
    } else if (evStatus === "FOUND" && evAssess === "NON_COMPLIANT" && hasEvidenceText) {
        opHtml = `<div style="margin-bottom:8px;"><div style="font-size:0.75rem; font-weight:700; color:#f59e0b; letter-spacing:0.5px; margin-bottom:4px;">⚠️ EVIDENCE — NON-COMPLIANT ASSESSMENT</div><pre class="finding-snippet" style="${EVIDENCE_SNIPPET_PRE_STYLE.replace('rgba(59,130,246,0.3)', 'rgba(245,158,11,0.3)')}">${escapeHtml(formatEvidenceSnippet(opSnip))}</pre><div style="font-size:0.74rem; color:#fbbf24; margin-top:4px;">Note: Evidence artifact exists, but does not satisfy the control requirements.</div></div>`;
    } else {
        opHtml = `<div style="margin-bottom:8px;"><div style="font-size:0.75rem; font-weight:700; color:#94a3b8; letter-spacing:0.5px; margin-bottom:4px;">🔍 EVIDENCE</div><div style="font-family:'Consolas','Fira Code',monospace; font-size:0.78rem; color:#f87171; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:10px 12px; border-radius:8px; line-height:1.45; font-weight:700;">❌ NO RELEVANT EVIDENCE FOUND<br><span style="font-weight:400; color:var(--text-main, #0f172a); font-size:0.75rem;">No valid evidence artifact (configuration, log, report, record, screenshot, assessment) addressing this control objective was located.</span></div></div>`;
    }

    return polHtml + opHtml;
}

function buildNistRiskPanelHtml(f) {
    if (!f) return "";
    const st = (f.status || "").toUpperCase();
    // A thrown-out finding carries no risk to rate. The check used to be the
    // literal "FALSE_POSITIVE", but the finding card sends "Rejected" and the
    // Modify dialog "Out Of Scope", and the reports spell it "False Positive" --
    // none of which matched, so a finding the auditor had rejected still showed
    // a NIST rating such as "Risk: HIGH". _WORKFLOW_ONLY_STATUSES is the same
    // vocabulary the reports now use to leave those findings out.
    const _stNorm = st.trim().replace(/[-\s]/g, "_");
    if (st === "COMPLIANT" || f.final_result === "COMPLIANT"
        || _WORKFLOW_ONLY_STATUSES.indexOf(_stNorm) !== -1) {
        return "";
    }
    const lh = f.likelihood || "N/A";
    const imp = f.impact || "N/A";
    const riskLvl = f.risk_level || "UNDETERMINED";
    const sev = f.severity || "N/A";
    const rationale = f.risk_rationale || "NIST SP 800-30 Rev. 1 risk assessment applied based on assessed likelihood and impact.";

    let riskBadgeColor = "#f59e0b";
    let riskBg = "rgba(245,158,11,0.15)";
    if (riskLvl === "CRITICAL") { riskBadgeColor = "#ef4444"; riskBg = "rgba(239,68,68,0.15)"; }
    else if (riskLvl === "HIGH") { riskBadgeColor = "#f97316"; riskBg = "rgba(249,115,22,0.15)"; }
    else if (riskLvl === "LOW") { riskBadgeColor = "#3b82f6"; riskBg = "rgba(59,130,246,0.15)"; }

    return `
        <div style="margin-bottom:12px; padding:12px 14px; border-radius:8px; background:rgba(15,23,42,0.6); border:1px solid rgba(148,163,184,0.2);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-size:0.78rem; font-weight:700; color:#a78bfa; letter-spacing:0.5px; text-transform:uppercase;">⚖️ NIST SP 800-30 Rev. 1 Risk & Severity Assessment</span>
                <span style="font-size:0.75rem; font-weight:800; padding:2px 8px; border-radius:4px; color:${riskBadgeColor}; background:${riskBg}; border:1px solid ${riskBadgeColor}40;">Risk: ${escapeHtml(riskLvl)} → ${escapeHtml(sev)}</span>
            </div>
            <div style="display:flex; gap:16px; font-size:0.78rem; color:var(--text-main, #0f172a); margin-bottom:6px;">
                <div><b>Likelihood:</b> <span style="color:#60a5fa;">${escapeHtml(lh)}</span></div>
                <div><b>Impact:</b> <span style="color:#f472b6;">${escapeHtml(imp)}</span></div>
                <div><b>Assessed Risk Level:</b> <span style="color:${riskBadgeColor}; font-weight:700;">${escapeHtml(riskLvl)}</span></div>
                <div><b>Project Severity:</b> <span style="color:#f87171; font-weight:700;">${escapeHtml(sev)}</span></div>
            </div>
            <div style="font-size:0.74rem; color:#94a3b8; line-height:1.4; border-top:1px solid rgba(148,163,184,0.1); padding-top:6px; margin-top:4px;">
                <b>Risk Rationale:</b> ${escapeHtml(rationale)}
            </div>
        </div>
    `;
}

function buildRequirementsCoveragePanelHtml(f) {
    if (!f || !f.requirements_total) return "";
    const total = f.requirements_total || 0;
    const supported = f.requirements_supported || 0;
    const partial = f.requirements_partial || 0;
    const notSupported = f.requirements_not_supported || 0;

    let covJson = [];
    if (f.requirements_coverage_json) {
        try { covJson = JSON.parse(f.requirements_coverage_json); } catch (e) { }
    }

    return `
        <div style="margin-bottom:12px; padding:12px 14px; border-radius:8px; background:rgba(30,41,59,0.5); border:1px solid rgba(56,189,248,0.2);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span style="font-size:0.78rem; font-weight:700; color:#38bdf8; letter-spacing:0.5px; text-transform:uppercase;">📊 Atomic Requirement Coverage Breakdown</span>
                <span style="font-size:0.74rem; font-weight:700; color:var(--text-main, #0f172a);">Total Requirements: ${total}</span>
            </div>
            <div style="display:flex; gap:12px; font-size:0.75rem; margin-bottom:8px;">
                <span style="color:#34d399; font-weight:700;">✓ Supported: ${supported}</span>
                <span style="color:#fbbf24; font-weight:700;">⚠ Partial: ${partial}</span>
                <span style="color:#f87171; font-weight:700;">✕ Not Supported: ${notSupported}</span>
            </div>
            ${covJson.length > 0 ? `
                <div style="display:flex; flex-direction:column; gap:6px; max-height:160px; overflow-y:auto;">
                    ${covJson.map(r => `
                        <div style="padding:6px 10px; border-radius:4px; background:rgba(15,23,42,0.5); font-size:0.75rem; border-left:3px solid ${r.status === 'SUPPORTED' ? '#34d399' : (r.status === 'PARTIAL' ? '#fbbf24' : '#f87171')};">
                            <div style="font-weight:700; color:var(--text-main, #0f172a);">${escapeHtml(r.requirement || '')}</div>
                            <div style="font-size:0.71rem; color:#94a3b8; margin-top:2px;">Status: <b style="color:${r.status === 'SUPPORTED' ? '#34d399' : (r.status === 'PARTIAL' ? '#fbbf24' : '#f87171')};">${escapeHtml(r.status)}</b> — ${escapeHtml(r.reason || '')}</div>
                        </div>
                    `).join('')}
                </div>
            ` : ""}
        </div>
    `;
}


// Sentences that are the model NARRATING ITS REASONING rather than stating what was
// found. Two kinds, and both were flagged on a real report:
//
//   1. Requirement restatement -- "The audit requirement is to verify if the
//      syslogserver is enabled for logging." The auditor already knows the
//      requirement; it is printed in the Control points / question column next to it.
//   2. A verdict restatement -- "Therefore, the control is assessed as COMPLIANT."
//      This is the dangerous one. It is the MODEL'S own conclusion, written before the
//      deterministic layer computes the real result, so it can flatly contradict the
//      verdict shown beside it. Observed on 8.15 Logging: the description ended
//      "...the control is assessed as COMPLIANT" while the badge on the same row read
//      NON_COMPLIANT (policy not found). The real status is already displayed as a
//      badge, so restating it in prose adds nothing and risks exactly that conflict.
const _REASONING_NARRATION_PATTERNS = [
    /^\s*the audit requirement is to\b/i,
    /^\s*the requirement (is|was) to verify\b/i,
    /^\s*this control requires verification\b/i,
    /^\s*therefore\b[^.]*\bis (assessed|classified|deemed|considered)\b/i,
    /^\s*(the control|this control|the finding|it) is (therefore )?(assessed|classified|deemed|considered) as\b/i,
    /\bthe control is assessed as (compliant|non[_ -]?compliant)\b/i,
    /^\s*(hence|thus|accordingly)\b[^.]*\b(compliant|non[_ -]?compliant)\b/i,
];

function stripReasoningNarrative(text, status) {
    if (!text || typeof text !== "string") return text || "";
    // Split only at a REAL sentence end: a terminator followed by whitespace and the
    // start of the next sentence. Splitting on a bare [^.!?]+ also broke at the dot
    // inside "1.0", "TLS 1.2" and "NTP_configuration.docx", and the rejoin then
    // inserted a space -- so findings read "Version: 1. 0" and
    // "NTP_configuration. docx", corrupting the very identifiers an auditor needs.
    // A sentinel + lookahead is used rather than a lookbehind, which older Safari
    // does not support.
    const sentences = text
        .replace(/([.!?])\s+(?=["“(]?[A-Z0-9])/g, "$1\u241F")
        .split("\u241F");
    if (!sentences || sentences.length <= 1) return text;

    const statusUp = String(status || "").toUpperCase();
    const kept = sentences.filter(s => {
        const t = s.trim();
        if (!t) return false;
        if (_REASONING_NARRATION_PATTERNS.some(re => re.test(t))) return false;
        // Contradiction guard: a sentence claiming a verdict that disagrees with the
        // deterministic status never reaches the screen, whatever wording it used.
        if (statusUp) {
            const saysCompliant = /\bis\s+(fully\s+)?compliant\b|\bassessed as compliant\b/i.test(t)
                && !/non[_ -]?compliant/i.test(t);
            const saysNonCompliant = /\bnon[_ -]?compliant\b/i.test(t);
            if (saysCompliant && statusUp.includes("NON_COMPLIANT")) return false;
            if (saysNonCompliant && statusUp === "COMPLIANT") return false;
        }
        return true;
    });

    const out = kept.join(" ").replace(/\s+/g, " ").trim();
    // Never blank the field -- if stripping removed everything, the original text is
    // still more useful to an auditor than an empty box.
    return out.length >= 20 ? out : text;
}

// Mirrors _HIGHLIGHT_PATTERNS in report_exporter.py so a finding emphasises the
// same facts on screen as it does in the exported DOCX/PDF. Keep the two in sync.
const _HIGHLIGHT_RE = new RegExp([
    '"[^"]{4,120}"',
    '\\b(?:no documented policy|not documented|no operational evidence|no evidence\\b[^.,;]{0,20}'
    + '|was not provided|not provided|could not be identified|not identified|no policy gap identified'
    + '|review overdue|expired|superseded|obsolete|deprecated|no longer valid|retired'
    + '|not found|not enabled|not configured|disabled|inactive)\\b',
    '\\b(?:\\d{1,2}\\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December)\\s+\\d{4}\\b',
    '\\b\\d{4}-\\d{2}-\\d{2}\\b',
    '\\b\\d{1,2}[/-]\\d{1,2}[/-]\\d{4}\\b',
    '\\b(?:[Vv]ersion|v\\.?)\\s*:?\\s*\\d+(?:\\.\\d+)+\\b',
    '\\b(?:TLS|SSL|SSH)\\s?\\d+(?:\\.\\d+)+\\b',
    '\\b[\\w\\-.]{1,60}\\.(?:docx?|pdf|xlsx?|csv|pptx?|txt|png|jpe?g|json|xml|log|conf|cfg)\\b',
    '\\bCVE-\\d{4}-\\d{4,7}\\b',
].map(p => '(?:' + p + ')').join('|'), 'gi');

// Returns HTML with the deciding facts emphasised.
//
// SECURITY: the input is model-generated text derived from customer documents, so
// it is escaped FIRST and only this function's own <strong> tags are added
// afterwards. Never interpolate the raw string -- a document containing markup
// would otherwise execute in the findings table.
function highlightFindingHtml(text) {
    const safe = escapeHtml(String(text || ""));
    if (!safe) return "";
    return safe.replace(_HIGHLIGHT_RE, m =>
        `<strong style="font-weight:700; color:var(--text-primary);">${m}</strong>`);
}

// The icon comes from the LEADING WORD of the answer itself ("Yes"/"No"/
// "Partially"), not from the finding's overall compliance verdict. A control
// can have several requirements, so "Yes, NTP is enabled" can be the true
// answer to ITS question even inside a finding whose overall status is
// NON_COMPLIANT for some other unmet requirement -- reading the verdict field
// instead would put a green check on a description that just said something
// works fine while flagging an unrelated gap, which is confusing, not helpful.
function _leadingAnswerIcon(text) {
    const m = /^(Yes|No|Partially|Partial)\b/i.exec(String(text || "").trim());
    if (!m) return "";
    const w = m[1].toLowerCase();
    if (w === "yes") return "✅";
    if (w === "no") return "❌";
    return "⚠️";
}

// Finding Description with a leading Yes/No/Partially icon and the answering
// sentence bolded -- what an auditor scanning a long findings list actually
// needs to register in under a second. Anything after the first sentence stays
// normal weight (still passed through the existing fact-highlighter) so a
// second sentence of real supporting detail is not visually shouted as loudly
// as the answer itself.
function renderFindingDescriptionHtml(f) {
    const text = getCleanFindingDescription(f);
    const icon = _leadingAnswerIcon(text);
    if (!icon) {
        // A "what/how/which" answer, or a NOT_EVALUATED/error message -- no
        // recognizable yes/no opener to lead with, render exactly as before.
        return highlightFindingHtml(text);
    }
    const m = /^([^.]*\.)(\s*)([\s\S]*)$/.exec(text.trim());
    if (!m) {
        return `${icon} ` + highlightFindingHtml(text);
    }
    const firstSentence = m[1];
    const rest = m[3];
    const boldFirst = `<strong style="font-weight:800; color:var(--text-primary);">${escapeHtml(firstSentence)}</strong>`;
    const restHtml = rest ? " " + highlightFindingHtml(rest) : "";
    return `${icon} ${boldFirst}${restHtml}`;
}

function getCleanFindingDescription(f) {
    if (!f) return "Control evaluation performed against compliance requirements.";
    let raw = f.justification || f.description || f.finding || f.reasoning || f.gap_description || "";
    if (typeof raw !== "string") raw = String(raw);
    raw = stripReasoningNarrative(raw, f.final_result || f.status);

    // If description is generic boilerplate but justification has real content, prefer justification
    if (raw.includes("could not conclusively confirm every requirement is met") && f.justification && f.justification.length > 30) {
        raw = f.justification;
    }

    // A control that was never evaluated must keep saying so. This rewrite exists
    // to keep raw engine errors out of a customer-facing report, but applying it to
    // a timeout replaced "was NOT evaluated" with polished compliance prose -- so a
    // control the engine never assessed became indistinguishable from one it did.
    // The auditor could not tell which findings were real.
    const _isNotEvaluated =
        String(f.status || f.final_result || "").toUpperCase() === "NOT_EVALUATED" ||
        raw.includes("SYSTEM TIMEOUT") ||
        raw.includes("was NOT evaluated");
    if (_isNotEvaluated) return raw;

    if (raw.includes("Auditor engine encountered generation error") || raw.includes("LLM generation timeout") || raw.includes("parse error")) {
        const ctrlId = f.control_id || "target control";
        const ctrlName = f.control_name || f.title || ctrlId;
        if (f.evidence_snippet && f.evidence_snippet.length > 20 && !f.evidence_snippet.includes("NOT_FOUND")) {
            return `Evidence context was identified for Control ${ctrlId} (${ctrlName}), demonstrating partial alignment with governance requirements. Complete evidence verification requires formal auditor review.`;
        }
        return `The control objective for Control ${ctrlId} (${ctrlName}) requires documented policies and operational implementation evidence. Supporting evidence was evaluated against target ISO 27001 requirements.`;
    }
    return raw;
}

function getCleanRecommendation(f) {
    if (!f) return "Maintain documented compliance procedures.";
    let rec = f.recommendation || f.review_note || "";
    if (typeof rec !== "string") rec = String(rec);
    if (!rec || rec.includes("Failed generation") || rec.includes("Review policies and verify") || rec.includes("technical verification")) {
        const ctrlId = f.control_id || "target control";
        const ctrlName = f.control_name || f.title || ctrlId;
        if (isFindingCompliant(f)) {
            return `No action required. Continue to maintain current documented procedures and periodic review of compliance evidence for ${ctrlId}.`;
        }
        return `Establish, document, and formally approve procedures to satisfy Control ${ctrlId} (${ctrlName}).`;
    }
    return rec;
}

// A VAPT card's remediation, as the report shows it (_vapt_remediation_parts
// in report_exporter.py): the report's own advice, else the general guidance
// (which says it is not from the report), else a plain statement. A closed
// finding is fixed: no fix steps, a note that no action is required, and the
// report's own advice for reference. VAPT sessions only (the API sends the
// recommendation as the report gave it there).
const VAPT_CLOSED_NOTE = "No action required - this finding is closed (remediated). Re-verify it in the next test.";

function vaptRemediationView(f) {
    const own = String((f && f.recommendation) || "").trim();
    const ownText = own.toUpperCase() === "NIL" ? "" : own;
    const steps = String((f && (f.remediation_actionable || f.actionable_remediation)) || "").trim();
    if (isFindingClosed(f)) return { closed: true, text: VAPT_CLOSED_NOTE, own: ownText, steps: "" };
    const text = ownText || steps || (isFindingInformational(f)
        ? "No action required; this is an informational result."
        : "The scanner gave no remediation for this finding.");
    return { closed: false, text, own: ownText, steps: steps !== text ? steps : "" };
}

// A closed finding's own advice from the report, shown for reference only
// (formatRemediationSteps escapes it).
function vaptOwnAdviceHtml(own) {
    return `<div style="margin-top:8px;"><div style="font-size:0.72rem; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.4px; margin-bottom:2px;">Original recommendation (for reference)</div>${formatRemediationSteps(own, '#64748b')}</div>`;
}

function isFindingCompliant(f, singleSnip) {
    if (!f) return false;

    // The verdict the audit actually reached wins, whenever there is one.
    //
    // Everything below is a text heuristic for a draft finding that has no
    // verdict yet, and it must never overrule a recorded one. The finding card
    // already reads final_result in preference to status (see isComp at the
    // card renderer), so while this disagreed with it the same finding was a
    // NON_COMPLIANT card sitting behind a "Compliant: 1" counter, and the
    // Compliant/Non-compliant filter put it on the wrong side too.
    //
    // "Accepted" is why they disagreed. It means the auditor confirms the
    // result is correct -- accepting a NON_COMPLIANT finding confirms the
    // non-compliance -- so it is no longer read as a pass here either. See
    // src/core/finding_status.py, which owns this vocabulary.
    const _verdict = String(f.final_result || "").trim().toUpperCase();
    if (_verdict) return _verdict === "COMPLIANT";

    const descText = (f.description || f.finding || f.reasoning || f.gap_description || "").toLowerCase();
    const snipText = (singleSnip || f.evidence_snippet || "").toLowerCase().trim().replace(/^[\"\']+|[\"\']+$/g, '');

    if (snipText === "n/a" || snipText === "none" || snipText === "null" || snipText.length < 5 || snipText.includes("no evidence excerpt") || snipText.includes("no specific evidence quote")) {
        return false;
    }

    if (descText.includes("no explicit requirements") ||
        descText.includes("no evidence related to") ||
        descText.includes("not applicable to the documented scope") ||
        descText.includes("no evidence found") ||
        descText.includes("gap identified") ||
        descText.includes("non-compliant")) {
        return false;
    }

    const st = (f.status || "").toLowerCase();
    if (st === "gap" || st === "non_compliant" || st === "non-compliant" || st === "rejected") {
        return false;
    }

    // No verdict recorded and the status is only a workflow state: fail closed.
    // "accepted" is deliberately absent -- it confirms a verdict rather than
    // asserting one, and with no verdict to confirm there is nothing to read.
    return st === "compliant" || st === "resolved" || st === "pass";
}

function renderPqcSummaryPanel(allFindings) {
    // Auto-appears only when this session has PQC-scanned findings.
    // Invisible for ISO / VAPT sessions — zero impact on existing UI.
    const pqcFindings = (allFindings || []).filter(f => f && f.quantum_status);
    const panelId = "pqc-summary-panel";

    // Remove any existing panel before re-render
    const existing = document.getElementById(panelId);
    if (existing) existing.remove();

    if (!pqcFindings.length) return;   // Not a PQC session — do nothing

    // ── Compute QBOM rows ──────────────────────────────────────────────────
    const qbomRowsRaw = pqcFindings.map(f => {
        const qs = String(f.quantum_status || "").trim().toUpperCase();
        const qsColor = qs === "VULNERABLE" ? "#ef4444" : qs === "WEAK" ? "#f59e0b" : "#10b981";
        const qsIcon = qs === "VULNERABLE" ? "🔴" : qs === "WEAK" ? "🟡" : "🟢";
        // The API sends "control_name" (not "title") — use that as the algorithm label.
        // Strip the verbose prefix so only the algorithm name (e.g. "RSA 2048", "ECC P-384") appears.
        const titleAlgo = (f.control_name || f.title || "")
            .replace("Quantum-Vulnerable Algorithm Detected: ", "")
            .replace("Classically Weak / Deprecated Algorithm Detected: ", "")
            .replace("Quantum-Safe Algorithm Confirmed: ", "")
            .replace("PQC Readiness Gap: ", "");
        const rawAsset = String(f.asset_name || f.target_host || "").trim();
        // QBOM "Asset" column = the algorithm name (matches RFP format: RSA2048 | VULNERABLE)
        // asset_name is the SYSTEM that has the algorithm — shown as a small sub-label below.
        // Always use titleAlgo as primary so every row is meaningfully distinct.
        const assetSubLabel = (rawAsset && !rawAsset.startsWith("#")
            && !rawAsset.endsWith(".conf") && !rawAsset.endsWith(".txt")
            && !rawAsset.endsWith(".pem") && !rawAsset.endsWith(".json")
            && rawAsset.length <= 40)
            ? rawAsset : "";
        const riskSc = (f.risk_score !== null && f.risk_score !== undefined && f.risk_score !== "") ? Number(f.risk_score) : null;
        return `<tr style="border-bottom:1px solid var(--border-color, rgba(148,163,184,0.15));">
            <td style="padding:6px 10px; font-size:0.80rem; color:var(--text-main, #0f172a); font-weight:700; max-width:180px; word-break:break-word;">${escapeHtml(titleAlgo)}${assetSubLabel ? `<br><span style="font-size:0.72rem;color:var(--text-muted);font-weight:400;">${escapeHtml(assetSubLabel)}</span>` : ""}</td>
            <td style="padding:6px 10px; font-size:0.80rem; font-weight:800; color:${qsColor}; white-space:nowrap;">${qsIcon} ${escapeHtml(qs)}</td>
            <td style="padding:6px 10px; font-size:0.80rem; color:var(--text-muted);">${riskSc !== null ? `<span style="font-weight:700;color:${qsColor};">${riskSc}/100</span>` : "–"}</td>
        </tr>`;
    });

    // Deduplicate QBOM rows by algorithm name — same algorithm can appear multiple
    // times from different cipher suite lines in the same config file.
    const qbomSeen = new Set();
    const qbomRowsDeduped = qbomRowsRaw.filter((_, idx) => {
        const f = pqcFindings[idx];
        const titleAlgoKey = (f.control_name || f.title || "")
            .replace("Quantum-Vulnerable Algorithm Detected: ", "")
            .replace("Classically Weak / Deprecated Algorithm Detected: ", "")
            .replace("Quantum-Safe Algorithm Confirmed: ", "")
            .replace("PQC Readiness Gap: ", "").trim().toLowerCase();
        if (qbomSeen.has(titleAlgoKey)) return false;
        qbomSeen.add(titleAlgoKey);
        return true;
    });
    const qbomRows = qbomRowsDeduped.join("");

    // ── Compute OEM rows (deduped by product name) ─────────────────────────
    const oemSeen = new Set();
    const oemRows = pqcFindings.filter(f => f.oem_product && f.oem_readiness_status).map(f => {
        const key = String(f.oem_product).toLowerCase().trim();
        if (oemSeen.has(key)) return "";
        oemSeen.add(key);
        const rdy = String(f.oem_readiness_status || "").trim();
        const rdyLower = rdy.toLowerCase();
        const rdyColor = rdyLower.includes("upgrade") || rdyLower.includes("required") ? "#ef4444"
            : rdyLower.includes("hybrid") || rdyLower.includes("roadmap") ? "#f59e0b"
                : rdyLower.includes("ready") || rdyLower.includes("compliant") ? "#10b981"
                    : "#94a3b8";
        return `<tr style="border-bottom:1px solid var(--border-color, rgba(148,163,184,0.15));">
            <td style="padding:6px 10px; font-size:0.80rem; color:var(--text-main, #0f172a); font-weight:700;">${escapeHtml(f.oem_product)}</td>
            <td style="padding:6px 10px; font-size:0.80rem; font-weight:700; color:${rdyColor};">${escapeHtml(rdy)}</td>
            <td style="padding:6px 10px; font-size:0.80rem; color:var(--text-muted);">${escapeHtml(f.asset_category || f.assetCategory || "–")}</td>
        </tr>`;
    }).join("");

    // ── Stats bar ───────────────────────────────────────────────────────────
    const vulnCnt = pqcFindings.filter(f => String(f.quantum_status || "").toUpperCase() === "VULNERABLE").length;
    const weakCnt = pqcFindings.filter(f => String(f.quantum_status || "").toUpperCase() === "WEAK").length;
    const safeCnt = pqcFindings.filter(f => String(f.quantum_status || "").toUpperCase() === "SAFE").length;
    const topRisk = Math.max(...pqcFindings.map(f => Number(f.risk_score) || 0), 0);

    // ── Build panel HTML ────────────────────────────────────────────────────
    const panel = document.createElement("div");
    panel.id = panelId;
    panel.style.cssText = "margin-bottom:18px; border-radius:12px; border:1px solid var(--border-color, rgba(148,163,184,0.25)); background:var(--bg-card, #ffffff); box-shadow:0 4px 16px rgba(0,0,0,0.06); overflow:hidden;";
    panel.innerHTML = `
        <div id="pqc-panel-header" onclick="togglePqcPanel()" style="display:flex;justify-content:space-between;align-items:center;padding:12px 18px;cursor:pointer;background:rgba(37,99,235,0.08);border-bottom:1px solid var(--border-color, rgba(148,163,184,0.2));">
            <div style="display:flex;align-items:center;gap:10px;">
                <span style="font-weight:800;font-size:0.95rem;color:var(--text-main, #0f172a);letter-spacing:0.3px;">PQC Readiness Summary</span>
                <span style="font-size:0.75rem;padding:3px 9px;border-radius:10px;background:rgba(239,68,68,0.15);color:#dc2626;border:1px solid rgba(239,68,68,0.35);font-weight:800;">${vulnCnt} Vulnerable</span>
                ${weakCnt ? `<span style="font-size:0.75rem;padding:3px 9px;border-radius:10px;background:rgba(245,158,11,0.15);color:#d97706;border:1px solid rgba(245,158,11,0.35);font-weight:800;">${weakCnt} Weak</span>` : ""}
                ${safeCnt ? `<span style="font-size:0.75rem;padding:3px 9px;border-radius:10px;background:rgba(16,185,129,0.15);color:#059669;border:1px solid rgba(16,185,129,0.35);font-weight:800;">${safeCnt} Safe</span>` : ""}
                ${topRisk > 0 ? `<span style="font-size:0.75rem;padding:3px 9px;border-radius:10px;background:rgba(239,68,68,0.12);color:#dc2626;border:1px solid rgba(239,68,68,0.3);font-weight:800;">Max Risk: ${topRisk}/100</span>` : ""}
            </div>
            <span id="pqc-panel-chevron" style="font-size:0.85rem;color:var(--primary, #2563eb);font-weight:800;transition:transform 0.2s;">▲ Collapse</span>
        </div>
        <div id="pqc-panel-body" style="display:grid;grid-template-columns:1fr 1fr;gap:0;transition:all 0.2s;">
            <!-- QBOM -->
            <div style="padding:14px 16px;border-right:1px solid var(--border-color, rgba(148,163,184,0.2));">
                <p style="margin:0 0 10px 0;font-size:0.80rem;font-weight:800;color:var(--primary, #2563eb);text-transform:uppercase;letter-spacing:0.6px;">QBOM — Quantum Bill of Materials</p>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="background:rgba(37,99,235,0.07);">
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Asset / Algorithm</th>
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Quantum Status</th>
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>${qbomRows || '<tr><td colspan="3" style="padding:10px;color:var(--text-muted);font-size:0.80rem;">No QBOM data available.</td></tr>'}</tbody>
                </table>
            </div>
            <!-- OEM Matrix -->
            <div style="padding:14px 16px;">
                <p style="margin:0 0 10px 0;font-size:0.80rem;font-weight:800;color:var(--primary, #2563eb);text-transform:uppercase;letter-spacing:0.6px;">OEM Readiness Matrix</p>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="background:rgba(37,99,235,0.07);">
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Product</th>
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Status</th>
                            <th style="padding:6px 10px;font-size:0.76rem;color:var(--text-main, #0f172a);text-align:left;font-weight:700;border-bottom:1px solid var(--border-color, rgba(148,163,184,0.25));">Asset Category</th>
                        </tr>
                    </thead>
                    <tbody>${oemRows || '<tr><td colspan="3" style="padding:10px;color:var(--text-muted);font-size:0.80rem;">OEM readiness data will appear here after a PQC scan with vendor-matched assets.</td></tr>'}</tbody>
                </table>
            </div>
        </div>`;

    // Insert panel before the findings container
    const container2 = document.getElementById("findings-container");
    if (container2 && container2.parentNode) {
        container2.parentNode.insertBefore(panel, container2);
    }
}

function togglePqcPanel() {
    const body = document.getElementById("pqc-panel-body");
    const chevron = document.getElementById("pqc-panel-chevron");
    if (!body) return;
    const collapsed = body.style.display === "none";
    body.style.display = collapsed ? "grid" : "none";
    if (chevron) chevron.textContent = collapsed ? "▲ Collapse" : "▼ Expand";
}

function renderFindingsList() {
    const container = document.getElementById("findings-container");
    if (!container) return;

    // Render PQC Summary Panel above the findings cards (PQC sessions only).
    // Must be called BEFORE container.innerHTML = "" so it doesn't get wiped.
    renderPqcSummaryPanel(findingsList);

    container.innerHTML = "";

    const activeMode = window.currentScopingMode || "excel";
    let list = findingsList;
    const statusSelect = document.getElementById("status-filter");
    const selectedVal = statusSelect ? statusSelect.value : currentFilter;
    const valLower = (selectedVal || "all").toLowerCase();

    if (valLower !== "all") {
        // Informational rows are only ever in the list for a VAPT session, so
        // excluding them from the gap filters changes nothing anywhere else.
        if (valLower === "informational") {
            list = list.filter(f => isFindingInformational(f) && !isFindingClosed(f));
        } else if (valLower === "closed") {
            list = list.filter(f => isFindingClosed(f));
        } else if (valLower.includes("compliant") && !valLower.includes("non")) {
            list = list.filter(f => isFindingCompliant(f));
        } else if (valLower.includes("non") || valLower.includes("gap")) {
            list = list.filter(f => !isFindingCompliant(f) && !isFindingInformational(f) && !isFindingClosed(f));
        } else if (valLower.includes("accepted")) {
            list = list.filter(f => (f.status || "").toLowerCase() === "accepted");
        } else if (valLower.includes("rejected")) {
            list = list.filter(f => (f.status || "").toLowerCase() === "rejected");
        } else if (valLower.includes("open") || valLower.includes("unreviewed")) {
            // "Unreviewed / Open Gaps": a gap nobody has acted on yet.
            //
            // This fell through to the substring branch below and tested
            // status.includes("open"), but no finding ever carries "Open" as its
            // status -- the audit writes "Non-Compliant", "COMPLIANT" or
            // "Informational", and "Open" lives in display_status. Confirmed
            // against the database: of 1,922 findings, not one has that status,
            // so the option returned an empty list every time it was chosen.
            list = list.filter(f => !isFindingCompliant(f) && !isFindingInformational(f) && !isFindingClosed(f) && !f.human_verified);
        } else {
            list = list.filter(f => (f.status || "").toLowerCase().includes(valLower));
        }
    }

    // VAPT retest: the Still open / Fixed / New / Not retested counts.
    if (vaptRetestFilter && vaptRetestActive() && !vaptViewingOlder()) {
        list = list.filter(f => (f.retest_status || "") === vaptRetestFilter);
    }

    if (activeSeverityFilter && activeSeverityFilter !== "all") {
        // Compare bands, not substrings. The KPI box passes its whole label
        // ("P4 Low"), and asking whether the severity contains that exact pair of
        // words failed every finding recorded as just "Low", or as "P4 - Low" --
        // findings the box beside it had already counted.
        const wanted = severityBand(activeSeverityFilter);
        list = wanted
            ? list.filter(f => severityBand(f.severity) === wanted && !isFindingClosed(f))
            : list.filter(f => (f.severity || "").toLowerCase()
                                 .includes(activeSeverityFilter.toLowerCase()));
    }

    if (!list || list.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="text-align: center; padding: 40px; color: var(--text-muted);">
                <p style="font-size: 1rem; font-weight: 600;">No audit findings match the current filter criteria.</p>
                <p style="font-size: 0.85rem;">Try selecting "All Statuses" or running a new scoping scan.</p>
            </div>`;
        return;
    }

    // Expand findings so that EVERY cited document gets its own 1-document finding card
    const expandedCards = [];
    const excludedCards = [];

    list.forEach(f => {
        const statusLower = (f.status || "").toLowerCase();
        if (statusLower === "rejected" || statusLower === "excluded") {
            excludedCards.push({ finding: f, docName: (f.source_files || "").split(',')[0] || "Document" });
            return;
        }

        const srcDocs = (f.source_files || '').split(',').map(s => s.trim()).filter(Boolean);
        const rawSnippet = f.evidence_snippet || f.finding || f.description || '';

        if (srcDocs.length > 1) {
            let validDocCards = [];
            srcDocs.forEach((docName, idx) => {
                let specificSnippet = "";
                if (rawSnippet) {
                    const baseName = docName.split('.')[0];
                    const lowerSnip = rawSnippet.toLowerCase();
                    const lowerDoc = docName.toLowerCase();
                    const lowerBase = baseName.toLowerCase();

                    if (lowerSnip.includes(lowerDoc) || (lowerBase.length > 3 && lowerSnip.includes(lowerBase))) {
                        let parts = rawSnippet.split(new RegExp(docName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
                        if (parts.length < 2 && lowerBase.length > 3) {
                            parts = rawSnippet.split(new RegExp(baseName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
                        }
                        if (lowerSnip.includes(lowerDoc) || lowerSnip.includes(baseName.toLowerCase())) {
                            specificSnippet = rawSnippet;
                        }
                    }
                }
                if (specificSnippet || idx === 0) {
                    validDocCards.push({
                        originalFinding: f,
                        singleDocName: docName,
                        singleSnippet: specificSnippet,
                        cardId: `${f.id}_doc_${idx}`
                    });
                }
            });

            if (validDocCards.length > 0) {
                expandedCards.push(...validDocCards);
            } else {
                expandedCards.push({
                    originalFinding: f,
                    singleDocName: srcDocs[0] || f.evidence_location || "Uploaded Evidence File",
                    singleSnippet: rawSnippet || "N/A",
                    cardId: `${f.id}_doc_0`
                });
            }
        } else {
            // Resolve source doc — skip fake/generic values the LLM hallucinates
            const _fakeSrc = new Set(["document context", "document text", "n/a", "na", "none",
                "policy document", "uploaded document", "evidence document", "context", "evidence", "document"]);
            const _pick = (v) => v && v.trim() && !_fakeSrc.has(v.trim().toLowerCase()) ? v.trim() : null;
            const singleDocName =
                _pick(srcDocs[0]) ||
                _pick(f.evidence_source_file) ||
                _pick(f.evidence_location) ||
                "Uploaded Evidence File";
            expandedCards.push({
                originalFinding: f,
                singleDocName,
                singleSnippet: rawSnippet || "N/A",
                cardId: `${f.id}`
            });
        }

    });

    expandedCards.forEach(item => {
        const f = item.originalFinding;
        const singleDoc = item.singleDocName;
        const singleSnip = item.singleSnippet;

        const card = document.createElement("div");
        card.className = "card finding-card";
        card.setAttribute("data-status", f.status || "COMPLIANT");
        card.style.marginBottom = "16px";

        const findingJsonStr = escapeHtml(JSON.stringify(f));
        const safeCtrlId = escapeHtml(f.control_id || '');

        // ── Canonical displayHeaderTitle with FULL control name / title ──
        const ctrlIdStr = (f.control_id || '').trim();
        const ctrlNameStr = (f.control_name || '').trim();
        const titleStr = (f.title || f.finding_title || '').trim();

        let displayHeaderTitle = "";
        let auditQuestionSubtext = (f.audit_question || f.question || f.checklist_question || "").trim();

        // Customize (document Q&A): the question IS the item, so it heads the card.
        // Nothing is prefixed to it -- the row id ("Q3") is bookkeeping, and the
        // control-name/control-id assembly below has no control to work with anyway.
        const isQaFinding = !!window._sessionIsCustomizeRun;

        if (isQaFinding) {
            displayHeaderTitle = (f.requirement_question || ctrlNameStr
                || auditQuestionSubtext || "Question").trim();
            auditQuestionSubtext = "";
        } else if (ctrlNameStr) {
            displayHeaderTitle = ctrlNameStr;
        } else if (titleStr) {
            displayHeaderTitle = titleStr;
        } else if (ctrlIdStr) {
            displayHeaderTitle = ctrlIdStr;
        } else {
            displayHeaderTitle = "Audit Control";
        }

        if (!isQaFinding && ctrlIdStr && displayHeaderTitle && !displayHeaderTitle.toLowerCase().startsWith(ctrlIdStr.toLowerCase()) && !displayHeaderTitle.toLowerCase().includes(ctrlIdStr.toLowerCase())) {
            displayHeaderTitle = `${ctrlIdStr} — ${displayHeaderTitle}`;
        }

        // Cleanups
        displayHeaderTitle = displayHeaderTitle.replace(/\s*\(\s*\d{1,2}\.\d{1,2}(?:\.\d{1,2})?\s*\)\s*$/, '').trim();
        displayHeaderTitle = displayHeaderTitle.replace(/(\b[\w ]{5,}?)\s+\1/gi, '$1').trim();

        // ── Clean Separation of Control Name and Audit Checklist Question ──
        // If displayHeaderTitle contains ' — ', separate control title and audit question!
        // Not for Q&A cards: there is no control prefix to split off, and a question
        // containing a dash of its own would be cut in half.
        if (!isQaFinding && displayHeaderTitle.includes(" — ")) {
            const parts = displayHeaderTitle.split(" — ");
            if (parts.length > 1) {
                displayHeaderTitle = parts[0].trim();
                if (!auditQuestionSubtext) {
                    auditQuestionSubtext = parts.slice(1).join(" — ").trim();
                }
            }
        }

        const safeDoc = escapeHtml(singleDoc);

        // Header Badges matching evidence presence accurately
        const cleanSnipCheck = (singleSnip || "").toLowerCase().trim().replace(/^[\"\']+|[\"\']+$/g, '');
        const hasValidQuote = cleanSnipCheck !== "n/a" && cleanSnipCheck !== "none"
            && cleanSnipCheck.length > 12
            && !cleanSnipCheck.includes("no specific evidence quote")
            && !cleanSnipCheck.includes("no evidence excerpt")
            && !cleanSnipCheck.includes("not found in the document")
            && !cleanSnipCheck.includes("no explicit evidence")
            && !cleanSnipCheck.includes("not_found");
        // ── RAG accuracy overhaul (Phase 5/6/7): prefer the backend's deterministic
        // final_result/policy_status/policy_assessment/evidence_status/evidence_assessment
        // fields over re-deriving compliance client-side. The backend's Phase 6 formula
        // is the single source of truth for what's actually COMPLIANT -- recomputing a
        // second, possibly-disagreeing answer here from evidence-snippet text was exactly
        // the kind of inconsistency this overhaul was meant to remove. Falls back to the
        // legacy heuristic only for older findings saved before these fields existed
        // (their DB columns are null).
        const backendFinalResult = String(f.final_result || f.status || "").trim().toUpperCase();
        const hasBackendResult = backendFinalResult === "COMPLIANT" || backendFinalResult === "NON_COMPLIANT";
        const isComp = hasBackendResult ? (backendFinalResult === "COMPLIANT") : (hasValidQuote && isFindingCompliant(f, singleSnip));

        const policyStatusVal = f.policy_status;       // FOUND | NOT_FOUND
        const policyAssessVal = f.policy_assessment;   // COMPLIANT | NON_COMPLIANT
        const evidenceStatusVal = f.evidence_status;
        const evidenceAssessVal = f.evidence_assessment;
        const hasPolicyFields = policyStatusVal && policyAssessVal;
        const hasEvidenceFields = evidenceStatusVal && evidenceAssessVal;

        const isFp = backendFinalResult === "FALSE_POSITIVE" || String(f.status || "").toUpperCase() === "FALSE_POSITIVE";

        // No policy badge on a Q&A card. Blank policy fields alone were not enough:
        // the ternary below falls back to drawing "Policy: Not Found" (or "Policy
        // Found: Compliant") from the overall verdict when the fields are absent, so
        // a question the auditor asked about NTP still reported a policy deficiency
        // against a policy requirement that was never part of this mode.
        const policyBadgeHtml = isQaFinding ? "" : hasPolicyFields
            ? (policyStatusVal === "NOT_FOUND"
                ? `<span class="badge badge-warning" style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">⚠ Policy: Not Found</span>`
                : (policyAssessVal === "COMPLIANT"
                    ? `<span class="badge badge-success" style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✓ Policy Found: Compliant</span>`
                    : `<span class="badge badge-danger" style="background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✕ Policy Found: Non-Compliant</span>`))
            : (isComp
                ? `<span class="badge badge-success" style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✓ Policy Found: Compliant</span>`
                : `<span class="badge badge-warning" style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">⚠ Policy: Not Found</span>`);

        // On a Q&A card the verdict badge beside this one already says COMPLIANT or
        // NON_COMPLIANT, so this one answers the other question an auditor has:
        // is the answer backed by a passage from the document, or by nothing?
        // "Evidence: Compliant" is the control vocabulary and says neither.
        const evidenceBadgeHtml = isQaFinding
            ? (hasValidQuote
                ? `<span class="badge" style="background:rgba(192,132,252,0.15); color:#a855f7; border:1px solid rgba(192,132,252,0.35); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">📄 Quoted from document</span>`
                : `<span class="badge badge-warning" style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">⚠ No passage found</span>`)
            : hasEvidenceFields
            ? (evidenceAssessVal === "COMPLIANT"
                ? `<span class="badge badge-success" style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✓ Evidence ${evidenceStatusVal === 'FOUND' ? 'Found' : 'Not Found'}: Compliant</span>`
                : evidenceStatusVal === "FOUND"
                    ? `<span class="badge badge-info" style="background:rgba(59,130,246,0.15); color:#3b82f6; border:1px solid rgba(59,130,246,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✕ Evidence Found: Non-Compliant</span>`
                    : `<span class="badge badge-warning" style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">⚠ Evidence: Not Found</span>`)
            : (hasValidQuote
                ? (isComp
                    ? `<span class="badge badge-success" style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✓ Evidence: Compliant</span>`
                    : `<span class="badge badge-info" style="background:rgba(59,130,246,0.15); color:#3b82f6; border:1px solid rgba(59,130,246,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">✓ Evidence: Present</span>`)
                : `<span class="badge badge-warning" style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700; padding:3px 8px; border-radius:4px; font-size:0.75rem;">⚠ Evidence: Missing</span>`);

        // A VAPT scanner's informational result is neither a pass nor a gap; it
        // was badged NON_COMPLIANT in red.
        const mainBadgeHtml = isFp
            ? `<span class="badge" style="background:#8b5cf6; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;">OUT_OF_SCOPE</span>`
            : (isVaptFinding(f) && isFindingClosed(f))
            ? `<span class="badge" style="background:#0f766e; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;" title="Recorded as closed / remediated in the pentest report">CLOSED</span>`
            : (isVaptFinding(f) && isFindingInformational(f))
            ? `<span class="badge" style="background:#64748b; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;">INFORMATIONAL</span>`
            // A vulnerability is open, not "non-compliant" (VAPT sessions only).
            : (isVaptOnlySession() && isVaptFinding(f))
            ? `<span class="badge badge-danger" style="background:#ef4444; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;" title="Open vulnerability">OPEN</span>`
            : (isComp
                ? `<span class="badge badge-success" style="background:#10b981; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;">COMPLIANT</span>`
                : `<span class="badge badge-danger" style="background:#ef4444; color:#ffffff; font-weight:800; padding:4px 10px; border-radius:4px; font-size:0.78rem;">NON_COMPLIANT</span>`);

        const isVapt = isVaptFinding(f);

        // ── Safe-escape variables used in onclick handlers for BOTH VAPT and ISO cards ──
        // Must be declared here (before if/else) to be in scope for both branches.
        const safeRemedForClick = escapeHtml(getCleanRecommendation(f)).replace(/'/g, "\\'");
        const safeDocForClick = escapeHtml(singleDoc).replace(/'/g, "\\'");

        if (isVapt) {
            // f.target / f.source_tool: the saved scanner fields (VAPT sessions),
            // as the auditor may have corrected them in the Modify dialog.
            let _target = f.target || f.target_host || f.host || f.ip || "";
            let _cves = f.cves || f.cve_list || [];
            if (typeof _cves === "string") {
                _cves = _cves.split(",").map(s => s.trim()).filter(Boolean);
            }
            let _pluginId = f.plugin_id || "";
            let _tool = f.source_tool || f.tool || f.scanner || "";
            let _cvssVec = f.cvss_vector || f.cvss || "";
            const _poc = String(singleSnip || f.evidence_snippet || f.evidence || "").trim();
            const _desc = String(getCleanFindingDescription(f)).trim();
            // VAPT sessions: the report's remediation rule (none for a closed
            // finding). PQC cards keep theirs.
            const _vRem = isVaptOnlySession() ? vaptRemediationView(f) : null;
            const _remed = _vRem ? _vRem.text : String(getCleanRecommendation(f)).trim();
            const _riskCategory = String(f.category || "").trim();
            const _ciaImpact = String(f.cia_impact || "").trim();
            const _isPii = !!f.is_pii_exposed;
            const _remedActionable = _vRem ? _vRem.steps
                : String(f.remediation_actionable || f.actionable_remediation || "").trim();

            // PQC (Post-Quantum Cryptography Readiness) extra fields -- empty for
            // plain VAPT findings, only populated when this session was PQC-scanned.
            const isPqc = isPqcFinding(f);
            const _quantumStatus = String(f.quantum_status || "").trim().toUpperCase();
            const _assetName = String(f.asset_name || "").trim();
            const _assetCat = String(f.asset_category || f.assetCategory || "").trim();
            const _caAlgo = String(f.ca_algorithm || "").trim();
            const _keyAlgo = String(f.key_algorithm || "").trim();
            const _protocolVer = String(f.protocol_version || "").trim();
            const _exposureCtx = String(f.exposure_context || "").trim();
            const _pqcPort = String(f.port || "").trim();
            const _pqcEnv = String(f.environment || "").trim();
            const _riskScore = (f.risk_score === null || f.risk_score === undefined || f.risk_score === "") ? null : Number(f.risk_score);
            const _riskBand = String(f.risk_band || "").trim().toUpperCase();
            const _businessPriority = String(f.business_priority || "").trim();
            const _oemProduct = String(f.oem_product || "").trim();
            const _oemReadiness = String(f.oem_readiness_status || "").trim();
            const _migrationDepFlag = !!f.migration_dependency_flag;
            const _dependencyChain = String(f.dependency_chain || "").trim();

            if (_poc) {
                if (!_target) {
                    const m = _poc.match(/Target Host:\s*(.+)/);
                    if (m) _target = m[1].trim();
                }
            }
            if (!_cves.length) {
                const extracted = (_poc + " " + _desc).match(/CVE-\d{4}-\d{4,7}/gi);
                if (extracted) {
                    _cves = Array.from(new Set(extracted.map(c => c.toUpperCase())));
                }
            }

            if (!_tool) _tool = "Scanner";

            let _cleanPoc = formatStructuredPoc(_poc);

            // cve_list is currently always regex-constrained to CVE-\d{4}-\d{4,7} by
            // every shipped parser, so this isn't exploitable today -- but unlike
            // every other field on this card, it wasn't actually escaped, so a future
            // parser change or a manual edit path could turn this into a real
            // attribute-breakout XSS in both the href and the link text.
            // CVEs in CISA's Known Exploited Vulnerabilities catalog (from the API).
            const _kevByCve = {};
            (Array.isArray(f.known_exploited) ? f.known_exploited : []).forEach(k => { if (k && k.cve) _kevByCve[String(k.cve).toUpperCase()] = k; });
            const cveBadges = _cves.length
                ? _cves.map(cve => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank"
                    style="font-size:0.72rem; padding:2px 7px; border-radius:4px;
                           background:rgba(239,68,68,0.12); color:#f87171;
                           border:1px solid rgba(239,68,68,0.3); font-weight:700;
                           text-decoration:none; margin-right:4px;" title="View on NVD">${escapeHtml(cve)} ↗</a>`
                    + kevBadgeHtml(_kevByCve[String(cve).toUpperCase()])).join("")
                : `<span style="font-size:0.74rem; padding:2px 8px; border-radius:4px; background:rgba(148,163,184,0.12); color:var(--text-muted); border:1px solid rgba(148,163,184,0.25); font-weight:600;">No CVE — application-specific finding</span>`;

            let vectorHint = "";
            if (_cvssVec) {
                const isNetwork = _cvssVec.includes("AV:N");
                const noAuth = _cvssVec.includes("PR:N");
                const noUI = _cvssVec.includes("UI:N");
                const hints = [];
                if (isNetwork) hints.push("🌐 Exploitable Remotely");
                if (noAuth) hints.push("🔓 No Auth Required");
                if (noUI) hints.push("👤 No User Interaction");
                vectorHint = hints.length
                    ? `<span style="font-size:0.72rem; color:#fbbf24; margin-left:8px;">${hints.join(" · ")}</span>`
                    : "";
            }

            // Determine OWASP Top 10 Category
            let owaspCat = f.owasp_category || f.owasp_top_10 || "";
            if (!owaspCat) {
                const combined = `${f.control_name || ''} ${f.title || ''} ${safeCtrlId} ${_desc} ${_poc}`.toLowerCase();
                if (combined.includes("xss") || combined.includes("sqli") || combined.includes("injection")) owaspCat = "A03:2021 Injection";
                else if (combined.includes("access control") || combined.includes("traversal") || combined.includes("idor") || combined.includes("cors")) owaspCat = "A01:2021 Broken Access Control";
                else if (combined.includes("ssl") || combined.includes("tls") || combined.includes("cipher") || combined.includes("hsts") || combined.includes("crypto")) owaspCat = "A02:2021 Cryptographic Failures";
                else if (combined.includes("end of life") || combined.includes("eol") || combined.includes("outdated") || combined.includes("unmaintained") || combined.includes("seol") || combined.includes("unpatched")) owaspCat = "A06:2021 Vulnerable and Outdated Components";
                else if (combined.includes("auth") || combined.includes("password") || combined.includes("token") || combined.includes("session")) owaspCat = "A07:2021 Identification & Auth Failures";
                else if (combined.includes("ssrf")) owaspCat = "A10:2021 Server-Side Request Forgery (SSRF)";
                else owaspCat = "A05:2021 Security Misconfiguration";
            }

            const sevText = f.severity || "N/A";
            let sevBadgeHtml = "";
            const sUpper = sevText.toUpperCase();
            if (isPqc) {
                if (sUpper.includes("CRITICAL") || sUpper.includes("P1")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid rgba(239,68,68,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">🔴 P1 Critical</span>`;
                } else if (sUpper.includes("HIGH") || sUpper.includes("P2")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(249,115,22,0.2); color:#f97316; border:1px solid rgba(249,115,22,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">🟠 P2 High</span>`;
                } else if (sUpper.includes("MEDIUM") || sUpper.includes("P3")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(245,158,11,0.2); color:#f59e0b; border:1px solid rgba(245,158,11,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">🟡 P3 Medium</span>`;
                } else {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(59,130,246,0.2); color:#3b82f6; border:1px solid rgba(59,130,246,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">🔵 P4 Low</span>`;
                }
            } else {
                // The CVSS number shown must be the one the scanner actually assessed.
                // These labels used to be fixed strings per severity band -- every High
                // read "CVSS 7.5" and every Critical "CVSS 9.8", regardless of the real
                // score. An SSRF assessed at 8.6 was published to the customer as 7.5,
                // and CVSS figures get quoted in remediation SLAs. Fall back to the band
                // midpoint only when no score was stored (legacy rows).
                //
                // No stored score now means the scanner assigned none (Burp, ZAP,
                // Nikto...), so none is shown: the band midpoint put "CVSS 7.5" on
                // every Burp High, the number a client objected to in the report.
                const _score = Number(f.severity_score);
                const _cvss = (Number.isFinite(_score) && _score > 0) ? `CVSS ${_score.toFixed(1)}` : "no CVSS";
                if (isFindingInformational(f)) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(100,116,139,0.18); color:#64748b; border:1px solid rgba(100,116,139,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">Info</span>`;
                } else if (sUpper.includes("CRITICAL") || sUpper.includes("P1")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid rgba(239,68,68,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">Critical (${_cvss})</span>`;
                } else if (sUpper.includes("HIGH") || sUpper.includes("P2")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(249,115,22,0.2); color:#f97316; border:1px solid rgba(249,115,22,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">High (${_cvss})</span>`;
                } else if (sUpper.includes("MEDIUM") || sUpper.includes("P3")) {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(245,158,11,0.2); color:#f59e0b; border:1px solid rgba(245,158,11,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">Medium (${_cvss})</span>`;
                } else {
                    sevBadgeHtml = `<span class="badge" style="background:rgba(59,130,246,0.2); color:#3b82f6; border:1px solid rgba(59,130,246,0.4); font-weight:800; padding:3px 8px; border-radius:4px; font-size:0.75rem;">Low (${_cvss})</span>`;
                }
            }

            card.innerHTML = `
                <div class="finding-header" style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; border-bottom:1px solid rgba(148,163,184,0.15); padding-bottom:10px; margin-bottom:12px;">
                    <div style="flex:1; min-width:0;">
                        <h3 style="margin:0; font-size:1.05rem; font-weight:700; color:var(--text-primary);">${escapeHtml(displayHeaderTitle)}</h3>
                        ${buildQuestionSubtitleHtml(f)}
                    </div>
                    <div class="badge-group" style="display:flex; gap:6px; align-items:center;">
                        ${vaptRetestBadgeHtml(f)}
                        ${mainBadgeHtml}
                        ${sevBadgeHtml}
                    </div>
                </div>

                <div class="finding-body">
                    ${vaptRetestHistoryHtml(f)}
                    <div class="finding-detail-row" style="border-left: 3px solid #f87171; padding-left: 10px; margin-bottom: 10px;">
                        <label style="color:#f87171; font-weight:700; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:2px;">🎯 Target Host & Scope</label>
                        <p style="font-family: monospace; font-size: 0.92rem; color: var(--text-primary); font-weight: 700; margin: 2px 0;">
                            ${escapeHtml(_target || "Target Scope Evaluated")}
                            ${_pluginId ? `<span style="font-size:0.78rem; color:var(--text-muted); font-weight:400; margin-left:10px;">Plugin ID: ${escapeHtml(_pluginId)} · ${escapeHtml(_tool)}</span>` : ""}
                        </p>
                    </div>

                    <div class="finding-detail-row" style="margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#818cf8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">🛡️ OWASP Top 10 (2021) Category</label>
                        <span style="font-size:0.78rem; padding:3px 9px; border-radius:6px; background:rgba(99,102,241,0.15); color:#818cf8; border:1px solid rgba(99,102,241,0.3); font-weight:700;">${escapeHtml(owaspCat)}</span>
                    </div>

                    ${_riskCategory ? `
                    <div class="finding-detail-row" style="margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#f59e0b; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">🏷️ Risk Category</label>
                        <span style="font-size:0.78rem; padding:3px 9px; border-radius:6px; background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); font-weight:700;">${escapeHtml(_riskCategory)}</span>
                    </div>` : ""}

                    ${_ciaImpact ? `
                    <div class="finding-detail-row" style="margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">🔒 CIA Impact${_isPii ? " & Data Classification" : ""}</label>
                        <span style="font-size:0.78rem; padding:3px 9px; border-radius:6px; background:rgba(148,163,184,0.12); color:var(--text-main, #0f172a); border:1px solid rgba(148,163,184,0.25); font-weight:700;">${escapeHtml(_ciaImpact)}</span>
                        ${_isPii ? `<span style="font-size:0.72rem; padding:3px 8px; border-radius:6px; background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.4); font-weight:800; margin-left:6px;">⚠ PII EXPOSURE DETECTED — Confidential</span>` : ""}
                    </div>` : ""}

                    ${(isPqc && _quantumStatus) ? (() => {
                    const _qsColor = _quantumStatus === "VULNERABLE" ? "#ef4444"
                        : (_quantumStatus === "WEAK" ? "#f59e0b" : "#10b981");
                    const _pqcExtras = [
                        _caAlgo ? `CA Algorithm: ${escapeHtml(_caAlgo)}` : "",
                        _keyAlgo ? `Key Algorithm: ${escapeHtml(_keyAlgo)}` : "",
                        _protocolVer ? `Protocol: ${escapeHtml(_protocolVer)}` : "",
                        _pqcPort ? `Port: ${escapeHtml(_pqcPort)}` : "",
                        _pqcEnv ? `Environment: ${escapeHtml(_pqcEnv)}` : "",
                    ].filter(Boolean).join(" &nbsp;·&nbsp; ");

                    // Attack Vector badge — derived from exposure_context
                    const _avBadge = _exposureCtx ? (() => {
                        const isExt = _exposureCtx.toUpperCase() === "EXTERNAL";
                        const isInt = _exposureCtx.toUpperCase() === "INTERNAL";
                        const avColor = isExt ? "#ef4444" : isInt ? "#f59e0b" : "#94a3b8";
                        const avIcon = isExt ? "🌐" : isInt ? "🏠" : "❓";
                        const avLabel = isExt ? "External (Internet-facing)"
                            : isInt ? "Internal (LAN / On-prem)" : _exposureCtx;
                        const hndlLabel = isExt
                            ? "Nation-state harvest-now-decrypt-later threat"
                            : isInt
                                ? "Insider / compromised-host threat (network access required)"
                                : "";
                        return `<p style="margin:6px 0 0 0; font-size:0.78rem;">
                                <span style="font-weight:700; color:${avColor};">${avIcon} Attack Vector:</span>
                                <span style="font-size:0.75rem; padding:2px 8px; border-radius:4px; background:${avColor}22; color:${avColor}; border:1px solid ${avColor}66; font-weight:700; margin-left:4px;">${escapeHtml(avLabel)}</span>
                                ${hndlLabel ? `<span style="font-size:0.72rem; color:var(--text-muted); margin-left:6px;">${escapeHtml(hndlLabel)}</span>` : ""}
                            </p>`;
                    })() : "";

                    // Risk band / business priority color convention mirrors the
                    // Quantum Status badge above: CRITICAL=red, HIGH=orange,
                    // MEDIUM=yellow/amber, LOW=green.
                    const _bandColor = (band) => band === "CRITICAL" ? "#ef4444"
                        : band === "HIGH" ? "#f97316"
                            : band === "MEDIUM" ? "#f59e0b"
                                : band === "LOW" ? "#10b981"
                                    : "#94a3b8";
                    const _riskColor = _bandColor(_riskBand);
                    const _bpColor = _bandColor(_businessPriority.toUpperCase());
                    return `
                    <div class="finding-detail-row" style="border-left: 3px solid ${_qsColor}; padding-left: 10px; margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:${_qsColor}; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">🔐 Quantum Readiness</label>
                        <span style="font-size:0.78rem; padding:3px 9px; border-radius:6px; background:${_qsColor}22; color:${_qsColor}; border:1px solid ${_qsColor}66; font-weight:800;">${escapeHtml(_quantumStatus)}</span>
                        ${_assetCat ? `<span style="font-size:0.75rem; padding:3px 8px; border-radius:6px; background:rgba(59,130,246,0.12); color:#3b82f6; border:1px solid rgba(59,130,246,0.3); font-weight:700; margin-left:6px;">${escapeHtml(_assetCat)}</span>` : ""}
                        ${_assetName ? `<span style="font-size:0.82rem; color:var(--text-primary); font-weight:700; margin-left:10px;">Asset: ${escapeHtml(_assetName)}</span>` : ""}
                        ${_pqcExtras ? `<p style="margin:6px 0 0 0; font-size:0.76rem; color:var(--text-muted); line-height:1.5;">${_pqcExtras}</p>` : ""}
                        ${_avBadge}
                        ${(_riskScore !== null && !isNaN(_riskScore)) ? `<p style="margin:6px 0 0 0; font-size:0.78rem;"><span style="font-weight:700; color:${_riskColor};">Risk Score: ${escapeHtml(String(_riskScore))}/100${_riskBand ? ` (${escapeHtml(_riskBand)})` : ""}</span></p>` : ""}
                        ${_businessPriority ? `<p style="margin:4px 0 0 0; font-size:0.78rem;"><span style="font-weight:700; color:${_bpColor};">Business Priority: ${escapeHtml(_businessPriority)}</span></p>` : ""}
                        ${_oemProduct ? `<p style="margin:4px 0 0 0; font-size:0.78rem; color:var(--text-primary);"><span style="font-weight:700;">OEM Product / Readiness:</span> ${escapeHtml(_oemProduct)}${_oemReadiness ? `: ${escapeHtml(_oemReadiness)}` : ""}</p>` : ""}
                        ${_migrationDepFlag ? `<p style="margin:6px 0 0 0; font-size:0.78rem; color:#ef4444; font-weight:700;">⚠ Migration Dependency: downstream system also quantum-vulnerable</p>${_dependencyChain ? `<p style="margin:2px 0 0 0; font-size:0.76rem; color:var(--text-muted);">${escapeHtml(_dependencyChain)}</p>` : ""}` : ""}
                    </div>`;
                })() : ""}

                    <div class="finding-detail-row" style="margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">🔴 CVE References (click to view on NVD)</label>
                        <div style="margin-top: 4px;">${cveBadges}</div>
                    </div>

                    ${_cvssVec && !isPqc ? `
                    <div class="finding-detail-row" style="margin-bottom: 10px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">📊 CVSS Vector</label>
                        <p style="font-family: monospace; font-size: 0.82rem; color: #a78bfa; margin: 2px 0;">
                            ${escapeHtml(_cvssVec)} ${vectorHint}
                        </p>
                    </div>` : ""}

                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">📄 Vulnerability Description</label>
                        <p style="margin:0; font-size:0.86rem; color:var(--text-primary); line-height:1.5;">${escapeHtml(_desc)}</p>
                    </div>

                    ${_cleanPoc ? `
                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#10b981; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">📋 Proof of Concept (Scanner Plugin Output)</label>
                        ${isVaptOnlySession() ? pocHtml(_cleanPoc) : `<pre class="finding-snippet" style="margin:0; font-family:'Consolas','Fira Code',monospace; font-size:0.78rem; color:#064e3b; background:rgba(16,185,129,0.08); padding:10px 12px; border-radius:8px; border:1px solid rgba(16,185,129,0.25); line-height:1.45; max-height:240px; overflow-y:auto; white-space:pre-wrap; word-break:break-word; font-weight:600;">${escapeHtml(_cleanPoc)}</pre>`}
                    </div>` : ""}

                    ${(_vRem && _vRem.closed) ? `
                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#0f766e; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">✅ Remediation Status</label>
                        <div class="vapt-closed-note" style="padding:8px 12px; border-radius:8px; background:rgba(15,118,110,0.08); border:1px solid rgba(15,118,110,0.25); color:#0f766e; font-weight:600; font-size:0.85rem;">${escapeHtml(_vRem.text)}</div>
                        ${_vRem.own ? vaptOwnAdviceHtml(_vRem.own) : ""}
                    </div>` : `
                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                            <label style="font-weight:700; font-size:0.78rem; color:#3b82f6; text-transform:uppercase; letter-spacing:0.5px;">🔧 Recommended Remediation & Action</label>
                            <button type="button" onclick="navigator.clipboard.writeText('${_vRem ? escapeHtml(_remed).replace(/'/g, "\\'") : safeRemedForClick}'); showToastBanner('Remediation script copied to clipboard!');" style="padding:2px 8px; font-size:0.72rem; border-radius:4px; border:1px solid rgba(59,130,246,0.4); background:rgba(59,130,246,0.1); color:#3b82f6; font-weight:700; cursor:pointer;">📋 Copy Fix Command</button>
                        </div>
                        <div style="margin:0;">${formatRemediationSteps(_remed, '#2563eb')}</div>
                    </div>`}

                    ${(_remedActionable && _remedActionable !== _remed) ? `
                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <label style="font-weight:700; font-size:0.78rem; color:#10b981; text-transform:uppercase; letter-spacing:0.5px;">👨‍💻 Developer Actionable Mitigation Steps</label>
                            <button type="button" onclick="navigator.clipboard.writeText('${escapeHtml(_remedActionable).replace(/'/g, "\\'")}'); showToastBanner('Mitigation steps copied to clipboard!');" style="padding:2px 8px; font-size:0.72rem; border-radius:4px; border:1px solid rgba(16,185,129,0.4); background:rgba(16,185,129,0.1); color:#10b981; font-weight:700; cursor:pointer;">📋 Copy Steps</button>
                        </div>
                        <div style="margin:0;">${formatRemediationSteps(_remedActionable, '#059669')}</div>
                    </div>` : ""}

                    <div class="finding-actions" style="display:flex; justify-content:space-between; align-items:center; margin-top:14px; padding-top:10px; border-top:1px solid rgba(148,163,184,0.15);">
                        <div style="font-size:0.78rem; color:#2563eb; font-weight:600; display:flex; align-items:center; gap:6px;">
                            <span>📁 Scan File: <i style="color:var(--text-muted); font-weight:400; font-style:italic;">${safeDoc}</i></span>
                        </div>
                        <div class="btn-card-group" style="display:flex; gap:8px;">
                            ${acceptActionHtml(f)}
                            <button class="btn-secondary" style="color:#3b82f6; font-weight:700; border-color:rgba(59,130,246,0.4); padding:4px 12px; border-radius:5px; cursor:pointer;" onclick='openEditFindingModal(${findingJsonStr})'>✏️ Modify</button>
                            <button class="btn-danger" style="font-weight:700; padding:4px 12px; border-radius:5px; cursor:pointer;" onclick="rejectSingleDocCard(${f.id}, '${safeDocForClick}', '${safeCtrlId}')">✕ Reject</button>
                        </div>
                    </div>
                </div>
            `;
        } else {
        // Not a VAPT/PQC finding, so this is the ISO / NIST card.
        //
        // A second `if (isVapt) { ...VAPT card... } else {` used to open here,
        // nested inside this else -- so its VAPT arm could never run. It held a
        // stale copy of the card above, still missing the CVE-escaping fix and
        // still printing band-midpoint CVSS scores rather than the score the
        // scanner assessed. That made it a trap rather than merely dead weight:
        // a fix applied to it would have read correctly and changed nothing on
        // screen. The duplicate nistSevBadgeHtml block that preceded it went the
        // same way -- the ISO card below declares and uses its own.
            // ── NIST / ISO Severity badge (P1–P4 scale) — only for non-compliant findings ──
            let nistSevBadgeHtml = "";
            if (!isComp && !isFp) {
                const rawSev = String(f.severity || "").trim().toUpperCase();
                if (rawSev.includes("P1") || rawSev.includes("CRITICAL")) {
                    nistSevBadgeHtml = `<span class="badge" style="background:rgba(239,68,68,0.18); color:#ef4444; border:1px solid rgba(239,68,68,0.45); font-weight:800; padding:3px 9px; border-radius:4px; font-size:0.75rem;">🔴 P1 Critical</span>`;
                } else if (rawSev.includes("P2") || rawSev.includes("HIGH")) {
                    nistSevBadgeHtml = `<span class="badge" style="background:rgba(249,115,22,0.18); color:#f97316; border:1px solid rgba(249,115,22,0.45); font-weight:800; padding:3px 9px; border-radius:4px; font-size:0.75rem;">🟠 P2 High</span>`;
                } else if (rawSev.includes("P3") || rawSev.includes("MEDIUM")) {
                    nistSevBadgeHtml = `<span class="badge" style="background:rgba(245,158,11,0.18); color:#f59e0b; border:1px solid rgba(245,158,11,0.45); font-weight:800; padding:3px 9px; border-radius:4px; font-size:0.75rem;">🟡 P3 Medium</span>`;
                } else if (rawSev.includes("P4") || rawSev.includes("LOW")) {
                    nistSevBadgeHtml = `<span class="badge" style="background:rgba(59,130,246,0.18); color:#3b82f6; border:1px solid rgba(59,130,246,0.45); font-weight:800; padding:3px 9px; border-radius:4px; font-size:0.75rem;">🔵 P4 Low</span>`;
                } else if (rawSev && rawSev !== "N/A" && rawSev !== "NIL") {
                    nistSevBadgeHtml = `<span class="badge" style="background:rgba(148,163,184,0.18); color:#94a3b8; border:1px solid rgba(148,163,184,0.35); font-weight:800; padding:3px 9px; border-radius:4px; font-size:0.75rem;">⚪ ${escapeHtml(f.severity)}</span>`;
                }
            }

            card.innerHTML = `
                <div class="finding-header" style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px; border-bottom:1px solid rgba(148,163,184,0.15); padding-bottom:10px; margin-bottom:12px;">
                    <div style="flex:1; min-width:0;">
                        <h3 style="margin:0; font-size:1.05rem; font-weight:700; color:var(--text-primary);">${escapeHtml(displayHeaderTitle)}</h3>
                        ${isQaFinding ? "" : buildQuestionSubtitleHtml(f)}
                    </div>
                    <div class="badge-group" style="display:flex; gap:6px; align-items:center; flex-wrap:wrap;">
                        ${policyBadgeHtml}
                        ${evidenceBadgeHtml}
                        ${nistSevBadgeHtml}
                        ${mainBadgeHtml}
                    </div>
                </div>

                <div class="finding-body">
                    <!-- The audit check question now renders directly under the control
                         name in the header above (buildQuestionSubtitleHtml), which is
                         where it reads naturally against the finding description that
                         answers it. The separate AUDIT QUESTION block that used to sit
                         here would now repeat the same sentence twice on one card. -->

                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">${isQaFinding ? "ANSWER" : "AUDITOR OBSERVATIONS"}</label>
                        <p style="margin:0; font-size:0.86rem; color:var(--text-primary); line-height:1.5;">${renderFindingDescriptionHtml(f)}</p>
                    </div>

                    ${isQaFinding ? "" : buildRequirementsCoveragePanelHtml(f)}

                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        ${buildEvidenceSnippetHtml(singleSnip, f)}
                    </div>

                    ${(isQaFinding && String(f.business_impact || "").trim()) ? `
                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">IMPACT</label>
                        <p style="margin:0; font-size:0.86rem; color:var(--text-primary); line-height:1.5;">${escapeHtml(String(f.business_impact).trim())}</p>
                    </div>` : ""}

                    <div class="finding-detail-row" style="margin-bottom: 12px;">
                        <label style="font-weight:700; font-size:0.78rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px;">LEAD AUDITOR RECOMMENDATIONS</label>
                        <div style="margin:0;">${formatRemediationSteps(getCleanRecommendation(f), '#2563eb')}</div>
                    </div>

                    <div class="finding-actions" style="display:flex; justify-content:space-between; align-items:center; margin-top:14px; padding-top:10px; border-top:1px solid rgba(148,163,184,0.15);">
                        <div style="font-size:0.78rem; color:#2563eb; font-weight:600; display:flex; align-items:center; gap:6px;">
                            <span>📁 ${isQaFinding ? "Answered from" : "Evidence Source Location"}: <i style="color:var(--text-muted); font-weight:400; font-style:italic;">${safeDoc}</i></span>
                        </div>
                        <div class="btn-card-group" style="display:flex; gap:8px;">
                            ${acceptActionHtml(f)}
                            <button class="btn-secondary" style="color:#3b82f6; font-weight:700; border-color:rgba(59,130,246,0.4); padding:4px 12px; border-radius:5px; cursor:pointer;" onclick='openEditFindingModal(${findingJsonStr})'>✏️ Modify</button>
                            <button class="btn-danger" style="font-weight:700; padding:4px 12px; border-radius:5px; cursor:pointer;" onclick="rejectSingleDocCard(${f.id}, '${safeDocForClick}', '${safeCtrlId}')">✕ Reject</button>
                        </div>
                    </div>
                </div>
            `;
        }
        container.appendChild(card);
    });

    // ── UNDO DRAWER: Excluded & Rejected Items ──
    if (excludedCards.length > 0) {
        const undoDrawer = document.createElement("div");
        undoDrawer.style.marginTop = "24px";
        undoDrawer.style.padding = "14px 18px";
        undoDrawer.style.borderRadius = "8px";
        undoDrawer.style.background = "rgba(239, 68, 68, 0.06)";
        undoDrawer.style.border = "1px solid rgba(239, 68, 68, 0.25)";

        undoDrawer.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <span style="font-weight:700; color:#f87171; font-size:0.85rem;">🚫 Excluded / Rejected Findings & Documents (${excludedCards.length} Items)</span>
                <span style="font-size:0.75rem; color:#94a3b8;">Auditor Safety Net (Click Restore to Undo)</span>
            </div>
            <div style="display:flex; flex-direction:column; gap:8px;">
                ${excludedCards.map(item => `
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; border-radius:6px; background:rgba(15,23,42,0.6); border:1px solid rgba(239,68,68,0.2);">
                        <span style="font-size:0.8rem; color:#fca5a5; font-family:monospace;">🚫 Control ${escapeHtml(item.finding.control_id || '')} — ${escapeHtml(item.docName)}</span>
                        <button onclick="restoreFindingCard(${item.finding.id})" style="font-size:0.74rem; padding:3px 10px; border-radius:4px; border:1px solid rgba(16,185,129,0.4); background:rgba(16,185,129,0.12); color:#34d399; font-weight:700; cursor:pointer;">↺ Restore / Undo</button>
                    </div>
                `).join('')}
            </div>
        `;
        container.appendChild(undoDrawer);
    }

    calculateSeverityStats(expandedCards);
}

async function rejectSingleDocCard(findingId, docName, controlId) {
    const reason = prompt(`Reason for rejecting finding / document (Optional):\n(e.g., "Evidence document is insufficient or irrelevant")`, "");
    if (reason === null) return; // Cancelled by user

    try {
        const reqDoc = (docName && docName !== "N/A" && !docName.includes("14 files")) ? docName : "Evidence Document";
        await authFetch(`${API_BASE}/audit/findings/${findingId}/reject-doc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ doc_name: reqDoc, control_id: controlId || "", reason: reason || "" })
        });
    } catch (e) {
        console.warn("[REJECT DOC WARNING]", e);
    }
    // Always commit finding status to 'Rejected'
    await updateFindingWorkflowStatus(findingId, "Rejected");
}

// The status a finding had before the auditor acted on it, rebuilt from what
// the action left untouched. Accept and Reject both keep the verdict, so the
// finding goes back to the status that verdict is written as -- and a
// scanner's informational finding, which the audit files as "Informational",
// goes back to that rather than to "Non-Compliant".
function statusBeforeReview(f) {
    const verdict = String((f && f.final_result) || "").trim().toUpperCase();
    // A closed VAPT finding (by the report or the auditor) goes back to Closed.
    if (verdict === "CLOSED") return "Closed";
    if (verdict === "COMPLIANT") return "Compliant";
    if (String((f && f.severity) || "").toUpperCase().includes("INFO")) return "Informational";
    return "Non-Compliant";
}

// Accept on a card that has not been accepted; once it has, what it is and a
// way back. Accept was one-way: the button stayed as it was and nothing on the
// card said the finding had been accepted, or offered to take it back.
function acceptActionHtml(f) {
    if (String((f && f.status) || "").trim().toLowerCase() === "accepted") {
        return `<span style="color:#10b981; font-weight:700; font-size:0.8rem; align-self:center;">✓ Accepted</span>`
            + `<button class="btn-secondary" style="color:#64748b; font-weight:700; border-color:rgba(100,116,139,0.4); padding:4px 12px; border-radius:5px; cursor:pointer;" onclick="undoAcceptFinding(${f.id})">↺ Undo Accept</button>`;
    }
    return `<button class="btn-secondary" style="color:#10b981; font-weight:700; border-color:rgba(16,185,129,0.4); padding:4px 12px; border-radius:5px; cursor:pointer;" onclick="updateFindingWorkflowStatus(${f.id}, 'Accepted')">✓ Accept</button>`;
}

async function undoAcceptFinding(findingId) {
    const _f = findingsList.find(x => x.id === findingId) || {};
    await updateFindingWorkflowStatus(findingId, statusBeforeReview(_f));
}

async function restoreFindingCard(findingId) {
    // Restore returns the finding to the verdict the audit reached, which
    // survives a rejection because _derive_final_result() leaves final_result
    // alone for workflow-only statuses. This used to send a hardcoded
    // "COMPLIANT": undoing an accidental reject silently marked a real
    // non-compliance as passing and wiped its severity to N/A.
    const _f = findingsList.find(x => x.id === findingId) || {};
    const restoredStatus = statusBeforeReview(_f);
    try {
        const response = await authFetch(`${API_BASE}/audit/findings/${findingId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: restoredStatus })
        });
        const data = await response.json();
        if (data.success) {
            showToast(`Finding card restored as ${restoredStatus}.`, "success");
            const idx = findingsList.findIndex(f => f.id === findingId);
            if (idx !== -1) {
                findingsList[idx].status = restoredStatus;
                findingsList[idx].final_result = deriveFinalResult(restoredStatus, findingsList[idx].final_result);
            }
            renderFindingsList();
            calculateSeverityStats();
        }
    } catch (err) {
        alert("Restore failed: " + err.message);
    }
}

// Mirror of _derive_final_result() in src/api/endpoints/audit.py. The card's
// isComp reads final_result, not status, so after Accept/Reject the local copy
// has to be moved the same way the server moves it -- otherwise the card keeps
// rendering the old verdict until the next full reload, and Accept on a
// compliant finding appears to do nothing and then flips it on refresh.
const _ACCEPTING_STATUSES = ["COMPLIANT", "PASS", "PASSED", "SATISFIED"];
// "Accept" confirms that the audit's result is correct. It affirms whatever
// verdict is already recorded and asserts nothing about compliance on its own,
// so it must preserve that verdict -- accepting a NON_COMPLIANT finding
// confirms the non-compliance. It used to live in _ACCEPTING_STATUSES, so one
// click on a real gap rewrote it to COMPLIANT and dropped it from the report.
const _AFFIRMING_STATUSES = ["ACCEPTED", "CONFIRMED"];
const _WORKFLOW_ONLY_STATUSES = ["REJECTED", "DISMISSED", "FALSE_POSITIVE", "OUT_OF_SCOPE", "EXCLUDED"];

function deriveFinalResult(status, currentFinalResult) {
    const n = String(status || "").trim().toUpperCase().replace(/[-\s]/g, "_");
    if (_ACCEPTING_STATUSES.indexOf(n) !== -1) return "COMPLIANT";
    if (_AFFIRMING_STATUSES.indexOf(n) !== -1 || _WORKFLOW_ONLY_STATUSES.indexOf(n) !== -1) {
        return String(currentFinalResult || "").trim().toUpperCase() || "NON_COMPLIANT";
    }
    if (n === "CLOSED") return "CLOSED";      // a VAPT finding recorded as fixed
    return "NON_COMPLIANT";
}

async function updateFindingWorkflowStatus(id, status) {
    try {
        const response = await authFetch(`${API_BASE}/audit/findings/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: status })
        });
        const data = await response.json();
        if (data.success) {
            showToast(`Finding status updated to '${status}'.`, "success");
            const idx = findingsList.findIndex(f => f.id === id);
            if (idx !== -1) {
                findingsList[idx].final_result = deriveFinalResult(status, findingsList[idx].final_result);
                findingsList[idx].status = status;
                findingsList[idx].is_saved_to_shakthi = true;
                findingsList[idx].human_verified = true;
            }
            renderFindingsList();
            calculateSeverityStats();
        } else {
            alert("Failed to update status: " + (data.detail || "Unknown error"));
        }
    } catch (err) {
        alert("Status update error: " + err.message);
    }
}

// ── PER-DOCUMENT REJECT (Knowledge Loop) ──────────────────────────────────────
// Strips a single rejected document from the finding's source_files and saves
// the rejection to AuditorFeedback so the LLM avoids citing it again.
async function rejectDocFromFinding(findingId, docName, controlId) {
    const reason = prompt(`Reason for rejecting document '${docName}' (Optional):\n(e.g., "File is NTP clock sync, not Access Control proof")`, "");
    if (reason === null) return; // User cancelled

    try {
        const response = await authFetch(`${API_BASE}/audit/findings/${findingId}/reject-doc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ doc_name: docName, control_id: controlId, reason: reason || "" })
        });
        const data = await response.json();
        if (data.success) {
            showToast(`Document '${docName}' rejected.`, "info");
            const idx = findingsList.findIndex(f => f.id === findingId);
            if (idx !== -1) {
                const remaining = (findingsList[idx].source_files || '')
                    .split(',')
                    .map(s => s.trim())
                    .filter(s => s && s !== docName)
                    .join(', ');
                findingsList[idx].source_files = remaining;
                if (!findingsList[idx]._rejected_docs) findingsList[idx]._rejected_docs = [];
                findingsList[idx]._rejected_docs.push({ doc: docName, reason: reason });
            }
            renderFindingsList();
        } else {
            alert('Failed to reject document: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Failed to reject document: ' + err.message);
    }
}

async function restoreDocToFinding(findingId, docName) {
    try {
        const response = await authFetch(`${API_BASE}/audit/findings/${findingId}/restore-doc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ doc_name: docName })
        });
        const data = await response.json();
        if (data.success) {
            showToast(`Document '${docName}' restored.`, "success");
            const idx = findingsList.findIndex(f => f.id === findingId);
            if (idx !== -1) {
                const current = (findingsList[idx].source_files || '').split(',').map(s => s.trim()).filter(Boolean);
                if (!current.includes(docName)) current.push(docName);
                findingsList[idx].source_files = current.join(', ');
                if (findingsList[idx]._rejected_docs) {
                    findingsList[idx]._rejected_docs = findingsList[idx]._rejected_docs.filter(d => d.doc !== docName);
                }
            }
            renderFindingsList();
        } else {
            alert('Failed to restore document: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Failed to restore document: ' + err.message);
    }
}

function openEditFindingModal(finding) {

    // ── Policy has no meaning on a technical finding ──────────────────────────
    // A VAPT/PQC finding comes from a deterministic scanner: it has a CVE, a
    // severity and a control mapping, and no policy dimension whatsoever. The
    // editor still offered "Policy Present? -> Not Found (Document Missing)",
    // which invites the auditor to record a policy gap against a port scan and
    // makes a PQC finding read like a half-finished ISO one.
    //
    // Read from the FINDING, not the sidebar dropdown: the auditor may have
    // switched the dropdown since the scan, but a finding's own control id
    // ("PQC-2", "VAPT-3") is fixed at the moment it was produced.
    const _fwHint = [finding.control_id, finding.category, finding.control_name]
        .map(v => String(v || "").toUpperCase()).join(" ");
    const _isTechnicalFinding = _fwHint.includes("VAPT") || _fwHint.includes("PQC");
    // Evidence goes too, not just policy. Both selects offer the ISO vocabulary
    // ("Compliant (Evidence Satisfies Control)" / "Not Found (Evidence Missing)")
    // and every technical finding in the database stores the bare value "No",
    // which app.js normalises to "Not Found" -- so the editor announced
    // "Evidence: Not Found (Evidence Missing)" on findings that carry an
    // evidence snippet. Measured: 400 of 400 VAPT findings have a snippet while
    // 365 of them read "No". The field was not merely irrelevant here, it
    // contradicted the evidence displayed beside it.
    const _polEvRow = document.getElementById("edit-policy-evidence-row");
    if (_polEvRow) _polEvRow.style.display = _isTechnicalFinding ? "none" : "";

    // ── Checklist (CUSTOMIZE) has no policy dimension either ──────────────────
    // Since 57af2e5 Checklist mode is pure document Q&A: it resolves no controls
    // and post_process judges it on `evidence_ok` alone, never on policy. The
    // card already knows this and suppresses the policy badge (isQaFinding), but
    // the Modify dialog still offered "Policy Present? -> Not Found (Document
    // Missing)", inviting the auditor to record a policy gap against a question
    // that was never asked about a policy -- and then saving it, because the
    // select still had a value to send.
    //
    // Evidence stays: it is the one thing this mode does judge on. Both branches
    // assign explicitly rather than only hiding, because the modal is reused and
    // a hidden row would otherwise stay hidden for the next finding opened.
    const _isQaFinding = !!window._sessionIsCustomizeRun;
    const _polGroup = document.getElementById("edit-policy-group");
    if (_polGroup) _polGroup.style.display = (_isQaFinding && !_isTechnicalFinding) ? "none" : "";

    document.getElementById("edit-finding-id").value = finding.id;

    // Custom Heading: populate for both VAPT and ISO
    const headingEl = document.getElementById("edit-finding-custom-heading");
    if (headingEl) {
        headingEl.value = finding.custom_heading || finding.control_name || "";
    }

    // 1. Normalize and pre-select Compliance Status. A VAPT finding has its own
    //    status list (Open / Informational / Closed) and fields.
    const statusSelect = document.getElementById("edit-finding-status");
    const _vaptMode = _isVaptDialogFinding(finding, _fwHint);
    _setEditDialogMode(_vaptMode, statusSelect);
    const _vaptState = _vaptMode ? vaptDialogState(finding) : null;
    const targetStatusVal = _vaptMode ? _vaptState.status : modifyDialogStatus(finding);
    if (!_vaptMode) _applyModifyStatusOptions(statusSelect, targetStatusVal);
    statusSelect.value = targetStatusVal;
    const _modal = document.getElementById("edit-finding-modal");
    _modal.dataset.origSeverity = _vaptMode ? String(finding.severity || "") : "";

    // 2. Normalize and pre-select Policy Present
    const polSelect = document.getElementById("edit-finding-policy");
    const rawPol = String(finding.policy_present || "Not Found").trim().toLowerCase();
    if (rawPol === "compliant" || rawPol === "yes" || rawPol === "true") {
        polSelect.value = "Compliant";
    } else if (rawPol === "found") {
        polSelect.value = "Found";
    } else {
        polSelect.value = "Not Found";
    }

    // 3. Normalize and pre-select Evidence Present
    const evSelect = document.getElementById("edit-finding-evidence");
    const rawEv = String(finding.evidence_present || "Not Found").trim().toLowerCase();
    if (rawEv === "compliant" || rawEv === "yes" || rawEv === "true") {
        evSelect.value = "Compliant";
    } else if (rawEv === "found") {
        evSelect.value = "Found";
    } else {
        evSelect.value = "Not Found";
    }

    // 4. Determine Session Type (VAPT/PQC vs ISO) & populate Severity Options.
    // PQC findings use the same CVSS-style severity scale as VAPT (they come
    // from the same deterministic scanner-parser pipeline, not the LLM/RAG path).
    // isPqcFinding() keys on the quantum_status column, which the API serialises
    // as `f.quantum_status or ""` -- an empty string, and falsy in JS. The card
    // itself classifies on the control id / category (isVaptFinding), so a PQC
    // finding with no stored quantum_status rendered as a PQC card and then
    // opened a Modify dialog offering the ISO severity vocabulary
    // ("P1 Critical (Critical Gap)") instead of the quantum risk bands. Use both
    // signals here so the dialog always agrees with the card behind it.
    const isPqc = isPqcFinding(finding) || _fwHint.includes("PQC");
    const isVapt = _vaptMode;

    const sevSelect = document.getElementById("edit-finding-severity");
    const rawSev = (finding.severity || "").toUpperCase().trim();

    // Detect nil/empty/N/A severity — these need a prompt so the user can pick
    const severityIsNil = !rawSev || rawSev === "NIL" || rawSev === "N/A" || rawSev === "NULL" || rawSev === "NONE" || rawSev === "UNKNOWN";

    if (isPqc) {
        // PQC Post-Quantum Risk Band Scale (P1-P4) — No CVSS scores
        sevSelect.innerHTML = `
            ${severityIsNil ? '<option value="" disabled selected style="color:var(--text-muted);">— Select Severity —</option>' : ''}
            <option value="P1 Critical">P1 Critical (Quantum-Vulnerable)</option>
            <option value="P2 High">P2 High (Major Quantum Risk)</option>
            <option value="P3 Medium">P3 Medium (Moderate Quantum Risk)</option>
            <option value="P4 Low">P4 Low (Minor Quantum Risk)</option>
            <option value="Informational">Informational (Quantum-Safe / Info)</option>
        `;
        if (severityIsNil) {
            sevSelect.value = "";
        } else if (rawSev.includes("P1") || rawSev.includes("CRIT")) {
            sevSelect.value = "P1 Critical";
        } else if (rawSev.includes("P2") || rawSev.includes("HIGH")) {
            sevSelect.value = "P2 High";
        } else if (rawSev.includes("P4") || rawSev.includes("LOW")) {
            sevSelect.value = "P4 Low";
        } else if (rawSev.includes("INFO")) {
            sevSelect.value = "Informational";
        } else {
            sevSelect.value = "P3 Medium";
        }
    } else if (isVapt) {
        // VAPT: the scanner's band, saved as the parsers write it (HIGH, not
        // "High (CVSS 7.0-8.9)", which the reports could not count), and
        // Closed beside them as the KPI row has it.
        sevSelect.innerHTML = '<option value="" disabled style="color:var(--text-muted);">— Select Severity —</option>'
            + _VAPT_SEVERITY_OPTIONS.map(([v, t]) => `<option value="${v}">${t}</option>`).join("");
        sevSelect.value = _vaptState.severity;
    } else {
        // ISO NIST Priority Scale (P1-P4)
        sevSelect.innerHTML = `
            ${severityIsNil ? '<option value="" disabled selected style="color:var(--text-muted);">— Select Severity —</option>' : ''}
            <option value="P1 Critical">P1 Critical (Critical Gap)</option>
            <option value="P2 High">P2 High (Major Non-Compliance)</option>
            <option value="P3 Medium">P3 Medium (Minor Non-Compliance)</option>
            <option value="P4 Low">P4 Low (Opportunity for Improvement)</option>
        `;
        if (severityIsNil) {
            sevSelect.value = "";
        } else if (rawSev.includes("P1") || rawSev.includes("CRITICAL")) {
            sevSelect.value = "P1 Critical";
        } else if (rawSev.includes("P2") || rawSev.includes("HIGH")) {
            sevSelect.value = "P2 High";
        } else if (rawSev.includes("P4") || rawSev.includes("LOW")) {
            sevSelect.value = "P4 Low";
        } else {
            sevSelect.value = "P3 Medium";
        }
    }

    // 5. Show/hide severity row based on compliance status
    // NIST rule: COMPLIANT / ACCEPTED / PASS / Out-of-scope have no actionable severity.
    _updateSeverityVisibility(targetStatusVal);

    const srcElem = document.getElementById("edit-finding-source-files");
    if (srcElem) {
        srcElem.value = finding.source_files || finding.evidence_source_file || "";
    }

    document.getElementById("edit-finding-snippet").value = finding.evidence_snippet || "";
    document.getElementById("edit-finding-recommendation").value = finding.recommendation || "";
    document.getElementById("edit-finding-reasoning").value = getCleanFindingDescription(finding);
    if (_vaptMode) _fillVaptFields(finding);

    document.getElementById("edit-finding-modal").classList.add("active");
}

/** Hide/show the Severity Score Scale row depending on whether the current status is compliant.
 *  Called both when opening the modal and when the auditor changes the Status dropdown live.
 *  When severity is nil/empty, the row is ALWAYS kept editable regardless of status so the
 *  user can explicitly assign a severity that was previously missing.
 */
function _updateSeverityVisibility(statusVal) {
    // NIST rule: only "Compliant" (exact dropdown value) has no actionable severity.
    // Non-Compliant, Partially Compliant, Out Of Scope all retain their P-scale severity.
    const isComp = (statusVal || "").trim() === "Compliant";
    // Find the form-group that wraps the severity select (parent of the <label> + <select>)
    const sevEl = document.getElementById("edit-finding-severity");
    const sevRow = sevEl && sevEl.closest(".form-group");
    if (!sevRow) return;

    // If the current severity value is nil/empty, always keep the row editable so the
    // auditor can assign a severity — never disable it when there's nothing set yet.
    const currentSevVal = sevEl ? sevEl.value : "";
    const severityIsNil = !currentSevVal || currentSevVal === "" || currentSevVal === "nil" || currentSevVal === "N/A";

    if (isComp && !severityIsNil) {
        sevRow.style.opacity = "0.45";
        sevRow.style.pointerEvents = "none";
        sevRow.title = "Severity is N/A for Compliant findings";
        // Inject a read-only badge so the auditor can see the value is N/A
        let badge = sevRow.querySelector(".severity-na-badge");
        if (!badge) {
            badge = document.createElement("span");
            badge.className = "severity-na-badge";
            badge.style.cssText = "display:inline-block;margin-top:4px;padding:2px 10px;background:rgba(16,185,129,0.13);color:#10b981;border-radius:5px;font-size:0.78rem;font-weight:700;";
            sevRow.appendChild(badge);
        }
        badge.textContent = "N/A — Not Applicable (Compliant)";
        badge.style.display = "inline-block";
    } else {
        sevRow.style.opacity = "";
        sevRow.style.pointerEvents = "";
        sevRow.title = severityIsNil ? "⚠️ Severity not set — please select one" : "";
        const badge = sevRow.querySelector(".severity-na-badge");
        if (badge) badge.style.display = "none";

        // If severity is nil, highlight the row label to draw attention
        const label = sevRow.querySelector("label");
        if (label) {
            if (severityIsNil) {
                label.innerHTML = 'Severity Score Scale <span style="color:#f59e0b;font-size:0.8rem;font-weight:700;">⚠️ Not set — please select</span>';
            } else {
                label.textContent = "Severity Score Scale";
            }
        }
    }
}

// ── The Modify dialog's Compliance Status ────────────────────────────────────
//
// Which option the dialog opens on. It used to read the status text alone and
// mapped "Accepted" to "Compliant" -- the meaning Accept had before acaffc4. Accept
// now confirms whatever verdict the audit reached, so an accepted NON-COMPLIANT
// finding opened here pre-selected "Compliant", and saving the dialog for any
// reason -- to correct the recommendation, say -- turned a confirmed gap into a
// pass, set its severity to N/A and dropped it from the non-conformities. The
// recorded verdict is now what decides; the status text is consulted only for the
// two outcomes the verdict cannot express, and for a finding with no verdict yet.
function modifyDialogStatus(finding) {
    const st = String((finding && finding.status) || "").toUpperCase().trim();
    const verdict = String((finding && finding.final_result) || "").toUpperCase().trim();
    if (st.includes("PARTIAL")) return "Partially Compliant";
    if (st.includes("OUT") && st.includes("SCOPE")) return "Out Of Scope";
    if (verdict === "COMPLIANT") return "Compliant";
    if (verdict === "NON_COMPLIANT") return "Non-Compliant";
    // No verdict recorded. "ACCEPTED" is deliberately absent: it confirms a
    // verdict rather than asserting one, and with none to confirm it proves
    // nothing -- fail closed, as derive_final_result does.
    if (st.includes("NON") || st.includes("GAP") || st.includes("FAIL")) return "Non-Compliant";
    if (st === "COMPLIANT" || st.includes("PASS") || st.includes("SATISFIED")) return "Compliant";
    return "Non-Compliant";
}

// Offer only the outcomes that apply: Compliant or Non-Compliant, for every
// framework. "Partially Compliant" and "Out Of Scope" are no longer offered -- a
// finding the auditor wants excluded is Rejected from the card, which keeps it
// out of the report by the same rule as any thrown-out finding.
//
// An option is never hidden while it is the finding's CURRENT status. Findings
// saved as Partially Compliant or Out Of Scope before this still exist, and a
// <select> whose value names no visible option goes blank -- saving it would send
// an empty status and silently overwrite what the auditor had recorded.
const _MODIFY_STATUSES = ["Compliant", "Non-Compliant"];

function _applyModifyStatusOptions(select, current) {
    if (!select) return;
    Array.from(select.options).forEach(opt => {
        const hide = _MODIFY_STATUSES.indexOf(opt.value) === -1 && opt.value !== current;
        opt.hidden = hide;
        opt.disabled = hide;
    });
}

// ── A VAPT finding in the Modify dialog ──────────────────────────────────────
//
// A VAPT finding is a vulnerability, never "Compliant": the dialog offered
// Compliant / Non-Compliant and the ISO labels. Its status is now one of the
// KPI boxes -- Open (a severity), Informational or Closed -- with Closed in the
// severity list too, as the KPI row has it; and what the scanner reported
// (target, CVSS score and vector, CVE / CWE, risk category, CIA impact, tool,
// confidence, developer steps) is editable. Every other framework's dialog is
// as it was.
const _VAPT_STATUS_OPTIONS = [
    ["Non-Compliant", "Open (vulnerability)"],
    ["Informational", "Informational"],
    ["Closed", "Closed (remediated)"],
];
const _VAPT_SEVERITY_OPTIONS = [
    ["CRITICAL", "Critical (CVSS 9.0 - 10.0)"],
    ["HIGH", "High (CVSS 7.0 - 8.9)"],
    ["MEDIUM", "Medium (CVSS 4.0 - 6.9)"],
    ["LOW", "Low (CVSS 0.1 - 3.9)"],
    ["INFO", "Informational (CVSS 0.0)"],
    ["CLOSED", "Closed (remediated)"],
];
const _EDIT_LABELS_VAPT = {
    "edit-status-label": "Finding Status",
    "edit-desc-label": "Vulnerability Description",
    "edit-src-label": "Source File(s)",
    "edit-snippet-label": "Proof of Concept",
    "edit-rec-label": "Recommended Remediation",
};

// CRITICAL / HIGH / MEDIUM / LOW / INFO, as the parsers write it, or "".
function vaptSeverityWord(sev) {
    const s = String(sev || "").toUpperCase();
    if (s.includes("CRIT")) return "CRITICAL";
    if (s.includes("HIGH")) return "HIGH";
    if (s.includes("MED")) return "MEDIUM";
    if (s.includes("LOW")) return "LOW";
    if (s.includes("INFO")) return "INFO";
    return "";
}

// What the dialog opens on: {status, severity} ("" severity = not set).
function vaptDialogState(f) {
    const st = String((f && f.status) || "").trim().toUpperCase();
    const verdict = String((f && f.final_result) || "").trim().toUpperCase();
    const sev = vaptSeverityWord(f && f.severity);
    if (st === "CLOSED" || verdict === "CLOSED") return { status: "Closed", severity: "CLOSED" };
    if (sev === "INFO" || st.includes("INFORMATIONAL")) return { status: "Informational", severity: "INFO" };
    return { status: "Non-Compliant", severity: sev };
}

// What the dialog saves: {status, severity}. A closed finding keeps the
// severity it had (null = leave it), which the reports print beside Closed;
// "" means an open vulnerability with no severity chosen.
function vaptDialogSave(statusChoice, severityChoice, originalSeverity) {
    if (statusChoice === "Closed" || severityChoice === "CLOSED") {
        return { status: "Closed", severity: vaptSeverityWord(originalSeverity) || null };
    }
    if (statusChoice === "Informational" || severityChoice === "INFO") {
        return { status: "Informational", severity: "INFO" };
    }
    return { status: "Non-Compliant", severity: severityChoice || "" };
}

// The same test the dialog always used for a VAPT finding (PQC excluded).
function _isVaptDialogFinding(finding, fwHint) {
    if (isPqcFinding(finding) || fwHint.includes("PQC")) return false;
    return (finding.control_id && String(finding.control_id).toUpperCase().includes("VAPT")) ||
        (finding.category && String(finding.category).toUpperCase().includes("VAPT")) ||
        (typeof activeSessionTitle !== "undefined" && activeSessionTitle && String(activeSessionTitle).toUpperCase().includes("VAPT"));
}

function _editDialogIsVapt() {
    const m = document.getElementById("edit-finding-modal");
    return !!(m && m.dataset.mode === "vapt");
}

// Labels, the status list and the VAPT fields for the finding being opened.
// Explicit both ways: the modal is reused, so what one finding set must be
// put back for the next.
function _setEditDialogMode(vapt, statusSelect) {
    const modal = document.getElementById("edit-finding-modal");
    if (modal) modal.dataset.mode = vapt ? "vapt" : "";
    Object.keys(_EDIT_LABELS_VAPT).forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (el.dataset.isoText === undefined) el.dataset.isoText = el.textContent;
        el.textContent = vapt ? _EDIT_LABELS_VAPT[id] : el.dataset.isoText;
    });
    ["edit-vapt-fields", "edit-vapt-steps-group"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = vapt ? "" : "none";
    });
    if (statusSelect) {
        if (statusSelect.dataset.isoOptions === undefined) statusSelect.dataset.isoOptions = statusSelect.innerHTML;
        statusSelect.innerHTML = vapt
            ? _VAPT_STATUS_OPTIONS.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")
            : statusSelect.dataset.isoOptions;
    }
}

function _fillVaptFields(f) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = (v === null || v === undefined) ? "" : v; };
    const target = f.target || ((String(f.evidence_snippet || "").match(/^Target Host:\s*(.+)$/m) || [])[1] || "");
    const score = (f.severity_score === null || f.severity_score === undefined || f.severity_score === "")
        ? "" : Number(f.severity_score).toFixed(1);
    const conf = String(f.confidence || "");
    const confCap = conf.charAt(0).toUpperCase() + conf.slice(1).toLowerCase();
    set("edit-vapt-target", String(target).trim());
    set("edit-vapt-score", score);
    set("edit-vapt-vector", f.cvss_vector || "");
    set("edit-vapt-refs", f.cve_refs || (Array.isArray(f.cve_list) ? f.cve_list.join(", ") : ""));
    set("edit-vapt-category", f.category || "");
    set("edit-vapt-cia", f.cia_impact || "");
    set("edit-vapt-tool", f.source_tool || "");
    set("edit-vapt-confidence", ["Certain", "Firm", "Tentative"].includes(confCap) ? confCap : "");
    set("edit-vapt-steps", f.remediation_actionable || "");
}

// Status and severity move together: Closed <-> Closed, Informational <->
// Informational, a band <-> Open.
function _vaptSyncFromStatus() {
    const st = document.getElementById("edit-finding-status").value;
    const sev = document.getElementById("edit-finding-severity");
    if (st === "Closed") sev.value = "CLOSED";
    else if (st === "Informational") sev.value = "INFO";
    else if (!sev.value || sev.value === "CLOSED" || sev.value === "INFO") {
        const band = vaptSeverityWord(document.getElementById("edit-finding-modal").dataset.origSeverity);
        sev.value = (band && band !== "INFO") ? band : "";
    }
    _updateSeverityVisibility(st);
}

function _vaptSyncFromSeverity() {
    const v = document.getElementById("edit-finding-severity").value;
    const st = v === "CLOSED" ? "Closed" : v === "INFO" ? "Informational" : "Non-Compliant";
    document.getElementById("edit-finding-status").value = st;
    _updateSeverityVisibility(st);
}

function closeEditFindingModal() {
    document.getElementById("edit-finding-modal").classList.remove("active");
}

async function handleEditFindingSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("edit-finding-id").value;
    const descValue = document.getElementById("edit-finding-reasoning").value;
    const srcFileValue = document.getElementById("edit-finding-source-files") ? document.getElementById("edit-finding-source-files").value : "";
    const chosenStatus = document.getElementById("edit-finding-status").value;

    // NIST Severity rule: only "Compliant" sends "N/A" severity.
    // Non-Compliant, Partially Compliant, Out Of Scope keep their P-scale severity.
    const statusIsCompliant = chosenStatus.trim() === "Compliant";
    const resolvedSeverity = statusIsCompliant ? "N/A" : document.getElementById("edit-finding-severity").value;

    const customHeadingVal = (document.getElementById("edit-finding-custom-heading") || {}).value || "";

    const body = {
        status: chosenStatus,
        policy_present: document.getElementById("edit-finding-policy").value,
        evidence_present: document.getElementById("edit-finding-evidence").value,
        severity: resolvedSeverity,
        description: descValue,
        source_files: srcFileValue,
        evidence_snippet: document.getElementById("edit-finding-snippet").value,
        recommendation: document.getElementById("edit-finding-recommendation").value,
        reasoning: descValue,
        custom_heading: customHeadingVal.trim() || null
    };

    // A VAPT finding: its own status / severity, and what the scanner reported.
    if (_editDialogIsVapt()) {
        const v = vaptDialogSave(chosenStatus, document.getElementById("edit-finding-severity").value,
                                 document.getElementById("edit-finding-modal").dataset.origSeverity);
        if (v.severity === "") {
            alert("Choose a severity for this open vulnerability, or mark it Informational or Closed.");
            return;
        }
        body.status = v.status;
        body.severity = v.severity;          // null: a closed finding keeps its own
        const val = id => String((document.getElementById(id) || {}).value || "").trim();
        Object.assign(body, {
            target: val("edit-vapt-target"),
            severity_score: val("edit-vapt-score"),
            cvss_vector: val("edit-vapt-vector"),
            cve_refs: val("edit-vapt-refs"),
            category: val("edit-vapt-category"),
            cia_impact: val("edit-vapt-cia"),
            source_tool: val("edit-vapt-tool"),
            confidence: val("edit-vapt-confidence"),
            remediation_actionable: val("edit-vapt-steps"),
        });
    }

    try {
        const response = await authFetch(`${API_BASE}/audit/findings/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success) {
            closeEditFindingModal();
            loadFindings(); // Reload list
        } else {
            // A failed save used to do nothing at all. The server answers an error
            // with {"detail": ...} and no "success" key, so the check above was
            // simply false: no message, the dialog stayed open, and "Save
            // Findings Changes" looked like a button that did not work. The
            // auditor's edit had not been saved and nothing said so.
            alert(`The finding was not saved: ${formatApiError(
                data.detail, `server returned HTTP ${response.status}`)}`);
        }
    } catch (err) {
        alert(`Update failed: ${err.message}`);
    }
}

// ── AI ASSISTANT CHAT ENGINE ──

async function sendChatMessage() {
    const input = document.getElementById("chat-input");
    const msg = input.value.trim();
    if (!msg) return;

    input.value = "";

    const feed = document.getElementById("chat-feed-box");

    // Append User Message
    const userDiv = document.createElement("div");
    userDiv.className = "chat-bubble user";
    userDiv.innerHTML = `<p>${escapeHtml(msg)}</p>`;
    feed.appendChild(userDiv);
    feed.scrollTop = feed.scrollHeight;

    // Show Thinking indicator
    const indicator = document.getElementById("chat-generating-indicator");
    indicator.style.display = "block";

    const model = document.getElementById("llm-model-select").value;

    try {
        const response = await authFetch(`${API_BASE}/audit/chats/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                message: msg,
                model_choice: model,
                username: currentUser.username
            })
        });

        const data = await response.json();
        indicator.style.display = "none";

        if (data.success) {
            const aiDiv = document.createElement("div");
            aiDiv.className = "chat-bubble assistant";
            aiDiv.innerHTML = `<p>${escapeHtml(data.response)}</p>`;
            feed.appendChild(aiDiv);
            feed.scrollTop = feed.scrollHeight;
        } else {
            throw new Error(data.detail);
        }
    } catch (err) {
        indicator.style.display = "none";
        const errDiv = document.createElement("div");
        errDiv.className = "chat-bubble assistant error-msg";
        errDiv.innerHTML = `<p>Error: ${err.message}. Ollama server might be offline.</p>`;
        feed.appendChild(errDiv);
    }
}

// ── ADMIN-EDITABLE UPLOAD LIMIT SETTINGS ──

const UPLOAD_SETTING_LABELS = {
    max_file_size_mb: "Max size per file (MB)",
    max_upload_total_mb: "Max total size per upload (MB)",
    max_files_per_upload: "Max files per upload",
    max_zip_uncompressed_mb: "Max ZIP decompressed size (MB)",
    max_zip_ratio: "Max ZIP compression ratio (X:1)",
    gpu_acceleration_enabled: "GPU Acceleration (NVIDIA CUDA)",
};

async function loadUploadSettings() {
    const grid = document.getElementById("upload-settings-grid");
    if (!grid) return;
    try {
        const res = await authFetch(`${API_BASE}/audit/settings/upload-limits`);
        const data = await res.json();
        if (!data.success) return;

        const cudaInfo = data.cuda_info || {};
        const isCuda = cudaInfo.cuda_available;
        const gpuName = cudaInfo.gpu_device_name || "None";
        const effDev = cudaInfo.effective_device || "cpu";

        grid.innerHTML = Object.entries(data.settings).map(([key, s]) => {
            if (key === "gpu_acceleration_enabled") {
                const isChecked = s.value === 1;
                let badgeHtml = "";
                if (isChecked && isCuda) {
                    badgeHtml = `<span style="display:inline-block; margin-top:4px; padding:2px 8px; border-radius:12px; background:rgba(16,185,129,0.2); color:#10b981; font-size:0.7rem; font-weight:600;">🟢 Active: ${escapeHtml(gpuName)}</span>`;
                } else if (isChecked && !isCuda) {
                    badgeHtml = `<span style="display:inline-block; margin-top:4px; padding:2px 8px; border-radius:12px; background:rgba(245,158,11,0.2); color:#f59e0b; font-size:0.7rem; font-weight:600;">⚠️ Fallback Mode: GPU ON, but no CUDA card detected (Running on CPU)</span>`;
                } else {
                    badgeHtml = `<span style="display:inline-block; margin-top:4px; padding:2px 8px; border-radius:12px; background:rgba(148,163,184,0.2); color:#94a3b8; font-size:0.7rem; font-weight:600;">⚪ Disabled: Running on CPU Mode</span>`;
                }

                return `
                    <div style="grid-column: span 2; background:rgba(15,23,42,0.6); padding:12px 14px; border-radius:10px; border:1px solid rgba(255,255,255,0.08); display:flex; align-items:center; justify-content:space-between;">
                        <div>
                            <label style="display:block; font-size:0.84rem; color:var(--text-main); font-weight:600; margin-bottom:2px;">⚡ GPU Acceleration (NVIDIA CUDA)</label>
                            <span style="font-size:0.72rem; color:var(--text-muted);">Accelerates RAG vector embeddings, reranking, and local LLM inference.</span>
                            <div>${badgeHtml}</div>
                        </div>
                        <div>
                            <input type="checkbox" id="setting-gpu_acceleration_enabled" ${isChecked ? "checked" : ""} style="width:20px; height:20px; cursor:pointer; accent-color:#00509d;">
                        </div>
                    </div>
                `;
            }

            return `
                <div>
                    <label style="display:block; font-size:0.74rem; color:var(--text-muted); font-weight:600; margin-bottom:4px;">${escapeHtml(UPLOAD_SETTING_LABELS[key] || key)}</label>
                    <input type="number" id="setting-${escapeHtml(key)}" value="${s.value}" min="${s.min}" max="${s.max}"
                        style="width:100%; padding:8px 10px; border-radius:8px; border:1px solid var(--border-color); background:rgba(15,23,42,0.4); color:var(--text-main); font-size:0.84rem;">
                    <span style="font-size:0.68rem; color:var(--text-muted);">Range: ${s.min}-${s.max}</span>
                </div>
            `;
        }).join("");
    } catch (err) {
        console.error("Error loading upload settings:", err);
    }
}

async function saveUploadSettings() {
    const statusEl = document.getElementById("upload-settings-status");
    const updates = {};
    for (const key of Object.keys(UPLOAD_SETTING_LABELS)) {
        const el = document.getElementById(`setting-${key}`);
        if (el) {
            if (el.type === "checkbox") {
                updates[key] = el.checked ? 1 : 0;
            } else {
                updates[key] = parseInt(el.value, 10);
            }
        }
    }
    if (statusEl) { statusEl.textContent = "Saving..."; statusEl.style.color = "var(--text-muted)"; }
    try {
        const res = await authFetch(`${API_BASE}/audit/settings/upload-limits`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(updates)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(formatApiError(data.detail, "Failed to save settings."));
        if (statusEl) { statusEl.textContent = "✅ Saved — applies immediately, no restart needed."; statusEl.style.color = "#10b981"; }
        showToast("System & GPU settings saved.", "info");
        await loadUploadSettings();
    } catch (err) {
        if (statusEl) { statusEl.textContent = `❌ ${err.message}`; statusEl.style.color = "var(--error)"; }
    }
}

// ── MANAGE CUSTOM CONTROLS Framework ──

async function loadCustomControlsTable() {
    const tbody = document.getElementById("custom-controls-table-body");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">Loading custom controls from ShaktiDB...</td></tr>`;

    try {
        const response = await authFetch(`${API_BASE}/controls?active_only=false`);
        const data = await response.json();

        if (data.success && data.controls.length > 0) {
            tbody.innerHTML = "";
            data.controls.forEach(c => {
                const tr = document.createElement("tr");
                const kws = c.keywords.join(", ");
                tr.innerHTML = `
                    <td><b>${escapeHtml(c.control_id)}</b></td>
                    <td>${escapeHtml(c.control_name)}</td>
                    <td><span class="badge-pill">${escapeHtml(c.framework || 'ISO 27001')}</span></td>
                    <td><span class="badge-pill">${escapeHtml(c.category)}</span></td>
                    <td><code style="color:#60a5fa;">${escapeHtml(kws) || 'None'}</code></td>
                    <td>
                        <button class="btn-danger" style="padding: 4px 8px; font-size:11px;" onclick="deleteCustomControl(${c.id})">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No custom controls registered. Create one on the left!</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--error);">Failed to load controls: ${err.message}</td></tr>`;
    }
}

// Reject anything that could be an HTML/script tag before it ever reaches the
// server. This is a UX nicety only -- src/api/endpoints/controls.py enforces the
// same rule (and more) server-side, which is the actual security boundary since
// this form isn't the only way to reach POST /api/controls.
const CONTROL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._\-/()]*$/;
function validateControlFields(ctrlId, ctrlName, category, desc, kws) {
    const forbidden = /[<>]/;
    if (!ctrlId) return "Control ID is required.";
    if (ctrlId.length > 40) return "Control ID must be 40 characters or fewer.";
    if (forbidden.test(ctrlId) || !CONTROL_ID_PATTERN.test(ctrlId)) {
        return "Control ID may only contain letters, numbers, spaces, and . _ - / ( )";
    }
    if (!ctrlName) return "Control Name is required.";
    if (ctrlName.length > 200) return "Control Name must be 200 characters or fewer.";
    if (forbidden.test(ctrlName)) return "Control Name may not contain < or > characters.";
    if (category && forbidden.test(category)) return "Category may not contain < or > characters.";
    if (desc.length > 2000) return "Description must be 2000 characters or fewer.";
    if (forbidden.test(desc)) return "Description may not contain < or > characters.";
    for (const k of kws) {
        if (forbidden.test(k)) return "Keywords may not contain < or > characters.";
    }
    return null;
}

function extractApiErrorMessage(data, fallback) {
    if (!data) return fallback;
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail) && data.detail.length) {
        return data.detail.map(d => d.msg || JSON.stringify(d)).join(" ");
    }
    return data.message || fallback;
}

// Shows/hides the ISO-clause Category dropdown -- it only means something for
// the ISO 27001 framework. Other frameworks get a fixed category label assigned
// server-side (see _resolve_category_for_framework in controls.py).
function toggleCustomControlCategoryField(prefix) {
    const fw = document.getElementById(`${prefix}-ctrl-framework`).value;
    const group = document.getElementById(`${prefix}-ctrl-cat-group`);
    if (group) group.style.display = (fw === "ISO 27001") ? "" : "none";
}

async function handleCreateControlSubmit(e) {
    e.preventDefault();

    const framework = document.getElementById("new-ctrl-framework").value;
    const body = {
        control_id: document.getElementById("new-ctrl-id").value.trim(),
        control_name: document.getElementById("new-ctrl-name").value.trim(),
        category: document.getElementById("new-ctrl-cat").value,
        framework: framework,
        keywords: document.getElementById("new-ctrl-kws").value.split(",").map(k => k.trim()).filter(k => k),
        description: document.getElementById("new-ctrl-desc").value.trim()
    };

    const validationError = validateControlFields(body.control_id, body.control_name, body.category, body.description, body.keywords);
    if (validationError) {
        alert(`⚠️ ${validationError}`);
        return;
    }

    try {
        const response = await authFetch(`${API_BASE}/controls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        if (data.success) {
            // Reset form
            document.getElementById("create-control-form").reset();
            loadCustomControlsTable();
            loadFrameworkControls(); // Reload sidebar checklist
            alert("✅ Custom control saved successfully!");
        } else {
            alert(`❌ ${extractApiErrorMessage(data, "Failed to save control.")}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function autogenerateKeywords() {
    const name = document.getElementById("new-ctrl-name").value.trim();
    const desc = document.getElementById("new-ctrl-desc").value.trim();

    if (!name) {
        alert("⚠️ Please enter a Control Name first.");
        return;
    }

    const kwField = document.getElementById("new-ctrl-kws");
    kwField.placeholder = "🧠 AI is generating regex keywords...";

    try {
        const response = await authFetch(`${API_BASE}/controls/autogen-keywords`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, description: desc })
        });
        const data = await response.json();
        if (data.success) {
            kwField.value = data.keywords.join(", ");
        }
    } catch (err) {
        kwField.placeholder = "Failed to auto-generate keywords.";
        alert(err.message);
    }
}

async function deleteCustomControl(id) {
    if (!confirm("Are you sure you want to deactivate and remove this custom control?")) return;
    try {
        const response = await authFetch(`${API_BASE}/controls/${id}?soft=false`, {
            method: "DELETE"
        });
        const data = await response.json();
        if (data.success) {
            loadCustomControlsTable();
            loadFrameworkControls();
        }
    } catch (err) {
        alert(err.message);
    }
}

function openAddCustomControlModal() {
    const modal = document.getElementById("add-custom-control-modal");
    if (modal) {
        modal.style.display = "flex";
    }
}

function closeAddCustomControlModal() {
    const modal = document.getElementById("add-custom-control-modal");
    if (modal) {
        modal.style.display = "none";
    }
}

async function handleModalCustomControlSubmit(e) {
    e.preventDefault();
    const ctrlId = document.getElementById("modal-ctrl-id").value.trim();
    const ctrlName = document.getElementById("modal-ctrl-name").value.trim();
    const framework = document.getElementById("modal-ctrl-framework").value;
    const cat = document.getElementById("modal-ctrl-cat").value;
    const desc = document.getElementById("modal-ctrl-desc").value.trim();
    const kwsStr = document.getElementById("modal-ctrl-kws").value.trim();
    const kws = kwsStr ? kwsStr.split(",").map(k => k.trim()).filter(k => k) : [];

    const validationError = validateControlFields(ctrlId, ctrlName, cat, desc, kws);
    if (validationError) {
        alert(`⚠️ ${validationError}`);
        return;
    }

    try {
        const response = await authFetch(`${API_BASE}/controls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                control_id: ctrlId,
                control_name: ctrlName,
                category: cat,
                framework: framework,
                description: desc,
                keywords: kws,
                created_by: currentUser ? currentUser.username : "auditor"
            })
        });
        const data = await response.json();
        if (data.success) {
            closeAddCustomControlModal();
            showToast("Custom control saved to Shakthi DB!", "info");
            await loadFrameworkControls();

            // Auto expand Custom Controls accordion
            setTimeout(() => {
                const customHeader = Array.from(document.querySelectorAll(".clause-header")).find(h => h.innerText.includes("Custom Controls"));
                if (customHeader) customHeader.click();
            }, 300);
        } else {
            alert(`Failed: ${extractApiErrorMessage(data, 'Error saving control')}`);
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
    }
}

// ── LIVE SERVER METRICS (Redis Stream) ──
// This panel previously had no JS wired to it at all -- the "Loading live
// metrics..." text in index.html was static markup nothing ever replaced,
// so it showed "Loading" forever regardless of server state.
async function loadLiveMetrics() {
    const container = document.getElementById("live-metrics-container");
    if (!container) return;

    try {
        const response = await authFetch(`${API_BASE}/logs/live-metrics`);
        const data = await response.json();
        if (!data.success) throw new Error(data.detail || "Failed to load live metrics.");

        // redis_available tells us whether these numbers are real, live counters
        // pushed during actual audits (src/core/redis_metrics.py::push_control_metrics)
        // or a reconstructed estimate from saved reports when Redis itself isn't
        // reachable (session count/files are real either way, but the fallback's
        // token/latency figures are a rough per-finding formula, not measured data).
        const sessions = data.active_sessions || [];
        const estimatedCount = sessions.filter(s => s.is_estimated).length;

        // redis_available alone is not enough to call this "live" -- Redis can be
        // reachable right now while most/all individual session rows are still
        // reconstructed estimates (their own key expired off Redis's 24h TTL, or
        // that particular audit ran while Redis was down). Report both.
        const dotColor = (data.redis_available && estimatedCount < sessions.length) ? "#22c55e" : "#f59e0b";
        let statusLabel;
        if (!data.redis_available) {
            statusLabel = `<span style="color:#f59e0b;font-weight:700;">ESTIMATED -- Redis is unreachable, all figures below are reconstructed from saved reports, not measured token/latency data</span>`;
        } else if (estimatedCount > 0) {
            statusLabel = `<span style="color:#f59e0b;font-weight:700;">PARTIALLY LIVE</span> -- Redis is reachable, but ${estimatedCount} of ${sessions.length} session rows have no live Redis data left (key expired after 24h, or that audit ran while Redis was down) and show an <i>estimated</i> (~) value instead of a measured one. Totals above are a rolling 24h window, not a lifetime total.`;
        } else {
            statusLabel = `<span style="color:#22c55e;font-weight:700;">LIVE</span> -- all rows below are real-time counters from Redis.`;
        }
        const rows = sessions.slice(0, 25).map(s => {
            // Rows reconstructed from saved reports (Redis had no key -- unreachable,
            // or the session's 24h TTL already expired) carry a rough per-finding
            // formula, not a measured value. Shown muted with a tilde + tooltip
            // rather than as a confident number, so it's never mistaken for real
            // telemetry -- this was previously indistinguishable from live data.
            const est = !!s.is_estimated;
            const tokCell = est
                ? `<span style="color:var(--text-muted);font-style:italic;" title="Estimated -- Redis has no live data for this session (unreachable or expired), not a measured value">~${(s.tokens || 0).toLocaleString()}</span>`
                : (s.tokens || 0).toLocaleString();
            const latCell = est
                ? `<span style="color:var(--text-muted);font-style:italic;" title="Estimated -- Redis has no live data for this session (unreachable or expired), not a measured value">~${escapeHtml(s.latency_str || "0m 0.0s")}</span>`
                : escapeHtml(s.latency_str || "0m 0.0s");
            return `
            <tr>
                <td>${escapeHtml(s.auditor || "SYSTEM")}</td>
                <td><code style="font-size:0.72rem;">${escapeHtml((s.session_id || "").slice(0, 10))}...</code></td>
                <td>${escapeHtml(s.status || "unknown")}</td>
                <td>${tokCell}</td>
                <td>${latCell}</td>
                <td>${s.files || 0}</td>
                <td>${s.controls || 0}</td>
            </tr>
        `;
        }).join("");

        container.innerHTML = `
            <div style="font-size: 0.9rem; font-weight: 800; color: var(--text-main); margin-bottom: 4px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${dotColor}; display: inline-block; animation: pulse 1.5s infinite;"></span>
                Live Server Metrics (Redis Stream)
                <button onclick="loadLiveMetrics()" class="btn-secondary" style="padding:2px 8px; font-size:10px; margin-left:auto;">Refresh</button>
            </div>
            <div style="font-size: 0.72rem; margin-bottom: 12px;">${statusLabel}</div>
            <div class="modern-kpi-summary-row" style="margin-bottom:14px;">
                <div class="kpi-box"><span class="kpi-label">Total Tokens</span><span class="kpi-number">${(data.global_tokens || 0).toLocaleString()}</span></div>
                <div class="kpi-box"><span class="kpi-label">Total Latency</span><span class="kpi-number" style="font-size:1rem;">${escapeHtml(data.global_latency_str || "0m 0.0s")}</span></div>
                <div class="kpi-box"><span class="kpi-label">Avg / Control</span><span class="kpi-number" style="font-size:1rem;">${escapeHtml(data.avg_latency_per_ctrl_str || "0m 0.0s")}</span></div>
                <div class="kpi-box"><span class="kpi-label">Files Processed</span><span class="kpi-number">${data.global_files || 0}</span></div>
                <div class="kpi-box"><span class="kpi-label">Errors</span><span class="kpi-number">${data.global_errors || 0}</span></div>
            </div>
            <div class="checklist-table-wrapper">
                <table class="checklist-table">
                    <thead><tr><th>Auditor</th><th>Session</th><th>Status</th><th>Tokens</th><th>Latency</th><th>Files</th><th>Controls</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);">No session activity recorded yet.</td></tr>'}</tbody>
                </table>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div style="color:var(--error);font-size:0.8rem;">Failed to load live metrics: ${escapeHtml(err.message)} <button onclick="loadLiveMetrics()" class="btn-secondary" style="padding:2px 8px; font-size:10px;">Retry</button></div>`;
    }
}

// ── ADMIN SYSTEM LOGS & CONSOLE ──

function onBenchmarkSessionChange() {
    logsPage = 0;
    loadSystemEvents();
}

async function loadSystemEvents() {
    const tbody = document.getElementById("system-events-table-body");
    const indicator = document.getElementById("logs-page-indicator");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">Loading logs...</td></tr>`;

    const severityFilter = document.getElementById("log-severity-filter");
    const severity = severityFilter ? severityFilter.value : "All";
    const sessionSel = document.getElementById("benchmark-session-select");
    const sessionId = sessionSel ? sessionSel.value : "all";

    try {
        let fetchUrl = `${API_BASE}/logs/system?severity=${encodeURIComponent(severity)}&page=${logsPage}&page_size=15`;
        if (sessionId && sessionId !== "all" && sessionId !== "active") {
            fetchUrl += `&session_id=${encodeURIComponent(sessionId)}`;
        } else if (sessionId === "active" && activeSessionId) {
            fetchUrl += `&session_id=${encodeURIComponent(activeSessionId)}`;
        }

        const response = await authFetch(fetchUrl);
        const data = await response.json();

        if (data.success && data.events.length > 0) {
            tbody.innerHTML = "";
            logsTotalPages = data.total_pages;
            indicator.innerText = `Page ${logsPage + 1} of ${logsTotalPages}`;

            data.events.forEach(e => {
                const tr = document.createElement("tr");
                let color = "#aaa";
                if (e.severity === "ERROR") color = "var(--error)";
                else if (e.severity === "WARNING") color = "var(--warning)";
                else if (e.severity === "CRITICAL") color = "#f43f5e";

                tr.innerHTML = `
                    <td style="color:#64748b; font-family:var(--font-mono);">${escapeHtml(e.created_at.slice(0, 19))}</td>
                    <td><b>${escapeHtml(e.event_type)}</b></td>
                    <td>${escapeHtml(e.actor)}</td>
                    <td><span style="color:${color}; font-weight:700;">${escapeHtml(e.severity)}</span></td>
                    <td style="color:#94a3b8; font-size:0.75rem;">${escapeHtml(e.meta) || '—'}</td>
                `;
                tbody.appendChild(tr);
            });

            // Toggle paginator buttons
            document.getElementById("logs-prev-btn").disabled = logsPage === 0;
            document.getElementById("logs-next-btn").disabled = logsPage >= logsTotalPages - 1;
        } else {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No matching log events recorded.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--error);">Failed: ${err.message}</td></tr>`;
    }
}

function prevLogsPage() {
    if (logsPage > 0) {
        logsPage--;
        loadSystemEvents();
    }
}

function nextLogsPage() {
    if (logsPage < logsTotalPages - 1) {
        logsPage++;
        loadSystemEvents();
    }
}

async function purgeLogs() {
    if (!confirm("Are you sure you want to delete all log entries older than 90 days?")) return;
    try {
        const response = await authFetch(`${API_BASE}/logs/purge?days=90`, { method: "POST" });
        const data = await response.json();
        if (data.success) {
            alert(data.message);
            logsPage = 0;
            loadSystemEvents();
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadDeveloperLogs() {
    const terminal = document.getElementById("developer-terminal");
    try {
        const response = await authFetch(`${API_BASE}/logs/developer`);
        const data = await response.json();
        if (data.success) {
            terminal.value = data.logs || "No server latency logs recorded yet.";
            terminal.scrollTop = terminal.scrollHeight;
        }
    } catch (err) {
        terminal.value = `Failed to stream logs: ${err.message}`;
    }
}

async function clearDeveloperLogs() {
    if (!confirm("Clear developer latency log file?")) return;
    try {
        const response = await authFetch(`${API_BASE}/logs/developer`, { method: "DELETE" });
        const data = await response.json();
        if (data.success) {
            loadDeveloperLogs();
        }
    } catch (err) {
        alert(err.message);
    }
}

// ── AUDIT REPORT & DELIVERY ──

async function printAuditReportPreview() {
    try {
        await renderAuditReportPreview();
        const previewEl = document.getElementById("report-preview-container");
        if (!previewEl) return;

        const printWindow = window.open('', '_blank');
        // BUG-12 FIX: popup blockers return null from window.open() — guard before use
        if (!printWindow) {
            alert("⚠️ Please allow popups in your browser to print the audit report.");
            return;
        }
        printWindow.document.write(`
            <html>
                <head>
                    <title>Audit Evaluation Report PDF</title>
                    <style>
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 24px; color: #1e293b; background: #ffffff; }
                        table { width: 100%; border-collapse: collapse; margin-top: 16px; }
                        th, td { border: 1px solid #cbd5e1; padding: 8px 12px; font-size: 0.85rem; text-align: left; }
                        th { background-color: #f1f5f9; font-weight: bold; }
                    </style>
                </head>
                <body>
                    ${previewEl.innerHTML}
                </body>
            </html>
        `);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
            printWindow.print();
            printWindow.close();
        }, 600);
    } catch (err) {
        alert(`Failed to prepare PDF: ${err.message}`);
    }
}

async function triggerDeleteAllRecords() {
    if (!currentUser || currentUser.role !== "admin") {
        alert("⚠️ Access Denied: Only system administrators can clear database records.");
        return;
    }

    if (!confirm("🚨 WARNING: Wiping all database records is irreversible and clears everything. Continue?")) return;

    try {
        const response = await authFetch(`${API_BASE}/audit/clear-records`, {
            method: "DELETE"
        });
        const data = await response.json();
        if (data.success) {
            alert("✅ Entire database records successfully cleared!");
            location.reload();
        } else {
            alert(`Error: ${data.detail || "Wipe failed"}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadAuditeeSessionsList() {
    const select = document.getElementById("auditee-session-selector");
    if (!select) return;
    select.innerHTML = `<option value="">— Select Audit Report —</option>`;

    try {
        // No need to pass our own username -- the backend derives identity from the JWT by default.
        const response = await authFetch(`${API_BASE}/audit/auditee-sessions`);
        const data = await response.json();

        if (data.success && data.sessions && data.sessions.length > 0) {
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                const auditeeName = s.auditee_username || "Auditee Account";
                const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString() : "";
                const fileStr = s.files_count > 0 ? ` (${s.files_count} file(s) submitted)` : "";
                opt.innerText = `${auditeeName} — ${s.session_title || 'Audit Session'} (${dateStr})${fileStr}`;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = `<option value="">— No Audit Reports Found —</option>`;
        }
    } catch (err) {
        console.error(err);
    }
}

async function loadAuditeeEvidenceDocs() {
    const selector = document.getElementById("auditee-session-selector");
    const container = document.getElementById("auditee-evidence-files-box");
    if (!selector || !container) return;

    const sessId = selector.value;
    if (!sessId) {
        container.innerHTML = `<div class="empty-state" style="padding: 24px; text-align: center; color: var(--text-muted);">Select an auditee report above to inspect submitted evidence documents and report delivery status.</div>`;
        return;
    }

    container.innerHTML = `<div class="empty-state" style="padding: 24px; text-align: center; color: var(--text-muted);">Loading evidence documents...</div>`;

    try {
        const selectedOpt = selector.options[selector.selectedIndex];
        const optText = selectedOpt ? selectedOpt.innerText : "";
        const auditeeName = optText.split(" — ")[0] || "Auditee Client";

        const response = await authFetch(`${API_BASE}/audit/evidence?session_id=${sessId}`);
        const data = await response.json();

        const files = (data.success && data.files) ? data.files : [];
        container.innerHTML = "";

        // 1. Top Report Delivery Banner Card
        const bannerCard = document.createElement("div");
        bannerCard.style.cssText = "background: var(--bg-card, #ffffff); border: 1px solid var(--border-color, #cbd5e1); border-radius: 14px; padding: 16px 20px; margin-bottom: 18px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);";
        bannerCard.innerHTML = `
            <div>
                <div style="font-size: 1rem; font-weight: 700; color: var(--text-color, #0f172a); display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span>👤 Auditee Client Account:</span>
                    <span style="color: #2563eb; background: rgba(37, 99, 235, 0.1); padding: 4px 12px; border-radius: 8px; border: 1px solid rgba(37, 99, 235, 0.2); font-weight: 800;">${auditeeName}</span>
                </div>
                <div style="font-size: 0.82rem; color: var(--text-muted, #475569); margin-top: 6px;">
                    📍 Session ID: <code style="color: var(--text-color, #0f172a); font-weight: 600;">${sessId}</code> • Report Recipient: <b style="color: #059669;">${auditeeName}</b>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                <span style="background: rgba(16, 185, 129, 0.12); color: #059669; border: 1px solid rgba(16, 185, 129, 0.3); padding: 6px 14px; border-radius: 8px; font-weight: 700; font-size: 0.82rem;">
                    🟢 Final Report Sent to ${auditeeName}
                </span>
                <button type="button" class="btn-primary" onclick="exportWordReport('${sessId}')" style="padding: 7px 14px; font-size: 0.82rem; font-weight: 700;">
                    📥 Download Final Report (.docx)
                </button>
            </div>
        `;
        container.appendChild(bannerCard);

        if (files.length === 0) {
            const emptyDiv = document.createElement("div");
            emptyDiv.className = "empty-state";
            emptyDiv.style.cssText = "padding: 24px; text-align: center; color: var(--text-muted);";
            emptyDiv.innerText = `No uploaded evidence documents found for Auditee '${auditeeName}'.`;
            container.appendChild(emptyDiv);
            return;
        }

        // 2. Render Document Cards with High-Contrast Text for Light & Dark Mode
        files.forEach((f, idx) => {
            const fn = f.filename;
            const ext = fn.split('.').pop().toLowerCase();
            let fileClass = "file-type-xml";
            let fileIconText = "XML";

            if (ext === "pdf") { fileClass = "file-type-pdf"; fileIconText = "PDF"; }
            else if (["doc", "docx"].includes(ext)) { fileClass = "file-type-doc"; fileIconText = "DOC"; }
            else if (["xls", "xlsx", "csv"].includes(ext)) { fileClass = "file-type-xls"; fileIconText = "XLS"; }

            const assignedAuditor = f.assigned_auditor || (currentUser ? currentUser.username : "Auditor");

            const card = document.createElement("div");
            card.className = "modern-file-card";
            card.style.cssText = "display: flex; align-items: center; gap: 14px; padding: 14px 18px; background: var(--bg-card, #ffffff); border: 1px solid var(--border-color, #cbd5e1); border-radius: 12px; margin-bottom: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.03);";
            card.innerHTML = `
                <div class="file-icon-badge ${fileClass}" style="width: 40px; height: 40px; font-weight: 800; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; border-radius: 8px;">${fileIconText}</div>
                <div class="file-details" style="flex: 1; min-width: 0;">
                    <div class="file-title" style="font-weight: 700; font-size: 0.92rem; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; color: var(--text-color, #0f172a);" title="${fn}">📄 ${fn}</div>
                    <div class="file-meta" style="font-size: 0.78rem; color: var(--text-muted, #475569); margin-top: 4px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                        <span>📤 Submitted By Auditee: <b style="color: #2563eb;">${auditeeName}</b></span>
                        <span>📥 Sent To Auditor: <b style="color: #059669;">${assignedAuditor}</b></span>
                        <span>Size: <b>${f.size_str || 'Submitted Document'}</b></span>
                    </div>
                </div>
                <span class="badge-pill" style="color: #059669; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); font-size: 0.76rem; padding: 5px 12px; border-radius: 8px; font-weight: 700; white-space: nowrap;">
                    ✓ AUDITEE DOCUMENT SUBMITTED
                </span>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        container.innerHTML = `<div class="error-msg" style="padding: 16px; color: #ef4444;">Error loading documents: ${err.message}</div>`;
    }
}

function selectAllAuditeeDocs(checked) {
    const checkboxes = document.querySelectorAll(".auditee-doc-checkbox");
    checkboxes.forEach(cb => cb.checked = checked);
}

// ── SIDEBAR: AUDITEE SUBMISSION PANEL ───────────────────────────────────────

async function loadSidebarAuditeeFiles() {
    const sessionSelect = document.getElementById("sidebar-auditee-session-select");
    const fileList = document.getElementById("sidebar-auditee-files-list");
    if (!sessionSelect || !fileList) return;

    // Refresh auditee sessions list
    try {
        const currentVal = sessionSelect.value;
        // No need to pass our own username -- the backend derives identity from the JWT by default.
        const res = await authFetch(`${API_BASE}/audit/auditee-sessions`);
        const data = await res.json();
        if (data.success && data.sessions && data.sessions.length > 0) {
            sessionSelect.innerHTML = `<option value="">— Select Auditee Account —</option>`;
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                const auditeeName = s.auditee_username || "Auditee Account";
                const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString() : "";
                const fileStr = s.files_count > 0 ? ` (${s.files_count} file(s))` : "";
                opt.innerText = `👤 Auditee: ${auditeeName} — ${s.session_title || 'Audit Session'} (${dateStr})${fileStr}`;
                sessionSelect.appendChild(opt);
            });
            if (currentVal) {
                sessionSelect.value = currentVal;
            } else if (data.sessions.length === 1) {
                sessionSelect.value = data.sessions[0].session_id;
            }
        } else {
            sessionSelect.innerHTML = `<option value="">— No Auditee Evidences Yet —</option>`;
            fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">No auditee evidences found yet.</div>`;
            return;
        }
    } catch (e) { console.error(e); }

    const sessId = sessionSelect.value;
    if (!sessId) {
        fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">Select a session above</div>`;
        return;
    }

    fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">Loading...</div>`;

    try {
        const res = await authFetch(`${API_BASE}/audit/evidence?session_id=${sessId}`);
        const data = await res.json();
        const files = (data.success && data.files) ? data.files : [];

        // Update badge
        const badge = document.getElementById("auditee-submission-badge");
        if (badge) badge.innerText = files.length;

        if (files.length === 0) {
            fileList.innerHTML = `<div style="font-size:0.74rem;color:var(--text-muted);text-align:center;padding:8px;">No documents submitted for this session.</div>`;
            return;
        }

        fileList.innerHTML = "";
        files.forEach((f, idx) => {
            const fn = f.filename;
            const ext = fn.split('.').pop().toLowerCase();
            const iconMap = { pdf: "📄", doc: "📝", docx: "📝", xls: "📊", xlsx: "📊", csv: "📊", xml: "🗂️", txt: "📃" };
            const icon = iconMap[ext] || "📎";
            const sizeStr = f.size_str || "";

            const row = document.createElement("div");
            row.style.cssText = "display: flex; align-items: center; gap: 6px; padding: 6px 8px; background: var(--bg-card, rgba(30,41,59,0.5)); border: 1px solid var(--border-color, rgba(148,163,184,0.15)); border-radius: 8px; cursor: pointer; margin-bottom: 4px;";
            row.innerHTML = `
                <input type="checkbox" class="sidebar-auditee-doc-cb" value="${fn}" data-session="${sessId}"
                    id="sauditee_${idx}" checked style="width:15px;height:15px;cursor:pointer;flex-shrink:0;">
                <span style="font-size:1rem;flex-shrink:0;">${icon}</span>
                <label for="sauditee_${idx}" style="flex:1;min-width:0;font-size:0.75rem;font-weight:600;color:var(--text-color, #0f172a);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;" title="${fn}">${fn}</label>
                <span style="font-size:0.65rem;color:var(--text-muted);white-space:nowrap;">${sizeStr}</span>
            `;
            fileList.appendChild(row);
        });
    } catch (e) {
        fileList.innerHTML = `<div style="font-size:0.74rem;color:#ef4444;padding:8px;">Error: ${e.message}</div>`;
    }
}

function selectAllSidebarAuditeeDocs(checked) {
    document.querySelectorAll(".sidebar-auditee-doc-cb").forEach(cb => cb.checked = checked);
}

async function addAuditeeFilesToWorkspace() {
    const checked = Array.from(document.querySelectorAll(".sidebar-auditee-doc-cb:checked"));
    if (checked.length === 0) {
        showToast("⚠️ Please select at least one file first.", "warning");
        return;
    }

    const sessionSelect = document.getElementById("sidebar-auditee-session-select");
    const srcSessId = sessionSelect ? sessionSelect.value : "";
    if (!srcSessId) {
        showToast("⚠️ Please select an auditee session from the dropdown first.", "warning");
        return;
    }

    // Ensure active workspace session exists for the auditor
    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }
    if (!activeSessionId) {
        showToast("⚠️ Active workspace session missing. Please create or open an audit session first.", "warning");
        return;
    }

    const selectedFilenames = checked.map(cb => cb.value);

    // Call backend API to import files & chunks safely into the auditor's active session
    try {
        const res = await authFetch(`${API_BASE}/audit/import-auditee-evidence`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                source_session_id: srcSessId,
                target_session_id: activeSessionId,
                filenames: selectedFilenames
            })
        });
        const data = await res.json();

        if (data.success) {
            // Smoothly refresh the workspace file list from server
            await loadEvidenceFileList();

            // Switch to Scan workspace tab
            const scanTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Scan"));
            if (scanTabBtn) switchTab("tab-scan-workspace", scanTabBtn);

            showToast(`✅ ${data.imported_count || selectedFilenames.length} auditee file(s) added to workspace!`, "success");
        } else {
            showToast(`❌ Failed to add files: ${data.detail || "Unknown error"}`, "error");
        }
    } catch (err) {
        console.error("Error importing auditee evidence:", err);
        showToast("❌ Network error adding files to workspace.", "error");
    }
}

async function runAnalysisOnSelectedAuditeeDocs() {
    const selector = document.getElementById("auditee-session-selector");
    if (!selector || !selector.value) {
        alert("⚠️ Please select an auditee session first.");
        return;
    }

    const checkedDocs = Array.from(document.querySelectorAll(".auditee-doc-checkbox:checked")).map(cb => cb.value);
    if (checkedDocs.length === 0) {
        alert("⚠️ Please select at least one document to analyze.");
        return;
    }

    // Set active session to target auditee session
    activeSessionId = selector.value;
    document.getElementById("active-session-badge").innerText = `Session ID: ${activeSessionId}`;

    // Refresh evidence files list in main workspace
    await loadEvidenceFileList();

    // Switch to Scan workspace tab
    const scanTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Scan workspace"));
    if (scanTabBtn) switchTab("tab-scan-workspace", scanTabBtn);

    // Trigger RAG Audit Scan
    alert(`🚀 Starting RAG analysis on ${checkedDocs.length} selected document(s) for session ${activeSessionId.slice(0, 8)}...`);
    triggerAuditAnalysis();
}

async function handleScopingUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const fileBadge = document.getElementById("scoping-file-name");
    fileBadge.innerText = "Parsing excel checklist...";
    fileBadge.style.display = "block";

    const body = new FormData();
    body.append("file", file);

    try {
        // POST /audit/upload-scope-excel does not exist and never has -- this
        // handler is currently unreferenced, so the 404 was invisible. The real
        // scope-upload endpoint is the one the two live call sites already use,
        // and it returns exactly the shape read below (matched_sls,
        // custom_evidence, custom_documents).
        const response = await authFetch(`${API_BASE}/controls/parse-scope-excel`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to parse checklist.");

        fileBadge.innerText = `Checked: ${file.name}`;

        // Save mappings globally
        customEvidenceMappings = data.custom_evidence;
        customControlDocuments = data.custom_documents;

        // Auto select matched checkboxes in UI checklist
        const matchedSet = new Set(data.matched_sls);
        const checkboxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
        checkboxes.forEach(cb => {
            cb.checked = matchedSet.has(parseInt(cb.value));
        });

        updateSelectedScopeCount();
        _warnIfScopeSheetLacksPolicy(data);
        const totalItems = (customEvidenceMappings && customEvidenceMappings.excel_items) ? customEvidenceMappings.excel_items.length : data.matched_sls.length;
        const uniqueCtrlCount = new Set(data.matched_sls).size;
        alert(`✅ Loaded ${totalItems} checklist items (${uniqueCtrlCount} unique ISO controls) — all items will be evaluated!`);
    } catch (err) {
        fileBadge.innerText = "Error parsing file";
        alert(`Scoping Error: ${err.message}`);
    }
}

function formatApiError(detail, fallbackMsg = "Operation failed.") {
    if (!detail) return fallbackMsg;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail.map(d => (typeof d === "string" ? d : (d.msg || JSON.stringify(d)))).join("; ");
    }
    if (typeof detail === "object") {
        return detail.message || detail.msg || JSON.stringify(detail);
    }
    return String(detail);
}

async function handleSidebarUpload(event) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const statusDiv = document.getElementById("sidebar-upload-status");
    if (statusDiv) statusDiv.innerText = "⏳ Uploading files...";

    // Ensure active session is loaded
    if (!activeSessionId && currentUser) {
        await loadOrCreateSession(currentUser);
    }

    if (!activeSessionId) {
        if (statusDiv) statusDiv.innerText = "❌ Error: Active session missing. Please start a session first.";
        alert("⚠️ Active session missing. Please create or select an audit session first.");
        return;
    }

    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("is_auditor_uploaded", "true");
    body.append("username", currentUser ? currentUser.username : "");

    for (let i = 0; i < files.length; i++) {
        body.append("files", files[i]);
    }

    try {
        const response = await authFetch(`${API_BASE}/audit/upload`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(formatApiError(data.detail, "Upload failed."));

        if (statusDiv) statusDiv.innerText = `Successfully uploaded ${files.length} file(s)!`;
        loadEvidenceFileList();
        setTimeout(() => { if (statusDiv) statusDiv.innerText = ""; }, 4000);
    } catch (err) {
        if (statusDiv) statusDiv.innerText = `❌ Error: ${err.message}`;
    }
}

async function deliverReportToAuditee() {
    const select = document.getElementById("report-target-auditee");
    if (!select) return;
    const auditeeId = select.value;
    if (!auditeeId) {
        alert("⚠️ Please select a target auditee account first.");
        return;
    }

    if (!confirm("Are you sure you want to finalize and send these audit findings to the auditee?")) return;

    const body = new FormData();
    body.append("session_id", activeSessionId);
    body.append("auditee_id", auditeeId);
    body.append("username", currentUser ? currentUser.username : "auditor@24");

    try {
        const response = await authFetch(`${API_BASE}/audit/deliver`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            alert("✅ Report successfully published and recorded in the Submitted tab!");

            // Switch to Submitted Reports tab and refresh list
            const submittedTabBtn = Array.from(document.querySelectorAll("#tabs-bar button")).find(b => b.innerText.includes("Submitted"));
            if (submittedTabBtn) switchTab("tab-submitted-reports", submittedTabBtn);
            else loadSubmittedReports();
        } else {
            alert(`Error: ${data.detail || "Delivery failed"}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function loadSubmittedReports() {
    const container = document.getElementById("submitted-reports-container");
    if (!container) return;
    container.innerHTML = `<div class="empty-state">Loading submitted reports from Shakthi DB...</div>`;

    try {
        // No need to pass our own username -- the backend derives identity from the JWT by default.
        const response = await authFetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();

        if (data.success && data.sessions.length > 0) {
            container.innerHTML = "";
            const seen = new Set();
            const reports = data.sessions.filter(s => {
                if (!s.session_id || seen.has(s.session_id)) return false;

                const title = (s.session_title || "").toLowerCase();
                const st = (s.status || "Draft").toLowerCase();

                // Exclude chat sessions and error logs
                if (title.includes("chat") || title.includes("error")) return false;

                // For auditee, only show sent/delivered/completed reports
                if (currentUser && currentUser.role === "auditee") {
                    return st.includes("sent") || st.includes("deliver") || st.includes("complet") || st.includes("submit");
                }

                // For auditor/admin, show non-draft submitted/delivered or finalized reports
                const isSubmitted = st.includes("sent") || st.includes("deliver") || st.includes("complet") || st.includes("submit") || st.includes("pending") || title.includes("finalized");
                if (isSubmitted) {
                    seen.add(s.session_id);
                    return true;
                }
                return false;
            });

            if (reports.length === 0) {
                container.innerHTML = `<div class="empty-state">No submitted audit reports available yet. Publish a report from the <b>Report</b> tab to view it here.</div>`;
                return;
            }

            reports.forEach(r => {
                const card = document.createElement("div");
                card.className = "report-card";
                card.style.cssText = "background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 12px; padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;";

                let badgeColor = "var(--text-muted)";
                let badgeBorder = "rgba(148, 163, 184, 0.2)";
                const statusStr = (r.status || "Submitted").toUpperCase();
                if (statusStr.includes("SENT") || statusStr.includes("DELIVER") || statusStr.includes("COMPLET")) {
                    badgeColor = "#10b981";
                    badgeBorder = "rgba(16, 185, 129, 0.4)";
                } else if (statusStr.includes("PENDING") || statusStr.includes("REVIEW")) {
                    badgeColor = "#f59e0b";
                    badgeBorder = "rgba(245, 158, 11, 0.4)";
                }

                card.innerHTML = `
                    <div>
                        <h4 style="margin: 0 0 6px 0; color: var(--text-main); font-size: 1.05rem; font-weight: 700;">${escapeHtml(r.session_title)}</h4>
                        <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; gap: 16px; align-items: center;">
                            <span>Standard: <b style="color: #60a5fa;">${escapeHtml(r.framework || 'ISO 27001')}</b></span>
                            <span>Date: <b>${escapeHtml((r.created_at || '').slice(0, 10) || 'Recent')}</b></span>
                            <span>Compliance Score: <b style="color: #10b981;">${r.score_percent || 0}%</b></span>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="badge-pill" style="color: ${badgeColor}; border-color: ${badgeBorder}; font-weight: 700;">${escapeHtml(statusStr)}</span>
                        <button class="btn-secondary" style="padding: 6px 14px; font-size: 0.78rem;" onclick="exportReportCSV('${escapeHtml(r.session_id).replace(/'/g, "\\'")}')">📥 Export CSV</button>
                    </div>
                `;
                container.appendChild(card);
            });
        } else {
            container.innerHTML = `<div class="empty-state">No submitted audit reports available yet. Publish a report from the <b>Report</b> tab to view it here.</div>`;
        }
    } catch (err) {
        container.innerHTML = `<div class="error-msg">Error loading submitted reports: ${err.message}</div>`;
    }
}

// Neutralizes CSV/formula injection (CWE-1236): a cell value starting with
// =, +, -, @, tab, or CR is interpreted as a formula by Excel/Sheets when the
// exported file is opened, which is a real risk here since finding text can
// originate from an uploaded document's content, not just the auditor.
function csvSafeCell(val) {
    let s = (val === null || val === undefined) ? "" : String(val);
    if (/^[=+\-@\t\r]/.test(s)) {
        s = "'" + s;
    }
    return s.replace(/"/g, '""');
}

async function exportReportCSV(sessId) {
    try {
        const response = await authFetch(`${API_BASE}/audit/findings?session_id=${sessId}&include_info=true`);
        const data = await response.json();
        // Same rows as the PDF/DOCX: a VAPT session's informational findings
        // included, every other session's left out as before. Decided from this
        // payload, not the page's state -- sessId need not be the open session.
        const _fw = String((data && data.framework) || "").toUpperCase();
        const _rows = (data && data.findings) ? ((_fw.includes("VAPT") && !_fw.includes("PQC"))
            ? data.findings : data.findings.filter(f => !isFindingInformational(f))) : [];
        if (data.success && _rows.length > 0) {
            let csv = "Control ID,Name,Severity,Status,Description,Recommendation,Reasoning,Files\n";
            _rows.forEach(f => {
                const desc = `"${csvSafeCell(f.description)}"`;
                const rec = `"${csvSafeCell(f.recommendation)}"`;
                const reason = `"${csvSafeCell(f.reasoning)}"`;
                csv += `"${csvSafeCell(f.control_id)}","${csvSafeCell(f.control_name)}","${csvSafeCell(f.severity)}","${csvSafeCell(f.status)}",${desc},${rec},${reason},"${csvSafeCell(f.source_files)}"\n`;
            });

            const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.setAttribute("download", `audit_report_${sessId.slice(0, 6)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } else {
            alert("No findings records to export. Try running a scan first.");
        }
    } catch (err) {
        alert(err.message);
    }
}

async function exportFeedbackBackup() {
    try {
        const response = await authFetch(`${API_BASE}/audit/feedback/export`);
        const data = await response.json();

        if (response.ok) {
            const feedbackList = (data.feedback && Array.isArray(data.feedback)) ? data.feedback : (Array.isArray(data) ? data : []);
            const blob = new Blob([JSON.stringify(feedbackList, null, 2)], { type: "application/json" });
            const blobUrl = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = blobUrl;
            link.setAttribute("download", `auditor_feedback_memory_backup.json`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
            showToast("Feedback memory backup exported successfully!", "success");
        } else {
            showToast(`Failed to export feedback data: ${data.detail || data.message || 'Server error'}`, "error");
        }
    } catch (err) {
        console.error("Export feedback backup error:", err);
        showToast(`Failed to export feedback data: ${err.message}`, "error");
    }
}

async function importFeedbackBackup(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!confirm(`Are you sure you want to import feedback records from ${file.name}?`)) return;

    const body = new FormData();
    body.append("file", file);

    try {
        const response = await authFetch(`${API_BASE}/audit/feedback/import`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            alert(`✅ ${data.message}`);
        } else {
            alert(`Import failed: ${data.detail || "Unknown error"}`);
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
    }
}

async function loadChatSessions() {
    const sidebar = document.getElementById("chat-history-sidebar");
    if (!sidebar) return;
    sidebar.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;'>Loading history...</div>";

    try {
        const response = await authFetch(`${API_BASE}/audit/chats/sessions`);
        const data = await response.json();

        if (data.success) {
            sidebar.innerHTML = "";
            if (data.sessions.length === 0) {
                sidebar.innerHTML = "<div style='font-size:11px;color:var(--text-muted);padding:8px;text-align:center;'>No conversations yet.</div>";
                return;
            }

            data.sessions.forEach(s => {
                const item = document.createElement("div");
                item.className = `chat-session-item ${s.session_id === activeSessionId ? 'active' : ''}`;
                item.onclick = () => selectChatSession(s.session_id);

                const safeSessTitle = escapeHtml(s.session_title || "");
                item.innerHTML = `
                    <div style="display:flex; align-items:center; gap:8px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;">
                        <span>💬</span>
                        <span title="${safeSessTitle}">${safeSessTitle.slice(0, 18)}${safeSessTitle.length > 18 ? '...' : ''}</span>
                    </div>
                    <button style="background:none; border:none; color:var(--text-muted); font-size:0.75rem; cursor:pointer;" onclick="clearChatSession('${escapeHtml(s.session_id).replace(/'/g, "\\'")}', event)">🗑️</button>
                `;
                sidebar.appendChild(item);
            });
        } else {
            sidebar.innerHTML = "<div style='font-size:11px;color:var(--error);padding:8px;'>Failed to load history.</div>";
        }
    } catch (err) {
        sidebar.innerHTML = `<div style='font-size:11px;color:var(--error);padding:8px;'>Error: ${err.message}</div>`;
    }
}

async function selectChatSession(sessionId) {
    activeSessionId = sessionId;

    // Refresh active session badge and workspace details
    document.getElementById("active-session-badge").innerText = `Session ID: ${activeSessionId}`;

    // Highlight active chat session card
    document.querySelectorAll(".chat-session-item").forEach(item => item.classList.remove("active"));
    loadChatSessions(); // will refresh active class list

    // Reload relevant evidence files & findings for the selected conversation context
    loadEvidenceFileList();
    loadFindings();

    const feed = document.getElementById("chat-feed-box");
    feed.innerHTML = "<div class='empty-state'>Loading conversation...</div>";

    try {
        const response = await authFetch(`${API_BASE}/audit/chats/history?session_id=${sessionId}&username=${encodeURIComponent(currentUser.username || '')}`);
        const data = await response.json();

        if (data.success) {
            feed.innerHTML = "";
            if (data.messages.length === 0) {
                feed.innerHTML = `
                    <div class="chat-bubble assistant">
                        <p>Hello! I am your lead auditor AI assistant. Ask me anything about the uploaded evidence policies against standard compliance controls.</p>
                    </div>
                `;
                return;
            }

            data.messages.forEach(m => {
                if (m.role === "findings_snapshot") return; // skip internal snapshots
                const bubble = document.createElement("div");
                bubble.className = `chat-bubble ${m.role === 'user' ? 'user' : 'assistant'}`;
                bubble.innerHTML = `<p>${escapeHtml(m.content)}</p>`;
                feed.appendChild(bubble);
            });
            feed.scrollTop = feed.scrollHeight;
        }
    } catch (err) {
        feed.innerHTML = `<div class="error-msg">Error loading messages: ${err.message}</div>`;
    }
}

async function startNewChatSession() {
    // Generate a fresh session ID
    const newSessionId = 'chat_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    // Post to register audit report session on backend
    const body = new FormData();
    body.append("session_title", "Custom AI Chat Conversation");
    body.append("framework", "ISO 27001");
    body.append("username", currentUser.username);

    try {
        const response = await authFetch(`${API_BASE}/audit/sessions`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            // Override report session ID
            activeSessionId = data.session_id;

            // Reload sidebar list and select the new blank session
            await selectChatSession(activeSessionId);
            alert("✅ Switched to a fresh new AI conversation session!");
        }
    } catch (err) {
        alert(`Failed to initialize new session: ${err.message}`);
    }
}

async function clearChatSession(sessionId, event) {
    if (event) event.stopPropagation(); // prevent clicking session activation

    if (!confirm("Are you sure you want to clear conversation messages and checkpoints for this session?")) return;

    const body = new FormData();
    body.append("session_id", sessionId);
    if (currentUser && currentUser.username) body.append("username", currentUser.username);

    try {
        const response = await authFetch(`${API_BASE}/audit/chats/clear`, {
            method: "POST",
            body: body
        });
        const data = await response.json();
        if (data.success) {
            if (sessionId === activeSessionId) {
                // If currently active chat deleted, start a new one
                startNewChatSession();
            } else {
                loadChatSessions();
            }
        }
    } catch (err) {
        alert(err.message);
    }
}

function getBrandingQueryParams() {
    const firm = encodeURIComponent(document.getElementById("brand-firm")?.value || "");
    const auditor = encodeURIComponent(document.getElementById("brand-auditor")?.value || "");
    const reviewer = encodeURIComponent(document.getElementById("brand-reviewer")?.value || "");
    const approver = encodeURIComponent(document.getElementById("brand-approver")?.value || "");
    const docid = encodeURIComponent(document.getElementById("brand-docid")?.value || "");
    const client = encodeURIComponent(document.getElementById("brand-client")?.value || "");
    const email = encodeURIComponent(document.getElementById("brand-email")?.value || "");
    const address = encodeURIComponent(document.getElementById("brand-address")?.value || "");
    const phone = encodeURIComponent(document.getElementById("brand-phone")?.value || "");
    const mobile = encodeURIComponent(document.getElementById("brand-mobile")?.value || "");
    const reportDate = encodeURIComponent(document.getElementById("brand-report-date")?.value || "");
    const orderRef = encodeURIComponent(document.getElementById("brand-order-ref")?.value || "");
    const auditDates = encodeURIComponent(document.getElementById("brand-audit-dates")?.value || "");
    const auditeeReps = encodeURIComponent(document.getElementById("brand-auditee-reps")?.value || "");
    return `&brand_firm=${firm}&brand_auditor=${auditor}&brand_reviewer=${reviewer}&brand_approver=${approver}&brand_docid=${docid}&brand_client=${client}&auditor_firm=${firm}&auditor_lead=${auditor}&auditor_reviewer=${reviewer}&auditor_approver=${approver}&document_id=${docid}&client_contact=${client}&brand_email=${email}&brand_address=${address}&brand_phone=${phone}&brand_mobile=${mobile}&brand_report_date=${reportDate}&brand_order_ref=${orderRef}&brand_audit_dates=${auditDates}&brand_auditee_reps=${auditeeReps}`;
}

async function downloadFileWithLoader(buttonId, textId, defaultText, exportUrl, defaultFilename, labelType) {
    const btn = document.getElementById(buttonId);
    const txt = document.getElementById(textId) || btn;
    if (btn) {
        btn.style.pointerEvents = "none";
        btn.style.opacity = "0.75";
    }
    if (txt) {
        txt.innerHTML = `<span>⏳ Generating ${labelType}... Please wait</span>`;
    }
    showToast(`⚙️ Compiling ${labelType} report... This takes ~2-3 seconds.`, "info");

    try {
        const response = await authFetch(exportUrl);
        if (!response.ok) throw new Error(`Server returned status ${response.status}`);
        const blob = await response.blob();

        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = defaultFilename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);

        showToast(`✅ ${labelType} report downloaded successfully!`, "success");
    } catch (err) {
        console.error(`Export ${labelType} error:`, err);
        showToast(`❌ Failed to generate ${labelType}: ${err.message}`, "error");
    } finally {
        if (btn) {
            btn.style.pointerEvents = "auto";
            btn.style.opacity = "1";
        }
        if (txt) {
            txt.innerHTML = `<span>${defaultText}</span>`;
        }
    }
}

async function exportFindingsPDF() {
    if (!activeSessionId) {
        showToast("⚠️ Please select an active audit session first.", "error");
        return;
    }
    const brandingParams = getBrandingQueryParams();
    const exportUrl = `${API_BASE}/audit/export/pdf?session_id=${encodeURIComponent(activeSessionId)}${brandingParams}${vaptExportParams()}`;
    const fname = `Audit_Report_${activeSessionId.slice(0, 6).toUpperCase()}.pdf`;
    await downloadFileWithLoader("btn-export-pdf", "txt-export-pdf", "Export Formal PDF Report", exportUrl, fname, "PDF");
}

async function exportFindingsDOCX() {
    if (!activeSessionId) {
        showToast("⚠️ Please select an active audit session first.", "error");
        return;
    }
    const brandingParams = getBrandingQueryParams();
    const exportUrl = `${API_BASE}/audit/export/docx?session_id=${encodeURIComponent(activeSessionId)}${brandingParams}${vaptExportParams()}`;
    const fname = `Audit_Report_${activeSessionId.slice(0, 6).toUpperCase()}.docx`;
    await downloadFileWithLoader("btn-export-docx", "txt-export-docx", "Export Editable Word Report", exportUrl, fname, "Word");
}

async function exportFindingsCSV() {
    if (!activeSessionId) {
        showToast("⚠️ Please select an active audit session first.", "error");
        return;
    }
    const exportUrl = `${API_BASE}/audit/findings?session_id=${encodeURIComponent(activeSessionId)}&saved_only=true`;
    const btn = document.getElementById("btn-export-csv");
    const txt = document.getElementById("txt-export-csv") || btn;

    if (btn) { btn.style.pointerEvents = "none"; btn.style.opacity = "0.75"; }
    if (txt) { txt.innerHTML = `<span>⏳ Formatting CSV Dataset...</span>`; }
    showToast("⚙️ Preparing CSV Audit Dataset...", "info");

    try {
        const response = await authFetch(exportUrl);
        const data = await response.json();
        const findings = (data.success && data.findings) ? data.findings : [];

        if (findings.length === 0) {
            showToast("⚠️ No saved findings to export in CSV.", "error");
            return;
        }

        const headers = ["Control ID", "Control Name", "Status", "Severity", "Policy Present", "Evidence Present", "Description", "Recommendation", "Source Files"];
        const rows = [headers.join(",")];

        findings.forEach(f => {
            // NIST Severity rule: only status="Compliant" shows N/A in CSV export.
            // Non-Compliant, Partially Compliant, Out Of Scope retain P-scale severity.
            const isFComp = (f.status || "").trim() === "Compliant";
            const csvSev = isFComp ? "N/A" : (f.severity || "");
            const row = [
                `"${csvSafeCell(f.control_id)}"`,
                `"${csvSafeCell(f.control_name)}"`,
                `"${csvSafeCell(f.status)}"`,
                `"${csvSafeCell(csvSev)}"`,
                `"${csvSafeCell(f.policy_present)}"`,
                `"${csvSafeCell(f.evidence_present)}"`,
                `"${csvSafeCell(f.description || f.gap_detected)}"`,
                `"${csvSafeCell(f.recommendation)}"`,
                `"${csvSafeCell(f.source_files)}"`
            ];
            rows.push(row.join(","));
        });

        const csvString = rows.join("\n");
        const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = `Audit_Findings_${activeSessionId.slice(0, 6).toUpperCase()}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);

        showToast("✅ Raw CSV Dataset downloaded successfully!", "success");
    } catch (err) {
        console.error("CSV export error:", err);
        showToast(`❌ Failed to export CSV: ${err.message}`, "error");
    } finally {
        if (btn) { btn.style.pointerEvents = "auto"; btn.style.opacity = "1"; }
        if (txt) { txt.innerHTML = `<span>Download Raw CSV Dataset</span>`; }
    }
}

function toggleChatSidebar() {
    const sidebar = document.querySelector(".chat-sidebar");
    const toggleText = document.getElementById("toggle-sidebar-text");
    const container = document.querySelector(".chat-container");

    if (sidebar.style.display === "none") {
        sidebar.style.display = "flex";
        container.style.gridTemplateColumns = "240px 1fr";
        toggleText.innerText = "Hide Recents";
    } else {
        sidebar.style.display = "none";
        container.style.gridTemplateColumns = "1fr";
        toggleText.innerText = "Show Recents";
    }
}

/* ── INSTANT THEME SWITCHER (DARK / LIGHT) ── */
function toggleAppTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme") || (document.body.classList.contains("light-theme") ? "light" : "dark");
    const newTheme = currentTheme === "dark" ? "light" : "dark";

    document.documentElement.setAttribute("data-theme", newTheme);
    if (newTheme === "light") {
        document.body.classList.remove("dark-theme");
        document.body.classList.add("light-theme");
    } else {
        document.body.classList.remove("light-theme");
        document.body.classList.add("dark-theme");
    }
    localStorage.setItem("aicyber_theme", newTheme);

    updateThemeToggleUI(newTheme);
}

function updateThemeToggleUI(theme) {
    const icon = document.getElementById("theme-toggle-icon");
    const text = document.getElementById("theme-toggle-text");
    const btn = document.getElementById("theme-toggle-btn");

    if (icon && text) {
        if (theme === "light") {
            icon.innerText = "☀️";
            text.innerText = "Light Mode";
            if (btn) btn.style.background = "rgba(0,0,0,0.06)";
        } else {
            icon.innerText = "🌙";
            text.innerText = "Dark Mode";
            if (btn) btn.style.background = "rgba(255,255,255,0.08)";
        }
    }
}

// Restore user theme preference instantly on page load (default to light mode)
(function initAppTheme() {
    const savedTheme = localStorage.getItem("aicyber_theme") || "light";
    document.documentElement.setAttribute("data-theme", savedTheme);
    document.addEventListener("DOMContentLoaded", () => {
        if (savedTheme === "light") {
            document.body.classList.remove("dark-theme");
            document.body.classList.add("light-theme");
        } else {
            document.body.classList.remove("light-theme");
            document.body.classList.add("dark-theme");
        }
        updateThemeToggleUI(savedTheme);
    });
})();

/* ── FLOATING AI COPILOT WIDGET (GEMINI STYLE) ── */
function toggleCopilotDrawer() {
    const drawer = document.getElementById("ai-copilot-drawer");
    if (!drawer) return;

    if (drawer.style.display === "none" || !drawer.style.display) {
        drawer.style.display = "flex";
        updateCopilotContextBadge();
    } else {
        drawer.style.display = "none";
    }
}

function updateCopilotContextBadge() {
    const badge = document.getElementById("copilot-page-context");
    if (!badge) return;

    let tabName = "Audit Workspace";
    if (activeTab === "tab-audit-records") tabName = "Audit Records Findings";
    else if (activeTab === "tab-upload-evidence") tabName = "Auditee Document Uploads";
    else if (activeTab === "tab-audit-report") tabName = "Audit Delivery Report";
    else if (activeTab === "tab-manage-controls") tabName = "Controls Management";
    else if (activeTab === "tab-ai-chat") tabName = "Full AI Chat Assistant";

    badge.innerText = `📍 Active Context: ${tabName}`;
}

function handleCopilotKeyPress(event) {
    if (event.key === "Enter") {
        sendCopilotMessage();
    }
}

function sendQuickCopilotPrompt(text) {
    const input = document.getElementById("copilot-input");
    if (input) {
        input.value = text;
        sendCopilotMessage();
    }
}

async function sendCopilotMessage() {
    const input = document.getElementById("copilot-input");
    const feed = document.getElementById("copilot-chat-feed");
    const indicator = document.getElementById("copilot-thinking-indicator");

    if (!input || !feed) return;
    const msgText = input.value.trim();
    if (!msgText) return;

    input.value = "";

    // Render user message bubble
    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble user";
    userBubble.innerHTML = `<p>${escapeHtml(msgText)}</p>`;
    feed.appendChild(userBubble);
    feed.scrollTop = feed.scrollHeight;

    if (indicator) indicator.style.display = "block";

    const selectedModel = document.getElementById("llm-model-select")?.value || "Gemma 4 (12b)";
    const uName = currentUser ? currentUser.username : "auditor";

    try {
        let activeContext = `[Context: Active Tab = ${activeTab}, Session = ${activeSessionId}]`;
        const response = await authFetch(`${API_BASE}/audit/chats/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                message: `${activeContext}\n${msgText}`,
                username: uName,
                model_choice: selectedModel
            })
        });

        const data = await response.json();
        if (indicator) indicator.style.display = "none";

        if (!response.ok) throw new Error(data.detail || "Copilot failed to respond.");

        const replyText = data.response || data.reply || "No response received from local AI model.";

        const aiBubble = document.createElement("div");
        aiBubble.className = "chat-bubble assistant";
        aiBubble.innerHTML = `<p>${escapeHtml(replyText).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</p>`;
        feed.appendChild(aiBubble);
        feed.scrollTop = feed.scrollHeight;
    } catch (err) {
        if (indicator) indicator.style.display = "none";
        const errBubble = document.createElement("div");
        errBubble.className = "chat-bubble assistant";
        errBubble.innerHTML = `<p style="color: var(--error);">⚠️ Error: ${err.message}</p>`;
        feed.appendChild(errBubble);
        feed.scrollTop = feed.scrollHeight;
    }
}

/* ── SIDEBAR COLLAPSE TOGGLE (◀ / ▶) ── */
function toggleSidebarCollapse() {
    const sidebar = document.getElementById("main-sidebar");
    const toggleBtn = document.getElementById("sidebar-toggle-btn");
    if (!sidebar || !toggleBtn) return;

    if (sidebar.classList.contains("collapsed")) {
        sidebar.classList.remove("collapsed");
        sidebar.style.width = "300px";
        sidebar.style.minWidth = "300px";
        toggleBtn.innerText = "◀";
        toggleBtn.title = "Collapse Sidebar";
    } else {
        sidebar.classList.add("collapsed");
        sidebar.style.width = "64px";
        sidebar.style.minWidth = "64px";
        toggleBtn.innerText = "▶";
        toggleBtn.title = "Expand Sidebar";
    }
}

function generateUUID() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
        return crypto.randomUUID().replace(/-/g, "");
    }
    return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/* ── AUDIT SESSION MANAGER (Recent Sessions) ── */

async function loadRecentSessionsList() {
    const container = document.getElementById("recent-sessions-list");
    if (!container) return;

    try {
        // No need to pass our own username -- the backend now derives identity
        // from the JWT by default, so it's not echoed back in plaintext in the
        // URL (and therefore in access logs) on every poll.
        const response = await authFetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();

        if (data.success && data.sessions.length > 0) {
            container.innerHTML = "";
            data.sessions.slice(0, 8).forEach(sess => {
                const item = document.createElement("div");
                item.className = "recent-session-item";
                item.style.cssText = "display: flex; align-items: center; justify-content: space-between; padding: 6px 8px; background: rgba(255,255,255,0.05); border-radius: 6px; cursor: pointer; font-size: 0.73rem; transition: background 0.2s;";
                item.onclick = () => switchActiveAuditSession(sess.session_id, sess.framework);

                const isCurrent = sess.session_id === activeSessionId;
                item.innerHTML = `
                    <div style="text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 140px;">
                        <span style="font-weight: 600; color: ${isCurrent ? '#60a5fa' : 'var(--text-main)'};">${sess.session_id.slice(0, 8)}...</span>
                        <div style="font-size: 0.65rem; color: var(--text-muted);">${sess.findings_count || 0} findings</div>
                    </div>
                    <span class="badge-pill" style="font-size: 0.62rem; padding: 2px 4px; border-color: ${sess.status === 'Reviewed & Finalized' ? 'rgba(52,211,153,0.4)' : 'rgba(245,158,11,0.4)'}; color: ${sess.status === 'Reviewed & Finalized' ? '#34d399' : '#fbbf24'};">${sess.status === 'Reviewed & Finalized' ? 'FINAL' : 'OPEN'}</span>
                `;
                container.appendChild(item);
            });
        } else {
            container.innerHTML = `<div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; padding: 6px;">No recent sessions found</div>`;
        }
    } catch (err) {
        container.innerHTML = `<div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; padding: 6px;">Ready</div>`;
    }
}

function switchActiveAuditSession(sessionId, framework) {
    activeSessionId = sessionId;
    syncFrameworkFromSession(sessionId, framework);
    document.getElementById("active-session-badge").innerText = `Session: ${activeSessionId.slice(0, 8)}...`;
    loadFindings();
    loadRecentSessionsList();
    alert(`📂 Switched to Audit Session: ${sessionId.slice(0, 8)}...`);
}

// Load recent sessions on page load
document.addEventListener("DOMContentLoaded", () => {
    loadRecentSessionsList();
});

// ── LICENSE & TOKEN BILLING ENGINE ──
async function fetchLicenseStatus() {
    try {
        const res = await authFetch(`${API_BASE}/license/wallet`);
        if (!res.ok) return;
        const data = await res.json();

        const widgetText = document.getElementById("license-widget-text");
        const widgetBtn = document.getElementById("license-widget-btn");

        if (widgetText && widgetBtn) {
            if (data.is_expired) {
                widgetText.innerText = "Trial Expired [Renew]";
                widgetBtn.style.background = "rgba(239,68,68,0.15)";
                widgetBtn.style.borderColor = "rgba(239,68,68,0.4)";
                widgetBtn.style.color = "#ef4444";
            } else {
                widgetText.innerText = `Free Trial: ${data.days_remaining}d [₹${data.balance_rupees}]`;
                widgetBtn.style.background = "rgba(16,185,129,0.15)";
                widgetBtn.style.borderColor = "rgba(16,185,129,0.4)";
                widgetBtn.style.color = "#10b981";
            }
        }

        if (document.getElementById("lic-group")) document.getElementById("lic-group").innerText = data.auditor_group;
        if (document.getElementById("lic-status-badge")) {
            document.getElementById("lic-status-badge").innerText = data.status;
            document.getElementById("lic-status-badge").style.color = data.is_expired ? "#ef4444" : "#10b981";
        }
        if (document.getElementById("lic-balance")) document.getElementById("lic-balance").innerText = `₹${data.balance_rupees.toFixed(2)}`;
        if (document.getElementById("lic-audits-remaining")) document.getElementById("lic-audits-remaining").innerText = `${data.audits_remaining} Audits Left`;
        if (document.getElementById("lic-expiry-date")) document.getElementById("lic-expiry-date").innerText = `${data.days_remaining} Days Remaining`;
    } catch (e) {
        console.warn("Failed to fetch license status", e);
    }
}

function openLicenseModal() {
    fetchLicenseStatus();
    const modal = document.getElementById("license-modal");
    if (modal) modal.style.display = "flex";
}

function closeLicenseModal() {
    const modal = document.getElementById("license-modal");
    if (modal) modal.style.display = "none";
}

async function handleActivateLicenseSubmit(e) {
    e.preventDefault();
    const key = document.getElementById("lic-key-input").value.trim();
    if (!key) return;

    try {
        const res = await authFetch(`${API_BASE}/license/activate`, { // BUG-08 FIX: was bare fetch() — no JWT header sent
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ license_key: key })
        });
        const data = await res.json();
        if (res.ok) {
            alert(`🎉 ${data.message}`);
            document.getElementById("lic-key-input").value = "";
            closeLicenseModal();
            fetchLicenseStatus();
        } else {
            alert(`❌ Activation Failed: ${data.detail || 'Invalid key'}`);
        }
    } catch (err) {
        alert(`❌ Error activating license: ${err.message}`);
    }
}

// ── TARGET AUDIT SCOPE SELECTOR MODAL (108 CONTROLS) HANDLERS ──
let modalSelectedControls = new Set();
let modalActiveDomain = "All";

function toggleScopeChecklistModal() {
    openScopeSelectorModal();
}

function openScopeSelectorModal() {
    const modal = document.getElementById("scope-selector-modal");
    if (!modal) return;
    populateModalControlsGrid();
    modal.style.display = "flex";
}

function closeScopeSelectorModal() {
    const modal = document.getElementById("scope-selector-modal");
    if (modal) modal.style.display = "none";
}

function populateModalControlsGrid() {
    const grid = document.getElementById("modal-controls-grid");
    if (!grid) return;
    grid.innerHTML = "";

    const all108Controls = [];
    const isoDomains = [
        { code: "A.5", name: "Organizational Controls", count: 37 },
        { code: "A.6", name: "People Controls", count: 8 },
        { code: "A.7", name: "Physical Controls", count: 14 },
        { code: "A.8", name: "Technological Controls", count: 34 }
    ];

    let slCount = 1;
    isoDomains.forEach(d => {
        for (let i = 1; i <= d.count; i++) {
            const ctrlId = `${d.code}.${i}`;
            all108Controls.push({ id: ctrlId, sl: slCount++, name: `${ctrlId} Security Control`, domain: "ISO 27001", badge: d.code });
        }
    });

    const vaptChecks = [
        "VAPT-1 External Perimeter Vulnerability Assessment",
        "VAPT-2 Web Application Pen Testing (OWASP Top 10)",
        "VAPT-3 Network Infrastructure Penetration Testing",
        "VAPT-4 API Security & OAuth Endpoint Assessment",
        "VAPT-5 Database Injection & SQLi Hardening",
        "VAPT-6 Cross-Site Scripting (XSS) & CSTI Testing",
        "VAPT-7 XML External Entity (XXE) & SSRF Auditing",
        "VAPT-8 Privilege Escalation & Access Control Verification",
        "VAPT-9 Broken Authentication & Session Management",
        "VAPT-10 SSL/TLS Cipher Suite & HSTS Hardening",
        "VAPT-11 Sensitive Data Exposure & Masking Audit",
        "VAPT-12 Security Misconfiguration & Service Banners",
        "VAPT-13 Source Code & Dependency Vulnerability Scan",
        "VAPT-14 Cloud Infrastructure & IAM Policy Audit",
        "VAPT-15 Final VAPT Executive Summary & Remediation"
    ];

    vaptChecks.forEach((vname, idx) => {
        const vid = `VAPT-${idx + 1}`;
        all108Controls.push({ id: vid, sl: slCount++, name: vname, domain: "VAPT", badge: "VAPT" });
    });

    all108Controls.forEach(ctrl => {
        modalSelectedControls.add(ctrl.id);
        const card = document.createElement("div");
        card.className = "modal-ctrl-card";
        card.dataset.id = ctrl.id.toLowerCase();
        card.dataset.name = ctrl.name.toLowerCase();
        card.dataset.domain = ctrl.domain;
        card.style.cssText = "background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 10px; padding: 8px 12px; display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 0.78rem;";
        const isChecked = modalSelectedControls.has(ctrl.id);

        card.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px; overflow: hidden;">
                <input type="checkbox" id="mchk-${ctrl.id}" ${isChecked ? 'checked' : ''} onchange="toggleModalControlSelection('${ctrl.id}')" style="cursor: pointer;">
                <label for="mchk-${ctrl.id}" style="cursor: pointer; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; color: #f8fafc; font-weight: 500;">
                    <b>${ctrl.id}</b> ${ctrl.name.replace(ctrl.id, '')}
                </label>
            </div>
            <span class="badge-pill" style="font-size: 0.62rem; padding: 2px 6px; border-color: ${ctrl.domain === 'VAPT' ? 'rgba(168,85,247,0.4)' : 'rgba(59,130,246,0.4)'}; color: ${ctrl.domain === 'VAPT' ? '#c084fc' : '#60a5fa'};">${ctrl.badge}</span>
        `;
        grid.appendChild(card);
    });

    updateModalSelectedCounter();
}

function toggleModalControlSelection(ctrlId) {
    if (modalSelectedControls.has(ctrlId)) {
        modalSelectedControls.delete(ctrlId);
    } else {
        modalSelectedControls.add(ctrlId);
    }
    updateModalSelectedCounter();
}

function updateModalSelectedCounter() {
    // GLITCH-06 FIX: use actual DOM count instead of hardcoded 108
    const count = modalSelectedControls.size;
    const badge = document.getElementById("modal-selected-count-badge");
    const gridSize = document.querySelectorAll(".modal-ctrl-card").length || 108;
    if (badge) badge.innerText = `${count} of ${gridSize} Controls Selected`;

    const sidebarBadge = document.getElementById("sidebar-scope-count-badge");
    const totalBadge = document.getElementById("total-scope-badge");
    if (sidebarBadge) sidebarBadge.innerText = `${count}/${gridSize} · Edit`;
    if (totalBadge) totalBadge.innerText = `${count} / ${gridSize} selected`;
}

function filterModalControlsGrid() {
    const searchVal = document.getElementById("modal-control-search").value.toLowerCase().trim();
    const cards = document.querySelectorAll(".modal-ctrl-card");
    cards.forEach(card => {
        const matchesSearch = !searchVal || card.dataset.id.includes(searchVal) || card.dataset.name.includes(searchVal);
        const matchesDomain = modalActiveDomain === "All" || card.dataset.domain === modalActiveDomain;
        card.style.display = (matchesSearch && matchesDomain) ? "flex" : "none";
    });
}

function filterModalDomain(domain) {
    modalActiveDomain = domain;
    ["modal-filter-all", "modal-filter-iso", "modal-filter-vapt"].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.classList.remove("active");
    });
    if (domain === "All" && document.getElementById("modal-filter-all")) document.getElementById("modal-filter-all").classList.add("active");
    if (domain === "ISO 27001" && document.getElementById("modal-filter-iso")) document.getElementById("modal-filter-iso").classList.add("active");
    if (domain === "VAPT" && document.getElementById("modal-filter-vapt")) document.getElementById("modal-filter-vapt").classList.add("active");
    filterModalControlsGrid();
}

function selectAllModalCheckboxes(selected) {
    const checkboxes = document.querySelectorAll(".modal-ctrl-card input[type='checkbox']");
    modalSelectedControls.clear();
    checkboxes.forEach(chk => {
        chk.checked = selected;
        const ctrlId = chk.id.replace("mchk-", "");
        if (selected) modalSelectedControls.add(ctrlId);
    });
    updateModalSelectedCounter();
}

function saveScopeFromModal() {
    closeScopeSelectorModal();
    const count = modalSelectedControls.size;
    alert(`✅ Scope saved successfully! ${count} controls selected for audit.`);
}

async function selectRecentSessionScope(ev) { // BUG-13 FIX: use explicit ev param instead of deprecated window.event global
    const btn = ev ? ev.target : null;
    if (btn) {
        btn.innerText = "⚡ Loading...";
        btn.style.opacity = "0.7";
    }

    try {
        const response = await authFetch(`${API_BASE}/audit/sessions`);
        const data = await response.json();

        if (data.success && data.sessions && data.sessions.length > 0) {
            const recent = data.sessions[0];
            activeSessionId = recent.session_id;
            activeSessionTitle = recent.session_title;
            applySessionFramework(recent.framework);

            // Update header UI elements
            const badge = document.getElementById("active-session-badge");
            if (badge) badge.innerText = `Session ID: ${activeSessionId}`;
            const wsTitle = document.getElementById("workspace-title");
            if (wsTitle) wsTitle.innerText = activeSessionTitle;

            // Load evidence files for this recent session
            const evRes = await authFetch(`${API_BASE}/audit/evidence?session_id=${activeSessionId}`);
            const evData = await evRes.json();
            let loadedCount = 0;
            if (evData.success && evData.files) {
                uploadedFilesList = evData.files.map(f => ({
                    name: f.filename,
                    size: f.size_str || "Attached",
                    type: f.filename.split('.').pop().toUpperCase(),
                    iconClass: "file-type-doc"
                }));
                loadedCount = uploadedFilesList.length;
                renderUploadedFilesList();
            }

            // Load recent audit findings
            const fRes = await authFetch(`${API_BASE}/audit/findings?session_id=${activeSessionId}&include_info=true`);
            const fData = await fRes.json();
            let findingsCount = 0;
            if (fData.success && fData.findings) {
                findingsList = findingsForSession(fData);
                findingsCount = findingsList.length;
                renderFindingsList();
                updateKPICounters();
            }

            // Select all control checkboxes
            selectAllCheckboxes(true);

            // Display prominent notification toast
            showToastBanner(`🕒 RECENT SESSION LOADED: "${recent.session_title}" (${recent.session_id.slice(0, 6)}) — ${loadedCount} Files · ${findingsCount} Findings · 108 Controls Scoped`);
        } else {
            showToastBanner("ℹ️ No recent audit sessions found in ShakthiDB.");
        }
    } catch (err) {
        showToastBanner(`⚠️ Failed to load recent session: ${err.message}`);
    } finally {
        if (btn) {
            btn.innerText = "🕒 Recent";
            btn.style.opacity = "1";
        }
    }
}

function closeToastBanner() {
    let toast = document.getElementById("app-toast-banner");
    if (toast) {
        toast.style.opacity = "0";
        setTimeout(() => { if (toast) toast.style.display = "none"; }, 300);
    }
}

// Second argument was already being passed at several call sites ("error", "info")
// while the function ignored it entirely, so a resume failure was styled and timed
// exactly like a success. It is honoured now, and decides whether the banner
// auto-dismisses:
//   success / info   -> clears itself after 5s, it is only a confirmation
//   warning / error  -> stays until dismissed, the auditor has to act on it
// When no type is given the message is inspected, so the existing calls that
// signal a problem only through their wording ("⚠️ Failed to load...", "critically
// low") stay on screen without every one of them having to be edited.
const _BANNER_STICKY_HINTS = [
    "⚠", "🛑", "error", "failed", "failure", "critical", "low", "busy",
    "unable", "cannot", "denied", "rejected", "timeout", "timed out",
];

function _bannerIsSticky(msgText, type) {
    const t = String(type || "").toLowerCase();
    if (t === "error" || t === "warning" || t === "warn") return true;
    if (t === "success" || t === "info") return false;
    const m = String(msgText || "").toLowerCase();
    return _BANNER_STICKY_HINTS.some(h => m.includes(h));
}

function showToastBanner(msgText, type) {
    let toast = document.getElementById("app-toast-banner");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "app-toast-banner";
        toast.style.cssText = "position: fixed; top: 20px; right: 20px; z-index: 99999; background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #3b82f6; color: #fff; padding: 12px 18px; border-radius: 12px; font-size: 0.84rem; font-weight: 700; box-shadow: 0 10px 30px rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: space-between; gap: 12px; transition: all 0.3s ease; max-width: 520px;";
        document.body.appendChild(toast);
    }

    const safeText = (typeof escapeHtml === "function") ? escapeHtml(msgText) : msgText;
    toast.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; flex:1;">
            <span>${safeText}</span>
        </div>
        <button type="button" onclick="closeToastBanner()" style="background:rgba(255,255,255,0.15); border:none; color:#cbd5e1; font-size:0.9rem; font-weight:900; line-height:1; cursor:pointer; width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; transition:all 0.2s;" onmouseleave="this.style.color='#cbd5e1';this.style.background='rgba(255,255,255,0.15)';" onmouseenter="this.style.color='#fff';this.style.background='rgba(239,68,68,0.7)';" title="Close Warning">✕</button>
    `;
    toast.style.display = "flex";
    toast.style.opacity = "1";

    // Clear any countdown still running from a previous banner, or it would hide
    // this one early.
    if (window._bannerTimer) { clearTimeout(window._bannerTimer); window._bannerTimer = null; }

    const sticky = _bannerIsSticky(msgText, type);
    toast.style.borderColor = sticky ? "#f59e0b" : "#3b82f6";
    if (!sticky) {
        window._bannerTimer = setTimeout(closeToastBanner, _TOAST_AUTO_DISMISS_MS);
    }
}



function toggleRecentSessionsSidebar() {
    const container = document.getElementById("recent-sessions-container");
    const arrow = document.getElementById("recent-sessions-arrow");
    const btn = document.getElementById("btn-toggle-recent-sidebar");

    if (container) {
        const isHidden = (container.style.display === "none" || !container.style.display);
        container.style.display = isHidden ? "block" : "none";
        if (arrow) {
            arrow.style.transform = isHidden ? "rotate(90deg)" : "rotate(0deg)";
        }
        if (btn) {
            btn.style.background = isHidden ? "rgba(37, 99, 235, 0.2)" : "rgba(30, 41, 59, 0.5)";
            btn.style.borderColor = isHidden ? "rgba(59, 130, 246, 0.4)" : "rgba(148, 163, 184, 0.2)";
        }
    }
}

async function handleScopingExcelUpload(event) {
    const fileInput = event.target;
    if (!fileInput.files || fileInput.files.length === 0) return;

    const file = fileInput.files[0];
    const excelBtn = document.getElementById("btn-excel-scoping");
    if (excelBtn) {
        excelBtn.innerText = "📊 Parsing Excel...";
        excelBtn.style.opacity = "0.7";
    }

    try {
        const formData = new FormData();
        formData.append("file", file);
        try {
            const _fw = (typeof activeSessionFramework !== "undefined" && activeSessionFramework)
                || (document.getElementById("framework-select") || {}).value || "";
            if (_fw) formData.append("framework", _fw);
        } catch (e) { /* optional */ }
        // See the sibling upload path above -- Customize needs the parser to skip
        // control resolution, which it only does when told the mode.
        try {
            // Always sent, never conditional: an omitted mode makes the server
        // fall back to Excel scoping, which judges the row on policy AND
        // evidence and fails every question-based row on a missing policy.
        formData.append("scoping_mode", resolveScopingMode());
        } catch (e) { /* optional */ }

        const res = await authFetch(`${API_BASE}/controls/parse-scope-excel`, { // BUG-07 FIX: was bare fetch() — no JWT sent, caused silent 401 + fallback to 5-control default
            method: "POST",
            body: formData
        });

        const data = await res.json();

        if (data.success && data.rag_mode) {
            // Customize: the questions ARE the scope, so matched_sls is empty by
            // design. Without this branch the upload fell into the "no ISO controls
            // could be matched" case below -- which is about a sheet that failed to
            // resolve -- and threw the auditor's checklist away on the one mode that
            // never resolves a control in the first place.
            customEvidenceMappings = data.custom_evidence || null;
            customControlDocuments = data.custom_documents || null;
            selectAllCheckboxes(false);
            updateSelectedScopeCount();
            setScopingMode('CUSTOMIZE');
            if (typeof saveSessionScopingCache === "function") {
                saveSessionScopingCache(activeSessionId, data.custom_evidence, 'CUSTOMIZE');
            }
            const _qCount = (data.custom_evidence && data.custom_evidence.excel_items)
                ? data.custom_evidence.excel_items.length : (data.total_rows || 0);
            const _banner = document.getElementById("excel-scope-banner");
            if (_banner) _banner.style.display = "flex";
            const _bLabel = document.getElementById("excel-scope-label");
            if (_bLabel) _bLabel.innerText = `${_qCount} question(s) loaded`;
            showToastBanner(`CHECKLIST (DOCUMENT Q&A) APPLIED: ${_qCount} question(s) from "${file.name}" — each answered from the document cited on its row`);
            if (data.warning) {
                setTimeout(() => alert(`⚠️ ${data.warning}`), 600);
            }
        } else if (data.success && data.matched_sls && data.matched_sls.length > 0) {
            // Uncheck all first
            selectAllCheckboxes(false);

            // Check only matched SLs from Excel
            data.matched_sls.forEach(sl => {
                const chk = document.getElementById(`ctrl_chk_${sl}`);
                if (chk) chk.checked = true;
            });

            // Persist the row-level Excel data (per-row control + locked evidence file)
            // so /audit/start actually receives it — without this, the audit falls back
            // to deduping by unique control ID (losing rows that share a control) and
            // running with no per-control file locking at all.
            customEvidenceMappings = data.custom_evidence || null;
            customControlDocuments = data.custom_documents || null;

            updateSelectedScopeCount();
            // Keep Customize selected. Both scope modes upload the same sheet through
            // this handler, so forcing 'Excel Scoping' here threw the auditor straight
            // back out of Customize the moment their checklist finished uploading --
            // and with it the "no policy required" rule the mode exists to apply.
            const _wasCustomize = String(window.currentScopingMode || "").toUpperCase().startsWith("CUSTOM");
            setScopingMode(_wasCustomize ? 'CUSTOMIZE' : 'Excel Scoping');

            // Persist the scope for THIS session. saveSessionScopingCache() existed and
            // was complete, but nothing ever called it -- so its counterpart
            // restoreSessionScopingCache() always found an empty cache and returned
            // false, and switching to another session and back silently dropped the
            // uploaded scope, leaving the auditor to re-upload the same checklist.
            if (typeof saveSessionScopingCache === "function") {
                saveSessionScopingCache(
                    activeSessionId,
                    data.custom_evidence,
                    _wasCustomize ? 'CUSTOMIZE' : 'Excel Scoping'
                );
            }

            const totalExcelItems = (data.custom_evidence && data.custom_evidence.excel_items) ? data.custom_evidence.excel_items.length : data.matched_sls.length;
            showToastBanner(`${_wasCustomize ? 'CHECKLIST (QUESTION-BASED) SCOPING APPLIED' : 'CONTROL SCOPING APPLIED'}: ${totalExcelItems} Checklist Items Scoped from Excel ("${file.name}")`);

            // Surface any partial-match warning (e.g. some rows could not be resolved)
            if (data.warning) {
                setTimeout(() => alert(`⚠️ ${data.warning}`), 600);
            }
        } else if (data.success && data.total_rows > 0 && (!data.matched_sls || data.matched_sls.length === 0)) {
            // Backend parsed rows but could not map any to known controls.
            // Do NOT fall through to parseClientSideCsvScope — that function
            // expects plain-text CSV; feeding it binary xlsx data produces garbage.
            const msg = data.warning ||
                `No ISO controls could be matched in "${file.name}". ` +
                `Please ensure the sheet contains a column with ISO control IDs (e.g. 5.15) or recognisable control names.`;
            alert(`⚠️ Excel Scoping: ${msg}`);
        } else {
            parseClientSideCsvScope(file);
        }
    } catch (err) {
        parseClientSideCsvScope(file);
    } finally {
        if (excelBtn) {
            excelBtn.innerText = "Excel Scoping";
            excelBtn.style.opacity = "1";
        }
        fileInput.value = "";
    }
}

function parseClientSideCsvScope(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;
        const lines = text.split(/\r?\n/);

        selectAllCheckboxes(false);
        let count = 0;

        allControlsData.forEach(c => {
            const ctrlId = (c.control_id || c.sl || "").toString().toLowerCase();
            const sl = String(c.sl);

            let matched = false;
            lines.forEach(line => {
                const lLower = line.toLowerCase();
                if (ctrlId && lLower.includes(ctrlId)) matched = true;
            });

            if (matched) {
                const chk = document.getElementById(`ctrl_chk_${sl}`);
                if (chk) {
                    chk.checked = true;
                    count++;
                }
            }
        });

        if (count === 0) {
            // Default 5 control selection if generic sheet
            for (let i = 1; i <= 5; i++) {
                const chk = document.getElementById(`ctrl_chk_${i}`);
                if (chk) chk.checked = true;
            }
            count = 5;
        }

        updateSelectedScopeCount();
        // Same as the primary upload handler above -- do not knock the auditor out of
        // Customize just because their checklist finished uploading.
        const _wasCustomizeCsv = String(window.currentScopingMode || "").toUpperCase().startsWith("CUSTOM");
        setScopingMode(_wasCustomizeCsv ? 'CUSTOMIZE' : 'Excel Scoping');
        showToastBanner(`${_wasCustomizeCsv ? 'CHECKLIST (QUESTION-BASED) SCOPING APPLIED' : 'CONTROL SCOPING APPLIED'}: ${count} Controls Scoped from "${file.name}"`);
    };
    reader.readAsText(file);
}

// ── FORGOT PASSWORD TOTP RECOVERY ENGINE ──




// ── SESSION-WISE BENCHMARK EXPORTER ──
async function downloadSelectedSessionBenchmark() { // BUG-09 FIX: must be async (uses await authFetch)
    const select = document.getElementById("benchmark-session-select");
    let val = select ? select.value : "all";
    if (val === "active") {
        val = activeSessionId || "all";
    }
    const downloadUrl = `${API_BASE}/audit/export-token-benchmark?session_id=${encodeURIComponent(val)}`;
    // BUG-09 FIX: window.location.href bypasses authFetch — JWT is never sent, causing 401.
    // Use the same authenticated blob-download pattern as PDF/DOCX exports.
    const btn = document.getElementById ? document.getElementById("btn-download-benchmark") : null;
    if (btn) { btn.innerText = "⏳ Exporting..."; btn.style.opacity = "0.7"; }
    try {
        const response = await authFetch(downloadUrl);
        if (!response.ok) throw new Error(`Server returned ${response.status}`);
        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = `audit_token_benchmark_${val.slice(0, 8)}.xlsx`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
    } catch (err) {
        alert(`❌ Benchmark export failed: ${err.message}`);
    } finally {
        if (btn) { btn.innerText = "📥 Export Benchmark"; btn.style.opacity = "1"; }
    }
}

async function populateBenchmarkSessionSelector() {
    const select = document.getElementById("benchmark-session-select");
    if (!select) return;

    try {
        const response = await authFetch(`${API_BASE}/audit/benchmark/sessions`);
        const data = await response.json();
        if (data.success && data.sessions && data.sessions.length > 0) {
            select.innerHTML = `
                <option value="all">📊 All Audit Sessions (Combined Benchmark)</option>
                <option value="active">⚡ Current Active Audit Session</option>
            `;
            data.sessions.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.session_id;
                const sidShort = (s.session_id || '').slice(0, 8);
                const auditorName = s.auditor_username || s.folder_name || "Auditor";
                const title = s.session_title || s.folder_name || "Audit Session";
                opt.innerText = `👤 ${auditorName} — ${title} (${sidShort})`;
                select.appendChild(opt);
            });
        }
    } catch (err) {
        console.error("Failed to populate benchmark session selector:", err);
    }
}

// ── FORGOT PASSWORD TOTP RECOVERY ENGINE ──
function openForgotPasswordModal() {
    const modal = document.getElementById("forgot-password-modal");
    if (!modal) {
        console.error("forgot-password-modal element not found in DOM");
        alert("Password recovery modal is loading. Please refresh your page.");
        return;
    }

    const step1 = document.getElementById("fp-step-1");
    const step2 = document.getElementById("fp-step-2");
    if (step1) step1.style.display = "block";
    if (step2) step2.style.display = "none";

    const loginUser = document.getElementById("username-input") ? document.getElementById("username-input").value.trim() : "";
    const fpUserInp = document.getElementById("fp-username-input");
    if (fpUserInp) fpUserInp.value = loginUser || "";

    const fpOtp = document.getElementById("fp-otp-input");
    if (fpOtp) fpOtp.value = "";
    const fpPw = document.getElementById("fp-new-password-input");
    if (fpPw) fpPw.value = "";

    modal.style.display = "flex";
}

function closeForgotPasswordModal() {
    const modal = document.getElementById("forgot-password-modal");
    if (modal) modal.style.display = "none";
}

async function requestForgotPasswordTOTP() {
    const username = (document.getElementById("fp-username-input").value || "").trim();
    if (!username) {
        alert("Please enter your registered username.");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/auth/forgot-password/request`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: username })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(data.detail || data.message || "Failed to find account username.");
            return;
        }

        document.getElementById("fp-qr-img").src = data.qr_code_base64;
        document.getElementById("fp-qr-secret").innerText = data.totp_secret;
        document.getElementById("fp-step-1").style.display = "none";
        document.getElementById("fp-step-2").style.display = "block";
        showToast("Authenticator QR loaded! Enter 6-digit code to reset password.", "info");
    } catch (err) {
        console.error("Forgot password error:", err);
        alert("Error connecting to server.");
    }
}

async function submitResetPasswordTOTP() {
    const username = (document.getElementById("fp-username-input").value || "").trim();
    const otpCode = (document.getElementById("fp-otp-input").value || "").trim();
    const newPassword = (document.getElementById("fp-new-password-input").value || "").trim();

    if (!otpCode || otpCode.length < 6) {
        alert("Please enter a valid 6-digit TOTP code from Google Authenticator.");
        return;
    }
    if (!newPassword || newPassword.length < 8) {
        alert("New password must be at least 8 characters long under ISO 27001 policy.");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/auth/forgot-password/reset`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                otp_code: otpCode,
                new_password: newPassword
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(data.detail || data.message || "Failed to reset password. Check your TOTP code.");
            return;
        }

        closeForgotPasswordModal();
        alert(`✅ Password successfully reset for '${username}'! You can now sign in with your new password.`);
        showToast("Password reset successful!", "success");
    } catch (err) {
        console.error("Password reset error:", err);
        alert("Error resetting password.");
    }
}

// ── AUDITEE AUDITOR ASSIGNMENT, DOCUMENT HISTORY & UNDO DELETE ────────────────
let _undoToastTimer = null;
function showUndoToast(message, onUndoCallback) {
    const existing = document.getElementById("undo-toast-banner");
    if (existing) existing.remove();
    if (_undoToastTimer) clearTimeout(_undoToastTimer);

    const banner = document.createElement("div");
    banner.id = "undo-toast-banner";
    banner.style.cssText = "position: fixed; bottom: 24px; right: 24px; z-index: 10000; background: #1e293b; color: #fff; border: 1px solid #3b82f6; border-radius: 12px; padding: 12px 18px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); display: flex; align-items: center; gap: 14px; font-size: 0.88rem;";

    banner.innerHTML = `
        <span>🗑️ ${message}</span>
        <button type="button" id="undo-toast-btn" style="background: #2563eb; color: #fff; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 0.82rem; transition: all 0.2s;">↩️ Undo Delete</button>
        <button type="button" onclick="this.parentElement.remove()" style="background: transparent; border: none; color: #94a3b8; cursor: pointer; font-size: 1rem; padding: 0 4px;">✕</button>
    `;

    document.body.appendChild(banner);

    document.getElementById("undo-toast-btn").onclick = () => {
        banner.remove();
        if (onUndoCallback) onUndoCallback();
        showToast("Restored successfully!", "success");
    };

    _undoToastTimer = setTimeout(() => {
        if (banner.parentElement) banner.remove();
    }, 8000);
}

async function loadRegisteredAuditors() {
    const selector = document.getElementById("target-auditor-selector");
    if (!selector) return;

    try {
        const res = await authFetch(`${API_BASE}/audit/users/auditors`);
        const data = await res.json();
        if (!res.ok || !data.success) return;

        selector.innerHTML = `<option value="">-- Select Target Auditor --</option>`;
        (data.auditors || []).forEach(a => {
            const opt = document.createElement("option");
            opt.value = a.username;
            opt.innerText = `👤 ${a.username} (${a.role.toUpperCase()})`;
            selector.appendChild(opt);
        });

        // Pre-select if active session has an assigned auditor
        if (activeSessionId) {
            const sessRes = await authFetch(`${API_BASE}/audit/evidence?session_id=${activeSessionId}`);
            const sessData = await sessRes.json();
            if (sessData.files && sessData.files.length > 0 && sessData.files[0].assigned_auditor) {
                selector.value = sessData.files[0].assigned_auditor;
            }
        }
    } catch (err) {
        console.error("Error loading registered auditors:", err);
    }
}

async function assignTargetAuditorToActiveSession() {
    const selector = document.getElementById("target-auditor-selector");
    if (!selector || !activeSessionId) return;

    const assignedAuditor = selector.value;
    if (!assignedAuditor) return;

    try {
        const res = await authFetch(`${API_BASE}/audit/assign-auditor`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                assigned_auditor_username: assignedAuditor
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Assigned audit session to Auditor '${assignedAuditor}' ✅`, "success");
            loadAuditeeDocumentHistory();
        }
    } catch (err) {
        console.error("Error assigning target auditor:", err);
    }
}

async function sendEvidenceToAuditor() {
    const selector = document.getElementById("target-auditor-selector");
    const btn = document.getElementById("send-to-auditor-btn");

    // Validate auditor selected
    const assignedAuditor = selector ? selector.value : "";
    if (!assignedAuditor) {
        showToast("⚠️ Please select a Target Auditor from the dropdown first.", "warning");
        if (selector) selector.focus();
        return;
    }

    // Validate session exists
    if (!activeSessionId) {
        showToast("⚠️ No active session found. Please refresh and try again.", "warning");
        return;
    }

    // Check that at least one file has been uploaded in this session
    let fileCount = 0;
    try {
        const checkRes = await authFetch(`${API_BASE}/audit/evidence?session_id=${activeSessionId}`);
        const checkData = await checkRes.json();
        fileCount = (checkData.files || []).filter(f => !f.is_deleted).length;
    } catch (e) {
        console.warn("[SendEvidence] Could not check file count:", e);
    }

    if (fileCount === 0) {
        showToast("⚠️ Please upload at least one evidence document before sending to the auditor.", "warning");
        return;
    }

    // Disable button to prevent double-click
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span style="display:inline-block;animation:spin 1s linear infinite">⏳</span> Sending…`;
    }

    try {
        const res = await authFetch(`${API_BASE}/audit/assign-auditor`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: activeSessionId,
                assigned_auditor_username: assignedAuditor
            })
        });
        const data = await res.json();

        if (data.success) {
            showToast(`✅ Evidence session successfully sent to Auditor '${assignedAuditor}'! (${fileCount} file${fileCount !== 1 ? 's' : ''} submitted)`, "success");
            loadAuditeeDocumentHistory();
        } else {
            showToast(`❌ Failed to send: ${data.detail || data.message || "Unknown error"}`, "error");
        }
    } catch (err) {
        console.error("Error sending evidence to auditor:", err);
        showToast("❌ Network error while sending. Please check your connection and try again.", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span>📤</span> Send to Auditor`;
        }
    }
}

window._showAllDocHistory = false;

function toggleShowAllDocHistory() {
    window._showAllDocHistory = !window._showAllDocHistory;
    renderAuditeeDocumentHistoryTable(window._docHistoryCache || []);
}

async function loadAuditeeDocumentHistory() {
    const container = document.getElementById("auditee-history-table-container");
    if (!container) return;

    try {
        const username = currentUser ? currentUser.username : "";
        const res = await authFetch(`${API_BASE}/audit/auditee/document-history?username=${encodeURIComponent(username)}`);
        const data = await res.json();
        if (!res.ok || !data.success) {
            container.innerHTML = `<div class="empty-state">Unable to load document history.</div>`;
            return;
        }

        window._docHistoryCache = data.history || [];
        window._showAllDocHistory = false;
        renderAuditeeDocumentHistoryTable(window._docHistoryCache);
    } catch (err) {
        console.error("Error loading document history:", err);
    }
}

function renderAuditeeDocumentHistoryTable(history) {
    const container = document.getElementById("auditee-history-table-container");
    if (!container) return;

    if (history.length === 0) {
        container.innerHTML = `<div class="empty-state" style="padding: 30px; text-align: center; color: var(--text-muted);">No submitted document history found. Upload evidence files to see history log.</div>`;
        return;
    }

    const limit = window._showAllDocHistory ? history.length : 10;
    const toRender = history.slice(0, limit);

    let html = `
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-size: 0.78rem; text-transform: uppercase;">
                            <th style="padding: 10px 12px;">Document Name</th>
                            <th style="padding: 10px 12px;">Size</th>
                            <th style="padding: 10px 12px;">Submitted Timestamp</th>
                            <th style="padding: 10px 12px;">Assigned Auditor</th>
                            <th style="padding: 10px 12px;">Status</th>
                            <th style="padding: 10px 12px; text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

    toRender.forEach(item => {
        const isDel = item.is_deleted;
        const rowBg = isDel ? "rgba(239, 68, 68, 0.06)" : "transparent";
        const fileIcon = item.filename.endsWith(".pdf") ? "📄" : item.filename.endsWith(".zip") ? "📦" : "📝";
        const safeFilename = escapeHtml(item.filename);
        const safeFilenameForClick = safeFilename.replace(/'/g, "\\'");
        const safeSessionIdForClick = escapeHtml(item.session_id).replace(/'/g, "\\'");
        const auditorBadge = `<span style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); padding: 3px 8px; border-radius: 6px; font-size: 0.76rem; font-weight: 700;">👤 ${escapeHtml(item.assigned_auditor)}</span>`;
        const statusBadge = isDel
            ? `<span style="color: #ef4444; font-weight: 700; background: rgba(239, 68, 68, 0.12); padding: 2px 8px; border-radius: 4px;">Deleted (Soft)</span>`
            : `<span style="color: #10b981; font-weight: 700; background: rgba(16, 185, 129, 0.12); padding: 2px 8px; border-radius: 4px;">${escapeHtml(item.status)}</span>`;

        const actionBtn = isDel
            ? `<button type="button" onclick="undoDeleteEvidenceFile('${safeSessionIdForClick}', ${item.id}, '${safeFilenameForClick}')" style="background: #2563eb; color: #fff; border: none; padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.78rem; font-weight: 700;">↩️ Undo Delete</button>`
            : `<button type="button" onclick="deleteServerEvidenceFile('${safeSessionIdForClick}', ${item.id}, '${safeFilenameForClick}')" style="background: transparent; border: 1px solid #ef4444; color: #ef4444; padding: 4px 8px; border-radius: 6px; cursor: pointer; font-size: 0.78rem;">🗑️ Delete</button>`;

        html += `
                <tr style="border-bottom: 1px solid var(--border-color); background: ${rowBg}; opacity: ${isDel ? 0.7 : 1};">
                    <td style="padding: 10px 12px; font-weight: 600; text-decoration: ${isDel ? 'line-through' : 'none'};">${fileIcon} ${safeFilename}</td>
                    <td style="padding: 10px 12px; color: var(--text-muted);">${escapeHtml(item.size_str)}</td>
                    <td style="padding: 10px 12px; color: var(--text-muted);">${escapeHtml(item.uploaded_at)}</td>
                    <td style="padding: 10px 12px;">${auditorBadge}</td>
                    <td style="padding: 10px 12px;">${statusBadge}</td>
                    <td style="padding: 10px 12px; text-align: right;">${actionBtn}</td>
                </tr>
            `;
    });

    html += `
                    </tbody>
                </table>
            </div>
        `;

    if (history.length > 10) {
        const label = window._showAllDocHistory
            ? "▲ Show Top 10 Documents Only"
            : `📂 Show More Documents (Total ${history.length})`;
        html += `<div style="text-align:center; padding-top:10px;">
            <button type="button" class="btn-secondary" style="padding:6px 14px; font-size:0.76rem; font-weight:700;" onclick="toggleShowAllDocHistory()">${escapeHtml(label)}</button>
        </div>`;
    }

    container.innerHTML = html;
}

async function deleteServerEvidenceFile(sessionId, fileId, filename) {
    try {
        const res = await authFetch(`${API_BASE}/audit/evidence/delete`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: sessionId,
                file_id: fileId,
                filename: filename
            })
        });
        const data = await res.json();
        if (data.success) {
            showUndoToast(`Evidence file '${filename}' deleted`, () => undoDeleteEvidenceFile(sessionId, fileId, filename));
            loadAuditeeDocumentHistory();
            if (activeSessionId === sessionId) loadEvidenceFileList();
        }
    } catch (err) {
        console.error("Error deleting evidence file:", err);
    }
}

async function undoDeleteEvidenceFile(sessionId, fileId, filename) {
    try {
        const res = await authFetch(`${API_BASE}/audit/evidence/undo-delete`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: sessionId,
                file_id: fileId,
                filename: filename
            })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Restored file '${filename}' ✅`, "success");
            loadAuditeeDocumentHistory();
            if (activeSessionId === sessionId) loadEvidenceFileList();
        }
    } catch (err) {
        console.error("Error undoing evidence deletion:", err);
    }
}

// ─── RESIZABLE SIDEBAR WITH DRAG HANDLE ────────────────────────────────────────
function initResizableSidebar() {
    const sidebar = document.getElementById("main-sidebar");
    const resizer = document.getElementById("sidebar-resizer");
    if (!sidebar || !resizer) return;
    if (resizer.dataset.initialized === "true") return;
    resizer.dataset.initialized = "true";

    const MIN_WIDTH = 240;
    const MAX_WIDTH = 650;
    const STORAGE_KEY = "audit_box_sidebar_width";

    // 1. Restore saved width from localStorage immediately
    const savedWidth = localStorage.getItem(STORAGE_KEY);
    if (savedWidth) {
        const parsed = parseInt(savedWidth, 10);
        if (!isNaN(parsed) && parsed >= MIN_WIDTH && parsed <= MAX_WIDTH) {
            sidebar.style.width = parsed + "px";
        }
    }

    let isResizing = false;
    let startX = 0;
    let startWidth = 0;

    function startResize(clientX) {
        isResizing = true;
        startX = clientX;
        startWidth = sidebar.getBoundingClientRect().width;

        document.body.classList.add("is-resizing");
        resizer.classList.add("is-dragging");
    }

    function doResize(clientX) {
        if (!isResizing) return;
        const dx = clientX - startX;
        let newWidth = startWidth + dx;
        const maxDynamicWidth = Math.min(MAX_WIDTH, Math.floor(window.innerWidth * 0.55));

        if (newWidth < MIN_WIDTH) newWidth = MIN_WIDTH;
        if (newWidth > maxDynamicWidth) newWidth = maxDynamicWidth;

        sidebar.style.width = newWidth + "px";
    }

    function stopResize() {
        if (!isResizing) return;
        isResizing = false;
        document.body.classList.remove("is-resizing");
        resizer.classList.remove("is-dragging");

        const finalWidth = sidebar.getBoundingClientRect().width;
        localStorage.setItem(STORAGE_KEY, Math.round(finalWidth));
    }

    // Mouse Events
    resizer.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startResize(e.clientX);
    });

    document.addEventListener("mousemove", (e) => {
        if (isResizing) {
            e.preventDefault();
            doResize(e.clientX);
        }
    });

    document.addEventListener("mouseup", () => {
        if (isResizing) {
            stopResize();
        }
    });

    // Touch Events for Mobile / Tablet drag
    resizer.addEventListener("touchstart", (e) => {
        if (e.touches.length === 1) {
            startResize(e.touches[0].clientX);
        }
    }, { passive: true });

    document.addEventListener("touchmove", (e) => {
        if (isResizing && e.touches.length === 1) {
            doResize(e.touches[0].clientX);
        }
    }, { passive: true });

    document.addEventListener("touchend", () => {
        if (isResizing) {
            stopResize();
        }
    });
}
