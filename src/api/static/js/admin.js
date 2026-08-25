// ── ADMIN AUDIT LOGS & WARNING MODALS MODULE ──

function closeUnreviewedWarningModal() {
    const modalEl = document.getElementById("unreviewed-warning-modal");
    if (modalEl) modalEl.style.display = "none";
}

async function forceCommitSessionToShaktiDB() {
    if (typeof commitSessionToShaktiDB === "function") {
        await commitSessionToShaktiDB(true);
    }
}

// loadAdminAuditLogs() and closeAdminLogModal() are defined in app.js
// (which loads after this file and builds the full tabbed admin modal DOM).

// ── EXPORT DOWNLOAD HANDLERS ──────────────────────────────────────────────────

/**
 * Download System Audit Event Logs as Excel (.xlsx) or PDF (.pdf).
 * Reads the #admin-log-auditor-filter input for optional per-user filtering.
 * Routes to /api/logs/system/export-excel or /api/logs/system/export-pdf.
 */
function downloadAdminLogsExport(format) {
    const auditorFilter = (document.getElementById("admin-log-auditor-filter")?.value || "").trim();
    const ext = format === "excel" ? "xlsx" : "pdf";
    let url = `${API_BASE}/logs/system/export-${format}`;
    if (auditorFilter) {
        url += `?auditor_user=${encodeURIComponent(auditorFilter)}`;
    }
    const btn = document.getElementById(format === "excel" ? "btn-download-logs-excel" : "btn-download-logs-pdf");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Generating..."; }
    const a = document.createElement("a");
    a.href = url;
    a.download = `System_Event_Logs_${auditorFilter || "all"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = format === "excel" ? "📥 Download Logs (.xlsx)" : "📄 Download Logs (.pdf)";
        }
    }, 2500);
}

/**
 * Download Telemetry Benchmark Report as Excel (.xlsx) or PDF (.pdf).
 * Reads the #admin-log-auditor-filter input for optional per-user filtering.
 * Routes to /api/logs/benchmark/export-excel or /api/logs/benchmark/export-pdf.
 */
function downloadBenchmarkExport(format) {
    const auditorFilter = (document.getElementById("admin-log-auditor-filter")?.value || "").trim();
    const ext = format === "excel" ? "xlsx" : "pdf";
    let url = `${API_BASE}/logs/benchmark/export-${format}`;
    if (auditorFilter) {
        url += `?auditor_user=${encodeURIComponent(auditorFilter)}`;
    }
    const btn = document.getElementById(format === "excel" ? "btn-download-telemetry-excel" : "btn-download-telemetry-pdf");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Generating..."; }
    const a = document.createElement("a");
    a.href = url;
    a.download = `Executive_Telemetry_Report_${auditorFilter || "all"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = format === "excel" ? "📥 Download Telemetry (.xlsx)" : "📄 Download Telemetry (.pdf)";
        }
    }, 2500);
}


// ── REDIS LIVE METRICS POLLING ────────────────────────────────────────────────
// Powers the "Live Server Metrics (Redis Stream)" KPI panel in the admin tab.
// Polls /api/logs/live-metrics every 3s and updates KPI cards + session table.
// ─────────────────────────────────────────────────────────────────────────────

let _liveMetricsInterval = null;

/**
 * Start polling Redis live metrics every 3 seconds.
 * Injects the KPI panel + Active Sessions table into #live-metrics-container.
 * Call this when the admin-logs tab is opened.
 */
function startLiveMetricsPolling() {
    stopLiveMetricsPolling(); // clear any previous interval
    _fetchAndRenderLiveMetrics(); // immediate first fetch
    _liveMetricsInterval = setInterval(_fetchAndRenderLiveMetrics, 3000);
}

function stopLiveMetricsPolling() {
    if (_liveMetricsInterval) {
        clearInterval(_liveMetricsInterval);
        _liveMetricsInterval = null;
    }
}

window._adminLogLimit = window._adminLogLimit || 500;
window.setAdminLogLimit = function(val) {
    window._adminLogLimit = parseInt(val, 10) || 500;
    if (typeof _fetchAndRenderLiveMetrics === "function") _fetchAndRenderLiveMetrics();
};

async function _fetchAndRenderLiveMetrics() {
    const container = document.getElementById("live-metrics-container");
    if (!container) return;
    try {
        const limit = window._adminLogLimit || 500;
        const res = await authFetch(`${API_BASE}/logs/live-metrics?limit=${limit}`);
        if (!res.ok) return;
        const d = await res.json();

        const redisOk = d.redis_available !== false;
        const tokens  = redisOk ? (d.global_tokens || 0).toLocaleString() : "---";
        const latency = redisOk ? (d.avg_latency_per_ctrl_str || "0m 0.0s") : "---";
        const files   = redisOk ? (d.global_files || 0) : "---";
        const errors  = redisOk ? (d.global_errors || 0) : "---";
        const sessions = redisOk ? (d.active_sessions || []) : [];

        const statusDot = redisOk
            ? `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:5px;"></span>Redis Connected`
            : `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#ef4444;margin-right:5px;"></span>Redis Offline`;

        container.innerHTML = `
            <!-- Status bar -->
            <div style="display:flex; align-items:center; gap:8px; font-size:0.78rem; font-weight:700; color:#cbd5e1; margin-bottom:12px;">
                ${statusDot}
                <span style="margin-left:auto; font-size:0.75rem; color:#94a3b8; font-weight:600;">Updated: ${new Date().toLocaleTimeString()}</span>
            </div>

            <!-- KPI Cards -->
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px;">
                ${_kpiCard("Tokens Consumed", tokens + " Tokens", "#4ade80", "↑")}
                ${_kpiCard("Avg Latency/Ctrl", latency, "#fbbf24", "⚡")}
                ${_kpiCard("Total Files/Size", files + " Files", "#38bdf8", "📁")}
                ${_kpiCard("Error Log", errors + " Errors", errors > 0 ? "#f87171" : "#4ade80", errors > 0 ? "⚠" : "✓")}
            </div>

            <!-- Auditor Sessions (Running + Completed) -->
            <div style="background:#0f172a; border:1px solid #334155; border-radius:10px; overflow:hidden; box-shadow:0 4px 16px rgba(0,0,0,0.4);">
                <div style="padding:12px 16px; font-size:0.88rem; font-weight:800; color:#ffffff; background:#1e293b; border-bottom:1px solid #334155; display:flex; align-items:center; gap:10px;">
                    <span>Auditor Sessions</span>
                    <span style="font-size:0.72rem; font-weight:800; color:#38bdf8; background:#0c4a6e; border:1px solid #075985; padding:3px 10px; border-radius:12px;">
                        ${sessions.filter(s=>s.status==='running').length} Running
                    </span>
                    <span style="font-size:0.72rem; font-weight:800; color:#4ade80; background:#052e16; border:1px solid #166534; padding:3px 10px; border-radius:12px;">
                        ${sessions.filter(s=>s.status==='done').length} Completed
                    </span>
                    <span style="margin-left:auto; display:flex; align-items:center; gap:6px; font-size:0.75rem; color:#cbd5e1; font-weight:700;">
                        Show:
                        <select onchange="window.setAdminLogLimit(this.value)" style="background:#0f172a; color:#38bdf8; border:1px solid #334155; border-radius:4px; padding:2px 6px; font-size:0.72rem; font-weight:800; cursor:pointer;">
                            <option value="50" ${limit===50?'selected':''}>50</option>
                            <option value="100" ${limit===100?'selected':''}>100</option>
                            <option value="500" ${limit===500?'selected':''}>500 (All)</option>
                            <option value="1000" ${limit===1000?'selected':''}>1000</option>
                        </select>
                        (${sessions.length} Loaded)
                    </span>
                </div>
                ${sessions.length > 0 ? `
                    <table style="width:100%; border-collapse:collapse; font-size:0.8rem; color:#f8fafc;">
                        <thead>

                            <tr style="background:#0f172a; border-bottom:2px solid #334155;">
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Auditor</th>
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Started</th>
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Files / Size</th>
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Tokens</th>
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Latency</th>
                                <th style="padding:10px 14px; text-align:left; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Controls</th>
                                <th style="padding:10px 14px; text-align:center; font-weight:800; color:#f8fafc; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.5px;">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sessions.map(s => {
                                const rowBg = s.status === 'running'
                                    ? 'rgba(56,189,248,0.06)'
                                    : s.status === 'done'
                                        ? 'rgba(34,197,94,0.05)'
                                        : 'rgba(239,68,68,0.06)';
                                const startedFmt = s.started_at
                                    ? new Date(s.started_at).toLocaleString('en-IN', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'short'})
                                    : '—';
                                const statusBadge = s.status === 'running'
                                    ? '<span style="display:inline-flex;align-items:center;gap:5px;color:#38bdf8;background:#0c4a6e;border:1px solid #075985;padding:4px 10px;border-radius:12px;font-size:0.72rem;font-weight:800;">🔄 Running</span>'
                                    : s.status === 'done'
                                        ? '<span style="display:inline-flex;align-items:center;gap:5px;color:#4ade80;background:#052e16;border:1px solid #166534;padding:4px 10px;border-radius:12px;font-size:0.72rem;font-weight:800;">✅ Done</span>'
                                        : '<span style="display:inline-flex;align-items:center;gap:5px;color:#f87171;background:#450a0a;border:1px solid #991b1b;padding:4px 10px;border-radius:12px;font-size:0.72rem;font-weight:800;">❌ Error</span>';
                                return `
                                <tr style="border-bottom:1px solid #1e293b; background:${rowBg};">
                                    <td style="padding:11px 14px; font-weight:800; color:#38bdf8; font-size:0.85rem;">${s.auditor || 'SYSTEM'}</td>
                                    <td style="padding:11px 14px; color:#cbd5e1; font-size:0.78rem; font-weight:600;">${startedFmt}</td>
                                    <td style="padding:11px 14px; color:#f8fafc; font-weight:700; font-size:0.8rem;">${s.files} Files <span style="color:#38bdf8;">/ ${s.file_mb} MB</span></td>
                                    <td style="padding:11px 14px; color:#c084fc; font-weight:900; font-size:0.85rem;">${(s.tokens||0).toLocaleString()}</td>
                                    <td style="padding:11px 14px; color:#fbbf24; font-weight:900; font-size:0.85rem;">${s.latency_str || '0m 0s'}</td>
                                    <td style="padding:11px 14px; color:#ffffff; font-weight:900; font-size:0.85rem;">${s.controls}</td>
                                    <td style="padding:11px 14px; text-align:center;">${statusBadge}</td>
                                </tr>`;
                            }).join('')}
                        </tbody>
                    </table>` : `
                    <div style="padding:32px; text-align:center; color:#94a3b8; font-size:0.85rem; font-weight:600;">
                        <div style="font-size:1.8rem; margin-bottom:8px;">📋</div>
                        No audit sessions recorded yet. Sessions appear here when auditors run scans.
                    </div>`}
            </div>`;
    } catch (err) {
        // Silently fail — Redis may be starting up
    }
}

function _kpiCard(label, value, color, icon) {
    return `
        <div style="background:#1e293b; border:1px solid #334155; border-radius:10px; padding:14px; box-shadow:0 4px 14px rgba(0,0,0,0.3);">
            <div style="font-size:0.76rem; font-weight:700; color:#f1f5f9; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px;">${label}</div>
            <div style="font-size:1.45rem; font-weight:900; color:${color}; display:flex; align-items:center; gap:6px; text-shadow:0 2px 6px rgba(0,0,0,0.4);">
                ${value}
                <span style="font-size:1.1rem;">${icon}</span>
            </div>
        </div>`;
}

// Auto-hook: start polling when admin-logs tab is switched to
// and stop polling when navigating away.
// Integrates with the existing switchTab() in app.js.
//
// /logs/live-metrics is admin-only on the backend, so polling must be
// gated by role here too. The old DOMContentLoaded check tested
// adminTab.style.display !== "none" -- an *inline* style that's never set
// (visibility is controlled by CSS classes), so that condition was true
// for essentially every role on every page load, and the "container
// exists" fallback below it made it unconditional even then. The net
// effect: every auditor/auditee session silently polled an endpoint it
// could never legitimately use, once every 3 seconds, forever.
if (typeof window !== 'undefined') {
    const _origSwitchTab = window.switchTab;
    window.switchTab = function(tabId) {
        if (typeof _origSwitchTab === 'function') _origSwitchTab(tabId);
        const isAdmin = typeof currentUser !== "undefined" && currentUser && currentUser.role === "admin";
        if (isAdmin && (tabId === 'tab-admin-logs' || tabId === 'admin-logs')) {
            startLiveMetricsPolling();
        } else {
            stopLiveMetricsPolling();
        }
    };

    document.addEventListener("DOMContentLoaded", () => {
        const isAdmin = typeof currentUser !== "undefined" && currentUser && currentUser.role === "admin";
        const adminTab = document.getElementById("tab-admin-logs");
        if (isAdmin && adminTab && adminTab.classList.contains("active")) {
            startLiveMetricsPolling();
        }
    });
}

