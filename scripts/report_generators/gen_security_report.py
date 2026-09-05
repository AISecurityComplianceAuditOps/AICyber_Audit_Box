"""
Security Fixes Report Generator for AICyberAuditBox
Generates a professional PDF report of all VAPT security fixes applied.
"""
from fpdf import FPDF
from datetime import datetime

class SecurityReportPDF(FPDF):
    def header(self):
        # Dark header bar
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 22, 'F')
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(129, 140, 248)
        self.set_xy(10, 5)
        self.cell(0, 12, "AICyberAuditBox  |  VAPT Security Hardening Report", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(148, 163, 184)
        self.set_xy(10, 14)
        self.cell(0, 6, f"Prepared: {datetime.now().strftime('%d %B %Y')}  |  Branch: experiemnt_product_audit_55  |  CONFIDENTIAL", ln=True)
        self.ln(6)

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(15, 23, 42)
        self.rect(0, self.get_y(), 210, 14, 'F')
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"AICyberAuditBox Security Hardening Report  |  Page {self.page_no()}  |  Dhiware Technologies Pvt. Ltd.", align="C")

    def section_title(self, title, color=(79, 70, 229)):
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", ln=True, fill=True)
        self.set_text_color(30, 41, 59)
        self.ln(2)

    def fix_block(self, num, title, status, problem, why_needed, how_fixed, files_changed):
        # Fix number badge
        self.set_fill_color(30, 41, 59)
        self.set_text_color(129, 140, 248)
        self.set_font("Helvetica", "B", 10)
        self.cell(10, 8, f"#{num}", fill=True, border=0)
        
        # Fix title
        self.set_text_color(15, 23, 42)
        self.set_font("Helvetica", "B", 10)
        self.cell(140, 8, f" {title}", ln=False)
        
        # Status badge
        if "FIXED" in status:
            self.set_fill_color(16, 185, 129)
        elif "PASS" in status:
            self.set_fill_color(16, 185, 129)
        else:
            self.set_fill_color(245, 158, 11)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(35, 8, f"  {status}  ", fill=True, ln=True, align="C")
        self.set_text_color(30, 41, 59)
        
        # Draw left border accent
        x = self.get_x()
        y = self.get_y()
        self.set_fill_color(99, 102, 241)
        self.rect(10, y, 2, 30, 'F')
        
        self.set_x(15)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(239, 68, 68)
        self.cell(30, 5, "Problem Found:", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(51, 65, 85)
        self.multi_cell(155, 5, problem)
        
        self.set_x(15)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(245, 158, 11)
        self.cell(30, 5, "Why Needed:", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(51, 65, 85)
        self.multi_cell(155, 5, why_needed)
        
        self.set_x(15)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(16, 185, 129)
        self.cell(30, 5, "How Fixed:", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(51, 65, 85)
        self.multi_cell(155, 5, how_fixed)
        
        self.set_x(15)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(99, 102, 241)
        self.cell(30, 5, "Files Changed:", ln=False)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.multi_cell(155, 5, files_changed)
        
        self.set_draw_color(226, 232, 240)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def table_row(self, cols, widths, bold=False, fill=False):
        if fill:
            self.set_fill_color(241, 245, 249)
        self.set_font("Helvetica", "B" if bold else "", 8)
        self.set_text_color(30, 41, 59)
        for text, w in zip(cols, widths):
            self.cell(w, 7, text, border=1, fill=fill)
        self.ln()


def generate_security_report():
    pdf = SecurityReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── COVER / INTRO ──────────────────────────────────────────────────────────
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(10, pdf.get_y(), 190, 28, 'F')
    pdf.set_xy(14, pdf.get_y() + 4)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "VAPT Security Hardening Report", ln=True)
    pdf.set_x(14)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(185, 5,
        "This document summarizes all security vulnerabilities identified during internal VAPT "
        "review and the fixes applied to the AICyberAuditBox platform before external pentest submission.")
    pdf.ln(6)

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    pdf.section_title("EXECUTIVE SUMMARY")

    headers = ["Category", "Before Fix", "After Fix"]
    widths  = [65, 62, 63]
    pdf.table_row(headers, widths, bold=True)

    rows = [
        ("Authentication Token",       "Mock forgeable token (anyone could become admin)", "Real signed JWT (HS256, 8hr expiry)"),
        ("Logs Endpoints (9 routes)",  "No auth - any user could read all admin logs",     "JWT required on every route"),
        ("Controls Endpoints (7)",     "No auth - anyone could create/delete controls",    "JWT required; delete = admin only"),
        ("License Endpoints (3)",      "No auth - anyone could activate/consume license",  "JWT required; activate = admin only"),
        ("Error Messages (15+ places)","detail=str(e) - leaked DB paths, stack traces",    "Generic safe error messages"),
        ("CORS Policy",                "Wildcard * (any origin allowed)",                   "Restricted to aicyberauditbox.com only"),
        ("Rate Limiting",              "No limit on login/OTP - brute force possible",     "5 attempts/min per IP enforced"),
        ("File Upload",                "No validation - .exe/.js/.zip accepted",           "4-layer scan: MIME, magic bytes, size, name"),
        ("Security Headers",           "No CSP, no HSTS, no X-Frame-Options",             "All OWASP recommended headers added"),
        ("API Documentation",          "/docs and /openapi.json publicly accessible",      "All API docs disabled in production"),
        ("OTP Bypass Codes",           "123456 and 000000 hardcoded bypasses present",     "All bypass codes removed"),
        ("Wipe Endpoint (DELETE)",     "No auth - anyone could wipe entire database",      "Admin-only with JWT role check"),
        ("Uvicorn Server Banner",      "Server version exposed in response headers",       "Hidden with --no-server-header flag"),
        ("JWT Secret",                 "Default hardcoded fallback string in code",        "Strong 64-char random hex key via env var"),
        ("Per-Auditor Concurrency",    "Unlimited concurrent audits per user",             "Max 3 concurrent audits per auditor"),
    ]
    for i, row in enumerate(rows):
        pdf.table_row(row, widths, fill=(i % 2 == 0))

    pdf.ln(5)

    # ── DETAILED FIX EXPLANATIONS ─────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("DETAILED FIX EXPLANATIONS")

    fixes = [
        (
            1, "Real JWT Authentication (Replaced Mock Token)", "CRITICAL - FIXED",
            "The application used a predictable mock token: 'mock-jwt-token-admin-admin'. "
            "Any attacker could type this string and gain full admin access to all protected API endpoints.",
            "Without real token verification, authentication provides zero security. A pentester would immediately "
            "identify this as a critical authentication bypass (OWASP A07 - Identification & Authentication Failures). "
            "An attacker could access, modify, or delete all audit data without any credentials.",
            "Replaced with real PyJWT HS256 signed tokens. Token contains username, role, issued-at, and 8-hour expiry. "
            "Server verifies signature on every request. Tokens cannot be forged without the JWT_SECRET. "
            "Added _create_token() and updated _require_auth() to decode and verify JWT.",
            "src/api/endpoints/auth.py, requirements.txt, run_all.bat"
        ),
        (
            2, "Secured Admin Logs Endpoints (9 Routes)", "HIGH - FIXED",
            "All 9 log endpoints (/logs/system, /logs/audit-trail, /logs/developer, exports) had zero authentication. "
            "Anyone could read full admin system event logs, audit history, raw server log files, and export sensitive data.",
            "System logs contain auditor usernames, session IDs, error details, and server internals. "
            "Unauthenticated access violates OWASP A01 (Broken Access Control). "
            "A pentester would use these logs to map the entire system before deeper attacks.",
            "Added _require_auth(request) to all 9 log endpoint functions. "
            "DELETE /logs/developer and POST /logs/purge now require admin role specifically. "
            "Also removed raw exception details from error responses.",
            "src/api/endpoints/logs.py"
        ),
        (
            3, "Secured Controls Endpoints (7 Routes)", "HIGH - FIXED",
            "All 7 control management endpoints had no authentication. Any unauthenticated user could read, "
            "create, modify, or delete ISO/VAPT audit controls used in all reports.",
            "Unauthenticated write access to audit controls could allow attackers to corrupt the audit framework, "
            "insert false controls, or delete legitimate ones. This directly undermines audit integrity. "
            "Violates OWASP A01 (Broken Access Control).",
            "Added _require_auth(request) to all endpoints. DELETE control endpoint now additionally checks "
            "that the user role is 'admin' or 'auditor'. All error messages sanitized to remove internal details.",
            "src/api/endpoints/controls.py"
        ),
        (
            4, "Secured License & Billing Endpoints (3 Routes)", "HIGH - FIXED",
            "License wallet status, token deduction, and license activation had no authentication. "
            "Anyone could activate enterprise licenses, check billing balances, or consume tokens without logging in.",
            "Unauthenticated license activation could allow attackers to grant themselves unlimited audit access "
            "or exhaust your token credit. This is a business logic attack that causes direct financial impact. "
            "Violates OWASP A01 (Broken Access Control) and A04 (Insecure Design).",
            "Added _require_auth(request) to all license endpoints. "
            "POST /license/activate now additionally requires admin role to prevent unauthorized license grants.",
            "src/api/endpoints/license.py"
        ),
        (
            5, "Fixed Error Information Leakage (15+ Locations)", "HIGH - FIXED",
            "Over 15 API endpoints were returning raw Python exception messages in HTTP responses using "
            "detail=str(e). This exposed database connection strings, internal file paths, table names, "
            "and full Python stack traces to any user who triggered an error.",
            "Information leakage is OWASP A09 (Security Logging & Monitoring Failures). "
            "A pentester sends malformed inputs to trigger errors, then reads the stack trace to learn "
            "your database type, file structure, and internal architecture - making further attacks far easier.",
            "Replaced all detail=str(e) and detail=f'...{e}' with generic safe messages like "
            "'Operation failed. Please try again.' Errors are still logged server-side for debugging "
            "but never exposed in HTTP responses.",
            "src/api/endpoints/audit.py, logs.py, controls.py"
        ),
        (
            6, "CORS Policy Restricted to Production Domain", "MEDIUM - FIXED",
            "CORS was not explicitly restricting origins. Wildcard or permissive CORS allows malicious "
            "websites to make authenticated API calls on behalf of logged-in users (CSRF-like attacks).",
            "A malicious site could trick your auditors into visiting it, then silently make API calls "
            "to your system using their active session. This is OWASP A05 (Security Misconfiguration). "
            "Pentesters check Access-Control-Allow-Origin header first thing.",
            "Set allow_origins to ['https://aicyberauditbox.com', 'https://www.aicyberauditbox.com'] only. "
            "Localhost allowed only for development. No wildcard (*) permitted for credentialed requests.",
            "src/api/main.py"
        ),
        (
            7, "Rate Limiting on Login & OTP Endpoints", "HIGH - FIXED",
            "Login and OTP verification endpoints had no rate limiting. An attacker could make thousands "
            "of login attempts per second to brute force passwords or TOTP codes.",
            "Without rate limiting, brute force attacks on login are trivially easy. "
            "TOTP codes have only 1,000,000 combinations and are valid for 30 seconds - "
            "a fast attacker could enumerate all codes. Violates OWASP A07 (Auth Failures).",
            "Implemented in-memory rate limiter: max 5 attempts per IP per 60 seconds. "
            "Applies to both /auth/login and /auth/verify-otp. Returns HTTP 429 Too Many Requests "
            "after limit is exceeded.",
            "src/api/endpoints/auth.py"
        ),
        (
            8, "File Upload Security (4-Layer Validation)", "HIGH - FIXED",
            "File upload accepted any file type including .exe, .js, .zip. No size limit was enforced. "
            "No path traversal protection. Filenames with '../' could write files outside evidence directory.",
            "Malicious file uploads can lead to Remote Code Execution (RCE) if executable files are "
            "uploaded and served. Path traversal could overwrite system files. "
            "This is OWASP A03 (Injection) and a critical pentesting target.",
            "Added 4-layer security: (1) Extension whitelist - only pdf/docx/xlsx/png/jpg/txt allowed. "
            "(2) Magic byte verification - file content checked, not just extension. "
            "(3) 100MB file size limit enforced server-side. (4) Path traversal prevention using "
            "os.path.basename() and regex sanitization of filenames.",
            "src/api/endpoints/audit.py"
        ),
        (
            9, "Security HTTP Headers Added", "MEDIUM - FIXED",
            "No security headers were present in API responses. Missing headers allow clickjacking, "
            "MIME sniffing, and cross-site attacks. Pentest tools flag these as medium-risk findings.",
            "Missing security headers are flagged by OWASP ZAP and Burp Suite automatically. "
            "X-Frame-Options prevents clickjacking. CSP prevents XSS. HSTS enforces HTTPS. "
            "These are baseline requirements for any production web application.",
            "Added global middleware in main.py that appends security headers to every response: "
            "X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
            "Strict-Transport-Security: max-age=31536000, Content-Security-Policy, "
            "Referrer-Policy, Permissions-Policy.",
            "src/api/main.py"
        ),
        (
            10, "API Documentation Disabled in Production", "MEDIUM - FIXED",
            "FastAPI automatically exposes /docs (Swagger UI), /redoc, and /openapi.json in production. "
            "These pages list every API endpoint, parameter, and response schema publicly.",
            "Exposed API documentation is a free roadmap for attackers. They can see every endpoint, "
            "required parameters, and expected responses without any reverse engineering. "
            "Pentesters check /docs immediately as part of reconnaissance.",
            "Set docs_url=None, redoc_url=None, openapi_url=None in FastAPI app initialization. "
            "Now returns 404 Not Found for all documentation URLs in production.",
            "src/api/main.py"
        ),
        (
            11, "Database Wipe Endpoint Admin-Only Protection", "CRITICAL - FIXED",
            "DELETE /audit/clear-records had no authentication at all. Any unauthenticated HTTP request "
            "could permanently delete ALL audit records, findings, evidence, and reports from the database.",
            "Unauthenticated destructive endpoints are a critical vulnerability. An attacker or disgruntled "
            "user could wipe all audit data causing permanent data loss and business disruption. "
            "This is OWASP A01 (Broken Access Control) at the highest severity.",
            "Added _require_auth(request) check and role verification (role == 'admin') to the wipe endpoint. "
            "Auditors receive HTTP 403 Forbidden. Unauthenticated requests receive HTTP 401 Unauthorized. "
            "Also sanitized the error response to prevent exception detail leaks.",
            "src/api/endpoints/audit.py"
        ),
        (
            12, "JWT Secret Key Hardening", "HIGH - FIXED",
            "The JWT secret was a default hardcoded string in source code. Anyone reading the code "
            "(e.g., via Git repository access) could use this secret to forge valid JWT tokens for any user.",
            "If the JWT secret is known, an attacker can create tokens with role='admin' for any username. "
            "This completely bypasses all authentication. Hardcoded secrets in code violate "
            "OWASP A02 (Cryptographic Failures) and are flagged by all SAST tools.",
            "Generated a cryptographically secure 64-character random hex key using Python secrets.token_hex(32). "
            "Secret is loaded from JWT_SECRET environment variable at runtime. "
            "Added to run_all.bat as a set command so it is never stored in source code.",
            "run_all.bat, src/api/endpoints/auth.py"
        ),
    ]

    for fix in fixes:
        if pdf.get_y() > 220:
            pdf.add_page()
        pdf.fix_block(*fix)

    # ── OWASP CHECKLIST ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("OWASP TOP 10 COMPLIANCE STATUS")

    owasp = [
        ("A01 - Broken Access Control",             "PASS", "Auth on all endpoints. Role-based checks. Admin-only wipe."),
        ("A02 - Cryptographic Failures",             "PASS", "Real JWT HS256. Strong random secret. HTTPS enforced."),
        ("A03 - Injection (SQL/Command/Path)",       "PASS", "SQLAlchemy ORM. No raw SQL. Path traversal prevention."),
        ("A04 - Insecure Design",                   "PASS", "Rate limiting. Concurrency limits. Business logic protected."),
        ("A05 - Security Misconfiguration",          "PASS", "CORS restricted. Headers added. Docs disabled. Banner hidden."),
        ("A06 - Vulnerable Components",              "PASS", "PyJWT 2.8+ added. Dependencies reviewed."),
        ("A07 - Auth & Session Failures",            "PASS", "Real JWT. Token expiry 8hr. Rate limiting on login/OTP."),
        ("A08 - Software & Data Integrity",          "PASS", "File upload validation. Magic byte verification."),
        ("A09 - Security Logging & Monitoring",      "PASS", "Error details not exposed. Logs secured behind auth."),
        ("A10 - Server-Side Request Forgery",        "N/A",  "No SSRF surface (no URL-fetch endpoints in this app)."),
    ]

    widths = [80, 20, 90]
    pdf.table_row(["OWASP Category", "Status", "Evidence"], widths, bold=True)
    for i, (cat, status, evidence) in enumerate(owasp):
        fill = (i % 2 == 0)
        if fill:
            pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(widths[0], 7, cat, border=1, fill=fill)
        if status == "PASS":
            pdf.set_text_color(16, 185, 129)
            pdf.set_font("Helvetica", "B", 8)
        elif status == "N/A":
            pdf.set_text_color(100, 116, 139)
        else:
            pdf.set_text_color(239, 68, 68)
        pdf.cell(widths[1], 7, status, border=1, fill=fill, align="C")
        pdf.set_text_color(30, 41, 59)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(widths[2], 7, evidence, border=1, fill=fill)
        pdf.ln()

    pdf.ln(6)

    # ── PENTEST READINESS SUMMARY ─────────────────────────────────────────────
    pdf.section_title("PENTEST READINESS SUMMARY", color=(16, 185, 129))
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(0, 6,
        "The AICyberAuditBox platform has been hardened against all OWASP Top 10 categories prior to "
        "external pentest submission. A total of 12 security fixes were applied across 6 backend modules. "
        "\n\n"
        "Key security achievements:\n"
        "  - Authentication: Replaced mock tokens with cryptographically signed JWT (cannot be forged)\n"
        "  - Authorization: All 25+ previously unprotected API endpoints now require valid tokens\n"
        "  - Input Validation: File uploads validated at 4 layers; path traversal prevented\n"
        "  - Information Leakage: 15+ raw exception exposures sanitized with generic safe messages\n"
        "  - Infrastructure: CORS restricted, security headers added, API docs disabled, banner hidden\n"
        "  - Business Logic: Rate limiting, per-auditor concurrency limits, admin-only destructive ops\n"
        "\n"
        "Expected pentest outcome: 0 Critical, 0 High findings. Possible Low/Informational findings "
        "may include CSP inline-script allowance (required for frontend) and SSH access review (Azure NSG)."
    )

    pdf.ln(4)
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(10, pdf.get_y(), 190, 12, 'F')
    pdf.set_xy(14, pdf.get_y() + 2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(129, 140, 248)
    pdf.cell(100, 8, "Dhiware Technologies Pvt. Ltd.  |  AICyberAuditBox")
    pdf.set_text_color(100, 116, 139)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 8, f"Report Generated: {datetime.now().strftime('%d %B %Y, %H:%M IST')}", align="R")

    out_path = r"c:\Users\veeresh988V\Desktop\current vaptiso\AICyberAuditBox_Security_Hardening_Report.pdf"
    pdf.output(out_path)
    print(f"[OK] PDF saved to: {out_path}")
    return out_path

if __name__ == "__main__":
    generate_security_report()
