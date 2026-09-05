import requests
import time
import os
import sys
import json
import pyotp

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_URL = "http://127.0.0.1:8000"
EVIDENCE_DIR = os.path.join(os.getcwd(), "aa audit evidence samples")

def run_test():
    session = requests.Session()
    
    # 1. Register or Login Auditor
    username = f"auditor_test_{int(time.time())}@auditfirm.com"
    password = "AuditUser123!@#"
    role = "auditor"
    
    print(f"[1] Registering fresh auditor account: {username}...")
    reg_resp = session.post(
        f"{BASE_URL}/api/auth/register",
        json={"username": username, "password": password, "role": role},
        timeout=15
    )
    print(f"Register status: {reg_resp.status_code}")
    reg_json = reg_resp.json()
    totp_secret = reg_json.get("totp_secret")
    
    if not totp_secret:
        raise Exception(f"Registration failed: {reg_json}")
        
    print(f"Got TOTP secret. Generating live OTP code...")
    otp_code = pyotp.TOTP(totp_secret).now()
    
    # Login
    print(f"[1b] Logging in...")
    login_resp = session.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": username, "password": password},
        timeout=15
    )
    print(f"Login status: {login_resp.status_code}")
    
    # Verify OTP
    print(f"[1c] Verifying OTP: {otp_code}...")
    v_resp = session.post(
        f"{BASE_URL}/api/auth/verify-otp",
        json={"username": username, "otp_code": otp_code},
        timeout=15
    )
    print(f"Verify OTP status: {v_resp.status_code}")
    v_json = v_resp.json()
    token = v_json.get("token")
    if not token:
        raise Exception(f"Failed to get JWT token: {v_json}")
        
    print(f"Successfully authenticated! Token: {token[:20]}...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Create session
    print("[2] Creating audit session...")
    sess_resp = session.post(
        f"{BASE_URL}/api/audit/sessions",
        headers=headers,
        data={"session_title": "TestSprite E2E Live Audit", "framework": "ISO/IEC 27001:2022", "username": username},
        timeout=15
    )
    print(f"Session create: {sess_resp.status_code}, {sess_resp.json()}")
    session_id = sess_resp.json()["session_id"]
    
    # 3. Parse Excel Scoping checklist
    excel_path = os.path.join(EVIDENCE_DIR, "Audit checklist and evidence files.xlsx")
    print(f"[3] Parsing Excel scoping checklist from {excel_path}...")
    with open(excel_path, "rb") as f:
        excel_resp = session.post(
            f"{BASE_URL}/api/controls/parse-scope-excel",
            headers=headers,
            files={"file": (os.path.basename(excel_path), f, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
            timeout=15
        )
    print(f"Excel parse response: {excel_resp.status_code}")
    excel_data = excel_resp.json()
    matched_sls = excel_data.get("matched_sls", [])
    custom_evidence = excel_data.get("custom_evidence", {})
    custom_documents = excel_data.get("custom_documents", {})
    print(f"Parsed {len(matched_sls)} matched controls from Excel.")
    
    # 4. Upload evidence files
    print("[4] Uploading evidence files...")
    files_to_upload = []
    file_handles = []
    for fname in os.listdir(EVIDENCE_DIR):
        if fname.endswith(".xlsx"):
            continue
        fpath = os.path.join(EVIDENCE_DIR, fname)
        fh = open(fpath, "rb")
        file_handles.append(fh)
        files_to_upload.append(("files", (fname, fh, "application/octet-stream")))
        
    upload_resp = session.post(
        f"{BASE_URL}/api/audit/upload",
        headers=headers,
        data={"session_id": session_id, "is_auditor_uploaded": "true", "username": username},
        files=files_to_upload,
        timeout=60
    )
    for fh in file_handles:
        fh.close()
    print(f"Upload response: {upload_resp.status_code}, {upload_resp.json()}")
    
    # 5. Start audit
    print(f"[5] Starting audit scan for {len(matched_sls)} controls...")
    start_payload = {
        "session_id": session_id,
        "selected_sls": matched_sls,
        "model_choice": "Gemma 4 (e4b)",
        "audit_mode": "Deep",
        "custom_evidence": custom_evidence,
        "custom_documents": custom_documents,
        "username": username
    }
    start_resp = session.post(
        f"{BASE_URL}/api/audit/start",
        headers=headers,
        json=start_payload,
        timeout=60
    )
    print(f"Start audit response: {start_resp.status_code}, {start_resp.json()}")
    
    # 6. Poll status until complete
    print("[6] Polling audit progress in real-time...")
    for poll_idx in range(120):
        time.sleep(2)
        st_resp = session.get(f"{BASE_URL}/api/audit/status/{session_id}", headers=headers, timeout=10)
        st_data = st_resp.json()
        status = st_data.get("status")
        progress = st_data.get("progress") or {}
        pct = progress.get("percent", 0)
        text = progress.get("text", "")
        print(f"  [Poll {poll_idx+1}] Status: {status} | Progress: {pct}% - {text}", flush=True)
        if status == "completed":
            print("Scan completed successfully!")
            break
        elif status == "failed":
            print(f"Scan failed! Error: {st_data.get('error')}")
            break
            
    # 7. Fetch findings
    print("[7] Fetching findings from database...")
    findings_resp = session.get(f"{BASE_URL}/api/audit/findings?session_id={session_id}&role=auditor", headers=headers, timeout=15)
    findings_data = findings_resp.json()
    findings = findings_data.get("findings", [])
    print(f"\n=======================================================")
    print(f"TOTAL FINDINGS GENERATED: {len(findings)}")
    print(f"=======================================================")
    for idx, f in enumerate(findings, 1):
        cid = f.get("control_id")
        cname = f.get("control_name") or ""
        stat = f.get("status")
        pol_stat = f.get("policy_status")
        ev_stat = f.get("evidence_status")
        gap = f.get("evidence_gap") or f.get("policy_gap") or "None"
        recom = f.get("recommendation") or "N/A"
        src = f.get("source_files") or f.get("evidence_source_file") or "N/A"
        print(f"\n[{idx}] Control: {cid} - {cname}")
        print(f"    Compliance Status : {stat}")
        print(f"    Policy Status     : {pol_stat}")
        print(f"    Evidence Status   : {ev_stat}")
        print(f"    Source Document   : {src}")
        print(f"    Gap Detail        : {gap[:120]}")
        print(f"    Recommendation    : {recom[:120]}")

if __name__ == "__main__":
    run_test()
