import requests
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default password is 'admin'
TIMEOUT = 30

def test_getapiauditreportwithcompletedsession():
    session_id = None
    jwt_token = None

    try:
        # 1. Login (POST /api/auth/login) with valid credentials to trigger OTP
        login_resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=TIMEOUT,
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"

        # 2. Obtain OTP code for the admin (since this is a test, assuming 6-digit OTP '123456' or retrieve from TOTP generator)
        # In this test scenario, assuming OTP is "123456" for testing purpose.
        otp_code = "123456"

        # 3. Verify OTP (POST /api/auth/verify-otp) to get JWT token
        otp_resp = requests.post(
            f"{BASE_URL}/api/auth/verify-otp",
            json={"username": ADMIN_USERNAME, "otp_code": otp_code},
            timeout=TIMEOUT,
        )
        assert otp_resp.status_code == 200, f"OTP verification failed: {otp_resp.text}"
        jwt_token = otp_resp.json().get("token")
        assert jwt_token is not None, "JWT token not found in OTP response"

        headers = {"Authorization": f"Bearer {jwt_token}"}

        # 4. Create audit session (POST /api/audit/sessions)
        session_title = "Test Audit Session for Completed Report"
        framework = "ISO27001"
        create_session_resp = requests.post(
            f"{BASE_URL}/api/audit/sessions",
            data={
                "session_title": session_title,
                "framework": framework,
                "username": ADMIN_USERNAME,
            },
            headers=headers,
            timeout=TIMEOUT,
        )
        assert create_session_resp.status_code == 200, f"Create session failed: {create_session_resp.text}"
        session_data = create_session_resp.json()
        session_id = session_data.get("session_id") or session_data.get("id")
        assert session_id, "Session ID not returned after creation"

        # 5. Upload evidence document (POST /api/audit/upload) with a minimal file
        # Using a small dummy text file in memory
        files = {
            "files": ("evidence.txt", b"This is test evidence content.", "text/plain")
        }
        upload_resp = requests.post(
            f"{BASE_URL}/api/audit/upload",
            headers=headers,
            data={"session_id": session_id},
            files=files,
            timeout=TIMEOUT,
        )
        assert upload_resp.status_code == 200, f"Evidence upload failed: {upload_resp.text}"

        # 6. Start ISO audit (POST /api/audit/start)
        # Assuming selected_sls is a list of integers for selected controls; passing sample [1,2,3]
        start_audit_resp = requests.post(
            f"{BASE_URL}/api/audit/start",
            json={
                "session_id": session_id,
                "selected_sls": [1, 2, 3],
                "model_choice": "default-model",
                "audit_mode": "auto",
            },
            headers=headers,
            timeout=TIMEOUT,
        )
        assert start_audit_resp.status_code == 200, f"Audit start failed: {start_audit_resp.text}"

        # 7. Poll audit status (GET /api/audit/status/{session_id}) until completed
        audit_completed = False
        for _ in range(60):  # Poll max 60 times (~30 minutes if waiting 30s each)
            status_resp = requests.get(
                f"{BASE_URL}/api/audit/status/{session_id}",
                headers=headers,
                timeout=TIMEOUT,
            )
            assert status_resp.status_code == 200, f"Audit status failed: {status_resp.text}"
            status_json = status_resp.json()
            if status_json.get("status") == "completed":
                audit_completed = True
                break
            time.sleep(30)

        assert audit_completed, "Audit did not complete in expected time"

        # 8. Get audit report for completed session (GET /api/audit/report/{session_id})
        report_resp = requests.get(
            f"{BASE_URL}/api/audit/report/{session_id}",
            headers=headers,
            timeout=TIMEOUT,
        )
        assert report_resp.status_code == 200, f"Audit report retrieval failed: {report_resp.text}"

        report_json = report_resp.json()
        # Validate presence of executive summary, compliance score, severity breakdown
        assert "executive_summary" in report_json, "Executive summary missing in report"
        assert "compliance_score" in report_json, "Compliance score missing in report"
        assert "severity_breakdown" in report_json, "Severity breakdown missing in report"

    finally:
        # Cleanup: Delete the created audit session if possible
        if jwt_token and session_id:
            # Attempt DELETE if supported by API (not specified in PRD, still try)
            try:
                requests.delete(
                    f"{BASE_URL}/api/audit/sessions/{session_id}",
                    headers={"Authorization": f"Bearer {jwt_token}"},
                    timeout=TIMEOUT,
                )
            except Exception:
                pass


test_getapiauditreportwithcompletedsession()