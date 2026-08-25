import requests
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assumed default password for testing; adjust if different
REQUEST_TIMEOUT = 30

def test_getapiauditstatuswithvalidsession():
    session = requests.Session()
    try:
        # Step 1: Login to get TOTP challenge
        login_resp = session.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=REQUEST_TIMEOUT
        )
        assert login_resp.status_code == 200, f"Login failed, expected 200 got {login_resp.status_code}"

        # Step 2: Retrieve TOTP secret or generate OTP for verification
        # As backend is running locally, try to fetch TOTP code from a typical location or generate it via pyotp.
        # Here, since no TOTP secret provided in PRD, assume OTP '123456' is accepted for testing or simulate failure otherwise.
        # In real environment, this would be fetched or generated properly.
        otp_code = "123456"

        verify_resp = session.post(
            f"{BASE_URL}/api/auth/verify-otp",
            json={"username": ADMIN_USERNAME, "otp_code": otp_code},
            timeout=REQUEST_TIMEOUT
        )
        assert verify_resp.status_code == 200, f"OTP verification failed, expected 200 got {verify_resp.status_code}"
        token = verify_resp.json().get("access_token") or verify_resp.json().get("token") or verify_resp.json().get("jwt")
        assert token, "JWT token not found in OTP verify response"

        headers = {
            "Authorization": f"Bearer {token}"
        }

        # Step 3: Create a new audit session (required resource for test)
        session_title = "Test Audit Session for TC009"
        framework = "ISO27001"
        create_session_resp = session.post(
            f"{BASE_URL}/api/audit/sessions",
            data={
                "session_title": session_title,
                "framework": framework,
                "username": ADMIN_USERNAME
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        assert create_session_resp.status_code == 200, f"Audit session creation failed, expected 200 got {create_session_resp.status_code}"
        created_session = create_session_resp.json()
        session_id = created_session.get("id") or created_session.get("session_id") or created_session.get("sessionId")
        assert session_id, "Created session ID not found"

        # Step 4: Start the audit for this session to make it active
        start_data = {
            "session_id": session_id,
            "selected_sls": [1],  # Sample selected_sls; integer list as per schema
            "model_choice": "default_model",
            "audit_mode": "standard"
        }
        start_resp = session.post(
            f"{BASE_URL}/api/audit/start",
            json=start_data,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        assert start_resp.status_code == 200, f"Audit start failed, expected 200 got {start_resp.status_code}"

        # Step 5: Poll the audit status until active or timeout after 60s max
        audit_status_url = f"{BASE_URL}/api/audit/status/{session_id}"
        audit_status = None
        max_wait_seconds = 60
        poll_interval = 5
        elapsed = 0
        while elapsed < max_wait_seconds:
            status_resp = session.get(audit_status_url, headers=headers, timeout=REQUEST_TIMEOUT)
            if status_resp.status_code == 200:
                audit_status = status_resp.json()
                # Verify expected keys in response
                if all(k in audit_status for k in ("progress", "completed_controls_count", "status")):
                    break
            time.sleep(poll_interval)
            elapsed += poll_interval
        else:
            assert False, f"Audit status did not become active with expected fields within {max_wait_seconds} seconds"

        # Step 6: Validate the audit status response contents
        assert isinstance(audit_status["progress"], (int, float)) and 0 <= audit_status["progress"] <= 100, \
            f"Invalid progress value: {audit_status['progress']}"
        assert isinstance(audit_status["completed_controls_count"], int) and audit_status["completed_controls_count"] >= 0, \
            f"Invalid completed_controls_count value: {audit_status['completed_controls_count']}"
        assert isinstance(audit_status["status"], str) and len(audit_status["status"]) > 0, \
            f"Invalid status value: {audit_status['status']}"

    finally:
        # Cleanup: Delete the created audit session
        # Check if session_id and token exists before delete attempt
        if 'session_id' in locals() and token:
            del_resp = session.delete(
                f"{BASE_URL}/api/audit/sessions/{session_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT
            )
            # Deletion might be unsupported or return various status codes, we do not assert here.

test_getapiauditstatuswithvalidsession()