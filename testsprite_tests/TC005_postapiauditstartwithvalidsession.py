import requests
import time

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming password is "admin" as per instructions

def test_post_api_audit_start_with_valid_session():
    session = requests.Session()
    try:
        # Step 1: Login admin to get OTP challenge or direct token
        login_resp = session.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=TIMEOUT
        )
        assert login_resp.status_code == 200
        login_json = login_resp.json()

        # Check if OTP verification required
        if login_json.get("otp_required"):
            # OTP verification required
            otp_code = "000000"  # Simulated OTP code for test
            verify_otp_resp = session.post(
                f"{BASE_URL}/api/auth/verify-otp",
                json={"username": ADMIN_USERNAME, "code": otp_code},
                timeout=TIMEOUT
            )
            assert verify_otp_resp.status_code == 200
            verify_otp_json = verify_otp_resp.json()
            assert "access_token" in verify_otp_json
            token = verify_otp_json["access_token"]
        else:
            # OTP not required, login_json should include access_token
            assert "access_token" in login_json
            token = login_json["access_token"]

        headers = {"Authorization": f"Bearer {token}"}

        # Step 3: Create an audit session (auditor token needed, but using admin token here)
        create_session_resp = session.post(
            f"{BASE_URL}/api/audit/sessions",
            json={"session_name": "Test Session for Audit Start"},
            headers=headers,
            timeout=TIMEOUT
        )
        # It's likely admin token unauthorized for creating auditor session; if 403, skip creation.
        if create_session_resp.status_code == 200:
            create_session_json = create_session_resp.json()
            session_id = create_session_json.get("session_id")
        else:
            # Fallback: try auditor login to create session since admin may not have access
            # Login auditor:
            auditor_username = "auditor1"
            auditor_password = "auditor1"
            login_auditor_resp = session.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": auditor_username, "password": auditor_password},
                timeout=TIMEOUT
            )
            assert login_auditor_resp.status_code == 200
            login_auditor_json = login_auditor_resp.json()
            if login_auditor_json.get("otp_required"):
                otp_auditor_resp = session.post(
                    f"{BASE_URL}/api/auth/verify-otp",
                    json={"username": auditor_username, "code": "000000"},
                    timeout=TIMEOUT
                )
                assert otp_auditor_resp.status_code == 200
                auditor_token = otp_auditor_resp.json()["access_token"]
            else:
                assert "access_token" in login_auditor_json
                auditor_token = login_auditor_json["access_token"]

            auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

            # Create session with auditor token
            create_session_resp = session.post(
                f"{BASE_URL}/api/audit/sessions",
                json={"session_name": "Test Session for Audit Start"},
                headers=auditor_headers,
                timeout=TIMEOUT
            )
            assert create_session_resp.status_code == 200
            session_id = create_session_resp.json().get("session_id")
            headers = auditor_headers

        assert session_id is not None and session_id != ""

        # Step 4: Upload an evidence document (minimal content) for session
        files = {
            "file": ("evidence.txt", b"Test evidence content", "text/plain"),
            "session_id": (None, session_id),
        }
        upload_resp = session.post(
            f"{BASE_URL}/api/audit/upload",
            files=files,
            headers=headers,
            timeout=TIMEOUT
        )
        assert upload_resp.status_code == 200

        # Step 5: Deduct tokens for the session (assuming a positive integer token amount)
        deduct_payload = {
            "session_id": session_id,
            "token_quantity": 1
        }
        deduct_resp = session.post(
            f"{BASE_URL}/api/license/deduct",
            json=deduct_payload,
            headers=headers,
            timeout=TIMEOUT
        )
        assert deduct_resp.status_code == 200

        # Step 6: Start audit analysis using valid session_id
        start_resp = session.post(
            f"{BASE_URL}/api/audit/start",
            json={"session_id": session_id},
            headers=headers,
            timeout=TIMEOUT
        )
        assert start_resp.status_code == 200
        start_json = start_resp.json()
        # Optional: check if response indicates audit started
        assert "message" in start_json or "status" in start_json

    finally:
        # Cleanup: Delete the audit session if possible
        # No delete endpoint documented, so try to clean evidence upload if possible
        # As not defined in PRD, just pass here.
        pass

test_post_api_audit_start_with_valid_session()
