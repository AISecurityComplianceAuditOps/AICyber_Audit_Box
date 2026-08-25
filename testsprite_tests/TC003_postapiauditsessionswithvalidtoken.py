import requests

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default password is admin or change accordingly
TIMEOUT = 30


def test_post_api_audit_sessions_with_valid_token():
    session = requests.Session()

    try:
        login_payload = {
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=TIMEOUT)
        assert login_resp.status_code == 200
        login_json = login_resp.json()

        otp_required = login_json.get("otp_required", False) or login_json.get("challenge", False)

        if otp_required:
            # Perform OTP verification step
            otp_verify_payload = {
                "username": ADMIN_USERNAME,
                "totp_code": "123456"  # Placeholder OTP for test
            }
            otp_verify_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=otp_verify_payload, timeout=TIMEOUT)
            assert otp_verify_resp.status_code == 200
            otp_verify_json = otp_verify_resp.json()

            token = otp_verify_json.get("token")
            role = otp_verify_json.get("role")
            assert token is not None
            assert role is not None

        else:
            token = login_json.get("token")
            assert token is not None

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        session_payload = {
            "title": "Test Audit Session",
            "description": "Session created during automated test",
            "start_date": "2026-08-18T10:00:00Z",
            "end_date": "2026-08-18T18:00:00Z",
            "auditee": "auditee1"
        }

        create_session_resp = session.post(f"{BASE_URL}/api/audit/sessions", headers=headers, json=session_payload, timeout=TIMEOUT)
        assert create_session_resp.status_code == 200
        create_session_json = create_session_resp.json()
        assert "session_id" in create_session_json
        session_id = create_session_json["session_id"]
        assert isinstance(session_id, (str, int)) and session_id

    finally:
        pass

test_post_api_audit_sessions_with_valid_token()
