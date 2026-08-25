import requests

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # assuming default admin password is "admin"
TIMEOUT = 30


def test_post_audit_sessions_create_with_valid_data():
    session = requests.Session()
    try:
        # Step 1: Login - POST /api/auth/login
        login_payload = {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=TIMEOUT)
        assert login_resp.status_code == 200
        # login requires OTP verification

        # Step 2: GET TOTP code for admin (simulate or hardcode)
        # Since backend is offline-first, we assume TOTP secret known or OTP code generator simulation
        # For test, assume OTP is always '123456' (adjust accordingly if real code needed)
        otp_code = "123456"

        # Step 3: Verify OTP - POST /api/auth/verify-otp
        verify_otp_payload = {"username": ADMIN_USERNAME, "otp_code": otp_code}
        otp_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=verify_otp_payload, timeout=TIMEOUT)
        # Accept both 200 (valid token) or 400 (invalid OTP) - if 400 retry once with a common OTP (like '000000')
        if otp_resp.status_code == 400:
            verify_otp_payload["otp_code"] = "000000"
            otp_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=verify_otp_payload, timeout=TIMEOUT)
        assert otp_resp.status_code == 200
        token = otp_resp.json().get("access_token") or otp_resp.json().get("token")
        assert token is not None

        # Set Auth header for next requests
        session.headers.update({"Authorization": f"Bearer {token}"})

        # Step 4: Create new audit session - POST /api/audit/sessions
        session_title = "Test Audit Session TC005"
        framework = "ISO27001:2022"
        create_payload = {
            "session_title": session_title,
            "framework": framework,
            "username": ADMIN_USERNAME
        }
        # Content type application/x-www-form-urlencoded
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        create_resp = session.post(f"{BASE_URL}/api/audit/sessions", data=create_payload, headers=headers, timeout=TIMEOUT)
        assert create_resp.status_code == 200

        data = create_resp.json()
        assert isinstance(data, dict)
        # Validate response contains session details including session_title and framework
        assert "session_title" in data and data["session_title"] == session_title
        assert "framework" in data and data["framework"] == framework
        assert "session_id" in data or "id" in data

    finally:
        # Cleanup: delete created audit session if possible
        session_id = None
        if 'data' in locals():
            session_id = data.get("session_id") or data.get("id")
        if session_id:
            try:
                session.delete(f"{BASE_URL}/api/audit/sessions/{session_id}", timeout=TIMEOUT)
            except Exception:
                pass


test_post_audit_sessions_create_with_valid_data()