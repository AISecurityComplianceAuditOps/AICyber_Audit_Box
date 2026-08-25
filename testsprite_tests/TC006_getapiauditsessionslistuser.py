import requests
import pyotp
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default admin password same as username or known
TIMEOUT = 30

def test_get_audit_sessions_list_user():
    session = requests.Session()

    # Step 1: POST /api/auth/login with valid admin credentials to initiate TOTP 2FA
    login_payload = {
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    }
    login_resp = session.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=TIMEOUT)
    assert login_resp.status_code == 200, f"Login failed with status code {login_resp.status_code}"
    # Backend indicates that TOTP verification is required (no token returned yet)
    # The response body is not specified to contain data, so just continue.

    # Step 2: Generate the current valid TOTP code for the admin user
    # NOTE: The PRD does not include a seed key for TOTP. We try to get the TOTP secret via a known method:
    # In a real test environment, we would have access or mock the TOTP secret.
    # For demonstration, we assume the TOTP secret is "JBSWY3DPEHPK3PXP" (base32, example).
    # In practice, adjust this secret to the actual test environment setup.

    TOTP_SECRET = "JBSWY3DPEHPK3PXP"
    totp = pyotp.TOTP(TOTP_SECRET)
    otp_code = totp.now()

    # Step 3: POST /api/auth/verify-otp with username and current OTP code to get JWT token
    otp_payload = {
        "username": ADMIN_USERNAME,
        "otp_code": otp_code
    }
    otp_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=otp_payload, timeout=TIMEOUT)
    assert otp_resp.status_code == 200, f"OTP verification failed with status code {otp_resp.status_code}"
    otp_data = otp_resp.json()
    assert "token" in otp_data, "JWT token not returned after OTP verification"
    token = otp_data["token"]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Step 4: GET /api/audit/sessions to retrieve list of audit sessions for the authenticated user
    sessions_resp = session.get(f"{BASE_URL}/api/audit/sessions", headers=headers, timeout=TIMEOUT)
    assert sessions_resp.status_code == 200, f"Failed to get audit sessions with status {sessions_resp.status_code}"
    sessions_data = sessions_resp.json()
    assert isinstance(sessions_data, list), "Audit sessions response is not a list"

    # Verify that response contains at least zero or more active sessions (list may be empty)
    # Check each session has likely minimal keys - e.g., session_title or id
    for session_obj in sessions_data:
        assert isinstance(session_obj, dict), "Each session should be an object/dict"
        assert "session_title" in session_obj or "id" in session_obj, "Session object missing expected keys"

test_get_audit_sessions_list_user()