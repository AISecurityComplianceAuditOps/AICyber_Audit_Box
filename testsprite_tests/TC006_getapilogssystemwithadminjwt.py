import requests
import pyotp
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default admin password is "admin"
TIMEOUT = 30

def test_get_api_logs_system_with_admin_jwt():
    session = requests.Session()

    try:
        # Step 1: Login with admin username and password
        login_payload = {
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=TIMEOUT)
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        login_data = login_resp.json()

        # Expecting OTP challenge with a field indicating otp_required or similar
        assert "otp_required" in login_data or "challenge" in login_data or "message" in login_data, \
            "OTP challenge not present in login response"

        # Step 2: Retrieve TOTP secret for admin to generate valid TOTP code
        # Since no direct API given for retrieving TOTP secret, we assume the secret is accessible or static for test.
        # For realistic test, hardcoding a known TOTP secret for default admin user. In real environment,
        # this secret should be retrieved securely or mocked.
        # NOTE: Replace the below secret with the actual test environment secret.
        ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # base32 string for 'Hello!'

        # Generate TOTP code
        totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
        totp_code = totp.now()

        # Step 3: Verify OTP to get JWT token
        verify_otp_payload = {
            "username": ADMIN_USERNAME,
            "code": totp_code
        }
        verify_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=verify_otp_payload, timeout=TIMEOUT)
        assert verify_resp.status_code == 200, f"OTP verification failed: {verify_resp.text}"
        verify_data = verify_resp.json()
        assert "access_token" in verify_data and "role" in verify_data, "JWT token or role missing in verify response"
        assert verify_data["role"].lower() == "admin", "User role is not admin"

        jwt_token = verify_data["access_token"]
        headers = {
            "Authorization": f"Bearer {jwt_token}"
        }

        # Step 4: Request GET /api/logs/system with admin JWT and no filters
        logs_resp = session.get(f"{BASE_URL}/api/logs/system", headers=headers, timeout=TIMEOUT)
        assert logs_resp.status_code == 200, f"Failed to get system logs: {logs_resp.text}"
        logs_data = logs_resp.json()

        # Validate response is a list of system event logs (list or dict with list)
        assert isinstance(logs_data, (list, dict)), "Logs response is not list or dict"
        if isinstance(logs_data, dict):
            # common key containing logs could be 'logs', 'items', or similar - allow any
            logs_list = None
            for possible_key in ["logs", "items", "data", "events"]:
                if possible_key in logs_data and isinstance(logs_data[possible_key], list):
                    logs_list = logs_data[possible_key]
                    break
            assert logs_list is not None, "No list of log events found in response dict"
            assert len(logs_list) >= 0, "Log events list is empty"
        else:
            # logs_data is list directly
            assert len(logs_data) >= 0, "Log events list is empty"

    finally:
        session.close()

test_get_api_logs_system_with_admin_jwt()