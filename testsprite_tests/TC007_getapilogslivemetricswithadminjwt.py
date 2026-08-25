import requests
import pyotp

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default password same as username or set accordingly
TIMEOUT = 30

def test_get_apilogslivemetrics_with_admin_jwt():
    session = requests.Session()
    try:
        # Step 1: Login with admin credentials
        login_payload = {
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=TIMEOUT)
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        login_data = login_resp.json()

        # The response should indicate an OTP challenge, get any needed info for OTP if present
        # For simplicity, assume TOTP secret or code can be derived or known for admin
        # This example assumes the server uses a fixed shared secret for admin TOTP (commonly stored on server side)
        # If server returns a challenge token or OTP secret, you must extract and use it here.
        # Since no OTP secret provided, we simulate a correct OTP code generation for 'admin'

        # Hardcoded TOTP secret for admin (Normally this should be securely retrieved/configured)
        ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # Example base32 TOTP secret
        totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
        otp_code = totp.now()

        # Step 2: Verify OTP with the generated TOTP code to get admin JWT token
        verify_otp_payload = {
            "username": ADMIN_USERNAME,
            "code": otp_code
        }
        verify_resp = session.post(f"{BASE_URL}/api/auth/verify-otp", json=verify_otp_payload, timeout=TIMEOUT)
        assert verify_resp.status_code == 200, f"OTP verification failed: {verify_resp.text}"
        verify_data = verify_resp.json()
        # Expect JWT token and role
        assert "token" in verify_data, "JWT token missing in OTP verification response"
        assert "role" in verify_data, "Role missing in OTP verification response"
        assert verify_data["role"].lower() == "admin", f"Role is not admin: {verify_data['role']}"

        jwt_token = verify_data["token"]
        headers = {"Authorization": f"Bearer {jwt_token}"}

        # Step 3: GET /api/logs/live-metrics with admin JWT
        live_metrics_resp = session.get(f"{BASE_URL}/api/logs/live-metrics", headers=headers, timeout=TIMEOUT)
        assert live_metrics_resp.status_code == 200, f"Live metrics request failed: {live_metrics_resp.text}"

        live_metrics_data = live_metrics_resp.json()
        # Validate expected keys in live metrics response (token and server metrics)
        # Since exact schema is not provided, check some plausible keys presence
        assert isinstance(live_metrics_data, dict), "Live metrics response is not a JSON object"
        # Expect keys like 'token_balance', 'server_metrics' or similar
        assert any(key in live_metrics_data for key in ["token_balance", "wallet_status", "live_tokens", "server_metrics", "metrics"]), \
            "Expected metric keys missing in live metrics response"

    finally:
        session.close()

test_get_apilogslivemetrics_with_admin_jwt()