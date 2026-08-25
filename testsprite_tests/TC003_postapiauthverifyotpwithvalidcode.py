import requests

base_url = "http://127.0.0.1:8000"
timeout = 30

def test_postapiauthverifyotpwithvalidcode():
    login_url = f"{base_url}/api/auth/login"
    verify_otp_url = f"{base_url}/api/auth/verify-otp"
    username = "admin"
    password = "admin"  # Assumed default admin password; update if needed
    
    try:
        # Step 1: Login to trigger TOTP verification requirement
        login_payload = {"username": username, "password": password}
        login_resp = requests.post(login_url, json=login_payload, timeout=timeout)
        assert login_resp.status_code == 200, f"Login failed with status {login_resp.status_code}"
        
        # The backend expects a valid 6-digit OTP from TOTP source for the user "admin".
        # We must fetch or generate the current valid OTP code. Since PRD says TOTP 2FA is used,
        # but no secret is given, assume for test environment the OTP code is '123456' or use any logic.
        # If no direct method is possible, skip here would cause test failure.
        # For this test, proceed using '123456' as valid OTP placeholder.
        
        otp_code = "123456"
        verify_otp_payload = {"username": username, "otp_code": otp_code}
        otp_resp = requests.post(verify_otp_url, json=verify_otp_payload, timeout=timeout)
        
        # Validate success response 200 and check the JWT token presence
        assert otp_resp.status_code == 200, f"OTP verification failed with status {otp_resp.status_code}"
        json_resp = otp_resp.json()
        assert isinstance(json_resp, dict), "Response is not a JSON object"
        # JWT token would typically be a non-empty string; key name might be 'token', 'access_token' or similar.
        # Since no explicit schema provided, check for a sensible JWT key in response.
        token = None
        for key in ("token", "access_token", "jwt", "session_token", "jwt_token"):
            if key in json_resp:
                token = json_resp[key]
                break
        assert token and isinstance(token, str) and len(token) > 10, "JWT token missing or invalid in response"

    except requests.RequestException as ex:
        assert False, f"Request failed: {ex}"

test_postapiauthverifyotpwithvalidcode()