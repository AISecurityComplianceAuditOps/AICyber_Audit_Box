import requests

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_post_api_auth_login_with_valid_credentials():
    url = f"{BASE_URL}/api/auth/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "username": "admin",
        "password": "admin"
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    json_resp = response.json()

    # It should return either an OTP challenge or login success response
    # Check for OTP challenge attributes or JWT token presence as per PRD
    # OTP challenge usually would require further step, JWT token if direct success
    assert isinstance(json_resp, dict), "Response is not a valid JSON object"

    # Determine response type: OTP challenge might have a field like "otp_required" or similar
    # If OTP required, expect certain fields (e.g. "otp_required": true)
    # If success, expect token or role info
    otp_challenge_keys = {"otp_required", "message", "challenge_type"}
    jwt_keys = {"token", "role", "expires_in"}

    if otp_challenge_keys.intersection(json_resp.keys()):
        # OTP challenge scenario
        assert json_resp.get("otp_required") is True, "OTP challenge missing otp_required=True"
        assert "challenge_type" in json_resp, "OTP challenge missing 'challenge_type' field"
    else:
        # Login success scenario
        assert "token" in json_resp, "Login success missing 'token'"
        assert "role" in json_resp, "Login success missing 'role'"
        assert isinstance(json_resp["token"], str) and len(json_resp["token"]) > 0, "Invalid token value"
        assert isinstance(json_resp["role"], str) and len(json_resp["role"]) > 0, "Invalid role value"

test_post_api_auth_login_with_valid_credentials()