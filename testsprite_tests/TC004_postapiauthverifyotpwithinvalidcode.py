import requests

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_post_api_auth_verify_otp_with_invalid_code():
    username = "admin"
    invalid_otp_code = "000000"

    url = f"{BASE_URL}/api/auth/verify-otp"
    json_payload = {
        "username": username,
        "otp_code": invalid_otp_code
    }
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=json_payload, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request to {url} failed with exception: {e}"

    assert response.status_code == 400, f"Expected status code 400 for invalid OTP, got {response.status_code}"

test_post_api_auth_verify_otp_with_invalid_code()