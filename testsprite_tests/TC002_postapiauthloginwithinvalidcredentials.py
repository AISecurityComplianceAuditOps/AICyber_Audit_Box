import requests

def test_post_api_auth_login_with_invalid_credentials():
    base_url = "http://127.0.0.1:8000"
    url = f"{base_url}/api/auth/login"
    payload = {
        "username": "invalid_user",
        "password": "wrong_password"
    }
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        assert response.status_code == 401, f"Expected status code 401, got {response.status_code}"
        # Optionally check response content for invalid credentials message if provided
        if response.headers.get("Content-Type", "").startswith("application/json"):
            resp_json = response.json()
            # Could validate error message structure if known, otherwise skip
            # Example: assert resp_json.get("detail") == "Invalid credentials"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_post_api_auth_login_with_invalid_credentials()