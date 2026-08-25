import requests

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default password is 'admin', adjust if different

def test_get_api_license_wallet_with_admin_jwt():
    session = requests.Session()
    try:
        # Step 1: POST /api/auth/login with admin credentials
        login_resp = session.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=30
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        login_data = login_resp.json()

        # Determine if OTP required
        if "otp_required" in login_data and login_data["otp_required"]:
            otp_code = "123456"  # fixed dummy OTP code as fallback

            verify_resp = session.post(
                f"{BASE_URL}/api/auth/verify-otp",
                json={"username": ADMIN_USERNAME, "totp_code": otp_code},
                timeout=30
            )
            assert verify_resp.status_code == 200, f"OTP verification failed: {verify_resp.text}"
            verify_data = verify_resp.json()
            jwt_token = verify_data.get("jwt_token")
            assert jwt_token, "JWT token missing after OTP verification"
        else:
            # OTP not required, JWT token may be directly returned
            jwt_token = login_data.get("jwt_token")
            assert jwt_token, "JWT token missing after login"

        # Step 2: GET /api/license/wallet with admin JWT
        headers = {"Authorization": f"Bearer {jwt_token}"}
        wallet_resp = session.get(f"{BASE_URL}/api/license/wallet", headers=headers, timeout=30)
        assert wallet_resp.status_code == 200, f"License wallet request failed: {wallet_resp.text}"
        wallet_data = wallet_resp.json()

        # Validate wallet balance and token counts exist and are of expected type
        assert "wallet_balance" in wallet_data, "wallet_balance field missing in response"
        assert isinstance(wallet_data["wallet_balance"], (int, float)), "wallet_balance is not numeric"

        assert "token_counts" in wallet_data, "token_counts field missing in response"
        assert isinstance(wallet_data["token_counts"], (dict, list)), "token_counts is not dict or list"

    finally:
        session.close()

test_get_api_license_wallet_with_admin_jwt()