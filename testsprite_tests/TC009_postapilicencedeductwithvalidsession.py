import requests
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming default password is 'admin'
TIMEOUT = 30


def test_post_api_license_deduct_with_valid_session():
    headers = {"Content-Type": "application/json"}
    try:
        # 1. Login as admin to get OTP challenge
        login_resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=TIMEOUT,
            headers=headers
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        login_data = login_resp.json()
        # Check if OTP challenge required
        if "otp_required" not in login_data or not login_data["otp_required"]:
            raise AssertionError("OTP challenge required but not indicated in login response.")

        # 2. Retrieve TOTP code (simulate or get from a known secret)
        # For test purposes, assume a fixed TOTP code retrieval routine here.
        # Since PRD doesn't provide secrets, emulate a successful OTP (usually requires external library).
        # Here, simulate by posting a "123456" (assuming test env accepts it).
        totp_code = "123456"

        verify_otp_resp = requests.post(
            f"{BASE_URL}/api/auth/verify-otp",
            json={"username": ADMIN_USERNAME, "totp_code": totp_code},
            timeout=TIMEOUT,
            headers=headers
        )

        assert verify_otp_resp.status_code == 200, f"OTP Verification failed: {verify_otp_resp.text}"
        verify_otp_data = verify_otp_resp.json()
        assert "token" in verify_otp_data, "JWT token not present after OTP verification."
        admin_jwt = verify_otp_data["token"]
        auth_headers = {"Authorization": f"Bearer {admin_jwt}", "Content-Type": "application/json"}

        # 3. Create auditor session to get a valid session_id to use in license deduction
        auditor_username = "auditor1"
        auditor_password = "auditor1"  # Assuming a default auditor user exists for test
        # Login auditor
        auditor_login_resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": auditor_username, "password": auditor_password},
            timeout=TIMEOUT,
            headers=headers
        )
        assert auditor_login_resp.status_code == 200, f"Auditor login failed: {auditor_login_resp.text}"
        auditor_login_data = auditor_login_resp.json()
        assert "otp_required" in auditor_login_data and auditor_login_data["otp_required"], "Auditor OTP not required as expected."

        # Verify auditor OTP with same fixed code for test
        auditor_verify_resp = requests.post(
            f"{BASE_URL}/api/auth/verify-otp",
            json={"username": auditor_username, "totp_code": totp_code},
            timeout=TIMEOUT,
            headers=headers
        )
        assert auditor_verify_resp.status_code == 200, f"Auditor OTP verification failed: {auditor_verify_resp.text}"
        auditor_token = auditor_verify_resp.json().get("token")
        assert auditor_token, "Auditor JWT token missing"
        auditor_headers = {"Authorization": f"Bearer {auditor_token}", "Content-Type": "application/json"}

        # Create audit session
        session_payload = {
            "title": "Test Audit Session for License Deduct",
            "description": "Session created by automated test.",
            "date": time.strftime("%Y-%m-%d")
        }
        session_resp = requests.post(
            f"{BASE_URL}/api/audit/sessions",
            json=session_payload,
            headers=auditor_headers,
            timeout=TIMEOUT
        )
        assert session_resp.status_code == 200, f"Session creation failed: {session_resp.text}"
        session_data = session_resp.json()
        assert "session_id" in session_data, "session_id missing in session creation response"
        session_id = session_data["session_id"]

        # 4. Get current wallet balance (optional) before deduction
        wallet_resp = requests.get(
            f"{BASE_URL}/api/license/wallet",
            headers=auth_headers,
            timeout=TIMEOUT
        )
        assert wallet_resp.status_code == 200, f"Wallet retrieval failed: {wallet_resp.text}"
        wallet_data = wallet_resp.json()
        initial_balance = wallet_data.get("balance") or wallet_data.get("token_balance") or wallet_data.get("tokens")
        if initial_balance is None:
            raise AssertionError("Could not determine initial wallet balance")

        # 5. Deduct tokens
        deduct_tokens = 1
        deduct_payload = {
            "session_id": session_id,
            "tokens": deduct_tokens
        }
        deduct_resp = requests.post(
            f"{BASE_URL}/api/license/deduct",
            json=deduct_payload,
            headers=auth_headers,
            timeout=TIMEOUT
        )
        assert deduct_resp.status_code == 200, f"Token deduction failed: {deduct_resp.text}"

        deduct_data = deduct_resp.json()
        # Assert updated balance present and decreased or token usage record is returned
        assert "updated_balance" in deduct_data or "balance" in deduct_data or "token_balance" in deduct_data, \
            "Updated balance not found in deduct response"
        updated_balance = deduct_data.get("updated_balance") or deduct_data.get("balance") or deduct_data.get("token_balance")
        assert isinstance(updated_balance, (int, float)), "Updated balance is not numeric"
        assert updated_balance <= initial_balance, "Updated balance is not less or equal to initial balance"

    finally:
        # Cleanup: delete the created audit session if possible
        if 'session_id' in locals():
            try:
                requests.delete(
                    f"{BASE_URL}/api/audit/sessions/{session_id}",
                    headers=auditor_headers,
                    timeout=TIMEOUT
                )
            except Exception:
                pass


test_post_api_license_deduct_with_valid_session()