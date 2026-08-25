import requests
import time

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assuming password is 'admin' as default is not specified otherwise
REQUEST_TIMEOUT = 30

def test_postauditstartwithvalidparameters():
    try:
        # Step 1: Login to get TOTP challenge
        login_resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=REQUEST_TIMEOUT,
        )
        assert login_resp.status_code == 200, f"Login failed with status {login_resp.status_code}"
        
        # Step 2: Retrieve OTP code from local TOTP for admin user (simulate OTP)
        # Since actual OTP generation secret is not provided, simulate a delay and reuse a known OTP or skip OTP call.
        # For this test, assume OTP is always "123456"
        otp_code = "123456"
        
        verify_resp = requests.post(
            f"{BASE_URL}/api/auth/verify-otp",
            json={"username": ADMIN_USERNAME, "otp_code": otp_code},
            timeout=REQUEST_TIMEOUT,
        )
        assert verify_resp.status_code == 200, f"OTP verification failed with status {verify_resp.status_code}"
        jwt_token = verify_resp.json().get("access_token") or verify_resp.json().get("token")
        assert jwt_token, "JWT token not found in OTP verification response"
        
        headers = {"Authorization": f"Bearer {jwt_token}"}

        # Step 3: Create an audit session to get a valid session_id
        session_title = "Test Audit Session for TC008"
        framework = "ISO27001"
        create_session_resp = requests.post(
            f"{BASE_URL}/api/audit/sessions",
            data={
                "session_title": session_title,
                "framework": framework,
                "username": ADMIN_USERNAME
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        assert create_session_resp.status_code == 200, f"Audit session creation failed with status {create_session_resp.status_code}"
        session_data = create_session_resp.json()
        session_id = session_data.get("session_id") or session_data.get("id")
        assert session_id, "Session ID not found in audit session creation response"
        
        # Step 4: Prepare valid parameters for /api/audit/start
        payload = {
            "session_id": session_id,
            "selected_sls": [1, 2],          # example control IDs for selected SLS
            "model_choice": "default-model", # example model choice string
            "audit_mode": "full"              # example audit mode string
        }
        
        # Step 5: Start ISO 27001 compliance audit
        start_resp = requests.post(
            f"{BASE_URL}/api/audit/start",
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        assert start_resp.status_code == 200, f"Audit start failed with status {start_resp.status_code}"
        
    finally:
        # Cleanup: delete created audit session if possible
        # The PRD does not specify a DELETE endpoint for audit sessions,
        # so cleanup may not be possible here.
        # If a DELETE endpoint existed, it would be called here.
        pass

test_postauditstartwithvalidparameters()
