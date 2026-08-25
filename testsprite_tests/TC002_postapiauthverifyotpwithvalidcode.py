import requests
import pyotp

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30

def test_postapiauthverifyotpwithvalidcode():
    login_url = f"{BASE_URL}/api/auth/login"
    verify_otp_url = f"{BASE_URL}/api/auth/verify-otp"
    username = "admin"
    password = "admin"  # Assuming default admin username and password are 'admin'
    
    try:
        # Step 1: Login to get OTP challenge (Assuming the TOTP secret is returned or retrievable)
        login_payload = {
            "username": username,
            "password": password
        }
        login_resp = requests.post(login_url, json=login_payload, timeout=TIMEOUT)
        assert login_resp.status_code == 200, f"Login failed with status: {login_resp.status_code}"
        login_json = login_resp.json()
        
        # The login response should prompt OTP challenge or may include a secret key or user info
        # We need the TOTP secret to generate a valid code. Since no schema details provide it,
        # Assume the server returns 'otp_secret' or 'totp_secret' in login response for testing purposes.
        
        # Extract the TOTP secret from login response
        otp_secret = login_json.get("otp_secret")
        assert otp_secret, "OTP secret not provided in login response for generating TOTP code"
        
        # Step 2: Generate valid TOTP code
        totp = pyotp.TOTP(otp_secret)
        valid_otp_code = totp.now()
        
        # Step 3: Verify OTP with valid TOTP code
        verify_payload = {
            "username": username,
            "code": valid_otp_code
        }
        verify_resp = requests.post(verify_otp_url, json=verify_payload, timeout=TIMEOUT)
        assert verify_resp.status_code == 200, f"OTP verification failed with status: {verify_resp.status_code}"
        
        verify_json = verify_resp.json()
        # Validate presence of JWT session token and assigned role in response
        jwt_token = verify_json.get("access_token") or verify_json.get("token") or verify_json.get("jwt")
        assigned_role = verify_json.get("role") or verify_json.get("assigned_role") or verify_json.get("user_role")
        
        assert jwt_token and isinstance(jwt_token, str) and len(jwt_token) > 0, "JWT session token missing or invalid"
        assert assigned_role and isinstance(assigned_role, str) and len(assigned_role) > 0, "Assigned role missing or invalid"
        
    except requests.RequestException as e:
        assert False, f"HTTP request failed: {str(e)}"

test_postapiauthverifyotpwithvalidcode()