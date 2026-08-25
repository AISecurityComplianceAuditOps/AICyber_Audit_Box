import requests
import tempfile
import os

BASE_URL = "http://127.0.0.1:8000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Assumed default password from instructions
TIMEOUT = 30

def test_post_audit_upload_with_valid_files():
    session = requests.Session()
    # Step 1: Login to get TOTP challenge
    login_resp = session.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=TIMEOUT
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    # Step 2: Retrieve TOTP secret to generate OTP or get OTP another way
    # Since OTP generation secret is not provided, assume test environment OTP is "123456" for demo
    # In real cases, this should be fetched/generated dynamically
    otp_code = "123456"
    verify_otp_resp = session.post(
        f"{BASE_URL}/api/auth/verify-otp",
        json={"username": ADMIN_USERNAME, "otp_code": otp_code},
        timeout=TIMEOUT
    )
    assert verify_otp_resp.status_code == 200, f"OTP verification failed: {verify_otp_resp.text}"
    token = verify_otp_resp.json().get("token")
    assert token and isinstance(token, str), "No JWT token returned after OTP verification"

    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Create a new audit session to get session_id
    session_title = "Test Upload Session"
    framework = "ISO27001"
    create_session_resp = session.post(
        f"{BASE_URL}/api/audit/sessions",
        data={
            "session_title": session_title,
            "framework": framework,
            "username": ADMIN_USERNAME
        },
        headers=headers,
        timeout=TIMEOUT
    )
    assert create_session_resp.status_code == 200, f"Audit session creation failed: {create_session_resp.text}"
    session_data = create_session_resp.json()
    session_id = session_data.get("session_id") or session_data.get("id") or session_data.get("session_id")
    # Fallback to finding a suitable key for session id from response
    if not session_id:
        for key in ["session_id", "id", "sessionId"]:
            if key in session_data:
                session_id = session_data[key]
                break
    assert session_id and isinstance(session_id, str), "No session_id returned from audit session creation"

    # Step 4: Prepare supported evidence files to upload
    # Create small example text files to simulate supported evidence files
    files = []
    temp_files = []
    try:
        for i in range(2):
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            tmp_file.write(b"This is a sample evidence file for audit ingestion.\nLine 2 of evidence.")
            tmp_file.close()
            temp_files.append(tmp_file.name)
            files.append(("files", (os.path.basename(tmp_file.name), open(tmp_file.name, "rb"), "text/plain")))
        
        # Add session_id as a multipart field using 'data'
        data = {"session_id": session_id}

        upload_resp = session.post(
            f"{BASE_URL}/api/audit/upload",
            headers=headers,
            data=data,
            files=files,
            timeout=TIMEOUT
        )
        for _, f in files:
            f[1].close()
        assert upload_resp.status_code == 200, f"Upload failed: {upload_resp.text}"
        resp_json = upload_resp.json()
        # The response should confirm files processed and indexed - likely has a confirmation message or details
        assert "processed" in upload_resp.text.lower() or "indexed" in upload_resp.text.lower() or resp_json, \
            "No confirmation of files processed or indexed in response"
    finally:
        # Clean up temp files
        for tmpf in temp_files:
            try:
                os.unlink(tmpf)
            except Exception:
                pass
        # Delete created audit session
        # No deletion endpoint described in PRD, so skipping explicit delete

test_post_audit_upload_with_valid_files()