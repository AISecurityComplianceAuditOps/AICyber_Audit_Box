import requests

BASE_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = "/api/audit/upload"
TIMEOUT = 30

# Placeholder auth token, in real scenario replace with valid token
AUTH_TOKEN = "Bearer dummy-valid-token"

def test_upload_iso_policy_documents_error_handling():
    # Malformed and unsupported document payloads and content-types to test error handling
    test_payloads = [
        # Plain text but declared as json (invalid json)
        ("not a json object", "application/json"),
        # Random binary data with unsupported mimetype
        (b"\x00\x01\x02\x03\x04", "application/octet-stream"),
        # Unsupported file type mimetype with string content
        ("<html>This is not valid policy doc</html>", "text/html"),
        # Empty file upload scenario
        ("", "application/pdf"),
    ]

    headers = {
        "Authorization": AUTH_TOKEN
    }

    for content, content_type in test_payloads:
        files = {
            "files": ("testfile", content, content_type),
        }
        data = {
            "session_id": "dummy-session-id"
        }
        try:
            response = requests.post(
                BASE_URL + UPLOAD_ENDPOINT,
                data=data,
                files=files,
                headers=headers,
                timeout=TIMEOUT,
            )
        except requests.RequestException as e:
            assert False, f"Request failed unexpectedly: {e}"

        # Validate that response status is 400 or 415
        assert response.status_code in (400, 415), (
            f"Expected 400 or 415 status code for malformed/unsupported upload, "
            f"got {response.status_code} with content: {response.text}"
        )
        # Optionally check error message presence or content types returned
        content_type_resp = response.headers.get("Content-Type", "").lower()
        assert "application/json" in content_type_resp or "application/problem+json" in content_type_resp or "text/plain" in content_type_resp, (
            "Expected error response content type to be JSON or plain text."
        )

test_upload_iso_policy_documents_error_handling()
