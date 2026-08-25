import requests
import base64

BASE_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = f"{BASE_URL}/api/audit/upload"
TIMEOUT = 30


def test_upload_vapt_scan_logs_error_handling():
    # Corrupted or malicious file content simulation
    corrupted_content = b"%PDF-1.4\n% corrupted file content with random binary \x00\xff\x00\xff"
    malicious_content = b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"

    # Assuming session_id is required, providing dummy or empty string
    session_id = "test-session"

    for file_content in [corrupted_content, malicious_content]:
        # Encoding file content as base64 string to safely include in JSON
        encoded_content = base64.b64encode(file_content).decode('utf-8')
        json_payload = {
            "session_id": session_id,
            "files": [
                {
                    "filename": "vapt_scan_log.bin",
                    "content": encoded_content,
                    "content_type": "application/octet-stream"
                }
            ]
        }
        try:
            response = requests.post(
                UPLOAD_ENDPOINT,
                json=json_payload,
                timeout=TIMEOUT,
            )
        except requests.RequestException as e:
            assert False, f"Request failed with exception: {e}"

        assert response.status_code in (400, 415), (
            f"Expected status code 400 or 415 for corrupted/malicious upload but got {response.status_code}.\n"
            f"Response content: {response.content.decode(errors='ignore')}"
        )

test_upload_vapt_scan_logs_error_handling()