import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {
    "Content-Type": "application/json"
}

def test_start_iso_27001_audit_evaluation_insufficient_input():
    url = f"{BASE_URL}/api/audit/start"
    # Provide a dummy non-empty session_id string to pass validation phase but no evidence uploaded
    payload = {
        "session_id": "dummy-session"
    }

    try:
        response = requests.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT)
        # Expecting 400 Bad Request due to insufficient input or zero-evidence guard
        assert response.status_code == 400, f"Expected 400 Bad Request but got {response.status_code}"
        # Validate error message structure or content
        json_resp = response.json()
        assert "error" in json_resp or "message" in json_resp, "Error details missing in response"
    except requests.RequestException as e:
        assert False, f"Request to start audit failed with exception: {str(e)}"

test_start_iso_27001_audit_evaluation_insufficient_input()
