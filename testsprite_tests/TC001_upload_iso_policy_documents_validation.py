import requests
import json

BASE_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = "/api/audit/upload"
TIMEOUT = 30
HEADERS = {
    "Content-Type": "application/json"
}

def test_upload_iso_policy_documents_validation():
    """
    Test POST /api/audit/upload endpoint with valid ISO policy and evidence documents 
    to ensure successful upload and 200 confirmation response.
    """
    url = BASE_URL + UPLOAD_ENDPOINT

    # Sample valid ISO policy and evidence documents payload conforming to expected schema
    payload = {
        "documents": [
            {
                "filename": "ISO27001_Policy_Manual.pdf",
                "content": "VGhpcyBpcyBhIHNhbXBsZSBpcyBvbjBsaW5lIGJhc2U2NCBlbmNvZGVkIENvbnRlbnQgb2YgSVMwIDI3MDAxIGF1ZGl0IGNvbnRlbnQgcG9saWN5Lg==",
                "document_type": "policy"
            },
            {
                "filename": "Evidence_2026-08-18.xlsx",
                "content": "UEsDBBQABgAIAAAAIQD9VZlA+e4kAAADMAAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                "document_type": "evidence"
            }
        ]
    }

    try:
        response = requests.post(url, headers=HEADERS, data=json.dumps(payload), timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request to {url} failed with exception: {e}"

    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        assert False, "Response is not a valid JSON"

    # Minimal validation: expect some confirmation field present
    assert "message" in response_json or "status" in response_json, "Response JSON missing confirmation message"
    # Optionally check that message confirms successful upload
    if "message" in response_json:
        assert "success" in response_json["message"].lower() or "uploaded" in response_json["message"].lower(), \
            f"Unexpected confirmation message: {response_json['message']}"

test_upload_iso_policy_documents_validation()
