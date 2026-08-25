import requests

BASE_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = "/api/audit/upload"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}


def test_upload_vapt_scan_logs_validation():
    """
    Test POST /api/audit/upload endpoint with valid VAPT scan logs and technical evidence 
    to ensure successful ingestion and 200 confirmation response.
    """

    # Sample valid VAPT scan logs payload based on typical structure inferred from PRD
    vapt_scan_logs_payload = {
        "scan_type": "vapt",
        "scan_date": "2026-08-17T10:00:00Z",
        "scan_metadata": {
            "scanner": "Acme VAPT Scanner 3.5",
            "target": "target.example.com",
            "vulnerabilities_count": 3
        },
        "vulnerabilities": [
            {
                "id": "VULN-001",
                "description": "SQL Injection vulnerability detected.",
                "severity": "High",
                "cvss_score": 9.1,
                "poc": "http://target.example.com?id=1' OR '1'='1",
                "controls": ["A.12.6.1", "A.14.2.5"],
                "evidence": {
                    "log_excerpt": "Error: syntax error near 'OR'",
                    "technical_details": "Payload used caused DB error"
                }
            },
            {
                "id": "VULN-002",
                "description": "Cross-site scripting (XSS) vulnerability.",
                "severity": "Medium",
                "cvss_score": 6.3,
                "poc": "<script>alert('XSS')</script>",
                "controls": ["A.10.1.1"],
                "evidence": {
                    "log_excerpt": "<script injected in input field>",
                    "technical_details": "Reflected XSS in search parameter"
                }
            },
            {
                "id": "VULN-003",
                "description": "Outdated software version detected.",
                "severity": "Low",
                "cvss_score": 3.1,
                "poc": "Apache version 2.4.29",
                "controls": ["A.12.5.1"],
                "evidence": {
                    "log_excerpt": "Server: Apache/2.4.29 (Ubuntu)",
                    "technical_details": "Version is vulnerable to CVE-XXXX-YYYY"
                }
            }
        ],
        "technical_evidence": {
            "log_files": [
                "scan_log_001.txt",
                "scan_log_002.txt"
            ],
            "raw_data": "base64encodedstring=="
        }
    }

    try:
        response = requests.post(
            url=BASE_URL + UPLOAD_ENDPOINT,
            headers=HEADERS,
            json=vapt_scan_logs_payload,
            timeout=TIMEOUT,
        )
        # Confirm HTTP 200 response indicating successful ingestion
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        # Optional deeper validation of response JSON content for confirmation message or id
        resp_json = response.json()
        msg = resp_json.get("message")
        status = resp_json.get("status")
        assert (msg in ["success", "uploaded", "ok"] or status in ["success", "uploaded", "ok"]), \
            "Response JSON does not contain expected success indication"

    except requests.RequestException as e:
        assert False, f"HTTP request failed: {e}"


test_upload_vapt_scan_logs_validation()
