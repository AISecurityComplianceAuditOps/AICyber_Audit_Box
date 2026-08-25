import requests
import time

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {"Content-Type": "application/json"}

def test_start_iso_27001_audit_evaluation_success():
    session_id = None
    try:
        # Step 1: Upload valid ISO 27001 policy and evidence documents
        upload_url = f"{BASE_URL}/api/audit/upload"
        iso_policy_payload = {
            "documents": [
                {
                    "filename": "iso27001_policy_doc.pdf",
                    "content": "VGhpcyBpcyBhIHNhbXBsZSBpc28gMjcwMTEgcG9saWN5IGRvY3VtZW50IGF0dGFjaG1lbnQu"
                },
                {
                    "filename": "audit_evidence_evidence.xlsx",
                    "content": "UEsDBBQABgAIAAAAIQDlNWv9X8EAAK0FAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            ]
        }
        upload_resp = requests.post(upload_url, json=iso_policy_payload, headers=HEADERS, timeout=TIMEOUT)
        assert upload_resp.status_code == 200, f"Upload failed with status {upload_resp.status_code}"
        
        # Step 2: Start audit evaluation with valid session payload
        start_url = f"{BASE_URL}/api/audit/start"
        start_payload = {
            "session_context": {
                "session_name": "test_iso_27001_session",
                "uploaded_documents": ["iso27001_policy_doc.pdf", "audit_evidence_evidence.xlsx"],
                "audit_type": "ISO_27001_2022"
            },
            "runtime_debug": True  # Enable mandatory runtime debug logs per instructions
        }
        start_resp = requests.post(start_url, json=start_payload, headers=HEADERS, timeout=TIMEOUT)
        assert start_resp.status_code == 200, f"Audit start failed with status {start_resp.status_code}"
        
        start_data = start_resp.json()
        session_id = start_data.get("session_id")
        findings = start_data.get("findings")
        
        assert session_id is not None and isinstance(session_id, str), "session_id missing or invalid in response"
        assert isinstance(findings, list) and len(findings) > 0, "No ISO 27001 audit findings generated"
        
        # Additional compliance checks per instructions
        # - Check presence of expected keys in findings (simulating canonical provenance, atomic requirements)
        sample_finding = findings[0]
        assert "control_id" in sample_finding and sample_finding["control_id"].startswith("A"), "Invalid control_id in findings"
        assert "provenance" in sample_finding and isinstance(sample_finding["provenance"], dict), "Provenance missing or invalid"
        assert "compliance_status" in sample_finding and sample_finding["compliance_status"] in ["compliant", "non-compliant", "not-applicable"], "Invalid compliance status"
        
    finally:
        if session_id:
            # Cleanup: Stop and delete the audit session if possible to maintain test isolation
            try:
                stop_url = f"{BASE_URL}/api/audit/stop/{session_id}"
                requests.post(stop_url, headers=HEADERS, timeout=TIMEOUT)
            except Exception:
                pass

test_start_iso_27001_audit_evaluation_success()
