import requests
from requests.exceptions import RequestException

BASE_URL = "http://localhost:8000"
UPLOAD_ENDPOINT = "/api/audit/upload"
TIMEOUT = 30
HEADERS = {
    # Assuming JSON content-type is not needed as we send multipart files.
    # Add auth headers here if required, e.g., "Authorization": "Bearer <token>"
}

def test_post_api_audit_upload_with_valid_and_invalid_documents():
    valid_files = [
        ('policy.pdf', b'%PDF-1.4\n%Valid PDF content with some dummy data\n', 'application/pdf'),
        ('evidence.docx', b'PK\x03\x04\x14\x00\x06\x00Valid docx minimal content', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        ('vapt_scan.log', b'[VAPT_SCAN]\nValid scan log content line 1\nLine 2\n', 'text/plain'),
    ]

    invalid_files_cases = [
        # Malformed file: corrupted pdf content
        {
            'files': [('policy_corrupt.pdf', b'%PDF-1.4 corrupted content \x00\x01\x02', 'application/pdf')],
            'expected_status': {400, 415}
        },
        # Unsupported file type
        {
            'files': [('script.exe', b'MZ\x90\x00\x03\x00\x00\x00', 'application/x-msdownload')],
            'expected_status': {400, 415}
        },
        # Malformed evidence docx file: truncated content
        {
            'files': [('evidence_corrupt.docx', b'PK\x03\x04 truncated content', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')],
            'expected_status': {400, 415}
        },
        # Corrupted VAPT scan log (binary junk instead of text)
        {
            'files': [('vapt_scan_corrupt.log', b'\x00\xff\xab\xcd\xef\x00\x00', 'text/plain')],
            'expected_status': {400, 415}
        }
    ]

    def make_upload_request(files):
        multipart_files = []
        for filename, content, mimetype in files:
            multipart_files.append(
                ('files', (filename, content, mimetype))
            )
        try:
            response = requests.post(
                BASE_URL + UPLOAD_ENDPOINT,
                files=multipart_files,
                headers=HEADERS,
                timeout=TIMEOUT
            )
            return response
        except RequestException as e:
            raise AssertionError(f"Request failed: {e}")

    # Test valid files upload - expect 200 OK
    response_valid = make_upload_request(valid_files)
    assert response_valid.status_code == 200, f"Expected 200 OK for valid upload, got {response_valid.status_code}"

    # Check confirmation in json or text safely
    try:
        json_resp = response_valid.json()
        assert any('confirmation' in str(value).lower() for value in json_resp.values()), \
            "Response JSON should indicate confirmation"
    except Exception:
        assert "confirmation" in response_valid.text.lower(), "Response text should indicate confirmation"

    # Test invalid/malformed/unsupported files - expect 400 or 415
    for case in invalid_files_cases:
        response_invalid = make_upload_request(case['files'])
        assert response_invalid.status_code in case['expected_status'], \
            f"Expected 400 or 415 error for invalid upload, got {response_invalid.status_code} for files {case['files']}"

test_post_api_audit_upload_with_valid_and_invalid_documents()
