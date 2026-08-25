"""
Locust load/concurrency test for AICyberAuditBox.

Complements tests/test_10_users_audit_evidence.py (left untouched) with a repeatable,
configurable load run instead of a one-off script.

Prerequisites:
  - The full local stack running (run_all.bat): API on :8000/https, LLM + embedding
    servers, Redis, Postgres.
  - A test auditor account already registered via /api/auth/register, with its TOTP
    secret set in the LOAD_TEST_TOTP_SECRET env var (real login requires a live 6-digit
    TOTP code — pyotp computes it here the same way the app does).
  - LOAD_TEST_USERNAME / LOAD_TEST_PASSWORD env vars for that account.

Run:
    set LOAD_TEST_USERNAME=loadtest@example.com
    set LOAD_TEST_PASSWORD=...
    set LOAD_TEST_TOTP_SECRET=...
    locust -f qa/load/locustfile.py --host https://localhost:8000
"""
import os
import time
import uuid

import pyotp
from locust import HttpUser, task, between

USERNAME = os.environ.get("LOAD_TEST_USERNAME", "")
PASSWORD = os.environ.get("LOAD_TEST_PASSWORD", "")
TOTP_SECRET = os.environ.get("LOAD_TEST_TOTP_SECRET", "")

SAMPLE_EVIDENCE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "samples", "audit_evidence", "dummy_evidence.txt"
)


class AuditorUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.session_id = f"auditor-{USERNAME.split('@')[0]}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.token = None
        self._login()

    def _login(self):
        resp = self.client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            name="/api/auth/login",
            verify=False,
        )
        if resp.status_code != 200:
            resp.failure(f"login failed: {resp.status_code} {resp.text}")
            return

        otp_code = pyotp.TOTP(TOTP_SECRET).now()
        resp = self.client.post(
            "/api/auth/verify-otp",
            json={"username": USERNAME, "otp_code": otp_code},
            name="/api/auth/verify-otp",
            verify=False,
        )
        if resp.status_code == 200:
            self.token = resp.json().get("token")
        else:
            resp.failure(f"verify-otp failed: {resp.status_code} {resp.text}")

    def _auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task(3)
    def upload_evidence(self):
        if not os.path.exists(SAMPLE_EVIDENCE_PATH):
            return
        with open(SAMPLE_EVIDENCE_PATH, "rb") as f:
            self.client.post(
                "/api/audit/upload",
                data={"session_id": self.session_id, "is_auditor_uploaded": "true", "username": USERNAME},
                files={"files": ("dummy_evidence.txt", f, "text/plain")},
                headers=self._auth_headers(),
                name="/api/audit/upload",
                verify=False,
            )

    @task(1)
    def start_audit(self):
        self.client.post(
            "/api/audit/start",
            json={
                "session_id": self.session_id,
                "selected_sls": [1],
                "model_choice": "default",
                "audit_mode": "Quick",
                "username": USERNAME,
            },
            headers=self._auth_headers(),
            name="/api/audit/start",
            verify=False,
        )

    @task(5)
    def poll_status(self):
        self.client.get(
            f"/api/audit/status/{self.session_id}",
            headers=self._auth_headers(),
            name="/api/audit/status/[session_id]",
            verify=False,
        )

    @task(2)
    def list_findings(self):
        self.client.get(
            "/api/audit/findings",
            params={"session_id": self.session_id},
            headers=self._auth_headers(),
            name="/api/audit/findings",
            verify=False,
        )
