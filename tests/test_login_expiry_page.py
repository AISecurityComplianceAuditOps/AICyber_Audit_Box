# -*- coding: utf-8 -*-
"""An expired sign-in sends the page back to sign-in, and says why.

A sign-in lasts JWT_EXPIRY_HOURS (8). It ran out near the end of an auditor's
35-finding AI scan: every call came back 401 and the page carried on --
Recent Sessions (0), the progress gone, the workspace locked -- while the scan
finished and saved on the server (log: 1,932 status polls answered 200, then
401). authFetch now reports a 401 once, signs out and shows why; signing in
again reopens the session, still locked while its scan runs.

Checked in a browser on a throwaway server: the old page stayed put with no
message; this one returns to sign-in, and after signing in the running scan
shows running and locked.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "src", "api", "static", "app.js")
AUTH_PY = os.path.join(ROOT, "src", "api", "endpoints", "auth.py")


def _src():
    return io.open(APP_JS, encoding="utf-8").read()


def _function(src, name):
    start = src.index(f"function {name}(")
    depth, i = 0, src.index("{", start)
    while True:
        depth += src[i] == "{"
        depth -= src[i] == "}"
        i += 1
        if depth == 0:
            return src[start:i]


def test_auth_fetch_hands_a_401_to_the_expiry_handler():
    body = _function(_src(), "authFetch")
    assert "res.status === 401" in body and "handleLoginExpired()" in body
    assert "currentUser && currentUser.token" in body          # only a signed-in page


def test_the_handler_signs_out_once_and_says_why():
    body = _function(_src(), "handleLoginExpired")
    assert "window._loginExpiredHandled" in body and "logout()" in body
    assert "expired" in body.lower() and "showError(" in body
    assert body.index("logout()") < body.index("showError(")   # logout clears the message first


def test_signing_in_again_rearms_it_and_signing_out_drops_the_run_lock():
    src = _src()
    assert "window._loginExpiredHandled = false;" in _function(src, "handleOTPSubmit")
    assert "_setRunLockedInputs(false)" in _function(src, "logout")


def test_wrong_credentials_never_go_through_auth_fetch():
    """The server's other 401s are for wrong credentials (sign-in, code check,
    password reset). Through authFetch they would sign the user out."""
    src = _src()
    for path in ("/auth/login", "/auth/verify-otp", "/auth/forgot-password/reset"):
        for m in re.finditer(re.escape(path), src):
            line = src[src.rfind("\n", 0, m.start()):src.find("\n", m.end())]
            assert "authFetch" not in line, line
    auth = io.open(AUTH_PY, encoding="utf-8").read()
    assert len(re.findall(r"status_code=401", auth)) == 6     # 3 token + 3 credential checks, as audited
