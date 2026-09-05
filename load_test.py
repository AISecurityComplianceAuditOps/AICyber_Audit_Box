# -*- coding: utf-8 -*-
"""
Concurrent-audit load test for a deployed AICyberAuditBox instance.

Simulates N auditor accounts uploading evidence and starting real audits AT
THE SAME TIME against a live deployment, then reports per-user timing and
success/failure -- exercises the actual HTTP API, the resource-guard memory
checks, and the LLM port-pool concurrency under real concurrent load, not
just document parsing in isolation.

Run from your own machine, pointed at the deployed VM's URL. Needs only:
    pip install requests pyotp

Usage:
    python load_test.py --base-url http://<vm-ip>:8000 --users 5 --controls 64 --mode Quick
    python load_test.py --base-url http://<vm-ip>:8000 --users 10 --controls 64,1,17 --mode Deep --smoke

--smoke skips the actual /audit/start call and only measures upload latency
under concurrency -- use this first to sanity-check throughput before
committing to a full N-user LLM run, since each real audit can take minutes
per control depending on the VM's hardware.

TWO-PHASE DESIGN -- READ THIS BEFORE ASSUMING A FAILURE MEANS THE SYSTEM CAN'T
HANDLE LOAD:
Account setup (register + login + TOTP verify) runs in Phase 1, SEQUENTIALLY,
before any timing starts. This is deliberate: every simulated user in this
script shares your one test machine's source IP, and the server's login rate
limiter is per-IP (5 attempts/60s, shared across /auth/login and
/auth/verify-otp) -- if all N users tried to log in AT ONCE, most of them
would get 429'd purely by that shared bucket, which would look exactly like
"the system can't handle N concurrent users" without actually testing
anything about audit concurrency. Phase 1 works around that with rate-aware
backoff. Only Phase 2 (session create -> upload -> audit start -> poll),
which is NOT IP-rate-limited, is measured concurrently and is what this
script's timing numbers actually describe.
"""
import argparse
import random
import string
import threading
import time
import os

import requests
import pyotp

SAMPLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "samples", "10 -Multi-factor authentication operator.docx")


def _post_with_rate_backoff(url, json_body, max_wait=70):
    """POSTs and, on a 429, waits out the server's rate-limit window once
    and retries -- used only in Phase 1 (account setup), never in the timed
    concurrent Phase 2."""
    r = requests.post(url, json=json_body, timeout=30)
    if r.status_code == 429:
        time.sleep(max_wait)
        r = requests.post(url, json=json_body, timeout=30)
    return r


def setup_one_user(base_url, user_idx, setup_results, setup_lock):
    """Phase 1: register + login + TOTP verify. Sequential-friendly by
    design (see module docstring) -- callers stagger these, not parallelize."""
    suf = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    username = f"loadtest_u{user_idx}_{suf}@test.com"
    password = "LoadTest123!"
    api = f"{base_url}/api"

    r = requests.post(f"{api}/auth/register", json={"username": username, "password": password, "role": "auditor"}, timeout=30)
    r.raise_for_status()
    secret = r.json()["totp_secret"]

    r = _post_with_rate_backoff(f"{api}/auth/login", {"username": username, "password": password})
    r.raise_for_status()
    totp = pyotp.TOTP(secret)
    r2 = _post_with_rate_backoff(f"{api}/auth/verify-otp", {"username": username, "otp_code": totp.now()})
    r2.raise_for_status()
    token = r2.json()["token"]

    with setup_lock:
        setup_results.append({"user_idx": user_idx, "username": username, "token": token})
        print(f"  [setup OK] user {user_idx} ({username})")


def run_one_user_load(base_url, user, control_ids, mode, smoke, results, lock):
    """Phase 2: the actual concurrent, timed load -- session create, upload,
    (optionally) start+poll a real audit. No auth calls happen here."""
    username, token = user["username"], user["token"]
    api = f"{base_url}/api"
    h = {"Authorization": f"Bearer {token}"}
    t0 = time.time()
    row = {"user": username, "session_id": None, "stage": "start", "ok": False, "detail": ""}

    try:
        r = requests.post(f"{api}/audit/sessions",
                           data={"session_title": f"LoadTest User {user['user_idx']}", "framework": "ISO 27001", "username": username},
                           headers=h, timeout=30)
        r.raise_for_status()
        session_id = r.json()["session_id"]
        row["session_id"] = session_id
        row["stage"] = "session_created"

        with open(SAMPLE_FILE, "rb") as f:
            files = {"files": (os.path.basename(SAMPLE_FILE), f, "application/octet-stream")}
            data = {"session_id": session_id, "is_auditor_uploaded": "true", "username": username}
            r = requests.post(f"{api}/audit/upload", data=data, files=files, headers=h, timeout=60)
        r.raise_for_status()
        row["stage"] = "uploaded"
        t_upload = time.time()

        if smoke:
            row["ok"] = True
            row["detail"] = f"smoke OK (session+upload {t_upload-t0:.1f}s)"
        else:
            r = requests.post(f"{api}/audit/start", json={
                "session_id": session_id, "selected_sls": control_ids,
                "model_choice": "Gemma 4 (e4b)", "audit_mode": mode, "username": username
            }, headers=h, timeout=30)
            r.raise_for_status()
            row["stage"] = "audit_started"

            deadline = time.time() + 1800  # 30 min ceiling per user
            last_status = None
            while time.time() < deadline:
                sr = requests.get(f"{api}/audit/status/{session_id}", headers=h, timeout=30)
                sd = sr.json()
                last_status = sd.get("status")
                if last_status in ("completed", "failed"):
                    break
                time.sleep(5)

            t_done = time.time()
            row["ok"] = (last_status == "completed")
            row["detail"] = f"status={last_status}, total={t_done-t0:.1f}s (upload {t_upload-t0:.1f}s, audit {t_done-t_upload:.1f}s)"

    except Exception as e:
        row["detail"] = f"FAILED at stage={row['stage']}: {e}"

    with lock:
        results.append(row)
        print(f"[{'OK' if row['ok'] else 'FAIL'}] user {user['user_idx']} ({username}): {row['detail']}")


def fetch_detailed_report(base_url, results, admin_user, admin_pass, admin_totp_secret):
    """Phase 3: pulls the server's own per-session telemetry (file size,
    character count, CPU core count, tokens, latency, compliant/non-compliant
    counts) for exactly the sessions this run created, via the admin-only
    /audit/benchmark/sessions endpoint.

    Needs REAL admin credentials (--admin-user/--admin-pass/--admin-totp-secret)
    -- this used to self-provision a throwaway admin account via
    /auth/register, but that endpoint no longer accepts role=admin at all
    (self-service admin signup was a real security gap, closed separately).
    Skipped entirely if credentials aren't supplied, or in --smoke mode
    since no real audit ran and there is no benchmark record to fetch.
    """
    if not (admin_user and admin_pass and admin_totp_secret):
        print("\n(Skipping detailed report: pass --admin-user, --admin-pass, and --admin-totp-secret")
        print(" for an existing admin account to pull per-session telemetry. The raw TOTP secret is")
        print(" the base32 string shown when that admin account was first registered/set up -- not")
        print(" a live 6-digit code, which would go stale before this script gets to use it.)")
        return

    api = f"{base_url}/api"
    r = _post_with_rate_backoff(f"{api}/auth/login", {"username": admin_user, "password": admin_pass})
    r.raise_for_status()
    r2 = _post_with_rate_backoff(f"{api}/auth/verify-otp", {"username": admin_user, "otp_code": pyotp.TOTP(admin_totp_secret).now()})
    r2.raise_for_status()
    admin_token = r2.json()["token"]

    r = requests.get(f"{api}/audit/benchmark/sessions", headers={"Authorization": f"Bearer {admin_token}"}, timeout=30)
    r.raise_for_status()
    all_records = {rec.get("session_id"): rec for rec in r.json().get("sessions", [])}

    session_ids = {row["session_id"] for row in results if row.get("session_id")}
    matched = [all_records[sid] for sid in session_ids if sid in all_records]

    if not matched:
        print("\n(No benchmark telemetry found yet for these sessions -- it's written once each audit fully")
        print(" finishes, so this can be empty if any runs were still in progress or failed early.)")
        return

    print("\n=== PER-USER DETAIL ===")
    totals = {"files": 0, "size_mb": 0.0, "chars": 0, "controls": 0, "compliant": 0,
              "non_compliant": 0, "out_of_scope": 0, "tokens": 0, "latency_sec": 0.0}
    for rec in matched:
        cpu_cores = rec.get("cpu_cores", "?")
        files = rec.get("files_count", 0)
        size_mb = rec.get("file_size_mb", 0.0)
        chars = rec.get("extracted_text_chars", 0)
        controls = rec.get("controls_audited_count", 0)
        compliant = rec.get("compliant_count", 0)
        non_compliant = rec.get("non_compliant_count", 0)
        out_of_scope = rec.get("out_of_scope_count", 0)
        tokens = rec.get("total_tokens", 0)
        latency = rec.get("total_latency_seconds", 0.0)
        avg_latency = rec.get("avg_latency_per_control_sec", 0.0)

        print(f"  {rec.get('auditor_username', '?')} [{rec.get('session_id', '')[:12]}...]")
        print(f"    Files: {files}  |  Total size: {size_mb:.2f} MB  |  Extracted chars: {chars:,}")
        print(f"    Controls run: {controls}  |  Compliant: {compliant}  |  Non-compliant: {non_compliant}  |  Out-of-scope: {out_of_scope}")
        print(f"    Tokens: {tokens:,}  |  Total latency: {latency:.1f}s  |  Avg/control: {avg_latency:.1f}s  |  CPU cores (host): {cpu_cores}")

        totals["files"] += files
        totals["size_mb"] += size_mb
        totals["chars"] += chars
        totals["controls"] += controls
        totals["compliant"] += compliant
        totals["non_compliant"] += non_compliant
        totals["out_of_scope"] += out_of_scope
        totals["tokens"] += tokens
        totals["latency_sec"] += latency

    n = len(matched)
    print(f"\n=== AGGREGATE ACROSS {n} SESSIONS ===")
    print(f"  Total files uploaded: {totals['files']}  |  Total size: {totals['size_mb']:.2f} MB  |  Total extracted chars: {totals['chars']:,}")
    print(f"  Total controls audited: {totals['controls']}  |  Total compliant: {totals['compliant']}  |  Total non-compliant: {totals['non_compliant']}  |  Total out-of-scope: {totals['out_of_scope']}")
    print(f"  Total tokens consumed: {totals['tokens']:,}  |  Sum of per-session latency: {totals['latency_sec']:.1f}s  |  Avg latency/session: {totals['latency_sec']/n:.1f}s")
    print(f"\n  NOTE: live CPU%/RAM% utilization during the run isn't exposed by the API (cpu_cores above is")
    print(f"  just the host's core count, not utilization). For that, run `docker stats` in a separate")
    print(f"  terminal on the Azure VM while this load test is running -- that's the standard, direct way")
    print(f"  to watch per-container CPU/RAM% live during the test.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True, help="e.g. http://20.1.2.3:8000")
    ap.add_argument("--users", type=int, default=5)
    ap.add_argument("--controls", default="64", help="comma-separated control SL numbers, e.g. 64,1,17")
    ap.add_argument("--mode", default="Quick", choices=["Quick", "Deep", "Normal"])
    ap.add_argument("--smoke", action="store_true", help="only test upload concurrency, skip real audits")
    ap.add_argument("--admin-user", default=None, help="existing admin account username, for the Phase 3 detailed report")
    ap.add_argument("--admin-pass", default=None, help="existing admin account password")
    ap.add_argument("--admin-totp-secret", default=None, help="existing admin account's raw base32 TOTP secret (not a live 6-digit code)")
    args = ap.parse_args()

    control_ids = [int(x) for x in args.controls.split(",")]

    print(f"=== Phase 1: provisioning {args.users} test accounts (sequential, rate-limit-safe) ===")
    setup_results, setup_lock = [], threading.Lock()
    for i in range(args.users):
        setup_one_user(args.base_url, i + 1, setup_results, setup_lock)
        time.sleep(0.5)
    if len(setup_results) < args.users:
        print(f"WARNING: only {len(setup_results)}/{args.users} accounts provisioned successfully; continuing with those.")

    print(f"\n=== Phase 2: {len(setup_results)} concurrent users against {args.base_url} ===")
    print(f"Mode: {'SMOKE (no LLM calls)' if args.smoke else f'FULL AUDIT (mode={args.mode}, controls={control_ids})'}\n")

    results, lock = [], threading.Lock()
    t_start = time.time()
    threads = []
    for user in setup_results:
        th = threading.Thread(target=run_one_user_load, args=(args.base_url, user, control_ids, args.mode, args.smoke, results, lock))
        threads.append(th)
        th.start()
    for th in threads:
        th.join()

    elapsed = time.time() - t_start
    ok = sum(1 for r in results if r["ok"])
    print(f"\n=== SUMMARY ===")
    print(f"{ok}/{len(results)} users succeeded, concurrent phase wall time {elapsed:.1f}s")
    for r in results:
        if not r["ok"]:
            print(f"  FAILED: {r['user']} -- {r['detail']}")

    if not args.smoke:
        fetch_detailed_report(args.base_url, results, args.admin_user, args.admin_pass, args.admin_totp_secret)


if __name__ == "__main__":
    main()
