# -*- coding: utf-8 -*-
"""Check a new app image against Postgres: a fresh install, and an upgrade of
a database an earlier version created -- before make_update.bat packages it.

    python scripts/upgrade_e2e_check.py --image aicyberauditbox-app:1.2.4 --new-version 1.2.4

WHY THIS EXISTS

1.2.3 passed every check and then saved 0 findings at a customer. Their
database was created by 1.1, where findings.confidence was INTEGER; the new
code writes "Firm" / "Certain" there, and Postgres refused every save. The
image check ran its sample scan on SQLite, which ignores column types, and on
an empty new database -- never Postgres, never an upgrade. This runs both, the
way a customer's installation does:

  1. starts a throwaway copy of the customer's database image (the one
     docker-compose.customer.yml names), with its own password and no ports;
  2. for each earlier version (default: the oldest earlier image here and the
     newest one below the new version; UPGRADE_FROM="1.1 1.2.3" overrides),
     builds the schema with THAT image and saves a finding with it;
  3. starts the NEW image on it (its startup migrations run), and checks that
     the earlier finding survived, that a sample scan through the real worker
     is SAVED in Postgres, and that every column's type in all three databases
     accepts what the code writes;
  4. does step 3 on an empty database too (a fresh install).

Every container is removed afterwards. Exit code 0 when all pass, 1 otherwise.
Output is plain ASCII.

With no earlier image on this machine the upgrade cannot be checked, and that
fails the check: load the image customers run now (docker load -i ...), or set
UPGRADE_FROM=none to package without it, knowingly.
"""
import os
import re
import secrets
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DB_PORT = "15234"


# ---------------------------------------------------------------- pure helpers

def version_tuple(tag):
    """'1.2.3' -> (1, 2, 3); None when the tag is not a plain version."""
    if not re.fullmatch(r"\d+(\.\d+)*", tag or ""):
        return None
    return tuple(int(p) for p in tag.split("."))


def pick_baselines(tags, new_version):
    """The earlier versions to upgrade from: the oldest and the newest tag of
    the same major line that are older than new_version."""
    new = version_tuple(new_version)
    if not new:
        return []
    older = sorted((version_tuple(t), t) for t in tags
                   if version_tuple(t) and version_tuple(t)[0] == new[0] and version_tuple(t) < new)
    if not older:
        return []
    picked = [older[0][1], older[-1][1]]
    return list(dict.fromkeys(picked))


def type_family(sa_type):
    """The kind of value a column holds, for comparing model and database."""
    from sqlalchemy import types as t
    if isinstance(sa_type, t.Boolean):
        return "bool"
    if isinstance(sa_type, t.Integer):
        return "int"
    if isinstance(sa_type, t.Numeric):      # Float is a Numeric
        return "num"
    if isinstance(sa_type, (t.DateTime, t.Date)):
        return "datetime"
    if isinstance(sa_type, t.String):       # VARCHAR, TEXT, CHAR
        return "text"
    return None                             # JSON, vector, binary: not compared


def write_compatible(model_family, db_family):
    """Whether the database column accepts what the code writes. Any value can
    be stored in a text column, and an int in a numeric one; the rest must
    match. (Text into an INTEGER column is the 1.2.3 failure.)"""
    if model_family is None or db_family is None or model_family == db_family:
        return True
    if db_family == "text":
        return True
    return model_family == "int" and db_family == "num"


# ---------------------------------------------------------- inside containers

NESSUS = ("<?xml version=\"1.0\" ?><NessusClientData_v2><Report name=\"upgrade\"><ReportHost name=\"10.0.0.5\">"
          "<HostProperties><tag name=\"host-ip\">10.0.0.5</tag></HostProperties>"
          "<ReportItem port=\"443\" svc_name=\"www\" protocol=\"tcp\" severity=\"3\" pluginID=\"42873\" "
          "pluginName=\"SSL Medium Strength Cipher Suites Supported (SWEET32)\" pluginFamily=\"General\">"
          "<cve>CVE-2016-2183</cve><cvss3_base_score>7.5</cvss3_base_score><risk_factor>High</risk_factor>"
          "<description>Medium strength ciphers are supported.</description>"
          "<solution>Disable 3DES.</solution><plugin_output>DES-CBC3-SHA</plugin_output>"
          "</ReportItem></ReportHost></Report></NessusClientData_v2>")
TRACKER = ("Vulnerability,Severity,Host,Description,Recommendation,Status,CVE\n"
           "SQL Injection in login form,Critical,https://portal.test/login,Injectable.,Use parameterised queries.,Open,\n"
           "Missing HSTS header,Low,https://portal.test/,HSTS not set.,Add the HSTS header.,Closed,\n")
OLD_SESSION = "upgrade-check-earlier-version"


def _db():
    sys.path.insert(0, "/app")
    os.chdir("/app")
    from src.db import database as D
    D.init_db()
    return D


def _master(D):
    import contextlib
    fm = getattr(D, "force_master", None)
    return fm() if fm else contextlib.nullcontext()


def in_container_old():
    """With the EARLIER image: build its schema and save one finding."""
    D = _db()
    with _master(D):
        s = D.SessionLocal()
        rep = D.AuditReport(session_id=OLD_SESSION, session_title=OLD_SESSION, framework="VAPT")
        s.add(rep)
        s.commit()
        s.add(D.Finding(report_id=rep.id, control_id="UPG-1", control_name="Saved by the earlier version",
                        severity="LOW", status="Non-Compliant"))
        s.commit()
        s.close()
    print("UPG ok earlier version built its schema and saved a finding")
    return 0


def in_container_new(upgraded):
    """With the NEW image: migrations ran at init; now prove it works."""
    D = _db()
    failures = []

    if upgraded:
        with _master(D):
            s = D.SessionLocal()
            rep = s.query(D.AuditReport).filter(D.AuditReport.session_id == OLD_SESSION).first()
            n = s.query(D.Finding).filter(D.Finding.report_id == rep.id).count() if rep else 0
            s.close()
        if n == 1:
            print("UPG ok the earlier version's finding survived the upgrade")
        else:
            failures.append("the earlier version's finding is gone after the upgrade (%d found)" % n)

    import src.core.bg_worker as worker
    sid = "upgrade-check-new-scan"
    with _master(D):
        s = D.SessionLocal()
        s.add(D.AuditReport(session_id=sid, session_title=sid, framework="VAPT"))
        s.commit()
        s.close()
    worker._run_fast_technical_vapt_bg(
        sid, [{"name": "scan.nessus", "bytes": NESSUS.encode(), "text": None},
              {"name": "tracker.csv", "bytes": TRACKER.encode(), "text": None}],
        selected_sls=[], framework="VAPT", ai_recommendations=False)
    with worker._bg_lock:
        err = (worker._bg_results.get(sid) or {}).get("error")
    with _master(D):
        s = D.SessionLocal()
        rep = s.query(D.AuditReport).filter(D.AuditReport.session_id == sid).first()
        saved = s.query(D.Finding).filter(D.Finding.report_id == rep.id).all()
        got = sorted((f.control_name, f.status) for f in saved)
        # The value that broke 1.2.3: text in `confidence`. At least one sample
        # finding carries it, so the check writes it rather than skipping it.
        confidences = sorted({f.confidence for f in saved if f.confidence})
        s.close()
    want = sorted([("SSL Medium Strength Cipher Suites Supported (SWEET32)", "Non-Compliant"),
                   ("SQL Injection in login form", "Non-Compliant"),
                   ("Missing HSTS header", "Closed")])
    if got == want and confidences and not err:
        print("UPG ok a sample scan was saved in Postgres (3 findings as the sources state them;"
              " confidence %s)" % "/".join(confidences))
    else:
        failures.append("the sample scan saved %d finding(s) %r, confidence %r; worker error: %s"
                        % (len(got), got, confidences, err))

    from sqlalchemy import inspect
    for label, eng in (("master", D.engine_master), ("slave1", D.engine_slave1), ("slave2", D.engine_slave2)):
        if eng is None:
            continue
        insp = inspect(eng)
        bad = []
        for table in D.Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                bad.append("%s: table missing" % table.name)
                continue
            db_cols = {c["name"]: c["type"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in db_cols:
                    bad.append("%s.%s: column missing" % (table.name, col.name))
                    continue
                mf, dbf = type_family(col.type), type_family(db_cols[col.name])
                if not write_compatible(mf, dbf):
                    bad.append("%s.%s: code writes %s, database column is %s"
                               % (table.name, col.name, mf, db_cols[col.name]))
        if bad:
            failures.append("%s schema: %s" % (label, "; ".join(bad[:10])))
        else:
            print("UPG ok %s: every column's type accepts what the code writes" % label)

    for f in failures:
        print("UPG FAIL " + f)
    return 1 if failures else 0


# --------------------------------------------------------------- on the host

def _run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def _db_image():
    compose = open(os.path.join(REPO, "docker-compose.customer.yml"), encoding="utf-8").read()
    m = re.search(r"image:\s*(\S*shakthidb\S*)", compose)
    return m.group(1) if m else None


def _image_exists(ref):
    return _run(["docker", "image", "inspect", ref]).returncode == 0


def _start_db(image):
    name = "auditbox_upgcheck_%s" % secrets.token_hex(4)
    pw = secrets.token_hex(16)
    r = _run(["docker", "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=" + pw,
              image, "postgres", "-p", DB_PORT])
    if r.returncode != 0:
        raise RuntimeError("could not start %s: %s" % (image, r.stderr.strip()))
    deadline = time.time() + 120
    while time.time() < deadline:
        r = _run(["docker", "logs", name])
        if "init process complete" in (r.stdout or "") + (r.stderr or ""):
            ok = _run(["docker", "exec", name, "psql", "-p", DB_PORT, "-U", "postgres", "-Atc", "select 1"])
            if ok.stdout.strip() == "1":
                return name, pw
        time.sleep(1)
    _run(["docker", "rm", "-f", name])
    raise RuntimeError("the database container did not become ready")


def _in_app(db, pw, image, mode, src=None):
    args = ["docker", "run", "--rm", "--network", "container:" + db,
            "-e", "POSTGRES_PASSWORD=" + pw, "-e", "REQUIRE_POSTGRES=1",
            "-v", "%s:/tmp/upgrade_e2e_check.py:ro" % os.path.abspath(__file__)]
    if src:
        args += ["-v", "%s:/app/src:ro" % os.path.abspath(src)]
    args += ["--entrypoint", "python", image, "/tmp/upgrade_e2e_check.py", "--in-container", mode]
    r = _run(args, timeout=900)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if line.startswith("UPG "):
            print("      " + line[4:])
    if r.returncode != 0:
        print("      --- last lines from %s ---" % image)
        for line in [l for l in out.splitlines() if not l.startswith("UPG ")][-25:]:
            print("      " + line[:300].encode("ascii", "replace").decode())
    return r.returncode == 0


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="the new app image, e.g. aicyberauditbox-app:1.2.4")
    ap.add_argument("--new-version", help="its version; defaults to the image tag")
    ap.add_argument("--src", help="mount this src/ over the image's (to check code before a build)")
    a = ap.parse_args(argv)
    new_version = a.new_version or a.image.rsplit(":", 1)[-1]

    db_image = _db_image()
    if not db_image or not _image_exists(db_image):
        print("  [X] the customer database image (%s) is not on this machine" % db_image)
        return 1
    repo = a.image.rsplit(":", 1)[0]
    env = os.environ.get("UPGRADE_FROM", "").strip()
    if env.lower() == "none":
        baselines = []
        print("  [!] UPGRADE_FROM=none -- upgrading an existing database is NOT checked")
    elif env:
        baselines = env.split()
    else:
        tags = _run(["docker", "images", repo, "--format", "{{.Tag}}"]).stdout.split()
        baselines = pick_baselines(tags, new_version)
        if not baselines:
            print("  [X] no earlier %s image on this machine to upgrade from, so the upgrade of a"
                  " customer database cannot be checked. Load the image customers run now"
                  " (docker load -i ...), or set UPGRADE_FROM=none to package without this check." % repo)
            return 1

    print("")
    print("  Postgres check  (database image %s, new image %s)" % (db_image, a.image))
    results = []
    for base in [None] + baselines:
        label = "fresh install" if base is None else "upgrade from %s" % base
        print("    %s" % label)
        db = None
        try:
            db, pw = _start_db(db_image)
            ok = True
            if base is not None:
                if not _image_exists("%s:%s" % (repo, base)):
                    print("      [X] image %s:%s not found" % (repo, base))
                    ok = False
                else:
                    ok = _in_app(db, pw, "%s:%s" % (repo, base), "old")
            if ok:
                ok = _in_app(db, pw, a.image, "new-upgraded" if base else "new-fresh", a.src)
        except Exception as e:                       # noqa: BLE001 -- report, never hang the build
            print("      [X] %s" % e)
            ok = False
        finally:
            if db:
                _run(["docker", "rm", "-f", db])
        results.append((label, ok))

    print("")
    for label, ok in results:
        print("    [%s] %s" % ("ok" if ok else "X ", label))
    failed = [r for r in results if not r[1]]
    print("")
    print("  %s" % ("POSTGRES CHECK PASSED" if not failed else "POSTGRES CHECK FAILED"))
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--in-container":
        mode = sys.argv[2]
        sys.exit(in_container_old() if mode == "old" else in_container_new(upgraded=(mode == "new-upgraded")))
    sys.exit(main(sys.argv[1:]))
