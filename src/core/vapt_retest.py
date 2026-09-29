# -*- coding: utf-8 -*-
"""A VAPT retest: the same session scanned again, compared with what it found.

WHY THIS EXISTS

A client fixes some of the vulnerabilities from the first scan and the auditor
uploads the retest into the same session. The tool only ever added: a second
run re-read every file, so each fixed vulnerability came back from the first
scan's file, still "open", and a retest report that marked a row Closed was
dropped as a duplicate of the open one. Nothing said what had changed.

Each scan of a session is now a version (v1, v2, ...). A retest scans only the
files added since the last version and compares:

  found again                                    -> Still open
  fixed earlier, found again                     -> Reopened
  not found, and its host WAS scanned this time  -> Fixed   (status Closed)
  reported Closed by the retest report           -> Fixed   (status Closed)
  not found, its host was NOT in this scan       -> Not retested (stays open)
  in this scan only                              -> New

THE RULE THAT KEEPS IT HONEST

Missing from a scan is not proof of a fix. The retest may have covered only
some hosts, or a different tool may have been used. A vulnerability is called
Fixed only when every host it names appears in the retest -- otherwise it is
Not retested and stays open. A host is "in the retest" when a finding of the
retest (informational ones included) names it; a host that came back entirely
clean therefore reads Not retested, the safe side: an auditor can close it by
hand, whereas a false Fixed would drop a real vulnerability from the report.

Matching is by the parser's own identity (dedup_key: issue + target), then --
for the same finding written differently by another export format -- by the
same title at the same location, or the same CVEs at the same location. Never
by title and host alone: an XSS fixed on /search/3 and a new one on /search/5
are two findings, and pairing them would hide the new one.

Pure functions only; bg_worker applies the plan and the API reads it back.
"""
import json
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

from src.core.finding_status import WORKFLOW_ONLY_STATUSES, normalise_status

# The finding's standing after the latest version (Finding.retest_status).
STILL_OPEN = "still_open"
FIXED = "fixed"
NEW = "new"
NOT_RETESTED = "not_retested"
REOPENED = "reopened"
RETEST_STATES = (STILL_OPEN, FIXED, NEW, NOT_RETESTED, REOPENED)

# What one version's scan said about a finding (an entry of its history).
FOUND = "found"
NOT_FOUND = "not_found"
NOT_SCANNED = "not_scanned"
REPORTED_CLOSED = "reported_closed"

# Targets that name no system (see vapt_suppression._PLACEHOLDER_TARGETS).
_PLACEHOLDERS = frozenset((
    "", "web application endpoint", "n/a", "na", "none", "unknown", "localhost",
    "target", "host", "-", "not recorded", "scoped target systems",
    "target scope evaluated",
))

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOTTED_HOST_RE = re.compile(r"^(?:%s|%s(?:\.%s)+)$" % (_IPV4, _LABEL, _LABEL))
_SINGLE_LABEL_RE = re.compile(r"^%s$" % _LABEL)
_IPV6_RE = re.compile(r"^[0-9a-f]*:[0-9a-f:]+$")


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ── identity helpers ─────────────────────────────────────────────────────────

def hosts_of(target):
    """The hosts or IP addresses a finding's target names, lower-cased.

    "https://shop.test/cart [id]" -> {"shop.test"}; "10.0.0.5:443/tcp (www)" ->
    {"10.0.0.5"}; "10.0.0.5 / web01:443" -> {"10.0.0.5", "web01"}; a comma list
    -> each host; a placeholder ("Not recorded") -> nothing.
    """
    t = str(target or "").strip()
    if t.lower() in _PLACEHOLDERS:
        return set()
    t = re.sub(r"\[[^\]]*\]", " ", t) if "://" in t or " [" in t else t   # "[request body]"
    t = re.sub(r"\([^)]*\)", " ", t)                                     # "(www)"
    hosts = set()
    for part in re.split(r"[,;\s]+", t):
        p = part.strip().strip(".").lower()
        if not p or p == "/":
            continue
        with_port = False
        if "://" in p:
            try:
                h = urlsplit(p).hostname or ""
            except ValueError:
                h = ""
            with_port = True
        elif p.startswith("["):                        # [v6]:port
            h = p[1:p.index("]")] if "]" in p else p.strip("[")
            with_port = True
        else:
            h = p.split("/", 1)[0]
            if h.count(":") == 1:                      # host:port
                h, port = h.split(":", 1)
                with_port = port.isdigit()
        h = h.strip("[]").rstrip(".")
        if not h or h in _PLACEHOLDERS:
            continue
        if _DOTTED_HOST_RE.match(h) or _IPV6_RE.match(h) or (with_port and _SINGLE_LABEL_RE.match(h)):
            hosts.add(h)
    return hosts


def location_key(target):
    """The target, normalised enough that two export formats of one scan agree:
    no scheme, no default web port, no "/tcp", no trailing service name.
    Parameter notes ("[category parameter]") stay -- they tell findings apart."""
    t = re.sub(r"\s+", " ", str(target or "").strip().lower())
    if t in _PLACEHOLDERS:
        return ""
    t = re.sub(r"\s*\([a-z0-9_ .-]*\)\s*$", "", t)               # "(www)"
    had_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", t))
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = re.sub(r"/(?:tcp|udp|sctp)\b", "", t)
    # A web URL's default port, whether or not the scheme was written. A
    # network target's port ("10.0.0.5:443") has no path after it and stays.
    t = re.sub(r"^([^/:\s]+):(?:80|443)(?=/)", r"\1", t)
    if had_scheme:
        t = re.sub(r"^([^/:\s]+):(?:80|443)$", r"\1", t)
    t = re.sub(r"/(?=\s|$)", "", t)                               # trailing slash
    return t.strip()


def norm_title(title):
    t = re.sub(r"\s+", " ", str(title or "").strip().lower())
    return re.sub(r"[\s:\-\u2013\u2014.]+$", "", t)


# A location written at the end of a title: "SQL injection (/catalog/filter
# [category parameter])", "... (https://shop.test/cart)". A plain parenthesis
# -- "(SWEET32)" -- is part of the name and stays.
_TITLE_LOCATION_RE = re.compile(r"\s*\(((?:[a-z][a-z0-9+.-]*://|/)[^()]*)\)\s*$", re.I)


def split_title(title):
    """(issue name, location written into the title or "")."""
    t = str(title or "").strip()
    m = _TITLE_LOCATION_RE.search(t)
    return (t[:m.start()].strip(), m.group(1).strip()) if m else (t, "")


def _location_parts(text):
    """(host, path, parameter note) of a target or a title's location."""
    t = re.sub(r"\s+", " ", str(text or "").strip().lower())
    if t in _PLACEHOLDERS:
        return "", "", ""
    note = ""
    m = re.search(r"\[([^\]]*)\]\s*$", t)
    if m:
        note, t = m.group(1).strip(), t[:m.start()].strip()
    t = re.sub(r"\s*\([a-z0-9_ .-]*\)\s*$", "", t)                # "(www)"
    had_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", t))
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = re.sub(r"/(?:tcp|udp|sctp)\b", "", t)
    if t.startswith("/"):
        host, path = "", t
    elif "/" in t:
        host, path = t.split("/", 1)
        path = "/" + path
    else:
        host, path = t, ""
    if path or had_scheme:
        host = re.sub(r":(?:80|443)$", "", host)                   # a web URL's default port
    path = path.rstrip("/")
    return (host if host not in _PLACEHOLDERS else ""), path, note


def split_locations(target):
    """The places a target names: "A:445/tcp (cifs), B:445/tcp (cifs)" is two.
    A list is split only when every part names a host; anything else is one
    place (a label with hosts after it, or a URL with a comma in it)."""
    t = str(target or "").strip()
    parts = [x.strip() for x in re.split(r"\s*[,;]\s*", t) if x.strip()]
    if len(parts) > 1 and all(hosts_of(x) for x in parts):
        return parts
    return [t]


def issue_and_location(title, target):
    """(issue name, host, canonical location) of a finding.

    Export formats split one fact differently: the PortSwigger PDF writes
    "SQL injection (https://shop/catalog/filter [category parameter])" with
    the same URL and parameter as the target; the HTML report writes
    "SQL injection (/catalog/filter [category parameter])" with a target of
    just "https://shop/catalog/filter". Both come out ("sql injection",
    "shop", "shop/catalog/filter [category parameter]").
    """
    name, title_loc = split_title(title)
    h1, p1, n1 = _location_parts(target)
    h2, p2, n2 = _location_parts(title_loc) if title_loc else ("", "", "")
    host = h1 or h2
    path = p1 if len(p1) >= len(p2) else p2
    note = n1 or n2
    if not host:
        return norm_title(name), "", ""
    return norm_title(name), host, host + path + (" [%s]" % note if note else "")


def cve_set(cves):
    if isinstance(cves, str):
        cves = cves.split(",")
    return frozenset(str(c).strip().upper() for c in (cves or [])
                     if str(c).strip().upper().startswith("CVE-"))


def is_closed(status, final_result=None, report_status=None):
    st = normalise_status(status)
    if st == "CLOSED" or str(report_status or "").strip().lower() == "closed":
        return True
    return st in ("ACCEPTED", "CONFIRMED") and normalise_status(final_result) == "CLOSED"


def is_workflow_only(status):
    """Rejected, dismissed, false positive, out of scope: not a vulnerability
    the report carries, so a retest neither counts nor changes it."""
    return normalise_status(status) in WORKFLOW_ONLY_STATUSES


def reopened_status(severity):
    return "Informational" if "INFO" in str(severity or "").upper() else "Non-Compliant"


# ── the comparison ───────────────────────────────────────────────────────────

def _loose_keys(identity, cves):
    name, _host, loc = identity
    if not loc:
        return []
    keys = [("issue", name, loc)]
    if cves:
        keys.append(("cve", cves, loc))
    return keys


def compare(previous, current, round_no, date=None):
    """Compare this version's findings with the session's earlier ones.

    previous: the saved findings, as dicts with id, dedup_key, title, target,
      cve_list, status, final_result, severity, first_round, retest_status,
      history (a list, possibly empty).
    current: this version's findings as the worker built them (f_dict: title,
      target, cve_list, status, report_status, dedup_key, severity).

    Returns {"updates": {id: change}, "new": [current dicts], "counts": {...},
    "hosts": [...]}. Each change holds retest_status, history (the full list,
    with this version's entry appended), and status / final_result when they
    change. Each new dict gains retest_status, first_round and history.
    """
    date = date or today()
    scanned = set()
    for c in current:
        scanned |= hosts_of(c.get("target"))

    prev = [p for p in previous if not is_workflow_only(p.get("status"))]
    # prev id -> the current findings it was found as (one, or one per host).
    matches = {p["id"]: set() for p in prev}
    matched_cur = set()

    # 1. The parser's own identity, finding to finding.
    by_key = {}
    for i, c in enumerate(current):
        if c.get("dedup_key"):
            by_key.setdefault(c["dedup_key"], []).append(i)
    for p in prev:
        for i in by_key.get(p.get("dedup_key") or None, []):
            if i not in matched_cur:
                matches[p["id"]].add(i)
                matched_cur.add(i)
                break

    # 2. Place by place. An export can list one finding with every host it was
    # seen on (Nessus by plugin: "A:445/tcp, B:445/tcp") where another lists it
    # once per host (Nessus by host). Each host of a finding is an instance and
    # instances pair one to one: the same issue, or the same CVEs, at the same
    # canonical location.
    def _instances(f):
        return [issue_and_location(f.get("title"), loc) for loc in split_locations(f.get("target"))]

    cur_inst = [(i, ident, cve_set(c.get("cve_list")))
                for i, c in enumerate(current) if i not in matched_cur for ident in _instances(c)]
    prev_inst = [(p["id"], ident, cve_set(p.get("cve_list")))
                 for p in prev if not matches[p["id"]] for ident in _instances(p)]
    used_cur, used_prev = set(), set()
    loose = {}
    for n, (i, ident, cves) in enumerate(cur_inst):
        for k in _loose_keys(ident, cves):
            loose.setdefault(k, []).append(n)
    for m, (pid, ident, cves) in enumerate(prev_inst):
        for k in _loose_keys(ident, cves):
            free = [n for n in loose.get(k, []) if n not in used_cur]
            if free:
                used_cur.add(free[0])
                used_prev.add(m)
                matches[pid].add(cur_inst[free[0]][0])
                break

    # 3. Last: the same issue on the same host, when one side does not say where
    # on the host (no path, no parameter) and the pair is the only one of its
    # kind on both sides. Two findings that both name a place, and name
    # different places (/search/3, /search/5), are never paired.
    by_issue_host = {}
    for n, (i, (name, host, loc), _c) in enumerate(cur_inst):
        if n not in used_cur and host:
            by_issue_host.setdefault((name, host), {"cur": [], "prev": []})["cur"].append(n)
    for m, (pid, (name, host, loc), _c) in enumerate(prev_inst):
        if m not in used_prev and host:
            by_issue_host.setdefault((name, host), {"cur": [], "prev": []})["prev"].append(m)
    for pair in by_issue_host.values():
        if len(pair["cur"]) == 1 and len(pair["prev"]) == 1:
            n, m = pair["cur"][0], pair["prev"][0]
            (_, c_host, c_loc), (_, p_host, p_loc) = cur_inst[n][1], prev_inst[m][1]
            if c_loc == c_host or p_loc == p_host:
                used_cur.add(n)
                used_prev.add(m)
                matches[prev_inst[m][0]].add(cur_inst[n][0])
    matched_cur |= {cur_inst[n][0] for n in used_cur}

    updates = {}
    for p in prev:
        was_closed = is_closed(p.get("status"), p.get("final_result"))
        history = list(p.get("history") or [])
        if not history:
            # The version it was found in, as it stood before this retest.
            history.append({"round": int(p.get("first_round") or 1),
                            "state": REPORTED_CLOSED if was_closed else FOUND,
                            "status": p.get("status") or "", "date": p.get("first_date") or ""})
        change = {"status": None, "final_result": None}
        found_as = [current[i] for i in sorted(matches[p["id"]])]
        if found_as:
            # Open on any host it was found on is open.
            if all(is_closed(c.get("status"), None, c.get("report_status")) for c in found_as):
                state = REPORTED_CLOSED
                retest = p.get("retest_status") if was_closed else FIXED
                if not was_closed:
                    change.update(status="Closed", final_result="CLOSED")
            elif was_closed:
                state, retest = FOUND, REOPENED
                change.update(status=reopened_status(p.get("severity")), final_result="")
            else:
                state, retest = FOUND, STILL_OPEN
        else:
            hosts = hosts_of(p.get("target"))
            if hosts and hosts <= scanned:
                state = NOT_FOUND
                if was_closed:
                    retest = p.get("retest_status")
                else:
                    retest = FIXED
                    change.update(status="Closed", final_result="CLOSED")
            else:
                state = NOT_SCANNED
                retest = p.get("retest_status") if was_closed else NOT_RETESTED
        resulting_status = change["status"] or p.get("status") or ""
        history.append({"round": int(round_no), "state": state,
                        "status": resulting_status, "date": date})
        change.update(retest_status=retest, history=history)
        updates[p["id"]] = change

    new = []
    for i, c in enumerate(current):
        if i in matched_cur:
            continue
        closed = is_closed(c.get("status"), None, c.get("report_status"))
        c["retest_status"] = None if closed else NEW
        c["first_round"] = int(round_no)
        c["history"] = [{"round": int(round_no), "state": REPORTED_CLOSED if closed else FOUND,
                         "status": c.get("status") or "", "date": date}]
        new.append(c)

    counts = Counter(u["retest_status"] for u in updates.values() if u["retest_status"])
    counts.update(c["retest_status"] for c in new if c["retest_status"])
    return {
        "updates": updates,
        "new": new,
        "counts": {s: counts.get(s, 0) for s in RETEST_STATES},
        "hosts": sorted(scanned),
        "found": len(current),
    }


# ── versions of a session ────────────────────────────────────────────────────

def load_rounds(raw):
    try:
        data = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []
    return [r for r in data if isinstance(r, dict) and r.get("round")] if isinstance(data, list) else []


def scanned_files(rounds):
    """(evidence ids, file names) the earlier versions scanned.

    Names come only from a version recorded without ids (one reconstructed for
    a session scanned before versions existed). Anywhere else a name is not
    enough: a retest export often has the first scan's file name.
    """
    ids, names = set(), set()
    for r in rounds:
        r_ids = [int(x) for x in (r.get("file_ids") or []) if str(x).isdigit()]
        if r_ids:
            ids.update(r_ids)
        else:
            names.update(str(n) for n in (r.get("files") or []) if n)
    return ids, names


def round_entry(round_no, files, file_ids, hosts, found, counts=None, date=None):
    entry = {"round": int(round_no), "date": date or today(), "files": sorted(set(files)),
             "file_ids": sorted(set(int(i) for i in file_ids if str(i).isdigit())),
             "hosts": sorted(set(hosts)), "found": int(found)}
    if counts is not None:
        entry["counts"] = counts
    return entry


def legacy_first_round(rows, created_at=None):
    """Version 1 for a session scanned before versions were recorded: its files
    are the ones its findings name, its hosts the ones they name."""
    files, hosts = set(), set()
    for r in rows:
        files.update(s.strip() for s in str(r.get("source_files") or "").split(",") if s.strip())
        hosts |= hosts_of(r.get("target"))
    date = created_at.strftime("%Y-%m-%d") if hasattr(created_at, "strftime") else today()
    return round_entry(1, files, [], hosts, len(rows), date=date)


def target_of(target, evidence_snippet=""):
    """The saved target, or the "Target Host:" line of the proof (older rows)."""
    if target and str(target).strip():
        return str(target).strip()
    m = re.search(r"(?m)^Target Host:\s*(.+)$", str(evidence_snippet or ""))
    return m.group(1).strip() if m else ""


def parse_history(raw):
    try:
        data = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []
    return [h for h in data if isinstance(h, dict)] if isinstance(data, list) else []


def status_as_of(history, round_no, current_status):
    """A finding's status as version `round_no` recorded it (its latest entry at
    or before that version); the current status when it has no history."""
    best = None
    for h in history or []:
        try:
            r = int(h.get("round") or 0)
        except (TypeError, ValueError):
            continue
        if r <= int(round_no) and (best is None or r >= best[0]):
            best = (r, h.get("status"))
    return best[1] if best and best[1] else current_status


def view_as_of_round(findings, round_no):
    """The findings as version `round_no` stood: those found by then, each with
    the status that version gave it. For showing or exporting an earlier
    version exactly as it was reported."""
    out = []
    for f in findings:
        first = int(f.get("first_round") or 1)
        if first > int(round_no):
            continue
        hist = f.get("retest_history")
        hist = parse_history(hist) if isinstance(hist, str) else (hist or [])
        g = dict(f)
        g["status"] = status_as_of(hist, round_no, f.get("status"))
        if str(g["status"]).strip().lower() != "closed" and str(f.get("final_result") or "").upper() == "CLOSED":
            g["final_result"] = ""
        elif str(g["status"]).strip().lower() == "closed":
            g["final_result"] = "CLOSED"
        out.append(g)
    return out
