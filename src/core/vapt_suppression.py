# -*- coding: utf-8 -*-
"""Remember a VAPT finding the auditor threw out, and carry that decision forward.

WHY THIS EXISTS

Rejecting a false positive in a VAPT session changed nothing about the next scan.
The knowledge loop that learns from rejections is wired into the ISO path only
(audit_graph, retrieval), and _run_fast_technical_vapt_bg never reads auditor
feedback -- so re-scanning the same target reported the same false positive
again, and the auditor dismissed it again, every engagement.

HOW IT DECIDES, AND WHY IT IS CAREFUL

Identity is the parser's own dedup_key: CVE, plugin id or tool + title, joined to
the TARGET. The same issue on another host is a different key and is never
suppressed by this one.

That only holds while the target is specific. A finding recovered from a
screenshot is given the placeholder target "Web Application Endpoint", so every
screenshot XSS on every application shares one key. Suppressing on that key would
mean rejecting one screenshot's XSS silently hid every screenshot XSS after it --
a real vulnerability hidden, which is worse than any false positive. Findings
whose target is a placeholder are therefore never suppressed.

A suppressed finding is not dropped. It is still saved and still listed, marked
with the status the auditor chose and a note saying who decided it and when. The
report leaves it out by the same rule as any other rejected finding, and restoring
it clears the suppression so later scans report it again. Nothing disappears
without a record an auditor can see and undo.
"""
from datetime import datetime, timezone

from src.core.finding_status import WORKFLOW_ONLY_STATUSES, normalise_status

# Targets that say where a finding was, without saying which system. A key built
# on one of these identifies a CLASS of finding, not an instance of it.
_PLACEHOLDER_TARGETS = frozenset((
    "", "web application endpoint", "n/a", "na", "none", "unknown",
    "localhost", "target", "host", "-",
    # What the parsers write when a report names no host.
    "not recorded", "scoped target systems",
))


def target_of(dedup_key):
    """The target part of a dedup key, lower-cased, or '' if it has none."""
    key = str(dedup_key or "")
    marker = "|target:"
    return key[key.rfind(marker) + len(marker):].strip().lower() if marker in key else ""


def is_suppressible(dedup_key):
    """True when the key names a specific target and so identifies one instance."""
    if not dedup_key:
        return False
    return target_of(dedup_key) not in _PLACEHOLDER_TARGETS


def is_thrown_out(status):
    """Rejected, dismissed, false positive, out of scope, excluded."""
    return normalise_status(status) in WORKFLOW_ONLY_STATUSES


def record(db, dedup_key, status, title="", decided_by="", source_session=""):
    """Remember that this finding was thrown out. Returns True if recorded."""
    from src.db.database import VaptSuppression
    if not is_suppressible(dedup_key) or not is_thrown_out(status):
        return False
    row = db.query(VaptSuppression).filter(VaptSuppression.dedup_key == dedup_key).first()
    if row is None:
        row = VaptSuppression(dedup_key=dedup_key)
        db.add(row)
    row.status = str(status)[:50]
    row.title = (title or "")[:1000]
    row.decided_by = (decided_by or "")[:100]
    row.source_session = (source_session or "")[:100]
    row.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    return True


def clear(db, dedup_key):
    """Forget a suppression -- the auditor has restored the finding."""
    from src.db.database import VaptSuppression
    if not dedup_key:
        return 0
    return db.query(VaptSuppression).filter(VaptSuppression.dedup_key == dedup_key).delete()


def load(db):
    """Every suppression, keyed by dedup_key."""
    from src.db.database import VaptSuppression
    return {r.dedup_key: r for r in db.query(VaptSuppression).all()}


def apply(findings, suppressions):
    """Carry each remembered decision onto this scan's matching findings.

    `findings` are the worker's dicts, changed in place. Returns how many were
    carried forward. A finding is matched only on its exact key, and only when
    that key names a specific target.
    """
    carried = 0
    for f in findings:
        key = f.get("dedup_key")
        if not is_suppressible(key):
            continue
        s = suppressions.get(key)
        if s is None:
            continue
        when = s.created_at.strftime("%d %b %Y") if getattr(s, "created_at", None) else "an earlier scan"
        who = s.decided_by or "an auditor"
        f["status"] = s.status or "Rejected"
        # An auditor made this decision; it is carried, not re-asked. The note is
        # what makes that auditable.
        f["human_verified"] = True
        f["is_saved_to_shakthi"] = True
        f["review_note"] = (
            f"Carried forward: marked '{f['status']}' by {who} on {when}"
            + (f" (session {s.source_session[:8]})" if s.source_session else "")
            + ". It is left out of the report. Restore it to report it again."
        )
        carried += 1
    return carried
