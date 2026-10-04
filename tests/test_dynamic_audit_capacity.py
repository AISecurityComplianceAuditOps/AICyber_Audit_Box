# -*- coding: utf-8 -*-
"""The audit cap must come from the machine, and say what would raise it.

    pytest tests/test_dynamic_audit_capacity.py -v

WHY THIS EXISTS

The appliance is sold on its hardware, so its limits have to follow the
hardware it is given. Two things stopped that being true:

1. A flat ceiling of 16 concurrent audits, written when a machine had about 8
   slots. A customer's 32-core/126GB server sized its AI engine to 49 slots and
   was still admitting 16 audits, with nothing in the product to show the number
   came from a constant rather than from the machine. On 128 cores it admitted
   16 as well.

2. The refusal said "the system is at capacity (limit 16)" -- and nothing else.
   Not why 16, not whether cores or memory were short, not what to add. A
   customer who could have fixed it by adding RAM had no way to learn that.

What replaces the ceiling is NOT "no limit", which is worse. Admitting more
audits than the model server has slots pushes the excess into llama-server's own
queue, which has no size limit: requests wait past their timeout and their
controls come back empty, and an empty control is a missing finding on a
compliance report. The cap is now the lower of what the cores can drive and what
the server actually has, both measured.

THE ONE NUMBER THAT IS STILL A GUESS

Cores-per-audit. Hardware cannot tell us how many cores one audit needs; the
default of 2 comes from a 4-core host where three audits (1.33 cores each) ran
900 seconds and finished nothing. It is a parameter, not a constant, so a
deployment that has load-tested its own hardware can lower it on evidence.
"""
import importlib

import pytest

from src.core.deployment_sizing import (DEFAULT_CORES_PER_AUDIT, audit_capacity,
                                        max_concurrent_audits, size_deployment)


# ── the ceiling is gone ──────────────────────────────────────────────────────

def test_a_big_machine_is_no_longer_capped_at_sixteen():
    """128 cores used to admit 16 audits, the same as 32 cores."""
    assert max_concurrent_audits(128, available_slots=105) == 64
    assert max_concurrent_audits(256, available_slots=200) == 128


def test_the_limit_tracks_the_core_count():
    seen = [max_concurrent_audits(c, available_slots=999) for c in (8, 16, 32, 64, 128)]
    assert seen == [4, 8, 16, 32, 64]
    assert seen == sorted(seen), "the limit must never fall as cores are added"


def test_the_customers_machine_is_unchanged():
    """32 physical cores still gives 16 -- the ceiling was never what bound it.

    Worth pinning: this change must not quietly alter what the shipped server
    admits today. 32 // 2 is 16 with or without a ceiling at 16.
    """
    d = size_deployment(32, 125.64, model_gb=11.8)
    assert d.max_concurrent_audits == 16


# ── slots are a real bound, not decoration ───────────────────────────────────

def test_more_audits_than_slots_are_never_admitted():
    """The excess would queue inside llama-server until requests time out."""
    assert max_concurrent_audits(64, available_slots=20) == 20


def test_slots_bind_on_a_high_core_low_memory_box():
    d = size_deployment(96, 64, model_gb=11.8)
    assert d.max_concurrent_audits <= d.np_slots, "admitted more audits than slots exist"
    assert d.audits_limited_by == "slots"


def test_an_unknown_slot_count_falls_back_to_cores():
    """A server too slow to answer must not refuse every audit.

    None means "could not find out". Read as zero it would compute a limit of
    zero and take the product down on a probe timeout.
    """
    assert max_concurrent_audits(32, available_slots=None) == 16
    assert max_concurrent_audits(32, available_slots=0) == 16


def test_a_tiny_machine_still_gets_the_floor_of_two():
    assert max_concurrent_audits(1, available_slots=1) == 2
    assert max_concurrent_audits(2, available_slots=1) == 2


# ── the customer is told what to buy ─────────────────────────────────────────

def test_the_advice_names_cores_when_cores_bind():
    a = audit_capacity(32, available_slots=49, total_ram_gb=125.64)
    assert a["limited_by"] == "cores"
    assert "more cores raise it" in a["advice"]
    assert "more RAM will not" in a["advice"]
    assert "32 physical core(s)" in a["advice"], "the machine is not described"


def test_the_advice_names_ram_when_memory_is_what_limits_the_slots():
    a = audit_capacity(64, available_slots=20, slots_limited_by="ram", total_ram_gb=64)
    assert a["limited_by"] == "slots"
    assert "more RAM raises it" in a["advice"]


def test_the_advice_is_a_sentence_a_customer_can_act_on():
    """Not a bare number. The old message was 'the system is at capacity (limit 16)'."""
    for cores, slots in ((32, 49), (4, 4), (96, 20)):
        advice = audit_capacity(cores, available_slots=slots)["advice"]
        assert advice.endswith("."), advice
        assert "supports" in advice or "minimum" in advice, advice
        assert str(cores) in advice, "the customer cannot tell which machine this is about"


def test_a_machine_too_small_for_one_audit_says_so_rather_than_refusing_everything():
    a = audit_capacity(1, available_slots=1)
    assert a["limit"] == 2
    assert a["limited_by"] == "floor"
    assert "slowly" in a["advice"]


# ── the operator's own number is still obeyed ────────────────────────────────

def test_cores_per_audit_is_a_parameter_not_a_constant():
    """A deployment that measured its hardware can lower it without a code change."""
    assert max_concurrent_audits(32, available_slots=99, cores_per_audit=1) == 32
    assert max_concurrent_audits(32, available_slots=99, cores_per_audit=4) == 8
    assert DEFAULT_CORES_PER_AUDIT == 2, "the measured default changed; was that intended?"


@pytest.mark.parametrize("cores", [2, 16])
def test_an_explicit_limit_wins_and_says_that_it_did(monkeypatch, cores):
    """The machine is pinned here, not read: at 2 physical cores the advice is
    the floor sentence ("below what one audit needs"), not "supports N", and a
    4-vCPU CI runner is that machine. Both must still describe the hardware."""
    monkeypatch.setenv("MAX_CONCURRENT_AUDITS", "30")
    import src.core.bg_state as bg
    importlib.reload(bg)
    monkeypatch.setattr(bg, "_physical_cores", lambda: cores)
    limit, advice = bg.current_audit_limit()
    assert limit == 30, "an operator's explicit number was overridden"
    assert "pinned to 30" in advice
    assert f"{cores} physical core(s)" in advice, "the machine's own figure is hidden from the operator"
    monkeypatch.delenv("MAX_CONCURRENT_AUDITS")
    importlib.reload(bg)


def test_cores_per_audit_can_be_set_by_an_operator(monkeypatch):
    monkeypatch.setenv("CORES_PER_AUDIT", "1")
    import src.core.bg_state as bg
    importlib.reload(bg)
    assert bg._cores_per_audit() == 1
    monkeypatch.delenv("CORES_PER_AUDIT")
    importlib.reload(bg)


# ── one owner for the arithmetic ─────────────────────────────────────────────

def test_bg_state_does_not_keep_its_own_copy_of_the_formula():
    """It used to. The two agreed, but nothing held them together.

    Nothing outside deployment_sizing called its version, so the figure the
    product enforced and the figure a build log reported could drift apart while
    both looked authoritative -- the same defect shape as the eight exporters
    with their own exclusion lists.
    """
    import io
    import os
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "src", "core", "bg_state.py"), encoding="utf-8").read()
    assert "deployment_sizing" in src, "bg_state no longer delegates the arithmetic"
    assert "min(16," not in src, "the ceiling is back, in a second copy"


def test_the_shipped_limit_and_the_sizing_report_agree():
    """Whatever bg_state admits must be what a build log would have predicted."""
    import src.core.bg_state as bg
    importlib.reload(bg)
    cores = bg._physical_cores()
    assert bg.MAX_CONCURRENT_AUDITS == max_concurrent_audits(
        cores, cores_per_audit=bg._cores_per_audit())


# ── what the refused customer actually reads ─────────────────────────────────

def test_the_refusal_tells_the_customer_what_to_add():
    from src.api.endpoints.audit import _capacity_refusal_detail
    advice = audit_capacity(32, available_slots=49, total_ram_gb=125.64)["advice"]
    msg = _capacity_refusal_detail(16, 16, licensed=False, advice=advice)
    assert "at capacity" in msg, "the refusal itself is gone"
    assert "Please wait" in msg
    assert "more cores raise it" in msg, "the customer is told nothing they can act on"
    assert "126GB" in msg, "the machine is not described"


def test_a_licence_limit_does_not_advise_buying_hardware():
    """More cores would change nothing when the licence is what binds."""
    from src.api.endpoints.audit import _capacity_refusal_detail
    msg = _capacity_refusal_detail(5, 5, licensed=True, advice="buy more CPU")
    assert "licensed for 5" in msg
    assert "buy more CPU" not in msg


def test_the_refusal_survives_having_no_advice():
    """The probe can fail; the refusal must still be a complete sentence."""
    from src.api.endpoints.audit import _capacity_refusal_detail
    msg = _capacity_refusal_detail(16, 16, licensed=False, advice="")
    assert msg.endswith("starting a new one.")
    assert "  " not in msg, "a missing advice left a double space"


def test_admission_sizes_itself_at_request_time_not_at_import():
    """Reading the import-time constant would pin the limit before /slots answers."""
    import io as _io
    import os as _os
    src = _io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                 "src", "api", "endpoints", "audit.py"), encoding="utf-8").read()
    start = src.index("def api_start_audit(")
    body = src[start:start + 12000]
    assert "current_audit_limit()" in body, (
        "admission still uses the constant computed before the LLM was up")


# ── the customer sees it before being refused ────────────────────────────────

def _app_js():
    import io as _io
    import os as _os
    return _io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                  "src", "api", "static", "app.js"), encoding="utf-8").read()


def test_the_start_response_carries_the_machines_rating():
    import io as _io
    import os as _os
    src = _io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                 "src", "api", "endpoints", "audit.py"), encoding="utf-8").read()
    assert '"audit_capacity": _audit_capacity' in src, (
        "the UI cannot warn about capacity it is never told about")


def test_the_ui_warns_when_the_last_audit_slot_is_taken():
    js = _app_js()
    assert "audit_capacity" in js, "the UI ignores the capacity the server sends"
    assert "acap.advice" in js, "the upgrade advice is fetched but never shown"


def test_the_existing_busy_slots_banner_still_works():
    """The queue notice predates this and must not have been replaced by it."""
    js = _app_js()
    assert "compute slot(s) busy right now" in js
    assert "cap.at_capacity" in js


def test_a_licence_limit_shows_no_hardware_advice_in_the_ui():
    """The server blanks the advice when a licence binds; nothing else should re-add it."""
    import io as _io
    import os as _os
    src = _io.open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                 "src", "api", "endpoints", "audit.py"), encoding="utf-8").read()
    assert '"advice": "" if _licensed else _hardware_advice' in src


# -- the Windows launchers leave the limit to the hardware sizing -------------------
# run_all.bat set MAX_CONCURRENT_AUDITS to slots x 2 (8 on a 4-core VM) and
# run_api.bat to cores x 2, overriding the hardware-sized limit with four times
# what a small machine runs comfortably. Two audits on a 4-core VM took 49 min.

def test_a_four_core_machine_admits_two():
    assert audit_capacity(4, available_slots=4, total_ram_gb=32)["limit"] == 2


@pytest.mark.parametrize("launcher", ["run_all.bat", "run_api.bat"])
def test_the_launchers_do_not_override_the_limit(launcher):
    import io as _io
    import os as _os
    import re as _re
    path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), launcher)
    src = _io.open(path, encoding="utf-8", errors="replace").read()
    assert not _re.search(r"(?im)^\s*set\s+(/a\s+)?\"?MAX_CONCURRENT_AUDITS\s*=", src), launcher
