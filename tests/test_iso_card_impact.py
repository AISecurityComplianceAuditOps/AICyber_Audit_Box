# -*- coding: utf-8 -*-
"""ISO Audit Records card: IMPACT shown as the final report shows it.

The report's ISO rows read Observation | Risk | Impact | Recommendation
(report_exporter._iso_observation_and_impact). The card showed no impact for
Control and Selective findings, and printed their stored description --
"Business Impact: X | Missing Requirements: Y" -- under AUDITOR OBSERVATIONS,
so the impact sat where the observation belongs. It now shows the observation
(reasoning) and missing requirements there, and an IMPACT row between the
evidence and LEAD AUDITOR RECOMMENDATIONS: the stored business_impact, NIL on a
compliant control, never a repeat of the observation.

ISO 27001 sessions only. NIST CSF, SOC 2, DPDP and BCMS share the card and keep
it as it was; the VAPT card is a separate template and is not touched.

Node is not required: the rule is mirrored here and app.js is checked for it.
Verified live (Edge, real /audit/findings JSON): Control 8.13 card impact equals
the report's, Checklist Q2 shows NIL, the old not-assessed 8.13 matches too.
"""
import os
import re

import pytest

import src.core.report_exporter as rx
from tests.test_iso_observation_impact import CHECKLIST_NO, CHECKLIST_YES, CONTROL, TIMED_OUT

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "api", "static", "app.js")


@pytest.fixture(scope="module")
def js():
    with open(APP_JS, encoding="utf-8") as fh:
        return fh.read()


def _func(js, name):
    start = js.index(f"function {name}(")
    end = js.index("\n}\n", start)
    return js[start:end]


def _iso_card(js):
    """The ISO / NIST card template: the else-arm after the VAPT card."""
    body = js[js.index("function renderFindingsList("):]
    start = body.index("Not a VAPT/PQC finding, so this is the ISO / NIST card.")
    end = body.index("`;", body.index("card.innerHTML = `", start))
    return body[start:end]


def _vapt_card(js):
    body = js[js.index("function renderFindingsList("):]
    start = body.index("if (isVapt) {")
    return body[start:body.index("Not a VAPT/PQC finding, so this is the ISO / NIST card.")]


# -- the rule, mirrored from isoObservationAndImpact ------------------------------

_BIZ = re.compile(r"^\s*Business Impact:\s*([\s\S]*?)\s*(?:\|\s*Missing Requirements:\s*([\s\S]*?))?\s*$", re.I)
_MISSING_TAIL = re.compile(r"(^|[.!?]|\n)\s*Missing requirements:\s*([^\n]*?)[\s.;,]*$", re.I)
NO_IMPACT = "Impact not recorded for this finding -- see Observations."


def _card_full(f):
    """(observation, missing, impact shown, impact stored) as isoObservationAndImpact gives them."""
    obs = str(f.get("description") or "").strip()
    impact = str(f.get("business_impact") or f.get("impact") or "").strip()
    missing = ""
    m = _BIZ.match(obs)
    if m:
        missing = re.sub(r"[\s.;,]+$", "", re.sub(r"\.\s*,\s*", "; ", m.group(2) or ""))
        obs = str(f.get("reasoning") or "").strip()
        impact = impact or (m.group(1) or "").strip()
    else:
        t = _MISSING_TAIL.search(obs)
        if t:
            missing = t.group(2).strip()
            obs = obs[:t.start() + len(t.group(1))].strip()
    stored = "" if (not impact or impact.lower() in ("nil", "n/a", "none") or rx._same_text(impact, obs)) else impact
    shown = "NIL" if (f.get("final_result") or f.get("status")) == "COMPLIANT" else (stored or NO_IMPACT)
    return obs, missing, shown, stored


def _card(f):
    """(observation, missing, impact) as the ISO card shows them."""
    return _card_full(f)[:3]


def _modify_and_save(f, new_impact):
    """What the ISO Modify dialog opens with, and the finding after Save."""
    obs, missing, _, stored = _card_full(f)
    box = obs + (("\n" if obs else "") + f"Missing requirements: {missing}." if missing else "")
    saved = dict(f, description=box, reasoning=box, gap_description=box, business_impact=new_impact)
    return box, stored, saved


@pytest.mark.parametrize("f", [CONTROL, CHECKLIST_YES, CHECKLIST_NO, TIMED_OUT],
                         ids=["control", "checklist-yes", "checklist-no", "timed-out"])
def test_the_card_impact_is_the_reports_impact(f):
    assert _card(f)[2] == rx._iso_observation_and_impact(f)[1]


def test_a_control_finding_shows_the_observation_not_the_impact():
    obs, missing, impact = _card(CONTROL)
    assert obs == CONTROL["reasoning"]
    assert not obs.lower().startswith("business impact")
    assert missing == ("Backup logs to verify nightly success; "
                       "Evidence of quarterly restore testing (only one test provided)")
    assert impact == CONTROL["business_impact"]
    report_obs = rx._iso_observation_and_impact(CONTROL)[0]
    assert report_obs == f"{obs}\nMissing requirements: {missing}."


def test_a_control_finding_with_no_stored_impact_uses_the_one_in_its_description():
    f = dict(CONTROL, business_impact="")
    assert _card(f)[2].startswith("Failure to verify backup integrity")


def test_a_checklist_answer_is_unchanged_and_never_its_own_impact():
    assert _card(CHECKLIST_YES)[0] == CHECKLIST_YES["description"]
    assert _card(CHECKLIST_YES)[2] == "NIL"
    assert _card(CHECKLIST_NO)[2] == CHECKLIST_NO["business_impact"]
    assert _card(dict(CHECKLIST_NO, business_impact=CHECKLIST_NO["description"]))[2] == NO_IMPACT


# -- app.js does the same -----------------------------------------------------------

def test_app_js_uses_the_reports_pattern_and_fallback(js):
    assert ("const _ISO_BIZ_IMPACT_DESC_RE = /^\\s*Business Impact:\\s*([\\s\\S]*?)\\s*"
            "(?:\\|\\s*Missing Requirements:\\s*([\\s\\S]*?))?\\s*$/i;") in js
    assert f'const ISO_NO_IMPACT_RECORDED = "{rx._NO_IMPACT_RECORDED}";' in js
    fn = _func(js, "isoObservationAndImpact")
    assert 'impact = isFindingCompliant(f) ? "NIL" : (stored || ISO_NO_IMPACT_RECORDED);' in fn
    assert "_isoSameText(impact, obs)" in fn
    assert "const _ISO_MISSING_TAIL_RE = /(^|[.!?]|\\n)\\s*Missing requirements:\\s*([^\\n]*?)[\\s.;,]*$/i;" in js


def test_only_iso_27001_sessions_get_it(js):
    assert "/ISO\\s*27001/i.test(String(findingsSessionFramework" in _func(js, "isIsoRecordsSession")
    card = _iso_card(js)
    assert "const _isoOI = isIsoRecordsSession() ? isoObservationAndImpact(f) : null;" in card


@pytest.mark.parametrize("fw, iso", [("ISO 27001", True), ("NIST CSF 2.0", False), ("SOC2", False),
                                     ("DPDP", False), ("BCMS", False), ("", False)])
def test_which_frameworks_count_as_iso(fw, iso):
    assert bool(re.search(r"ISO\s*27001", fw, re.I)) is iso


def test_other_frameworks_keep_the_old_card(js):
    card = _iso_card(js)
    assert "${_isoOI ? renderFindingTextHtml(_isoOI.obs) : renderFindingDescriptionHtml(f)}" in card
    assert "${(_isoOI && _isoOI.missing) ?" in card
    # the Checklist-only impact the card always had
    assert ("` : (isQaFinding && String(f.business_impact || \"\").trim()) ? `" in card
            and "escapeHtml(String(f.business_impact).trim())" in card)


def test_impact_sits_between_the_evidence_and_the_recommendations(js):
    card = _iso_card(js)
    order = [card.index("AUDITOR OBSERVATIONS"), card.index("buildEvidenceSnippetHtml(singleSnip, f)"),
             card.index("iso-impact-row"), card.index("escapeHtml(_isoOI.impact)"),
             card.index("LEAD AUDITOR RECOMMENDATIONS")]
    assert order == sorted(order)
    assert card.count("iso-impact-row") == 1


def test_the_vapt_card_is_untouched(js):
    vapt = _vapt_card(js)
    assert "_isoOI" not in vapt and "isoObservationAndImpact" not in vapt and "iso-impact-row" not in vapt


# -- Modify: the auditor can change the Impact --------------------------------------
#
# The dialog had no Impact field, and for a Control or Selective finding its
# description box held "Business Impact: X | Missing Requirements: Y" -- saving
# wrote that over the observation. Live check (Edge, :8010): the edited impact
# reached the card, the database and the exported DOCX; the observation and the
# missing-requirements line were unchanged.

EDITED = "Unverified backups may fail during a real restore, losing up to a day of business data."


def test_modify_opens_with_the_observation_and_the_stored_impact():
    box, stored, _ = _modify_and_save(CONTROL, EDITED)
    assert not box.lower().startswith("business impact")
    assert box.startswith(CONTROL["reasoning"]) and "\nMissing requirements: Backup logs" in box
    assert stored == CONTROL["business_impact"]
    assert _modify_and_save(CHECKLIST_YES, "")[1] == ""          # compliant, nothing stored


def test_after_save_the_card_and_report_show_the_edit_and_nothing_else_moves():
    before = _card(CONTROL)
    _, _, saved = _modify_and_save(CONTROL, EDITED)
    obs, missing, impact = _card(saved)
    assert (obs, missing) == before[:2], "the save changed the observation"
    assert impact == EDITED
    r_obs, r_impact = rx._iso_observation_and_impact(saved)
    assert r_impact == EDITED
    assert r_obs.count("Missing requirements:") == 1
    # and a second Modify opens with exactly what the first saved
    box2, stored2, _ = _modify_and_save(saved, EDITED)
    assert box2 == _modify_and_save(CONTROL, EDITED)[0] and stored2 == EDITED


def test_a_cleared_impact_reads_not_recorded_and_compliant_stays_nil():
    _, _, saved = _modify_and_save(CONTROL, "")
    assert _card(saved)[2] == NO_IMPACT == rx._iso_observation_and_impact(saved)[1]
    _, _, saved = _modify_and_save(CHECKLIST_YES, "Some impact")
    assert _card(saved)[2] == "NIL" == rx._iso_observation_and_impact(saved)[1]


def test_the_api_accepts_and_stores_business_impact():
    import inspect
    from src.api.endpoints import audit as A
    req = A.UpdateFindingRequest(status="Non-Compliant", business_impact=EDITED)
    assert req.business_impact == EDITED
    assert A.UpdateFindingRequest(status="Non-Compliant").business_impact is None   # unchanged when absent
    with pytest.raises(Exception):
        A.UpdateFindingRequest(status="Non-Compliant", business_impact="x\x00y")
    src = inspect.getsource(A.api_update_finding)
    assert "if req.business_impact is not None: finding.business_impact = req.business_impact" in src


def test_the_dialog_has_an_iso_only_impact_box_in_the_cards_place():
    html = open(os.path.join(os.path.dirname(APP_JS), "index.html"), encoding="utf-8").read()
    form = html[html.index('<form id="edit-finding-form">'):]
    group = form[form.index('id="edit-impact-group"') - 40:form.index('id="edit-impact-group"') + 80]
    assert 'style="display:none;"' in group, "the Impact box must start hidden"
    assert (form.index('id="edit-finding-snippet"') < form.index('id="edit-finding-impact"')
            < form.index('id="edit-finding-recommendation"'))


def test_modify_fills_and_sends_impact_for_iso_27001_only(js):
    opener = _func(js, "openEditFindingModal")
    assert "const _isoEdit = !_vaptMode && !_isTechnicalFinding && isIsoRecordsSession();" in opener
    assert '_impactGroup.style.display = _isoEdit ? "" : "none";' in opener
    assert 'document.getElementById("edit-finding-impact").value = _oi.stored;' in opener
    save = _func(js, "handleEditFindingSubmit")
    assert 'dataset.isoImpact === "1"' in save and "body.business_impact" in save
    assert save.index('dataset.isoImpact === "1"') < save.index("body.business_impact")
