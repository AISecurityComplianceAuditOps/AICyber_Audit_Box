"""A finding must not state a value its evidence denies.

Gates 2, 3 and 3.5 all compare word overlap, which cannot separate a claim from
its opposite. This was not theoretical: an OCR chunk reading

    NTP enabled: yes  NTP synchronized: yes  RTC in local TZ: no

scored 100% against a model quote claiming "NTP synchronized: no", because the
chunk does contain "no" -- for a different field -- and set intersection has no
idea which label a value belongs to. A compliant host was published as
NON_COMPLIANT. Removing yes/no from the stopword list does not fix it, for the
same reason; that was tried and still scored 100%.

Gate 4 binds each value to its own label instead.
"""
import pytest

from src.core.validator import (
    _field_value_pairs, _normalise_label, _quote_contradicts_source,
)

# The real OCR text, sidebar noise and all, as it is stored for the NTP screenshot.
OCR_CHUNK = (
    "L S2 172.16.32 18 (root) S3 172.16.32.18 (roof) L t X "
    "[root@dcauaweivmlhcip *l# timedatectl status Local time: Thu 2026-04-16 "
    "13:52:03 IST root Universal time: Thu 2026-04-16 08:22:03 UTC I Name A "
    "RTC time: Thu 2026-04-16 08:22:01 Time zone: Asta/Kolkata (IST, +0530) "
    "a NTP enabled: yes cache NTP synchronized: yes .config RTC in local TZ: no "
    ".dbus DST active: n/a java local mozila pki Desktop Documents Downloads"
)


def test_pairs_are_recovered_from_noisy_ocr():
    pairs = _field_value_pairs(OCR_CHUNK)
    assert pairs["ntp enabled"] == "yes"
    assert pairs["ntp synchronized"] == "yes"
    assert pairs["rtc in local tz"] == "no"


def test_labels_shed_the_prefixes_ocr_glues_on():
    """A screenshot with a file browser open produced "cache NTP synchronized"."""
    assert _normalise_label("cache NTP synchronized") == "ntp synchronized"
    assert _normalise_label(".config RTC in local TZ") == "rtc in local tz"
    assert _normalise_label("a NTP enabled") == "ntp enabled"


def test_the_finding_that_shipped_is_now_held():
    """The exact quote from the run that published a false NON_COMPLIANT."""
    quoted = ("a NTP enabled: yes cache NTP synchronized: no "
              ".config RTC in local TZ: no .dbus DST active: n/a")
    conflicts = _quote_contradicts_source(quoted, OCR_CHUNK)
    assert conflicts, "the inverted quote was accepted"
    assert ("ntp synchronized", "no", "yes") in conflicts


def test_a_faithful_quote_passes():
    quoted = "NTP enabled: yes NTP synchronized: yes RTC in local TZ: no"
    assert _quote_contradicts_source(quoted, OCR_CHUNK) == []


@pytest.mark.parametrize("said,truth", [
    ("Service: enabled", "Service: yes"),
    ("Service: disabled", "Service: no"),
    ("Firewall: active", "Firewall: on"),
    ("Logging: false", "Logging: off"),
])
def test_synonyms_are_not_contradictions(said, truth):
    """"enabled" and "yes" mean the same thing; flagging that would be noise."""
    assert _quote_contradicts_source(said, truth) == []


def test_a_field_absent_from_the_source_is_not_a_contradiction():
    """Only shared fields are compared, so added context is never penalised."""
    assert _quote_contradicts_source("Backups configured: yes", OCR_CHUNK) == []


def test_prose_with_no_field_values_is_left_alone():
    """The gate must not fire on ordinary narrative -- that would hold everything."""
    assert _quote_contradicts_source(
        "The host synchronises its clock with an internal time source.",
        OCR_CHUNK) == []


def test_an_empty_source_never_holds_a_finding():
    assert _quote_contradicts_source("NTP synchronized: no", "") == []


def test_case_and_spacing_do_not_matter():
    assert _quote_contradicts_source("NTP  Synchronized :  NO", OCR_CHUNK)
