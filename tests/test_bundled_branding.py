# -*- coding: utf-8 -*-
"""Branding must ship inside the image, not depend on an upload.

    pytest tests/test_bundled_branding.py -v

WHY THIS EXISTS

The appliance is air-gapped. Every asset a report draws has to be in the bundle
already, because the customer has no internet and, on a fresh installation, has
uploaded nothing.

Default branding was resolved only out of data/assets. That directory is a
Docker volume (app_data:/app/data) and is excluded from the build context by
.dockerignore, so it ships EMPTY and stays empty until somebody uploads a logo.
Every report on every customer installation therefore rendered with no logo --
and the VAPT exporter, which passed the resulting None to os.path.exists,
answered 500 instead.

It never reproduced in development because data/assets exists here, populated.
That is the whole difference between the two machines.

Seeding data/assets at build time would not have been enough: Docker only
copies image content into a named volume that is EMPTY, so an upgrade reusing
an existing app_data volume is never re-seeded. The bundled copy lives under
src/ instead, which is COPYed into the image and is not under the mount.
"""
import io
import os
import re

import pytest

import src.core.report_exporter as rx


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def test_branding_ships_inside_the_repo():
    """The bundled asset exists and is a real PNG, not a placeholder."""
    shield = os.path.join(rx._BUNDLED_BRANDING_DIR, "shield_logo.png")
    assert os.path.exists(shield), (
        "no bundled shield logo at %s -- an air-gapped install has no other "
        "source for it" % shield)
    with io.open(shield, "rb") as fh:
        assert fh.read(8) == PNG_MAGIC, "bundled shield logo is not a PNG"


def test_bundled_branding_is_not_under_the_data_volume():
    """The invariant the whole fix rests on.

    app_data is mounted at /app/data. Anything under that path is hidden by the
    volume on a customer machine no matter what the image contains, which is
    exactly how the original bug worked. If someone moves the bundled branding
    back under data/, this fails rather than silently shipping nothing again.
    """
    bundled = os.path.abspath(rx._BUNDLED_BRANDING_DIR)
    data_dir = os.path.abspath(os.path.join(
        os.path.dirname(rx.__file__), "..", "..", "data"))
    assert not bundled.startswith(data_dir + os.sep), (
        "bundled branding at %s sits under the data volume at %s -- the mount "
        "will hide it on every customer installation" % (bundled, data_dir))


def test_a_logo_resolves_when_nothing_has_been_uploaded(tmp_path):
    """The customer's machine: data/assets present but empty."""
    empty = str(tmp_path / "assets")
    os.makedirs(empty)
    got = rx._default_auditor_logo(empty)
    assert got is not None, "no logo resolved with an empty assets dir"
    assert os.path.exists(got)


def test_a_logo_resolves_when_the_assets_dir_does_not_exist_at_all(tmp_path):
    """A fresh volume may not even have the assets subdirectory yet."""
    got = rx._default_auditor_logo(str(tmp_path / "nope"))
    assert got is not None and os.path.exists(got)


def test_an_upload_still_wins_over_the_bundled_copy(tmp_path):
    """Bundling a default must not override a customer's own branding."""
    assets = tmp_path / "assets"
    assets.mkdir()
    uploaded = assets / "dhiware_logo.png"
    uploaded.write_bytes(PNG_MAGIC + b"uploaded")
    assert rx._default_auditor_logo(str(assets)) == str(uploaded)


def test_no_exporter_resolves_branding_straight_off_the_volume():
    """Checked across the module, not on the lines that were wrong.

    Nine exporters can each make this mistake independently; one of them did
    for the VAPT cover, and another pointed at src/assets -- a directory that
    exists in neither the repo nor the image -- so its cover never found a logo
    on any machine at all.
    """
    src_text = io.open(rx.__file__, encoding="utf-8").read()
    raw = re.findall(r'os\.path\.join\(assets_dir, "(?:shield|dhiware)_logo\.png"\)', src_text)
    assert not raw, (
        "branding resolved directly off the data volume: %r -- go through "
        "_default_auditor_logo/_branding_asset so the bundled copy is used" % (raw,))
    assert 'os.path.dirname(os.path.abspath(__file__))), "assets")' not in src_text, (
        "an exporter is looking in src/assets, which does not exist")


def test_vapt_export_draws_a_logo_with_nothing_uploaded(tmp_path, monkeypatch):
    """End to end: the export that 500'd now renders, and renders branded."""
    empty = str(tmp_path / "assets")
    os.makedirs(empty)
    drawn = []

    _real = rx._default_auditor_logo

    def _spy(assets_dir):
        got = _real(empty)          # force the customer's empty-volume case
        drawn.append(got)
        return got

    monkeypatch.setattr(rx, "_default_auditor_logo", _spy)

    out = rx._export_vapt_pdf(
        session_title="VAPT Audit Report",
        findings=[{
            "control_id": "VAPT-001", "control_name": "TLS 1.0 accepted",
            "severity": "P2 High", "status": "Non-Compliant",
            "final_result": "NON_COMPLIANT", "asset_name": "web-01",
            "port": "443", "description": "Negotiates TLS 1.0.",
            "recommendation": "Disable TLS 1.0.",
            "evidence_snippet": "sslscan web-01:443 | TLSv1.0 enabled",
            "source_files": "nmap_scan.xml",
        }],
        resolved_list=[], status="Final", comments="test",
        metadata={"brand_firm": "Dhiware Technologies Pvt Ltd"})
    data = out.getvalue() if hasattr(out, "getvalue") else out

    assert data[:4] == b"%PDF"
    assert drawn and all(p and os.path.exists(p) for p in drawn), (
        "the VAPT cover resolved no logo on an empty volume: %r" % (drawn,))
