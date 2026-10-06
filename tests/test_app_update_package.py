# -*- coding: utf-8 -*-
"""An application update ships the app image alone -- no configuration files.

    pytest tests/test_app_update_package.py -v

make_update.bat (choice 1) packaged through build_customer_bundle.py, which also
wrote aicyberauditbox-<v>-companion.zip: the compose files and the model
server's entrypoint. A customer already has those, and apply_update points
their existing installation at the new version itself; shipped with every app
update the zip read as a second thing to install. Choice 1 now passes
--app-only; a full bundle and a code patch package as before.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    return open(os.path.join(ROOT, name), encoding="utf-8").read()


def test_make_update_packages_an_app_update_without_config():
    bat = _read("make_update.bat")
    calls = re.findall(r'^python build_customer_bundle\.py .*$', bat, re.MULTILINE)
    assert calls == ['python build_customer_bundle.py --version !VERSION! --skip-build --app-only --out "!BUILDS_ROOT!"']


def test_app_only_stops_before_the_companion_zip():
    src = _read("build_customer_bundle.py")
    assert '"--app-only"' in src
    app_only = src.index("if args.app_only:")
    assert app_only < src.index('companion = os.path.join(out, f"aicyberauditbox-{version}-companion.zip")')
    assert "return 0" in src[app_only:app_only + 700]


def test_a_full_bundle_still_carries_its_files():
    bat = _read("make_bundle.bat")
    assert "--app-only" not in bat
    assert re.search(r'^python build_customer_bundle\.py .*--full', bat, re.MULTILINE)


def test_the_applier_needs_no_companion_files():
    for name in ("apply_update.ps1", "apply_update.sh"):
        assert "companion" not in _read(name).lower(), name
