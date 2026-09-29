# -*- coding: utf-8 -*-
"""Linux customers can apply an update, and the build scripts check what they ship.

    pytest tests/test_linux_updaters.py -v

make_update.bat produced an update only a Windows site could apply: both
appliers (apply_update, apply_llm_config) were PowerShell. A Linux server --
a customer's GCP VM -- could load an application tar by hand and could not apply
an LLM settings update at all, because that one is a recipe built on site.
apply_update.sh and apply_llm_config.sh are their Linux twins; here they run
against a fake docker that records every call and keeps no images.

The same review found the build scripts shipping untested pieces: options 2
and 3 of make_update.bat and all of make_bundle.bat ran no tests or checks;
make_bundle.bat's default version was the image NAME; and it reused an LLM
image of the same version, old startup script and all. The wiring tests at the
bottom pin each of those.
"""
import hashlib
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    return open(os.path.join(ROOT, name), encoding="utf-8").read()


def _find_sh():
    for cand in (shutil.which("sh"), r"C:\Program Files\Git\bin\sh.exe",
                 r"C:\Program Files\Git\usr\bin\sh.exe"):
        if cand and os.path.exists(cand):
            return cand
    return None


SH = _find_sh()
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on this machine")

# Records each call in $FAKE_STATE/calls. Images are marker files (":" is not
# allowed in a Windows file name, so it is stored as "@").
FAKE_DOCKER = r'''#!/bin/sh
S="$FAKE_STATE"
echo "$*" >> "$S/calls"
mark() { touch "$S/img_$(printf '%s' "$1" | tr ':' '@')"; }
has()  { [ -f "$S/img_$(printf '%s' "$1" | tr ':' '@')" ]; }
case "$1" in
  info) exit 0 ;;
  compose)
    [ "$2" = ls ] && { printf '[{"Name":"aicb","Status":"running(5)","ConfigFiles":"%s"}]\n' "$FAKE_COMPOSE"; exit 0; }
    exit 0 ;;
  inspect)
    if [ "$2" = "-f" ] || [ "$2" = "--format" ]; then
      case "$3" in
        *State.Running*) [ "$4" = shakthidb_service ] && { echo "${FAKE_DB_RUNNING:-true}"; exit 0; }; exit 1 ;;
        *Config.Image*)
          case "$4" in
            aicyberauditbox_app) img=aicyberauditbox-app ;;
            aicyberauditbox_llm) img=aicyberauditbox-llm ;;
            *) img=aicyberauditbox-shakthidb ;;
          esac
          v=$(sed -nE "s/.*image:[[:space:]]*$img:([0-9][0-9.]*).*/\1/p" "$FAKE_COMPOSE" | head -1)
          echo "$img:$v"; exit 0 ;;
      esac
    fi
    [ "$2" = aicyberauditbox_app ] && exit 0
    exit 1 ;;
  exec)
    echo "-- pg_dumpall: shakthidb_master"
    i=0; while [ $i -lt 60 ]; do echo "INSERT INTO findings VALUES ($i, 'row of the customer audit');"; i=$((i+1)); done
    exit 0 ;;
  cp) mkdir -p "$3" && echo evidence > "$3/evidence.txt"; exit 0 ;;
  load)
    n=$(basename "$3" .tar)
    comp=$(printf '%s' "$n" | sed -E 's/^aicyberauditbox-([a-z]+)-([0-9.]+)$/\1/')
    ver=$(printf '%s' "$n" | sed -E 's/^aicyberauditbox-([a-z]+)-([0-9.]+)$/\2/')
    mark "aicyberauditbox-$comp:$ver"
    [ "$comp" = llm ] && mark "aicyberauditbox-llm-embed:$ver"
    exit 0 ;;
  image) has "$3" && exit 0; exit 1 ;;
  build) while [ $# -gt 0 ]; do [ "$1" = -t ] && mark "$2"; shift; done; exit 0 ;;
  tag) mark "$3"; exit 0 ;;
esac
exit 1
'''

COMPOSE = """services:
  shakthidb:
    image: aicyberauditbox-shakthidb:3.10
  llm:
    image: aicyberauditbox-llm:1.1
  llm-embed:
    image: aicyberauditbox-llm-embed:1.1
  app:
    image: aicyberauditbox-app:1.2.3
"""


def _posix(path):
    return path.replace("\\", "/")


class Site:
    """A folder holding an 'installation' and the update files beside it."""

    def __init__(self, tmp_path, compose_text=COMPOSE):
        self.root = tmp_path
        self.install = tmp_path / "install"
        self.update = tmp_path / "update"
        self.state = tmp_path / "state"
        self.bin = tmp_path / "bin"
        for d in (self.install, self.update, self.state, self.bin):
            d.mkdir()
        self.compose = self.install / "docker-compose.yml"
        self.compose.write_text(compose_text, encoding="utf-8", newline="\n")
        (self.bin / "docker").write_text(FAKE_DOCKER, encoding="utf-8", newline="\n")
        os.chmod(self.bin / "docker", 0o755)

    def add_tar(self, name, good_checksum=True):
        tar = self.update / name
        tar.write_bytes(b"image layers")
        digest = hashlib.sha256(b"image layers").hexdigest().upper()
        if not good_checksum:
            digest = "0" * 64
        # As make_update.bat writes it on Windows: upper case, CRLF.
        (self.update / (name + ".sha256")).write_bytes(digest.encode() + b"\r\n")

    def mark_image(self, tag):
        (self.state / ("img_" + tag.replace(":", "@"))).write_text("")

    def run(self, script, env_extra=None):
        shutil.copy(os.path.join(ROOT, script), self.update / script)
        env = dict(os.environ)
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        env["FAKE_STATE"] = _posix(str(self.state))
        env["FAKE_COMPOSE"] = _posix(str(self.compose))
        env.update(env_extra or {})
        r = subprocess.run([SH, _posix(str(self.update / script))], capture_output=True,
                           text=True, errors="replace", env=env, cwd=str(self.root))
        return r.returncode, r.stdout + r.stderr

    def calls(self):
        p = self.state / "calls"
        return p.read_text() if p.exists() else ""

    def compose_text(self):
        return self.compose.read_text(encoding="utf-8")


# ----------------------------------------------------------- apply_update.sh

@needs_sh
def test_app_update_repoints_only_the_app_and_backs_up_first(tmp_path):
    site = Site(tmp_path)
    site.add_tar("aicyberauditbox-app-1.2.4.tar")
    rc, out = site.run("apply_update.sh")
    assert rc == 0, out
    text = site.compose_text()
    assert "aicyberauditbox-app:1.2.4" in text
    for untouched in ("aicyberauditbox-llm:1.1", "aicyberauditbox-llm-embed:1.1",
                      "aicyberauditbox-shakthidb:3.10"):
        assert untouched in text
    backups = list((site.install / "backups").iterdir())
    assert any(b.name.startswith("db_before_1.2.4_") for b in backups), out
    assert any(b.name.startswith("files_before_1.2.4_") for b in backups), out
    assert (site.install / "docker-compose.yml.before-app-1.2.4.bak").exists()
    calls = site.calls()
    assert calls.index("exec shakthidb_service pg_dumpall") < calls.index("load -i"), \
        "the backup must come before anything changes"
    assert "up -d app" in calls
    assert "Update complete" in out


@needs_sh
def test_llm_update_moves_both_llm_lines_together(tmp_path):
    site = Site(tmp_path)
    site.add_tar("aicyberauditbox-llm-1.2.tar")
    rc, out = site.run("apply_update.sh")
    assert rc == 0, out
    text = site.compose_text()
    assert "aicyberauditbox-llm:1.2" in text and "aicyberauditbox-llm-embed:1.2" in text
    assert "aicyberauditbox-app:1.2.3" in text and "aicyberauditbox-shakthidb:3.10" in text
    assert "up -d llm llm-embed" in site.calls()


@needs_sh
def test_a_damaged_download_changes_nothing(tmp_path):
    site = Site(tmp_path)
    site.add_tar("aicyberauditbox-app-1.2.4.tar", good_checksum=False)
    before = site.compose_text()
    rc, out = site.run("apply_update.sh")
    assert rc == 1
    assert "damaged" in out and "Nothing has been changed" in out
    assert site.compose_text() == before
    assert "load" not in site.calls()


@needs_sh
def test_a_stopped_database_is_not_updated_without_a_backup(tmp_path):
    site = Site(tmp_path)
    site.add_tar("aicyberauditbox-app-1.2.4.tar")
    before = site.compose_text()
    rc, out = site.run("apply_update.sh", {"FAKE_DB_RUNNING": "false"})
    assert rc == 1 and "stopped" in out
    assert site.compose_text() == before


@needs_sh
def test_a_registry_installation_is_sent_to_setup_registry(tmp_path):
    site = Site(tmp_path, _read("docker-compose.registry.yml"))
    site.add_tar("aicyberauditbox-app-1.2.4.tar")
    before = site.compose_text()
    rc, out = site.run("apply_update.sh")
    assert rc == 1 and "setup_registry.sh" in out
    assert site.compose_text() == before
    assert "load" not in site.calls()


# ------------------------------------------------------- apply_llm_config.sh

def _stage_llm_config(site):
    shutil.copy(os.path.join(ROOT, "Dockerfile.llm.rebase"), site.update / "Dockerfile.llm.rebase")
    (site.update / "docker").mkdir()
    shutil.copy(os.path.join(ROOT, "docker", "llm-entrypoint.sh"),
                site.update / "docker" / "llm-entrypoint.sh")


@needs_sh
def test_llm_config_rebuilds_on_the_installed_image_and_switches_both_lines(tmp_path):
    site = Site(tmp_path)
    _stage_llm_config(site)
    site.mark_image("aicyberauditbox-llm:1.1")
    rc, out = site.run("apply_llm_config.sh")
    assert rc == 0, out
    calls = site.calls()
    assert "build -f Dockerfile.llm.rebase --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm:1.1 -t aicyberauditbox-llm:1.2 ." in calls
    assert "tag aicyberauditbox-llm:1.2 aicyberauditbox-llm-embed:1.2" in calls
    text = site.compose_text()
    assert "aicyberauditbox-llm:1.2" in text and "aicyberauditbox-llm-embed:1.2" in text
    assert "aicyberauditbox-app:1.2.3" in text and "aicyberauditbox-shakthidb:3.10" in text
    assert "up -d llm llm-embed" in calls


@needs_sh
def test_llm_config_refuses_a_script_with_windows_line_endings(tmp_path):
    site = Site(tmp_path)
    _stage_llm_config(site)
    p = site.update / "docker" / "llm-entrypoint.sh"
    p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
    site.mark_image("aicyberauditbox-llm:1.1")
    before = site.compose_text()
    rc, out = site.run("apply_llm_config.sh")
    assert rc == 1 and "line endings" in out
    assert site.compose_text() == before


@needs_sh
def test_llm_config_sends_a_registry_installation_to_setup_registry(tmp_path):
    site = Site(tmp_path, _read("docker-compose.registry.yml"))
    _stage_llm_config(site)
    rc, out = site.run("apply_llm_config.sh")
    assert rc == 1 and "setup_registry.sh" in out
    assert "build" not in site.calls()


# ------------------------------------------------------------ the scripts

SHIPPED_SH = ["apply_update.sh", "apply_llm_config.sh", "install.sh", "setup_registry.sh",
              "apply_patch.sh", os.path.join("docker", "llm-entrypoint.sh")]


@pytest.mark.parametrize("name", SHIPPED_SH)
def test_shipped_shell_scripts_have_linux_line_endings(name):
    assert b"\r" not in open(os.path.join(ROOT, name), "rb").read()


@needs_sh
@pytest.mark.parametrize("name", SHIPPED_SH)
def test_shipped_shell_scripts_parse(name):
    r = subprocess.run([SH, "-n", _posix(os.path.join(ROOT, name))], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("name", ["make_update.bat", "make_bundle.bat", "install.bat",
                                  "apply_update.bat", "apply_llm_config.bat"])
def test_batch_files_have_windows_line_endings(name):
    """cmd finds goto/call labels unreliably in a batch file with bare LF."""
    raw = open(os.path.join(ROOT, name), "rb").read()
    assert raw.count(b"\n") == raw.count(b"\r\n")


# ------------------------------------------------------ build-script wiring

def test_make_update_ships_the_linux_appliers():
    bat = _read("make_update.bat")
    assert 'copy /y apply_update.sh "!OUTDIR!\\"' in bat
    assert 'copy /y apply_llm_config.sh "!STAGE!\\"' in bat
    assert "apply_llm_config.sh" in bat[bat.index("tar.exe"):bat.index("tar.exe") + 400]


def test_make_update_runs_the_tests_for_every_choice():
    bat = _read("make_update.bat")
    tests = bat.index("python -m pytest -q")
    assert 'if "!CHOICE!"=="1" (\n    echo ---^> Running the tests' not in bat
    assert bat.rfind('if "!CHOICE!"=="1" (', 0, tests) < bat.rfind("REM --- Tests", 0, tests)


def _section(bat, label, next_label):
    """The lines of a batch file from one label to the next (the label lines
    themselves, not the goto statements naming them)."""
    return bat[bat.index("\n" + label + "\n"):bat.index("\n" + next_label + "\n")]


def test_make_update_checks_the_llm_image_before_packaging_it():
    bat = _read("make_update.bat")
    conf = _section(bat, ":llmconf", ":llmfull")
    assert conf.index("llm_image_check.py --rebase-on newest") < conf.index("tar.exe")
    full = _section(bat, ":llmfull", ":db")
    assert full.index("llm_image_check.py --image") < full.index("docker save")


def test_make_update_version_hint_is_a_version_not_the_image_name():
    bat = _read("make_update.bat")
    assert 'for /f "tokens=2 delims=:"' not in bat


def test_make_bundle_has_no_default_version():
    bat = _read("make_bundle.bat")
    assert 'for /f "tokens=2 delims=:"' not in bat
    assert 'if "!VERSION!"=="" set VERSION=' not in bat
    assert "A version is required" in bat


def test_make_bundle_tests_before_building_and_checks_what_it_built():
    bat = _read("make_bundle.bat")
    assert bat.index("python -m pytest -q") < bat.index("docker build")
    assert "llm_image_check.py --image !LLM_TAG! --refresh" in bat
    pkg = bat.index("python build_customer_bundle.py --version !VERSION! --full --skip-build")
    assert bat.index("image_smoke_test.py") < pkg
    assert bat.index("upgrade_e2e_check.py --image !APP_TAG!") < pkg


def test_make_bundle_builds_a_new_llm_version_on_the_tested_engine():
    bat = _read("make_bundle.bat")
    assert "Dockerfile.llm.rebase --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm:!LLM_BASE!" in bat
    # The only unescaped ")" inside that block used to end it early.
    assert "building (copies ~18 GB" not in bat
