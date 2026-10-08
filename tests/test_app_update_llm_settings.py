# -*- coding: utf-8 -*-
"""An application update brings the model server's startup script with it.

    pytest tests/test_app_update_llm_settings.py -v

How many audits a machine can hold is decided by docker/llm-entrypoint.sh, the
model server's startup script: the slots it opens, and the memory it keeps back
for the app and database. That script lives in the LLM image, so it reached a
site only as a separate settings package (make_update option 2). A site that
took application updates kept the script its LLM image shipped with: llm 1.1
opened 3 slots on a customer's 23.5GB machine that holds one, kept nothing back,
and the AI recommendations ran out of memory.

The app image now carries the script (/app/llm-config), and apply_update -- for
an application update -- builds it onto the LLM image the site already has when
it differs, restarts the model servers, and shows the slot count it chose. A
refusal (the machine cannot hold the model) or any failure puts the model server
back as it was; the application update stands either way.

Both appliers run here against the fake docker of test_linux_updaters.py:
apply_update.sh directly, apply_update.ps1 through a docker.cmd shim.
"""
import os
import shutil
import subprocess
import sys

import pytest

from test_linux_updaters import ROOT, SH, Site, _posix, _read, needs_sh

SIZED_LOG = (
    "[LLM ENTRYPOINT] Detected 23.47GB and 8 core(s), ~0.96GB per 16384-token slot, "
    "8GB kept for the app, database and system -> 1 slot(s), bounded by RAM (23.47GB; 8 core(s) available).\n"
    "[LLM ENTRYPOINT] WARNING: 23.47GB is less than this model plus the rest of the stack need; "
    "running 1 slot. Add memory for more.\n"
    "[LLM ENTRYPOINT] Model weights held in memory: yes.\n"
)
REFUSED_LOG = (
    "[LLM ENTRYPOINT] Not enough memory to serve Gemma 4 12B (Q8_0).\n"
    "[LLM ENTRYPOINT]   this container can see : 12.00GB\n"
    "[LLM ENTRYPOINT]   weights need           : 12.5GB resident\n"
)
OLD_SCRIPT = "#!/bin/sh\n# the startup script llm 1.1 shipped with\n"


def _llm_site(tmp_path, log=SIZED_LOG, carried=True, current=OLD_SCRIPT, llm_present=True,
              compose_text=None):
    """An app update to 1.2.4 on a site running llm 1.1."""
    site = Site(tmp_path) if compose_text is None else Site(tmp_path, compose_text)
    site.add_tar("aicyberauditbox-app-1.2.4.tar")
    env = {}
    if carried:
        cfg = tmp_path / "llmcfg"
        (cfg / "docker").mkdir(parents=True)
        shutil.copy(os.path.join(ROOT, "Dockerfile.llm.rebase"), cfg / "Dockerfile.llm.rebase")
        shutil.copy(os.path.join(ROOT, "docker", "llm-entrypoint.sh"), cfg / "docker" / "llm-entrypoint.sh")
        env["FAKE_LLMCFG"] = _posix(str(cfg))
    cur = tmp_path / "current.sh"
    cur.write_bytes(current.encode() if isinstance(current, str) else current)
    env["FAKE_LLM_CURRENT"] = _posix(str(cur))
    logf = tmp_path / "llm.log"
    logf.write_text(log, encoding="utf-8", newline="\n")
    env["FAKE_LLM_LOG"] = _posix(str(logf))
    if llm_present:
        site.mark_image("aicyberauditbox-llm:1.1")
    return site, env


def _run_ps1(site, env_extra):
    """apply_update.ps1 against the same fake docker, reached through docker.cmd."""
    winbin = site.root / "winbin"
    winbin.mkdir()
    (winbin / "docker.cmd").write_text(
        '@"%s" "%s" %%*\r\n' % (SH, _posix(str(site.bin / "docker"))), encoding="ascii")
    shutil.copy(os.path.join(ROOT, "apply_update.ps1"), site.update / "apply_update.ps1")
    env = dict(os.environ)
    env["PATH"] = str(winbin) + os.pathsep + env["PATH"]
    env["FAKE_STATE"] = _posix(str(site.state))
    env["FAKE_COMPOSE"] = _posix(str(site.compose))
    env.update(env_extra)
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(site.update / "apply_update.ps1")],
                       capture_output=True, text=True, errors="replace", env=env, cwd=str(site.root))
    return r.returncode, r.stdout + r.stderr


def _run(which, site, env):
    if which == "sh":
        return site.run("apply_update.sh", env)
    return _run_ps1(site, env)


APPLIERS = [pytest.param("sh", marks=needs_sh, id="apply_update.sh"),
            pytest.param("ps1", marks=pytest.mark.skipif(
                sys.platform != "win32" or SH is None, reason="needs Windows PowerShell and sh"),
                id="apply_update.ps1")]

REBUILD = ("build -q -f Dockerfile.llm.rebase --build-arg LLM_BASE_IMAGE=aicyberauditbox-llm:1.1 "
           "-t aicyberauditbox-llm:1.2 .")


@pytest.mark.parametrize("which", APPLIERS)
def test_new_settings_are_built_onto_the_sites_llm_image(tmp_path, which):
    site, env = _llm_site(tmp_path)
    rc, out = _run(which, site, env)
    assert rc == 0, out
    calls = site.calls()
    assert REBUILD in calls, calls
    assert "tag aicyberauditbox-llm:1.2 aicyberauditbox-llm-embed:1.2" in calls
    # The model servers first, then the app: the app reads the slot count once,
    # and restarted first it could read the old server's.
    assert calls.index("build -q") < calls.index("up -d llm llm-embed") < calls.index("up -d app")
    text = site.compose_text()
    for line in ("aicyberauditbox-app:1.2.4", "aicyberauditbox-llm:1.2", "aicyberauditbox-llm-embed:1.2",
                 "aicyberauditbox-shakthidb:3.10"):
        assert line in text, text
    assert (site.install / "docker-compose.yml.before-llm-1.2.bak").exists()
    # The operator sees what the machine can hold, and the warning when short.
    assert "-> 1 slot(s)" in out and "WARNING" in out
    assert "aicyberauditbox-llm:1.2, 1 slot(s) on this machine" in out
    # It waited for the weights, not only the decision.
    assert "The model has loaded and is serving" in out
    assert "loaded on its new settings and ready" in out
    assert "Update complete" in out


@pytest.mark.parametrize("which", APPLIERS)
def test_the_same_settings_restart_nothing(tmp_path, which):
    current = open(os.path.join(ROOT, "docker", "llm-entrypoint.sh"), "rb").read()
    site, env = _llm_site(tmp_path, current=current)
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "Already current" in out
    assert "build" not in site.calls() and "up -d llm" not in site.calls()
    assert "aicyberauditbox-llm:1.1" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_an_app_image_without_the_settings_leaves_the_llm_alone(tmp_path, which):
    """An app image built before this change carries no /app/llm-config."""
    site, env = _llm_site(tmp_path, carried=False)
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "carries no model server settings" in out
    assert "build" not in site.calls()
    assert "aicyberauditbox-app:1.2.4" in site.compose_text()
    assert "aicyberauditbox-llm:1.1" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_a_machine_that_cannot_hold_the_model_is_put_back(tmp_path, which):
    site, env = _llm_site(tmp_path, log=REFUSED_LOG)
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "cannot hold the model" in out and "this container can see : 12.00GB" in out
    assert "Put back to aicyberauditbox-llm:1.1" in out
    text = site.compose_text()
    assert "aicyberauditbox-llm:1.1" in text and "aicyberauditbox-llm-embed:1.1" in text
    assert "aicyberauditbox-app:1.2.4" in text, "the application update must stand"
    assert site.calls().count("up -d llm llm-embed") == 2, "restarted on the old settings"
    # It did restart, so the closing note must not say otherwise.
    assert "restarted on its previous settings" in out
    assert "The AI model and database are not restarted" not in out


@pytest.mark.parametrize("which", APPLIERS)
def test_a_failed_rebuild_keeps_the_model_server_and_the_app_update(tmp_path, which):
    site, env = _llm_site(tmp_path)
    env["FAKE_BUILD_FAIL"] = "1"
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "the rebuild failed" in out and "keeps the settings it had" in out
    text = site.compose_text()
    assert "aicyberauditbox-llm:1.1" in text and "aicyberauditbox-app:1.2.4" in text
    assert "up -d llm" not in site.calls()
    assert "The AI model and database are not restarted" in out


@pytest.mark.parametrize("which", APPLIERS)
def test_a_stopped_model_server_is_put_back(tmp_path, which):
    site, env = _llm_site(tmp_path, log="")
    env["FAKE_LLM_RUNNING"] = "false"
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "stopped on the new settings" in out
    assert "aicyberauditbox-llm:1.1" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_a_model_killed_while_loading_is_put_back(tmp_path, which):
    """The decision passed, then the weights did not fit: killed and restarted."""
    site, env = _llm_site(tmp_path)
    # Up when first looked at, restarted by the time the weights were loading.
    env.update({"FAKE_LLM_HEALTH": "starting", "FAKE_LLM_RESTARTS_AFTER": "1", "FAKE_LLM_OOM": "true"})
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "stopped while loading on the new settings -- it ran out of memory" in out
    assert "Put back to aicyberauditbox-llm:1.1" in out
    text = site.compose_text()
    assert "aicyberauditbox-llm:1.1" in text and "aicyberauditbox-app:1.2.4" in text


@pytest.mark.parametrize("which", APPLIERS)
def test_a_model_still_loading_at_the_limit_is_left_running(tmp_path, which):
    """Slow is not broken: no put-back, and the operator is told how to check."""
    site, env = _llm_site(tmp_path)
    env.update({"FAKE_LLM_HEALTH": "starting", "AICB_LLM_READY_SECONDS": "0"})
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "Still loading after 0 minutes -- left running" in out
    assert "aicyberauditbox-llm:1.2" in site.compose_text()
    assert "Put back" not in out
    assert "reloads on its new settings" in out


@pytest.mark.parametrize("which", APPLIERS)
def test_an_image_without_a_health_check_is_not_waited_on(tmp_path, which):
    site, env = _llm_site(tmp_path)
    env.update({"FAKE_LLM_NO_HEALTH": "1", "AICB_LLM_READY_SECONDS": "0"})
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "Waiting for the model to load" not in out
    assert "aicyberauditbox-llm:1.2" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_without_a_health_check_a_server_that_falls_over_is_still_put_back(tmp_path, which):
    site, env = _llm_site(tmp_path)
    env.update({"FAKE_LLM_NO_HEALTH": "1", "AICB_LLM_READY_SECONDS": "0",
                "FAKE_LLM_RESTARTS_AFTER": "1"})
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "stopped while loading on the new settings" in out
    assert "aicyberauditbox-llm:1.1" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_a_server_that_restarted_straight_away_is_put_back(tmp_path, which):
    """It stated its slots, then crashed; "restart: always" had it up again by
    the time it was looked at."""
    site, env = _llm_site(tmp_path)
    env["FAKE_LLM_RESTARTS"] = "1"
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "restarted on the new settings" in out
    assert "aicyberauditbox-llm:1.1" in site.compose_text()


@pytest.mark.parametrize("which", APPLIERS)
def test_a_copy_error_is_not_mistaken_for_an_older_image(tmp_path, which):
    """Only Docker's "Could not find the file" means the image has no settings."""
    site, env = _llm_site(tmp_path)
    env["FAKE_CP_ERROR"] = "write /tmp/new: no space left on device"
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "carries no model server settings" not in out
    assert "could not read the settings from the new application image" in out
    assert "no space left on device" in out
    assert "build" not in site.calls()


@pytest.mark.parametrize("which", APPLIERS)
def test_a_put_back_that_did_not_happen_is_reported(tmp_path, which):
    site, env = _llm_site(tmp_path, log=REFUSED_LOG)
    env["FAKE_LLM_STUCK"] = "1"
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "did not come back by itself" in out
    assert "AI model server: NOT RUNNING" in out


@pytest.mark.parametrize("which", APPLIERS)
def test_a_failure_after_the_switch_names_a_backup_that_undoes_it(tmp_path, which):
    """The app line needed no change, so only the model server's backup exists;
    the app then failed to restart. The message must not say nothing changed."""
    already = ("services:\n  shakthidb:\n    image: aicyberauditbox-shakthidb:3.10\n"
               "  llm:\n    image: aicyberauditbox-llm:1.1\n"
               "  llm-embed:\n    image: aicyberauditbox-llm-embed:1.1\n"
               "  app:\n    image: aicyberauditbox-app:1.2.4\n")
    site, env = _llm_site(tmp_path, compose_text=already)
    env["FAKE_APP_UP_FAIL"] = "1"
    rc, out = _run(which, site, env)
    assert rc == 1, out
    assert "Nothing has been changed" not in out
    assert "The configuration WAS updated before this failed" in out
    assert "docker-compose.yml.before-llm-1.2.bak" in out


@pytest.mark.parametrize("which", APPLIERS)
def test_an_llm_image_missing_from_the_machine_is_left_alone(tmp_path, which):
    site, env = _llm_site(tmp_path, llm_present=False)
    rc, out = _run(which, site, env)
    assert rc == 0, out
    assert "is not on this machine" in out
    assert "build" not in site.calls()


@pytest.mark.skipif(sys.platform != "win32" or SH is None, reason="needs Windows PowerShell and sh")
def test_a_temp_folder_with_a_space_in_its_name_still_works(tmp_path):
    """A Windows user folder like C:\\Users\\John Smith puts a space in TEMP.
    Escaped quotes inside "$( ... )" are dropped by Windows PowerShell 5.1, and
    the copy split that path in two."""
    site, env = _llm_site(tmp_path)
    spaced = tmp_path / "John Smith temp"
    spaced.mkdir()
    env.update({"TMP": str(spaced), "TEMP": str(spaced)})
    rc, out = _run_ps1(site, env)
    assert rc == 0, out
    assert REBUILD in site.calls(), out


@needs_sh
def test_an_llm_update_does_not_run_the_settings_step(tmp_path):
    site, env = _llm_site(tmp_path)
    for p in site.update.iterdir():
        p.unlink()
    site.add_tar("aicyberauditbox-llm-1.2.tar")
    rc, out = site.run("apply_update.sh", env)
    assert rc == 0, out
    assert "Model server startup settings" not in out
    assert "build" not in site.calls()


# --------------------------------------------------------------- the wiring

def test_the_app_image_carries_the_script_where_the_appliers_read_it():
    df = _read("Dockerfile.app")
    assert "COPY Dockerfile.llm.rebase /app/llm-config/Dockerfile.llm.rebase" in df
    assert "COPY docker/llm-entrypoint.sh /app/llm-config/docker/llm-entrypoint.sh" in df
    # After the offline model check: a change to the script rebuilds one small
    # layer, not the OCR caches or the check above it.
    assert df.index("/app/llm-config/") > df.index("from doctr.models import ocr_predictor")
    for name in ("apply_update.sh", "apply_update.ps1"):
        assert "/app/llm-config/." in _read(name), name


def test_make_update_starts_the_script_it_now_ships_with_the_app():
    bat = _read("make_update.bat")
    app = bat[bat.index("\n:app\n"):bat.index("\n:llmconf\n")]
    assert app.index("llm_image_check.py --rebase-on newest") < app.index("build_customer_bundle.py")


def test_the_image_check_looks_for_the_script():
    assert '"llm-config"' in _read(os.path.join("scripts", "image_smoke_test.py"))


def test_the_appliers_read_the_lines_the_script_prints():
    """The appliers match the script's own words; pin both ends."""
    script = _read(os.path.join("docker", "llm-entrypoint.sh"))
    assert "-> $SLOTS slot(s)" in script
    assert "Not enough memory to serve" in script
    assert "LLM_SLOTS_OVERRIDE set" in script
    assert "WARNING:" in script
