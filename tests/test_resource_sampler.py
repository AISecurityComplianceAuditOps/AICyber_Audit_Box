# -*- coding: utf-8 -*-
"""The load-test resource sampler parses what `docker stats` actually prints.

    pytest tests/test_resource_sampler.py -v

WHY THIS EXISTS

load_test.py measures latency, file size and tokens through the API, but the API
cannot report the machine's own utilisation -- it only knows the host's core
count, and says so. qa/load/resource_sampler.py fills that gap by sampling
`docker stats` on the server during a run.

Its whole job is reading one text format correctly. `docker stats` mixes units
within a single line ("1.234GiB / 30.5GiB", "512MiB / 2GiB") and reports CPU as a
percentage of ONE core, so 800% on an 8-core host is fully busy rather than an
error. Getting either wrong would misreport the capacity numbers the sizing
advice to a customer is based on, so the parsing is pinned here against real
output rather than checked by eye during a run.
"""
import importlib.util
import os

import pytest


_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "qa", "load", "resource_sampler.py")
_spec = importlib.util.spec_from_file_location("resource_sampler", _PATH)
sampler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sampler)


# Real `docker stats --no-stream` output from this project's stack.
REAL_OUTPUT = (
    "aicyberauditbox_app\t12.34%\t1.234GiB / 30.5GiB\t4.05%\n"
    "aicyberauditbox_llm\t793.21%\t18.7GiB / 30.5GiB\t61.31%\n"
    "shakthidb_service\t0.51%\t512MiB / 30.5GiB\t1.64%\n"
    "aicyberauditbox_redis\t0.09%\t7.766MiB / 30.5GiB\t0.02%\n"
)


@pytest.fixture
def stats(monkeypatch):
    """Stand in for the docker CLI, returning the output above."""
    class _R:
        returncode = 0
        stdout = REAL_OUTPUT
        stderr = ""
    monkeypatch.setattr(sampler.subprocess, "run", lambda *a, **k: _R())
    return sampler.sample()


# ── the units docker mixes within one line ───────────────────────────────────

@pytest.mark.parametrize("text,mb", [
    ("1.234GiB", 1263.62), ("18.7GiB", 19148.8), ("512MiB", 512.0),
    ("7.766MiB", 7.77), ("30.5GiB", 31232.0), ("900kB", 0.88), ("2GB", 2048.0),
])
def test_memory_units_are_converted(text, mb):
    assert sampler.to_mb(text) == pytest.approx(mb, rel=0.001)


@pytest.mark.parametrize("junk", ["", "   ", None, "--", "n/a"])
def test_unparseable_memory_gives_none_rather_than_zero(junk):
    """Zero would be averaged in as a real reading and pull the numbers down."""
    assert sampler.to_mb(junk) is None


@pytest.mark.parametrize("text,pct", [("12.34%", 12.34), ("793.21%", 793.21), ("0.00%", 0.0)])
def test_cpu_percentages_are_read(text, pct):
    assert sampler.to_pct(text) == pct


@pytest.mark.parametrize("junk", ["", None, "--%", "n/a"])
def test_unparseable_percentage_gives_none(junk):
    assert sampler.to_pct(junk) is None


# ── a sample of the real stack ───────────────────────────────────────────────

def test_every_container_is_captured(stats):
    assert sorted(r["container"] for r in stats) == [
        "aicyberauditbox_app", "aicyberauditbox_llm",
        "aicyberauditbox_redis", "shakthidb_service"]


def test_the_llm_container_is_read_correctly(stats):
    llm = next(r for r in stats if r["container"] == "aicyberauditbox_llm")
    assert llm["cpu_pct"] == 793.21, "CPU is per ONE core; 793% is ~8 cores busy"
    assert llm["mem_used_mb"] == pytest.approx(19148.8, rel=0.001)
    assert llm["mem_limit_mb"] == pytest.approx(31232.0, rel=0.001)
    assert llm["mem_pct"] == 61.31


def test_the_used_and_limit_halves_are_not_swapped(stats):
    for r in stats:
        assert r["mem_used_mb"] <= r["mem_limit_mb"], r


def test_every_sample_is_timestamped(stats):
    for r in stats:
        assert r["timestamp"].count(":") >= 2 and "T" in r["timestamp"], r


# ── it must not take the load test down with it ──────────────────────────────

def test_a_docker_failure_raises_rather_than_returning_junk(monkeypatch):
    class _R:
        returncode = 1
        stdout = ""
        stderr = "Cannot connect to the Docker daemon"
    monkeypatch.setattr(sampler.subprocess, "run", lambda *a, **k: _R())
    with pytest.raises(RuntimeError) as e:
        sampler.sample()
    assert "Cannot connect" in str(e.value)


def test_short_or_blank_lines_are_skipped(monkeypatch):
    class _R:
        returncode = 0
        stdout = "\nbroken-line-with-no-tabs\naicyberauditbox_app\t1.0%\t10MiB / 1GiB\t1.0%\n"
        stderr = ""
    monkeypatch.setattr(sampler.subprocess, "run", lambda *a, **k: _R())
    rows = sampler.sample()
    assert len(rows) == 1 and rows[0]["container"] == "aicyberauditbox_app"


def test_the_summary_reports_peak_and_mean(capsys):
    rows = [
        {"container": "llm", "cpu_pct": 100.0, "mem_used_mb": 1000.0},
        {"container": "llm", "cpu_pct": 800.0, "mem_used_mb": 2000.0},
        {"container": "app", "cpu_pct": 10.0, "mem_used_mb": 100.0},
    ]
    sampler.summarise(rows, cores=8)
    out = capsys.readouterr().out
    assert "800.0" in out and "450.0" in out, out      # llm peak and mean cpu
    assert "2000" in out and "1500" in out, out        # llm peak and mean memory
    assert "800%" in out, "the reader is not told what 100% means"
