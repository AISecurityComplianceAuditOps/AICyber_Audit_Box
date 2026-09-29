# -*- coding: utf-8 -*-
"""The model container leaves memory for the rest of the stack and keeps its
weights in memory.

    pytest tests/test_llm_memory_reserve.py -v

On a 16-core / 32GB GCP VM an ISO audit sat at 0% for 30 minutes: the model
container sized 7 slots (12.5GB weights + 13.4GB KV = ~26GB) as if it owned
the machine, Linux evicted the memory-mapped weights, and after a long idle the
first request waited while 12.7GB were read back from a network disk (~3% CPU,
not one token). The same bundle idle for two days on a Windows machine never
showed it: run_all.bat sizes from FREE memory and keeps 2.5GB aside, and a
local SSD reloads in seconds.

The container now keeps LLM_STACK_RESERVE_GB (8) for the app, ShaktiDB, the
embedding server and the OS, and loads the weights (--no-mmap). The sizing
itself was run on 32 / 64 / 124 / 24 / 16 GB: 3 / 17 / 44 / 1 (with a warning)
/ refused, as before for 16.
"""
import os
import re

from src.core import deployment_sizing

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = open(os.path.join(ROOT, "docker", "llm-entrypoint.sh"), encoding="utf-8").read()


def test_the_slot_count_leaves_memory_for_the_rest_of_the_stack():
    assert 'STACK_RESERVE_GB="${LLM_STACK_RESERVE_GB:-8}"' in ENTRY
    assert "usable = (t * m) - o - r" in ENTRY, "the slot count must subtract the reserve"


def test_the_planner_plans_what_the_container_runs():
    default = float(re.search(r'LLM_STACK_RESERVE_GB:-([0-9.]+)', ENTRY).group(1))
    assert deployment_sizing._FIXED_OVERHEAD_GB == default


def test_the_planner_on_the_machines_that_prompted_this():
    assert deployment_sizing.size_deployment(16, 31.33, model_gb=12.7).np_slots == 3
    assert deployment_sizing.size_deployment(64, 124, model_gb=12.7).np_slots == 44


def test_a_machine_that_could_start_before_still_starts():
    """The reserve lowers the slot count; it never adds a refusal."""
    refuse = re.search(r"exit !\(\(\(t \* m\) - o\) < g\)", ENTRY)
    assert refuse, "the refusal must stay 'weights plus one slot do not fit', without the reserve"


def test_the_weights_are_held_in_memory_when_the_build_supports_it():
    assert 'supports_flag "--no-mmap"' in ENTRY
    assert 'EXTRA_ARGS="$EXTRA_ARGS --no-mmap"' in ENTRY
    assert "LLM_MMAP" in ENTRY, "an operator can still choose mapped weights"


def test_the_shipped_engine_gets_its_own_flag_for_it():
    """llama.cpp build 10991 (in aicyberauditbox-llm:1.1) has no --no-mmap; it
    has --load-mode. Measured on that engine with a real model: default mode
    kept the weights in file cache (RssFile 282MB of a 274MB model), and
    --load-mode none in the process's own memory (RssAnon 278MB)."""
    assert 'supports_flag "--load-mode"' in ENTRY
    assert 'EXTRA_ARGS="$EXTRA_ARGS --load-mode none"' in ENTRY
    assert ENTRY.index('supports_flag "--load-mode"') < ENTRY.index('supports_flag "--no-mmap"'), \
        "the newer flag must be tried first: an engine with both is a new one"
    assert "mmap+mlock" not in ENTRY.split("supports_flag \"--load-mode\"")[1][:200]


def test_the_embedding_server_is_unchanged():
    embed = ENTRY[ENTRY.index('if [ "$LLM_MODE" = "embedding" ]'):ENTRY.index("MODEL_PATH")]
    assert "--no-mmap" not in embed and "STACK_RESERVE" not in embed


def test_the_script_runs_on_linux():
    raw = open(os.path.join(ROOT, "docker", "llm-entrypoint.sh"), "rb").read()
    assert b"\r" not in raw
