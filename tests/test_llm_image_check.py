# -*- coding: utf-8 -*-
"""The LLM image check judges a start the way a customer machine would see it.

    pytest tests/test_llm_image_check.py -v

scripts/llm_image_check.py starts a real LLM image with llama-server swapped
for a stub and reads what the startup script would have run. These pin how it
reads that output, without Docker.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import llm_image_check as c  # noqa: E402

HELP = "  --kv-unified  ...\n  -ctk, --cache-type-k TYPE\n  --no-mmap  do not memory-map model\n"
GOOD = """MODEL-FILE gemma-4-12B-it-Q8_0.gguf
MODEL-FILE nomic-embed-text-v1.5.f16.gguf
[LLM ENTRYPOINT] Serving Gemma 4 12B (Q8_0) from /models/gemma-4-12B-it-Q8_0.gguf.
[LLM ENTRYPOINT] Model weights held in memory: yes.
PROBE-START --host 0.0.0.0 --port 11434 -m /models/gemma-4-12B-it-Q8_0.gguf -c 98304 -np 3 -t 16 -b 512 -ub 256 --cont-batching --flash-attn on --kv-unified -ctk q8_0 -ctv q8_0 --no-mmap
"""


def _all_ok(results):
    return all(ok for ok, _ in results)


def test_a_good_start_passes():
    assert _all_ok(c.evaluate_completion(GOOD, 0, HELP))
    assert _all_ok(c.evaluate_models(GOOD))


def test_the_expected_slots_are_the_entrypoint_formula_on_32gb():
    usable = 32 * 0.85 - 12.5 - 8
    per_slot = (int(c.PROBE_CTX) / 1024) * 0.12 * 0.5
    assert c.EXPECTED_SLOTS == max(1, min(int(c.PROBE_CORES), int(usable / per_slot)))


def test_weights_left_mapped_fail():
    out = GOOD.replace(" --no-mmap", "").replace("memory: yes", "memory: no")
    results = c.evaluate_completion(out, 0, HELP)
    assert not _all_ok(results)
    assert any("--no-mmap" in m for ok, m in results if not ok)


# The engine in the shipped aicyberauditbox-llm:1.1 (build 10991): --no-mmap is
# gone, --load-mode replaced it. The first real run of the check caught the
# startup script asking for the old name and leaving the weights mapped.
HELP_NEW = ("  --kv-unified  ...\n  -ctk, --cache-type-k TYPE\n"
            "-lm,   --load-mode MODE   model loading mode (default: auto)\n"
            "   - none: no special loading mode\n")
GOOD_NEW = GOOD.replace("--no-mmap", "--load-mode none")


def test_the_newer_engine_passes_with_load_mode_none():
    assert _all_ok(c.evaluate_completion(GOOD_NEW, 0, HELP_NEW))
    assert c.engine_can_load_into_memory(HELP_NEW)


def test_the_newer_engine_fails_when_weights_stay_mapped():
    mapped = GOOD.replace(" --no-mmap", "").replace("memory: yes", "memory: no")
    assert not _all_ok(c.evaluate_completion(mapped, 0, HELP_NEW))
    assert not _all_ok(c.evaluate_completion(GOOD_NEW.replace("none", "auto"), 0, HELP_NEW))


def test_an_engine_with_neither_flag_is_reported():
    assert not c.engine_can_load_into_memory("  --kv-unified\n  -ctk\n")


def test_the_old_slot_count_fails():
    """7 slots on 32GB is what held the GCP audit at 0%."""
    assert not _all_ok(c.evaluate_completion(GOOD.replace("-np 3", "-np 7"), 0, HELP))


def test_a_flag_the_engine_lacks_is_not_required():
    out = GOOD.replace(" --kv-unified", "")
    assert _all_ok(c.evaluate_completion(out, 0, HELP.replace("--kv-unified", "")))


def test_a_script_that_did_not_start_fails_with_its_last_words():
    out = "[LLM ENTRYPOINT] Model file not found: /models/gemma-4-12B-it-Q8_0.gguf\n"
    results = c.evaluate_completion(out, 1, HELP)
    assert not _all_ok(results) and "Model file not found" in results[0][1]


def test_a_missing_model_file_fails():
    assert not _all_ok(c.evaluate_models(GOOD.replace("MODEL-FILE nomic-embed-text-v1.5.f16.gguf\n", "")))


def test_the_embedding_start():
    ok = "PROBE-START --host 0.0.0.0 --port 11435 -m /models/nomic-embed-text-v1.5.f16.gguf -t 16 --embedding\n"
    assert _all_ok(c.evaluate_embedding(ok, 0))
    assert not _all_ok(c.evaluate_embedding(ok.replace(" --embedding", ""), 0))


def test_newest_tag_skips_untagged_and_its_own_temporary_image():
    assert c.newest_llm_tag("<none>\nentrypoint-check\n1.2\n1.1\n") == "1.2"
    assert c.newest_llm_tag("") is None


def test_the_probe_scripts_are_plain_ascii_with_linux_endings():
    for body in (c.STUB, c.RUN):
        body.encode("ascii")
        assert "\r" not in body
