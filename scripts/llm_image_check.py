# -*- coding: utf-8 -*-
"""Check an LLM image starts the way it will at a customer -- before it ships.

    python scripts/llm_image_check.py --image aicyberauditbox-llm:1.2
    python scripts/llm_image_check.py --image aicyberauditbox-llm:1.2 --refresh
    python scripts/llm_image_check.py --rebase-on newest

--image      checks that image as it is.
--refresh    first rebuilds the image's startup script from docker/ when the
             one inside it differs (make_bundle.bat: an image of that version
             may already exist from an earlier build, and reusing it shipped
             the OLD script).
--rebase-on  builds docker/llm-entrypoint.sh onto an LLM image already here
             (a tag, or "newest"), checks the result and removes it again --
             what make_update.bat option 2 ships, tested before it is zipped.

WHY THIS EXISTS

make_update.bat option 1 tests the application image (tests, a scan, the
reports, Postgres upgrades). The model image had no check at all: options 2
and 3 and make_bundle.bat shipped whatever built, and a startup script that
fails, a model file that is not in the image, or an engine without a flag the
script relies on would be found at the customer. The last one matters now:
the fix for audits held at 0% on a 16-core / 32GB Linux VM loads the weights
into memory, and the script leaves the flag out, silently, when the engine
lacks it. This check's first real run found exactly that: the shipped engine
had renamed --no-mmap to --load-mode, and the weights would have stayed mapped.

WHAT IT CHECKS

  1. the image's /llm-entrypoint.sh is byte-identical to docker/llm-entrypoint.sh;
  2. this llama.cpp build can load the weights into memory: --load-mode
     (build 10991 and later, the shipped 1.1 engine) or --no-mmap (older);
  3. the completion server, started as on a 16-core / 32GB machine with the
     customer compose's settings: serves the 12B, opens 3 slots (the sizing
     keeps 8GB for the rest of the stack), holds the weights in memory, and
     passes every optional flag the engine supports;
  4. the embedding server reaches its start with the embedding model;
  5. both model files are in the image.

llama-server itself is replaced by a stub for the start -- only --help reaches
the real binary -- so this takes seconds and loads no weights. Output is ASCII.
Exit code 0 when every check passes, 1 otherwise.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ENTRYPOINT = os.path.join(REPO, "docker", "llm-entrypoint.sh")

MODEL_12B = "/models/gemma-4-12B-it-Q8_0.gguf"
MODEL_EMBED = "/models/nomic-embed-text-v1.5.f16.gguf"
TEMP_TAG = "aicyberauditbox-llm:entrypoint-check"

# The machine that prompted the stack reserve and --no-mmap: 16 cores, 32GB,
# run with docker-compose.customer.yml's context per request.
PROBE_MEMORY = "32g"
PROBE_CORES = "16"
PROBE_CTX = "32768"
# 32 x 0.85 - 12.5 (weights) - 8 (rest of the stack) = 6.7GB for KV; one
# 32768-token q8_0 slot is 32 x 0.12 x 0.5 = 1.92GB; int(6.7 / 1.92) = 3.
EXPECTED_SLOTS = 3

# Stands in for llama-server: --help goes to the real binary (the script reads
# the engine's flags from it), anything else prints the arguments it was given.
STUB = ('#!/bin/sh\n'
        'if [ "$1" = "--help" ]; then exec /app/llama-server.real --help; fi\n'
        'echo "PROBE-START $*"\n')
RUN = ('#!/bin/sh\n'
       'set -e\n'
       'for f in /models/*; do echo "MODEL-FILE $(basename "$f")"; done\n'
       'mv /app/llama-server /app/llama-server.real\n'
       'cp /probe/stub.sh /app/llama-server\n'
       'chmod +x /app/llama-server\n'
       'exec /llm-entrypoint.sh\n')


# ---------------------------------------------------------------- pure helpers

def newest_llm_tag(tags_text, skip=()):
    """The first usable tag in `docker images aicyberauditbox-llm` order
    (newest first); never this script's own temporary tag."""
    for line in (tags_text or "").splitlines():
        tag = line.strip()
        if not tag or tag == "<none>" or tag == TEMP_TAG.split(":", 1)[1] or tag in skip:
            continue
        return tag
    return None


def start_args(output):
    """The arguments the entrypoint started llama-server with, or None."""
    for line in (output or "").splitlines():
        if line.startswith("PROBE-START"):
            return line[len("PROBE-START"):].split()
    return None


def arg_value(args, flag):
    try:
        return args[args.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def evaluate_completion(output, returncode, help_text):
    """[(ok, message)] for the completion start on the probe machine."""
    results = []
    args = start_args(output)
    if returncode != 0 or args is None:
        tail = " | ".join((output or "").strip().splitlines()[-4:])
        return [(False, "the completion server would not start: %s" % (tail or "no output"))]
    results.append((arg_value(args, "-m") == MODEL_12B,
                    "serves the 12B model (%s)" % arg_value(args, "-m")))
    slots = arg_value(args, "-np")
    results.append((slots == str(EXPECTED_SLOTS),
                    "%s slots on 16 cores / 32GB (expected %d)" % (slots, EXPECTED_SLOTS)))
    results.append(("Model weights held in memory: yes" in output, "weights held in memory"))
    for flag, label in (("--kv-unified", "shared KV cache"), ("-ctk", "8-bit KV cache")):
        if flag in (help_text or ""):
            results.append((flag in args, "%s: %s passed" % (label, flag)))
    # Newer engines replaced --no-mmap with --load-mode; "none" is the mode
    # that reads the weights into memory (measured: RssAnon, not RssFile).
    if "--load-mode" in (help_text or ""):
        results.append((arg_value(args, "--load-mode") == "none",
                        "weights loaded, not mapped: --load-mode none passed"))
    elif "--no-mmap" in (help_text or ""):
        results.append(("--no-mmap" in args, "weights loaded, not mapped: --no-mmap passed"))
    return results


def engine_can_load_into_memory(help_text):
    return "--load-mode" in (help_text or "") or "--no-mmap" in (help_text or "")


def evaluate_embedding(output, returncode):
    args = start_args(output)
    if returncode != 0 or args is None:
        tail = " | ".join((output or "").strip().splitlines()[-4:])
        return [(False, "the embedding server would not start: %s" % (tail or "no output"))]
    return [(arg_value(args, "-m") == MODEL_EMBED and "--embedding" in args
             and arg_value(args, "--port") == "11435",
             "embedding server starts with %s on 11435" % arg_value(args, "-m"))]


def evaluate_models(output):
    present = {line.split(" ", 1)[1].strip() for line in (output or "").splitlines()
               if line.startswith("MODEL-FILE ")}
    return [(os.path.basename(p) in present, "model file in the image: %s" % os.path.basename(p))
            for p in (MODEL_12B, MODEL_EMBED)]


# ---------------------------------------------------------------- docker side

def docker(*args, text=True):
    return subprocess.run(["docker"] + list(args), capture_output=True, text=text,
                          **({"errors": "replace"} if text else {}))


def image_exists(tag):
    return docker("image", "inspect", tag).returncode == 0


def image_entrypoint(image):
    r = docker("run", "--rm", "--network", "none", "--entrypoint", "cat", image,
               "/llm-entrypoint.sh", text=False)
    return r.stdout if r.returncode == 0 else None


def rebase(base, tag):
    """docker/llm-entrypoint.sh onto `base`, tagged `tag` (seconds, no weights copied)."""
    print("  building %s: docker/llm-entrypoint.sh on %s" % (tag, base))
    r = subprocess.run(["docker", "build", "-q", "-f", "Dockerfile.llm.rebase",
                        "--build-arg", "LLM_BASE_IMAGE=" + base, "-t", tag, "."],
                       cwd=REPO, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        print("  FAIL the rebuild failed:\n" + (r.stderr or r.stdout)[-1500:])
        return False
    return True


def probe(image, env, memory=PROBE_MEMORY):
    tmp = tempfile.mkdtemp(prefix="llmcheck-")
    try:
        for name, body in (("stub.sh", STUB), ("run.sh", RUN)):
            with open(os.path.join(tmp, name), "w", encoding="ascii", newline="\n") as f:
                f.write(body)
        cmd = ["run", "--rm", "--network", "none", "--user", "0", "-m", memory,
               "-v", "%s:/probe:ro" % tmp, "--entrypoint", "sh"]
        for k, v in env.items():
            cmd += ["-e", "%s=%s" % (k, v)]
        cmd += [image, "/probe/run.sh"]
        r = docker(*cmd)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_image(image):
    """Runs checks 1-5 on `image`; prints them; True when all pass."""
    results = []
    want = open(ENTRYPOINT, "rb").read()
    have = image_entrypoint(image)
    results.append((have == want, "startup script in the image is docker/llm-entrypoint.sh"
                    + ("" if have == want else " -- it is an OLDER one" if have else " -- could not read it")))
    r = docker("run", "--rm", "--network", "none", "--entrypoint", "/app/llama-server", image, "--help")
    help_text = (r.stdout or "") + (r.stderr or "")
    results.append((engine_can_load_into_memory(help_text),
                    "this llama.cpp build can hold the weights in memory (--load-mode or --no-mmap)"))

    out, rc = probe(image, {"LLM_MODE": "completion", "LLM_MODEL": "12b",
                            "MIN_CTX_PER_REQUEST": PROBE_CTX, "LLM_CORES_OVERRIDE": PROBE_CORES})
    results += evaluate_completion(out, rc, help_text)
    results += evaluate_models(out)
    out_e, rc_e = probe(image, {"LLM_MODE": "embedding"})
    results += evaluate_embedding(out_e, rc_e)

    for ok, message in results:
        print("    %s %s" % ("ok  " if ok else "FAIL", message))
    return all(ok for ok, _ in results)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--image", help="the LLM image to check")
    ap.add_argument("--refresh", action="store_true",
                    help="with --image: rebuild its startup script from docker/ first if it differs")
    ap.add_argument("--rebase-on", metavar="TAG",
                    help='build docker/llm-entrypoint.sh onto aicyberauditbox-llm:TAG (or "newest"), check, remove')
    args = ap.parse_args()
    if not args.image and not args.rebase_on:
        ap.error("give --image or --rebase-on")

    if docker("info").returncode != 0:
        print("  FAIL Docker is not running.")
        return 1

    print("")
    temp = None
    if args.rebase_on:
        tag = args.rebase_on
        if tag == "newest":
            tag = newest_llm_tag(docker("images", "aicyberauditbox-llm", "--format", "{{.Tag}}").stdout)
            if not tag:
                print("  FAIL no aicyberauditbox-llm image on this PC to test the startup script on.")
                print("       Load the one customers run (docker load -i ...), then run this again.")
                return 1
        base = "aicyberauditbox-llm:" + tag
        if not image_exists(base):
            print("  FAIL %s is not on this PC." % base)
            return 1
        if not rebase(base, TEMP_TAG):
            return 1
        image, temp = TEMP_TAG, TEMP_TAG
    else:
        image = args.image
        if not image_exists(image):
            print("  FAIL %s is not on this PC." % image)
            return 1
        if args.refresh and image_entrypoint(image) != open(ENTRYPOINT, "rb").read():
            print("  %s carries an older startup script -- rebuilding that layer" % image)
            if not rebase(image, image):
                return 1

    print("  LLM image check  (%s)" % (image if not temp else "docker/llm-entrypoint.sh on " + base))
    try:
        ok = check_image(image)
    finally:
        if temp:
            docker("rmi", temp)
    print("")
    print("  LLM IMAGE CHECK PASSED" if ok else "  LLM IMAGE CHECK FAILED -- do not ship this")
    print("")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
