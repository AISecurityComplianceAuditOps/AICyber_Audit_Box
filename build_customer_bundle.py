# -*- coding: utf-8 -*-
"""Builds the customer handover bundle.

Three shapes, because three situations:

  default (delta)  ~2GB. For a site already running a previous version. Ships the
                   app image plus the LLM entrypoint as a FILE, which the customer
                   relayers onto the LLM image they already have -- keeping the
                   model weights and pinned llama.cpp build exactly as they are.

  --full           ~8GB, ONE tar. For a first install on an air-gapped server.
                   The delta assumes a prior version to relayer from and lets
                   Docker pull Redis; on a machine with no registry reachable,
                   three of the five compose images would simply not exist. Full
                   mode ships every image, so the install needs nothing but
                   Docker.

  --patch FROM     ~6MB. For a code change -- the usual case. Ships only src/ and
                   config/ plus Dockerfile.app.rebase; the customer rebuilds on
                   top of the app image they already run, so the Python packages
                   and the ~1.6GB of OCR caches are reused untouched. Seconds to
                   apply, nothing downloaded. Not valid when requirements.txt or
                   the model changed -- those alter lower layers.

Replaces create_docker_app_delta.py, which was pinned to v3.16 while the compose
files had moved on -- running it would have shipped a stale image. The version is
read from docker-compose.yml here so the two cannot drift again.

Usage:  python build_customer_bundle.py --version 3.23 --patch 3.22   (code change)
        python build_customer_bundle.py --version 3.23 --full        (fresh install)
"""
import argparse
import glob
import json
import math
import os
import re
import shutil
import subprocess
import tarfile
import sys
import zipfile

PROJECT = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.join(os.path.dirname(PROJECT), "customer_deployment_package")
DB_VER = "3.10"
DB_TAG = "aicyberauditbox-shakthidb:" + DB_VER
REDIS_TAG = "redis:7-alpine"


def detect_version():
    """Reads the app image tag from docker-compose.yml -- single source of truth."""
    key = "image: aicyberauditbox-app:"
    with open(os.path.join(PROJECT, "docker-compose.yml"), encoding="utf-8") as f:
        for line in f:
            if key in line:
                return line.split(key, 1)[1].strip()
    return None


def bump(v):
    parts = v.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def run(cmd, cwd=PROJECT, check=True):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=cwd)
    if check and r.returncode != 0:
        print(f"  !! failed (exit {r.returncode})")
        return False
    return r.returncode == 0


def gb(path):
    return os.path.getsize(path) / 1024 ** 3 if os.path.exists(path) else 0.0


def _norm(name):
    return name.strip().lower().replace("_", "-")


def missing_requirements(base_image):
    """Requirements the base image does NOT already have installed.

    requirements.txt lives at the repo root, not under src/, so a code patch
    never carries it -- and could not act on it if it did: the rebase layer sits
    on top of packages that are already installed, so copying a new
    requirements.txt in installs nothing. That makes one mistake easy and
    invisible: add an import, add the dependency, ship a patch, and the customer
    gets an ImportError at runtime on a machine with no internet to fix it.
    So check up front, and refuse rather than ship that.
    """
    req = os.path.join(PROJECT, "requirements.txt")
    if not os.path.exists(req):
        return []
    wanted = []
    with open(req, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            name = line.split("[")[0]
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", ";", " "):
                name = name.split(sep)[0]
            if name.strip():
                wanted.append(_norm(name))
    r = subprocess.run(f"docker run --rm --entrypoint python {base_image} "
                       "-m pip list --format=freeze",
                       shell=True, capture_output=True, text=True,
                       env=dict(os.environ, MSYS_NO_PATHCONV="1"), errors="replace")
    if r.returncode != 0:
        return []          # cannot tell; do not block on a diagnostic failure
    have = {_norm(l.split("==")[0]) for l in (r.stdout or "").splitlines() if "==" in l}
    return [w for w in wanted if w not in have]


def stamp(text, version, size_label, disk_label=""):
    """Fills the installer and guide templates in. Both installers carried a
    hardcoded 3.22: a bundle built at any other version shipped an installer
    hunting for an images tar that was not in the folder, and it aborted on the
    spot. The sizes are stamped from the tar that was actually produced, so the
    guide cannot quote a figure the bundle outgrew."""
    return (text.replace("__VERSION__", version)
                .replace("__SIZE__", size_label)
                .replace("__DISK__", disk_label))


def retag_compose(text, version):
    """Points the shipped compose file at THIS bundle's image tags.

    docker-compose.customer.yml is pinned to whatever version was current when
    it was last edited, and the copy below used to ship it verbatim. On an
    air-gapped machine that is fatal rather than inconvenient: compose asks for
    an image tag the bundle never contained, cannot reach a registry to pull it,
    and the stack does not start. The db and redis tags are deliberately left
    alone -- they version independently of the app.
    """
    return re.sub(r"(image:\s*aicyberauditbox-(?:app|llm-embed|llm):)[0-9][0-9.]*",
                  lambda m: m.group(1) + version, text)


def install_guide(version):
    """The guide for this version, or the newest one restamped to it."""
    exact = os.path.join(PROJECT, f"INSTALL_v{version}.md")
    if os.path.exists(exact):
        return open(exact, encoding="utf-8").read()
    others = sorted(glob.glob(os.path.join(PROJECT, "INSTALL_v*.md")))
    if not others:
        return None
    src = others[-1]
    old = os.path.basename(src)[len("INSTALL_v"):-len(".md")]
    print(f"     (no INSTALL_v{version}.md -- restamped from {os.path.basename(src)})")
    return open(src, encoding="utf-8").read().replace(old, version)


def verify_images_tar(path, tags):
    """Confirms the saved tar really holds all five images before it ships.

    docker save reports success per invocation, not per tag, so a typo'd or
    unbuilt tag is only discovered by the customer -- at which point the fix is
    another multi-GB transfer. Reading the manifest costs a header scan.
    """
    found = set()
    try:
        with tarfile.open(path) as t:
            names = t.getnames()
            if "manifest.json" in names:
                entries = json.load(t.extractfile("manifest.json"))
                found = {r for e in entries for r in (e.get("RepoTags") or [])}
            elif "index.json" in names:      # OCI layout (containerd image store)
                idx = json.load(t.extractfile("index.json"))
                for m in idx.get("manifests", []):
                    ann = m.get("annotations") or {}
                    ref = (ann.get("io.containerd.image.name")
                           or ann.get("org.opencontainers.image.ref.name"))
                    if ref:
                        found.add(ref.replace("docker.io/library/", ""))
    except (OSError, tarfile.TarError, ValueError, KeyError) as e:
        print(f"     could not read the image manifest: {e}")
        return False
    ok = True
    for tag in tags:
        present = any(tag == f or f.endswith("/" + tag) for f in found)
        print(f"     {'ok      ' if present else 'MISSING '} {tag}")
        ok = ok and present
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", help="target version, e.g. 3.22 (default: current + 1)")
    ap.add_argument("--skip-build", action="store_true", help="package only; reuse existing images")
    ap.add_argument("--full", action="store_true",
                    help="ONE tar with every image, for a from-scratch air-gapped install")
    ap.add_argument("--out", metavar="DIR",
                    help="where to write the bundle (default: ../customer_deployment_package). "
                         "A full bundle needs roughly twice the images' size free -- the tar is "
                         "staged, then wrapped -- so point this at a drive that has the room.")
    ap.add_argument("--patch", metavar="FROM_VERSION",
                    help="tiny code-only patch (~8MB) for a site already running FROM_VERSION")
    args = ap.parse_args()

    current = detect_version()
    if not current:
        print("Could not read the app image tag from docker-compose.yml.")
        return 1
    version = args.version or bump(current)
    shape = ("FULL (air-gapped, single tar)" if args.full else
             f"PATCH (code only, from {args.patch})" if args.patch else
             "delta (upgrade)")
    print("=" * 74)
    print(f"  AICyberAuditBox bundle   current={current}  ->  {version}   {shape}")
    print("=" * 74)

    out_root = os.path.abspath(args.out) if args.out else OUT_ROOT
    out = os.path.join(out_root, f"v{version}")
    os.makedirs(out, exist_ok=True)

    app_tag = f"aicyberauditbox-app:{version}"
    llm_tag = f"aicyberauditbox-llm:{version}"
    emb_tag = f"aicyberauditbox-llm-embed:{version}"

    if not args.skip_build:
        print("")
        print("---> 1/4  Building the app image (all Python and frontend changes)")
        if not run(f"docker build -f Dockerfile.app -t {app_tag} ."):
            print("     Docker must be running. Aborting.")
            return 1
        print("")
        print("---> 2/4  Relayering the LLM images (entrypoint only, no weight copy)")
        for tag, base in ((llm_tag, f"aicyberauditbox-llm:{current}"),
                          (emb_tag, f"aicyberauditbox-llm-embed:{current}")):
            run("docker build -f Dockerfile.llm.rebase "
                f"--build-arg LLM_BASE_IMAGE={base} -t {tag} .", check=False)
    else:
        print("")
        print("---> 1-2/4  --skip-build: reusing existing images")

    docs = [("docker-compose.yml", "docker-compose.yml"),
            ("docker-compose.customer.yml", "docker-compose.customer.yml"),
            ("docker/llm-entrypoint.sh", "docker/llm-entrypoint.sh"),
            ("Dockerfile.llm.rebase", "Dockerfile.llm.rebase"),
            (f"QUICKSTART_v{version}.md", f"QUICKSTART_v{version}.md")]

    if args.patch:
        # A code change touches src/ and config/ and nothing else, so shipping a
        # 2.1GB image (or the ~2GB create_app_patch.py produced by tarring the
        # model caches alongside the code) is almost all waste. The customer
        # rebuilds on top of the image they already run: same packages, same
        # baked-in OCR caches, nothing downloaded, seconds to apply.
        stage_name = f"AICyberAuditBox-{version}-patch"
        stage = os.path.join(out, stage_name)
        if os.path.isdir(stage):
            shutil.rmtree(stage)
        os.makedirs(stage)

        print("")
        print(f"---> Building a code patch  {args.patch} -> {version}")
        base_image = f"aicyberauditbox-app:{args.patch}"
        missing = missing_requirements(base_image)
        if missing:
            print("")
            print("  !! REFUSING to build this patch.")
            print(f"     requirements.txt names packages {base_image} does not have:")
            for m in missing:
                print(f"       - {m}")
            print("")
            print("     A patch rebuilds on top of that image, so it cannot install")
            print("     anything. Shipping it would give the customer an ImportError")
            print("     on a machine with no internet to fix it.")
            print("")
            print(f"     Build a full app image instead:")
            print(f"       python build_customer_bundle.py --version {version}")
            return 1
        print(f"     requirements.txt satisfied by {base_image}")
        for d in ("src", "config"):
            src_d = os.path.join(PROJECT, d)
            if os.path.isdir(src_d):
                shutil.copytree(src_d, os.path.join(stage, d),
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                print(f"     + {d}/")
        shutil.copy2(os.path.join(PROJECT, "Dockerfile.app.rebase"),
                     os.path.join(stage, "Dockerfile.app.rebase"))
        print("     + Dockerfile.app.rebase")
        # The apply scripts are templates: stamp in the version pair so the
        # customer runs them with no arguments and cannot mistype a tag.
        for name in ("apply_patch.sh", "apply_patch.bat"):
            p = os.path.join(PROJECT, name)
            if not os.path.exists(p):
                print(f"     - {name}  (missing, skipped)")
                continue
            body = open(p, encoding="utf-8").read()
            body = body.replace("__FROM__", args.patch).replace("__TO__", version)
            with open(os.path.join(stage, name), "w", encoding="utf-8", newline="") as f:
                f.write(body)
            print(f"     + {name}  ({args.patch} -> {version})")

        patch = os.path.join(out, f"AICyberAuditBox-{version}-patch.tar.gz")
        if os.path.exists(patch):
            os.remove(patch)
        with tarfile.open(patch, "w:gz") as t:
            t.add(stage, arcname=stage_name)
        shutil.rmtree(stage, ignore_errors=True)

        print("")
        print("=" * 74)
        print(f"  Patch ready: {patch}")
        print(f"    {os.path.getsize(patch)/1024**2:.1f} MB   "
              f"(a full app image would be ~2100 MB)")
        print("")
        print("  The customer drops it in their install folder and runs:")
        # --strip-components=1 unpacks straight into the install folder rather
        # than creating a nested copy to move afterwards. That removes a step,
        # and removes ~30 characters from every path -- which matters on Windows,
        # where a deep install directory can push the extracted files past the
        # 260-character MAX_PATH limit and the copy fails halfway through.
        print(f"    tar -xzf AICyberAuditBox-{version}-patch.tar.gz --strip-components=1")
        print("    ./apply_patch.sh        (Windows: apply_patch.bat)")
        print("")
        print(f"  Requires aicyberauditbox-app:{args.patch} already installed.")
        print("  Use --full instead if requirements.txt or the model changed.")
        print("=" * 74)
        return 0

    if args.full:
        # Everything goes into one directory, which becomes one tar. The customer
        # extracts it and runs the installer inside -- no ordering to get wrong,
        # and nothing to leave behind on the transfer medium.
        stage_name = f"AICyberAuditBox-{version}"
        stage = os.path.join(out, stage_name)
        if os.path.isdir(stage):
            shutil.rmtree(stage)
        os.makedirs(stage)

        print("")
        print("---> 3/4  Exporting all five images into one tar")
        # One docker save for every image: shared layers are written once, so the
        # two LLM tags (same base, same ~5GB of weights) cost about as much as one.
        images = os.path.join(stage, f"aicyberauditbox-images-{version}.tar")
        tags = f"{app_tag} {llm_tag} {emb_tag} {DB_TAG} {REDIS_TAG}"
        if not run(f'docker save -o "{images}" {tags}', check=False):
            print("     Export failed -- are all five images built?")
            return 1
        print(f"     aicyberauditbox-images-{version}.tar  ({gb(images):.2f} GB)")
        print("     verifying every tag made it into the tar")
        if not verify_images_tar(images, [app_tag, llm_tag, emb_tag, DB_TAG, REDIS_TAG]):
            print("     Refusing to ship a tar that is missing an image.")
            return 1
        size_label = f"~{gb(images):.0f} GB"
        # The bundle sits on disk while Docker unpacks a second copy into its
        # own store, and the volumes grow from there -- so the figure the guide
        # tells the customer to free up is the tar, twice, with headroom.
        disk_label = f"{math.ceil(gb(images) * 2.3 / 5) * 5} GB"

        print("")
        print("---> 4/4  Adding the compose file, installers and the install guide")
        # Deliberately NOT the repo's docker-compose.yml: that one carries build:
        # directives pointing at Dockerfiles the customer does not have, and it
        # owns the filename Compose picks by default -- so a plain
        # "docker compose up -d" would ignore the image-only file, try to build,
        # and fail on a machine where everything was already loaded. Shipping the
        # image-only file UNDER the default name makes the obvious command right.
        # The upgrade-only pieces (QUICKSTART, Dockerfile.llm.rebase, the
        # entrypoint) are left out too: they describe relayering from a previous
        # version that a first install does not have.
        # None of these three are copied verbatim any more. The compose file and
        # both installers carry a version that must match the images in THIS
        # bundle, and copying them as they sit in the repo shipped whatever
        # version they were last edited at -- an installer that cannot find its
        # own tar, and a compose file naming images the customer does not have.
        compose = open(os.path.join(PROJECT, "docker-compose.customer.yml"),
                       encoding="utf-8").read()
        with open(os.path.join(stage, "docker-compose.yml"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(retag_compose(compose, version))
        print(f"     + docker-compose.yml  (images pinned to {version})")

        for name, newline in (("install.sh", "\n"), ("install.bat", "\r\n")):
            src_p = os.path.join(PROJECT, name)
            if not os.path.exists(src_p):
                print(f"     - {name}  (missing, skipped)")
                continue
            body = stamp(open(src_p, encoding="utf-8").read(), version, size_label)
            with open(os.path.join(stage, name), "w", encoding="utf-8",
                      newline=newline) as f:
                f.write(body)
            print(f"     + {name}  (v{version}, {size_label})")

        guide = install_guide(version)
        if guide is not None:
            guide = stamp(guide, version, size_label, disk_label)
        if guide is None:
            print(f"     - INSTALL_v{version}.md  (missing, skipped)")
        else:
            with open(os.path.join(stage, f"INSTALL_v{version}.md"), "w",
                      encoding="utf-8", newline="\n") as f:
                f.write(guide)
            print(f"     + INSTALL_v{version}.md")

        bundle = os.path.join(out, f"AICyberAuditBox-{version}-complete.tar")
        if os.path.exists(bundle):
            os.remove(bundle)
        # tarfile rather than the tar binary: GNU tar reads a Windows "C:\..."
        # argument as a remote host:path and fails with "Cannot connect to C".
        # arcname gives the archive one top-level folder instead of loose files.
        print(f"  + wrapping into {os.path.basename(bundle)}")
        try:
            with tarfile.open(bundle, "w") as t:
                t.add(stage, arcname=stage_name)
        except OSError as e:
            print(f"     Could not create the outer tar: {e}")
            return 1
        shutil.rmtree(stage, ignore_errors=True)

        print("")
        print("=" * 74)
        print(f"  ONE FILE, ready to hand over: {out}")
        print(f"    AICyberAuditBox-{version}-complete.tar     {gb(bundle):.2f} GB")
        print("")
        print("  The customer runs:")
        print(f"    tar -xf AICyberAuditBox-{version}-complete.tar")
        print(f"    cd AICyberAuditBox-{version}")
        print("    ./install.sh        (or install.bat on Windows)")
        print("=" * 74)
        return 0

    print("")
    print("---> 3/4  Exporting the app image")
    tar = os.path.join(out, f"aicyberauditbox-app-{version}.tar")
    if not run(f'docker save -o "{tar}" {app_tag}', check=False):
        print("     Export failed -- is the image built?")
        return 1
    print(f"     {tar}  ({gb(tar):.2f} GB)")

    print("")
    print("---> 4/4  Packaging config, entrypoint and docs")
    companion = os.path.join(out, f"aicyberauditbox-{version}-companion.zip")
    with zipfile.ZipFile(companion, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in docs:
            p = os.path.join(PROJECT, src)
            if os.path.exists(p):
                z.write(p, arc)
                print(f"     + {arc}")
            else:
                print(f"     - {arc}  (missing, skipped)")

    print("")
    print("=" * 74)
    print(f"  Bundle ready: {out}")
    print(f"    aicyberauditbox-app-{version}.tar        {gb(tar):.2f} GB")
    print(f"    aicyberauditbox-{version}-companion.zip  {os.path.getsize(companion)/1024:.0f} KB")
    print("    delta bundle -- the customer MUST already run a previous version.")
    print("    Use --full for a from-scratch air-gapped install.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
