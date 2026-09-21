# AICyberAuditBox application image.
#
# Kept as a separate file (Dockerfile.app) from the existing Dockerfile at the
# repo root, which only builds the ShaktiDB Postgres image -- that one is
# untouched. This one packages the FastAPI app + static frontend + the LLM
# model weights, so `docker-compose up` is genuinely one command with nothing
# to install separately: pip dependencies are installed at build time here,
# and the model file is baked directly into the image (already present
# locally in this repo, no download step needed).
#
# Deliberately does NOT touch src/ -- this only packages the existing,
# unmodified application code.

# Ships readable .py by default. COMPILE_SOURCE=1 selects the Nuitka-compiled
# variant instead -- see the compiler stage and app-1 below, and make_bundle.bat,
# which asks and passes it through.
ARG COMPILE_SOURCE=0

FROM python:3.11-slim AS builder

# System build dependencies for packages with native extensions
# (psycopg2-binary ships wheels so no libpq-dev needed; easyocr/opencv and
# sentence-transformers pull in a fair amount at pip-install time).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# CPU-only torch installed FIRST, deliberately, before requirements.txt.
# sentence-transformers depends on torch but doesn't pin a CPU/GPU variant,
# so a plain `pip install -r requirements.txt` resolves the default (CUDA)
# build and pulls several GB of unused NVIDIA libraries -- this app never
# runs torch on a GPU (llama-server handles all LLM compute separately over
# HTTP). Installing the CPU wheel first satisfies that dependency before pip
# ever considers the CUDA variant.
# Deliberately BEFORE `COPY requirements.txt`. Docker invalidates every layer
# after a changed COPY, so with the copy first, editing any line of
# requirements.txt re-downloaded torch -- a slow, failure-prone transfer that
# has nothing to do with what changed. Editing one pin should not cost that.
#
# Versions are pinned to the same values requirements.txt carries. Unpinned,
# this installed whatever the CPU index called latest, and if that differed
# from the pin below, the next command reinstalled torch from PyPI -- the CUDA
# build, several GB of unused NVIDIA libraries -- which is the exact outcome
# this split exists to prevent. Keep the two in step.
#
# --timeout/--retries are well above pip's defaults (15s, 5): both indexes have
# timed out mid-transfer on this connection, and a single slow response aborts
# the whole build.
RUN pip install --no-cache-dir --user --timeout 120 --retries 10 \
        torch==2.13.0 torchvision==0.28.0 \
        --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir --user --timeout 120 --retries 10 \
        -r requirements.txt psycopg2-binary



# ---------------------------------------------------------------------------
# Optional: compile src/ into a single binary so the shipped image holds no
# readable Python. Only built when COMPILE_SOURCE=1 selects app-1 below;
# Docker skips unreferenced stages entirely, so the default build never pays
# for this.
#
# --module (not --standalone): src/ becomes ONE extension module that the
# existing `uvicorn src.api.main:app` command imports exactly as it imports the
# package today, so nothing about how the app starts changes.
#
# Deliberately NOT passing --python-flag=no_docstrings. It is the obvious way
# to strip the docstrings that remain readable inside the binary, and it
# segfaults on import -- already discovered on this project, do not re-try it
# without testing the built image.
FROM builder AS compiler

RUN pip install --no-cache-dir --user nuitka

WORKDIR /compile
COPY src/ /compile/src/

RUN python -m nuitka --module src --include-package=src \
        --output-dir=/compile/out --no-pyi-file --remove-output --assume-yes-for-downloads

# The 41 non-.py files under src/ -- 13 knowledge JSON, the frontend, 17 fonts,
# and the bundled branding in src/branding -- are NOT inside the .so. They are read from disk at runtime, so they are
# staged back into the same relative layout the source tree had. Two separate
# things depend on that layout:
#   * 15 __file__-relative loads (pqc_crypto_db walks ../knowledge, and so on)
#   * StaticFiles(directory="src/api/static"), which is relative to the
#     working directory, not to __file__
# install -D recreates each parent directory as it copies.
RUN cd /compile && find src -type f ! -name '*.py' \
        -exec install -D {} /compile/out/{} \;



FROM python:3.11-slim AS base

# Runtime system libraries needed by easyocr's OpenCV dependency and by
# libraries that render/parse office documents and images.
#
# libreoffice-writer-nogui renders the ISO report. That report's design lives
# inside the firm's own Sample report.docx -- cover page, running header, table
# styling -- so the DOCX exporter fills the template in while the PDF exporter
# used to redraw an approximation of it, and the two drifted apart. The PDF is
# now produced by rendering the same DOCX, which is only possible with a
# converter present. The -nogui variant omits the desktop stack: ~200MB rather
# than the ~700MB full suite, and it never needs a display.
#
# fonts-liberation supplies metric-compatible stand-ins for Arial / Times New
# Roman / Courier New. Without them LibreOffice substitutes whatever it can
# find, and the substitute's different metrics reflow the document -- so the
# PDF would silently paginate differently from the Word original it is supposed
# to match.
#
# The app still runs as a non-root user with no home-directory writes needed:
# each conversion gets a private LibreOffice profile in a temp directory (see
# _docx_bytes_to_pdf), so nothing here requires a shared writable profile.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libgomp1 \
    libreoffice-writer-nogui \
    fonts-liberation \
    fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

# Non-root user -- standard container hardening, no reason to run as root here.
RUN useradd --create-home --uid 1000 appuser

COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Application source is NOT copied here -- it is the one thing that differs
# between the readable and compiled variants, so it is copied in app-0 / app-1
# below. Everything above and below this line is shared by both, which also
# means the ~1.6GB of OCR caches are built and cached once.
#
# config/retrieval_config.json (TOP_K tuning per file type) was missing from
# this image entirely -- load_top_k_config() (src/core/retrieval.py) found no
# file at that path inside the container, silently created a fresh one using
# the plain code defaults (12 for every file type), and the repo actual
# tuned values (e.g. 40 for pdf/docx, 45 for xlsx/csv) never reached the
# running app. Confirmed via container logs showing the CONFIG line loading
# 12 for every type instead of the real config files values.
COPY config/ /app/config/
# ISO DOCX export's branded template (report_exporter.py::_export_iso_template_docx)
# looks for this at VAPT/Sample report.docx or Sample report.docx relative to the
# app's own directory -- neither was ever copied into this image, so
# template_path always stayed None inside the container and every ISO export
# silently fell back to the plainer programmatic DOCX generator instead of the
# real template. Only the root-level copy is added here (not the VAPT/ one --
# .dockerignore excludes the whole VAPT/ directory from the build context
# entirely, and Docker cannot reliably re-include a single file from an
# already-excluded directory); the file is byte-identical either way and the
# code's own fallback loop already tries this path second.
COPY ["Sample report.docx", "/app/Sample report.docx"]
COPY docker/wait_for_postgres.py /app/docker/wait_for_postgres.py
COPY docker/generate_secrets.sh /app/docker/generate_secrets.sh
RUN chmod +x /app/docker/generate_secrets.sh

# Persisted, volume-backed data (generated secrets, SQLite fallback file if
# ever used, etc.) -- survives container restarts/recreates.
RUN mkdir -p /app/data

# Note: model weights are NOT copied here -- they live in the separate LLM
# container (Dockerfile.llm), which the app talks to over HTTP via
# LLM_HOSTS/EMBEDDING_HOST, exactly like it already talks to llama-server.exe
# natively today.

# Bake doctr OCR and SentenceTransformer Reranker model caches directly into the image
# so they are baked into the container for 100% offline air-gapped operation without build-time internet dependency.
COPY --chown=appuser:appuser docker/cache/doctr /home/appuser/.cache/doctr
COPY --chown=appuser:appuser docker/cache/huggingface /home/appuser/.cache/huggingface



# ---------------------------------------------------------------------------
# The two source variants. Docker builds only the one named by COMPILE_SOURCE.

# app-0: readable Python. The default, and byte-identical to what this image
# has always shipped.
FROM base AS app-0
COPY src/ /app/src/


# app-1: compiled. The .so plus the 39 staged data files, and no .py at all.
#
# /app/src/ exists here as a data directory with no __init__.py, alongside
# /app/src.cpython-311-*.so. Python resolves `import src` to the extension
# module: a bare directory is only ever treated as a namespace package, which
# is the lowest-priority match and loses to a file loader. The directory is
# therefore data, not a shadowing package -- but it is the reason this image
# must never be built with a stray .py left under /app/src.
FROM base AS app-1
COPY --from=compiler /compile/out/src*.so /app/
COPY --from=compiler /compile/out/src/ /app/src/

# Prove the compile actually works before this image can be tagged.
#
# This exists because the failure it catches is silent. pqc_crypto_db._load_json
# resolves its four JSON files by walking up from __file__ -- which compiling
# into a single .so moves -- and on failure it prints a warning and returns {}.
# A broken compile would therefore start cleanly, run audits, and return empty
# PQC results at a customer site with no internet and no source to inspect.
# Failing the build here costs minutes; failing at the customer costs a
# rebuilt bundle and a shipped false result.
# The offline flags and cache paths are set inline rather than inherited: this
# stage runs before the ENV block and as root, so without them a stray model
# load inside the import would look in root's empty cache and quietly DOWNLOAD
# during the build -- passing here, then failing at an air-gapped customer.
# Set this way, the check runs under the same conditions the container will.
RUN HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/home/appuser/.cache/huggingface \
    DOCTR_CACHE_DIR=/home/appuser/.cache/doctr \
    python -c "\
import src.core.parsers.pqc_crypto_db as m; \
assert m.X509_OID_DB, 'pqc_x509_oids.json did not load from the compiled module'; \
assert m.IANA_CIPHER_DB, 'iana_tls_ciphersuites.json did not load'; \
assert m.LIBOQS_ALGO_DB, 'liboqs_algorithms.json did not load'; \
assert m.CWE_NIST_DB, 'cwe_nist_mappings.json did not load'; \
import os; \
assert os.path.isdir('/app/src/api/static'), 'frontend assets were not staged'; \
assert not any(f.endswith('.py') for _, _, fs in os.walk('/app/src') for f in fs), \
    'readable .py found under /app/src -- the compiled image must ship none'; \
import src.api.main; \
print('compiled source verified:', len(m.X509_OID_DB), 'OIDs, app imports')"


# ---------------------------------------------------------------------------
# COMPILE_SOURCE picks which of the two stages above becomes the final image.
# This resolves against the ARG declared before the first FROM: a global ARG is
# in scope for FROM lines (and only for FROM lines), which is exactly the case
# here. Do not "fix" this by adding an ARG inside a stage -- that one would be
# scoped to the stage and would not reach this FROM.
FROM app-${COMPILE_SOURCE} AS final

RUN chown -R appuser:appuser /app /home/appuser/.cache
USER appuser

# Hard offline guarantee at container runtime: the models above are already
# cached in this image layer, so transformers/sentence-transformers/huggingface-hub/doctr
# operate strictly offline with zero external network attempts.
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 DOCTR_CACHE_DIR=/home/appuser/.cache/doctr

# Verify model loading in pure offline mode during build
RUN python -c "from doctr.models import ocr_predictor; ocr_predictor(pretrained=True); from sentence_transformers import CrossEncoder; CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2'); CrossEncoder('BAAI/bge-reranker-base')"

EXPOSE 8000

# 1. Generate/reuse a persisted JWT_SECRET (docker/generate_secrets.sh).
# 2. Pre-flight blocks startup until Postgres is confirmed reachable (see
#    docker/wait_for_postgres.py for why this exists instead of relying on
#    database.py's own fallback behavior).
# 3. Start the API.
# The .generated_env source is GUARDED, not unconditional.
#
# generate_secrets.sh writes that file only when it had to generate a secret. If
# the operator set JWT_SECRET in the compose environment -- which
# docker-compose.customer.yml explicitly offers ("Uncomment to pin one yourself
# instead") -- the script correctly treats the explicit value as authoritative and
# exits without writing anything. The unguarded `. /app/data/.generated_env` that
# followed then failed with "sh: 1: .: cannot open /app/data/.generated_env", the
# && chain broke, and the container exited before uvicorn ever started.
#
# So following the documented instruction to pin your own secret produced a
# container that would not boot. Verified by execution: identical image, boots
# without JWT_SECRET, dies instantly with it.
#
# `|| true` keeps the chain alive when the file is absent; JWT_SECRET is already
# in the environment in that case, so the export below still does its job. The
# operator's own secret is deliberately NOT written to the volume.
CMD ["sh", "-c", "\
    ./docker/generate_secrets.sh && \
    { [ -f /app/data/.generated_env ] && . /app/data/.generated_env || true; } && \
    export JWT_SECRET && \
    python docker/wait_for_postgres.py && \
    python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 \
"]
