#!/bin/sh
# Single entrypoint for both LLM roles this app needs, selected via LLM_MODE
# so one built image serves both docker-compose services (completion + embed)
# instead of maintaining two near-identical Dockerfiles.
#
# LLM_MODE=completion (default): main generation server, port 11434.
#   -np (parallel slot count) auto-sizes to this container's actual available
#   RAM, mirroring the same formula src/core/resource_guard.py uses for the
#   app's own concurrency semaphore (see that file for the full explanation):
#   baseline ~8GB fixed overhead, ~2.5GB KV cache per additional full-context
#   slot, 0.85 safety margin, floor of 1. Duplicated here in shell because
#   this is a separate container image with no Python app code to import
#   resource_guard.py from.
# LLM_MODE=embedding: embedding-only server, port 11435, nomic-embed-text.
#   No -np/context concerns here -- single-purpose, short requests.
#
# Reads cgroup memory limits first (this container's actual allowance, which
# may be less than host total RAM if the operator set --memory on it),
# falling back to /proc/meminfo (host total) if no cgroup limit is set.
#
# CPU thread count (-t) is auto-detected the same way (cgroup CPU quota
# first, falling back to the host's logical core count) -- LLM_THREADS and
# EMBED_THREADS previously had a hardcoded default of 4 regardless of the
# machine's actual core count, so a customer VM with 8, 16, or more vCPUs
# silently ran generation on a fraction of its real compute unless someone
# manually knew to override it. This makes "use everything available" the
# out-of-the-box default, matching how RAM/slot sizing already behaves,
# while still letting LLM_THREADS/EMBED_THREADS/LLM_CORES_OVERRIDE win
# explicitly for an operator who wants to reserve cores for something else.

LLM_MODE="${LLM_MODE:-completion}"

detect_total_mem_gb() {
    if [ -f /sys/fs/cgroup/memory.max ]; then
        limit=$(cat /sys/fs/cgroup/memory.max)
        if [ "$limit" != "max" ]; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
        if [ "$limit" -lt 1000000000000 ] 2>/dev/null; then
            awk -v b="$limit" 'BEGIN { printf "%.2f", b / 1073741824 }'
            return
        fi
    fi
    kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    awk -v k="$kb" 'BEGIN { printf "%.2f", k / 1048576 }'
}

detect_cpu_cores() {
    # cgroup v2: "quota period" in microseconds, e.g. "800000 100000" == 8 cores.
    # "max" as the quota means uncapped -- fall through to the next check.
    if [ -f /sys/fs/cgroup/cpu.max ]; then
        read -r quota period < /sys/fs/cgroup/cpu.max
        if [ "$quota" != "max" ] && [ -n "$quota" ] && [ -n "$period" ] && [ "$period" -gt 0 ] 2>/dev/null; then
            cores=$(awk -v q="$quota" -v p="$period" 'BEGIN { c = int(q / p); if (c < 1) c = 1; print c }')
            echo "$cores"
            return
        fi
    fi
    # cgroup v1: cfs_quota_us / cfs_period_us. quota of -1 means uncapped.
    if [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] && [ -f /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        if [ "$quota" -gt 0 ] 2>/dev/null && [ "$period" -gt 0 ] 2>/dev/null; then
            cores=$(awk -v q="$quota" -v p="$period" 'BEGIN { c = int(q / p); if (c < 1) c = 1; print c }')
            echo "$cores"
            return
        fi
    fi
    # No cgroup CPU limit set -- use the host's actual logical core count.
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return
    fi
    grep -c ^processor /proc/cpuinfo
}

DETECTED_CORES=$(detect_cpu_cores)
if [ -z "$DETECTED_CORES" ] || [ "$DETECTED_CORES" -lt 1 ] 2>/dev/null; then
    DETECTED_CORES=4
fi
if [ -n "$LLM_CORES_OVERRIDE" ]; then
    DETECTED_CORES="$LLM_CORES_OVERRIDE"
fi

if [ "$LLM_MODE" = "embedding" ]; then
    EMBED_T="${EMBED_THREADS:-$DETECTED_CORES}"
    echo "[LLM ENTRYPOINT] Detected ${DETECTED_CORES} CPU core(s) -> using ${EMBED_T} thread(s) for the embedding server."
    echo "[LLM ENTRYPOINT] Starting embedding server (nomic-embed-text) on port 11435."
    exec /app/llama-server \
        --host 0.0.0.0 --port 11435 \
        -m /models/nomic-embed-text-v1.5.f16.gguf \
        -t "$EMBED_T" \
        --embedding
fi

# completion mode
# These MUST stay in sync with resource_guard.py and llm_client.py:
# model_gb=4.0, slot_gb=0.5 — if you change one, change all three.
FIXED_OVERHEAD_GB="${RESOURCE_GUARD_FIXED_OVERHEAD_GB:-4.5}"
PER_SLOT_GB="${RESOURCE_GUARD_PER_SLOT_GB:-0.5}"
SAFETY_MARGIN="${RESOURCE_GUARD_SAFETY_MARGIN:-0.85}"

TOTAL_GB=$(detect_total_mem_gb)
MAX_SLOTS=8   # cap matches llm_client.py: max(1, min(8, ...))
SLOTS=$(awk -v t="$TOTAL_GB" -v o="$FIXED_OVERHEAD_GB" -v p="$PER_SLOT_GB" -v m="$SAFETY_MARGIN" -v max="$MAX_SLOTS" '
    BEGIN {
        usable = (t * m) - o
        slots = int(usable / p)
        if (slots < 1)    slots = 1
        if (slots > max)  slots = max
        print slots
    }
')

if [ -n "$LLM_SLOTS_OVERRIDE" ]; then
    SLOTS="$LLM_SLOTS_OVERRIDE"
    echo "[LLM ENTRYPOINT] LLM_SLOTS_OVERRIDE set -- using $SLOTS slots instead of auto-detection."
else
    echo "[LLM ENTRYPOINT] Detected ${TOTAL_GB}GB available -> auto-sized to $SLOTS concurrent slot(s)."
fi

LLM_T="${LLM_THREADS:-$DETECTED_CORES}"
echo "[LLM ENTRYPOINT] Detected ${DETECTED_CORES} CPU core(s) -> using ${LLM_T} thread(s) for the completion server."

exec /app/llama-server \
    --host 0.0.0.0 --port 11434 \
    -m /models/google_gemma-4-E4B-it-Q4_K_M.gguf \
    -c 32768 -np "$SLOTS" \
    -t "$LLM_T" \
    -b 512 -ub 256 \
    --cont-batching \
    --flash-attn on
