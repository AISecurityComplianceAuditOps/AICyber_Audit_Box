# -*- coding: utf-8 -*-
"""Record CPU and RAM per container while a load test runs.

load_test.py measures latency, file sizes and token counts through the API, but
the API cannot report the machine's own utilisation -- it only knows the host's
core count. This samples `docker stats` on the server itself, writes every
sample to CSV, and prints the peak and mean per container at the end, so a run
at 10, 20 and 30 users can be compared on the same axes.

Run it ON THE SERVER (it needs the Docker socket), in its own terminal, while
load_test.py runs from your machine:

    python3 qa/load/resource_sampler.py --label 10users --duration 1800

    # or until you stop it with Ctrl+C
    python3 qa/load/resource_sampler.py --label 30users

Each run writes qa/load/results/<label>.csv and prints a summary. Nothing here
talks to the application, so it cannot affect what it is measuring beyond the
cost of one `docker stats` call per interval.
"""
import argparse
import csv
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

_UNITS = {"b": 1.0 / (1024 * 1024), "kib": 1.0 / 1024, "kb": 1.0 / 1024,
          "mib": 1.0, "mb": 1.0, "gib": 1024.0, "gb": 1024.0,
          "tib": 1024.0 * 1024, "tb": 1024.0 * 1024}

_stop = False


def _on_signal(_sig, _frm):
    global _stop
    _stop = True


def to_mb(text):
    """'1.234GiB' -> megabytes. Returns None when the value is unparseable."""
    t = (text or "").strip().lower()
    num = ""
    for ch in t:
        if ch.isdigit() or ch in ".-":
            num += ch
        else:
            break
    if not num:
        return None
    unit = t[len(num):].strip()
    try:
        return round(float(num) * _UNITS.get(unit, 1.0), 2)
    except ValueError:
        return None


def to_pct(text):
    try:
        return round(float(str(text).replace("%", "").strip()), 2)
    except (TypeError, ValueError):
        return None


def sample():
    """One `docker stats` pass. Returns a list of per-container dicts."""
    out = subprocess.run(
        ["docker", "stats", "--no-stream", "--format",
         "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError("docker stats failed: %s" % out.stderr.strip()[:200])
    rows = []
    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, cpu, mem, mem_pct = parts[0], parts[1], parts[2], parts[3]
        used, _, limit = mem.partition("/")
        rows.append({
            "timestamp": stamp,
            "container": name.strip(),
            "cpu_pct": to_pct(cpu),
            "mem_used_mb": to_mb(used),
            "mem_limit_mb": to_mb(limit),
            "mem_pct": to_pct(mem_pct),
        })
    return rows


def host_cores():
    """Total cores, so a CPU% over 100 can be read against what exists.

    docker stats reports percent of ONE core: 800% on an 8-core box is fully
    busy, not an error.
    """
    try:
        return os.cpu_count() or 0
    except Exception:
        return 0


def summarise(rows, cores):
    by = {}
    for r in rows:
        by.setdefault(r["container"], []).append(r)
    print("")
    print("=" * 78)
    print("  RESOURCE SUMMARY   (%d samples, host has %d core(s))" % (len(rows), cores))
    print("  CPU%% is of ONE core: %d%% means every core busy." % (cores * 100 if cores else 100))
    print("=" * 78)
    print("  %-28s %9s %9s %11s %11s" % ("container", "cpu avg", "cpu peak",
                                         "mem avg MB", "mem peak MB"))
    for name in sorted(by):
        rs = by[name]
        cpus = [r["cpu_pct"] for r in rs if r["cpu_pct"] is not None]
        mems = [r["mem_used_mb"] for r in rs if r["mem_used_mb"] is not None]
        print("  %-28s %9s %9s %11s %11s" % (
            name[:28],
            "%.1f" % (sum(cpus) / len(cpus)) if cpus else "-",
            "%.1f" % max(cpus) if cpus else "-",
            "%.0f" % (sum(mems) / len(mems)) if mems else "-",
            "%.0f" % max(mems) if mems else "-"))
    print("")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True,
                    help="names the output file, e.g. 10users")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between samples")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="stop after this many seconds (0 = until Ctrl+C)")
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      "results"))
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, "%s.csv" % args.label)
    cores = host_cores()

    print("Sampling every %.0fs -> %s" % (args.interval, path))
    print("Host cores: %d. Stop with Ctrl+C.\n" % cores)

    rows = []
    started = time.time()
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["timestamp", "container", "cpu_pct",
                                                "mem_used_mb", "mem_limit_mb", "mem_pct"])
        writer.writeheader()
        while not _stop:
            try:
                batch = sample()
            except Exception as e:
                # A sampler must never be the reason a load test is abandoned.
                print("  sample skipped: %s" % e)
                batch = []
            for r in batch:
                writer.writerow(r)
                rows.append(r)
            fh.flush()          # so the file is readable while the run continues
            if batch:
                busiest = max(batch, key=lambda r: r["cpu_pct"] or 0)
                print("  %s  %-24s cpu %6s%%  mem %8s MB"
                      % (batch[0]["timestamp"][11:19], busiest["container"][:24],
                         busiest["cpu_pct"], busiest["mem_used_mb"]))
            if args.duration and (time.time() - started) >= args.duration:
                break
            time.sleep(args.interval)

    if not rows:
        print("No samples recorded -- is Docker running, and are the containers up?")
        return 1
    summarise(rows, cores)
    print("  Samples written to %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
