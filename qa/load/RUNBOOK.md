# Load test: 10, 20 and 30 concurrent auditors

How to measure **latency, CPU, RAM and file size** on a deployed AICyberAuditBox,
and what to write down.

Two scripts do the work, and they run in **two different places at the same time**:

| script | runs on | measures |
|---|---|---|
| `load_test.py` | your laptop | latency, file size, tokens, pass/fail per user |
| `qa/load/resource_sampler.py` | the server | CPU % and RAM per container |

The API cannot report the server's own CPU and RAM — it only knows the core
count. That is why the sampler runs separately, on the machine being measured.

---

## Before you start

**On your laptop**

```bash
pip install requests pyotp
```

**Know the numbers you are testing against.** The LLM container sizes itself from
the RAM and cores it can see, and prints what it chose. Read it first, because it
sets the ceiling on how many audits can run at once:

```bash
docker logs aicyberauditbox_llm | grep "LLM ENTRYPOINT"
```

Expect something like `Detected 64.00GB and 32 core(s) ... -> 12 slot(s)`.
A run with more concurrent users than slots is measuring the **queue**, not the
engine — which is a fair thing to measure, as long as you say so in the result.

**Check disk.** Each user uploads the evidence file and stores findings.

---

## Step 1 — a smoke run first

Never start with 30. Confirm the plumbing works and see upload latency alone:

```bash
python load_test.py --base-url http://<server-ip>:8000 --users 10 --smoke
```

`--smoke` uploads concurrently but does not start the audits, so it finishes in
seconds. If accounts fail to provision here, fix that before measuring anything.

---

## Step 2 — start the sampler on the server

In its own terminal, **on the server**, before each measured run:

```bash
python3 qa/load/resource_sampler.py --label 10users
```

It prints a line every 5 seconds and writes `qa/load/results/10users.csv`.
Leave it running. Stop it with Ctrl+C when the load test finishes, and it prints
the peak and mean per container.

> **CPU % is per one core.** On a 32-core box, 3200% is fully busy, not an error.
> The summary says so at the top.

---

## Step 3 — the measured run

From your laptop, while the sampler runs:

```bash
python load_test.py --base-url http://<server-ip>:8000 \
    --users 10 --controls 64,1,17 --mode Deep \
    --admin-user <admin> --admin-pass <pass> --admin-totp-secret <base32>
```

The three `--admin-*` options are what produce the per-session detail — files,
total MB, extracted characters, controls, tokens and latency per control. Without
them you only get pass/fail and wall time.

Then stop the sampler (Ctrl+C) and record both outputs.

**Repeat for 20 and 30**, changing `--users` and the sampler's `--label` each
time. Keep everything else identical, or the runs are not comparable.

---

## Step 4 — file size as a variable

File size is one of the metrics, so vary it deliberately rather than leaving it
at whatever the default is:

```bash
python load_test.py --base-url http://<server-ip>:8000 --users 10 --file "samples/.../122_Fraud_Analytics_Policy_API_Auth.docx"   # 44 KB
python load_test.py --base-url http://<server-ip>:8000 --users 10 --file "samples/.../10 -Multi-factor authentication operator.docx"   # 912 KB
```

The script prints the file and its size at startup, and the per-session report
gives total MB uploaded and **extracted characters** — the second is what
actually drives the work, since a scanned PDF of the same size yields far more
OCR work than a text-native one.

---

## What to record

One row per run:

| users | file KB | wall time | avg latency/session | avg latency/control | tokens | LLM CPU peak % | LLM RAM peak MB | app RAM peak MB | failures |
|---|---|---|---|---|---|---|---|---|---|
| 10 | | | | | | | | | |
| 20 | | | | | | | | | |
| 30 | | | | | | | | | |

Latency, tokens and file size come from `load_test.py`. The CPU and RAM columns
come from the sampler's summary. Failures are the `FAILED:` lines.

---

## Reading the result honestly

**Queueing is not failure.** Once concurrent audits exceed the LLM's slot count,
requests wait for a slot. Latency per user rises while throughput stays flat.
That is the system working as designed, and the number to report is where the
curve bends — it is the sizing advice a customer needs.

**A refusal is not a crash.** `/audit/start` admits against licensed seats and a
hardware limit, and the resource guard stops an audit if memory gets critical. If
users are turned away at 30, say which limit did it — that is a capacity finding,
not a defect.

**Latency is dominated by the model, not the web app.** Each control is roughly
1,500 generated tokens on CPU. Measured on a 10-core machine that was about four
minutes per control; a 32-core customer machine was about one minute. Multiply by
`--controls` before wondering why a 30-user Deep run takes hours — use one or two
controls if you only want the concurrency curve.

**Run each configuration twice.** The first run of a session warms caches. If the
two disagree by more than a little, say so rather than reporting the better one.
