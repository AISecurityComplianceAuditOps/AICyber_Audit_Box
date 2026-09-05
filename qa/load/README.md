# qa/load — Locust load/concurrency tests

Complements (does not replace) `tests/test_10_users_audit_evidence.py`, which stays as-is. This is a
repeatable, configurable Locust suite for repeated load runs rather than a one-off script.

## Setup

```bat
pip install locust
```

## Run

App must already be running (e.g. via `run_all.bat`) before starting a load run.

```bat
:: Interactive web UI at http://localhost:8089
locust -f qa/load/locustfile.py --host https://localhost:8000

:: Headless, fixed run
locust -f qa/load/locustfile.py --host https://localhost:8000 --users 10 --spawn-rate 2 --run-time 5m --headless
```
