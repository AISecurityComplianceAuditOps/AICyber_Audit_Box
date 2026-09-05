# qa/security — SAST + container scanning

Scans this project's own source and Docker images. Unrelated to `src/core/parsers/trivy_parser.py`,
which parses *uploaded* Trivy JSON reports as audit evidence — a different, application-level
concern.

## Semgrep (static analysis of `src/`)

```bat
pip install semgrep
semgrep --config p/python --config p/security-audit --config qa/security/semgrep.yml src/
```

`qa/security/semgrep.yml` holds project-specific custom rules (subprocess shell=True,
hardcoded-looking secret assignments, string-built SQL) on top of the two registry rulesets.

## Trivy (scans this project's own Docker images)

```bat
:: after building the images via docker-compose
trivy image --ignorefile qa/security/trivy-ignore.yaml aicyberauditbox-app:latest
trivy image --ignorefile qa/security/trivy-ignore.yaml aicyberauditbox-llm:latest
```

Both are report-only for now — findings don't block merges until reviewed and the ruleset/ignore
list is tuned to this codebase.
