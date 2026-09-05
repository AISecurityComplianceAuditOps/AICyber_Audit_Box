# Golden Dataset Evaluation Report
**Date:** 2026-08-14 23:43:42

## Metrics (binary, COMPLIANT = positive class)
- **Total cases:** 28 (0 errored)
- **Accuracy:** 78.6%
- **Precision:** 100.0%
- **Recall:** 53.8%
- **F1:** 70.0%
- **False Positives:** 0 | **False Negatives:** 6
- **Retrieval Recall Rate:** 100.0%

Target from the RAG accuracy plan: Accuracy >= 80%, ideally 85-90%. Treat this as directional until the dataset covers ~30-50 real examples across ~15-20 controls -- 4 seeded cases on one control isn't enough to draw real conclusions from.

## Per-case results

| ID | Control | Expected | Actual | Match | Retrieval Recall | Time (s) |
|---|---|---|---|---|---|---|
| GD-001 | 8.5 | COMPLIANT | COMPLIANT | PASS | True | 410.63 |
| GD-002 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 372.5 |
| GD-003 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 597.95 |
| GD-004 | 8.5 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 601.76 |
| GD-005 | 5.1 | COMPLIANT | COMPLIANT | PASS | True | 249.9 |
| GD-006 | 5.1 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 334.01 |
| GD-007 | 5.9 | COMPLIANT | NON_COMPLIANT | FAIL | True | 307.16 |
| GD-008 | 5.9 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 295.06 |
| GD-009 | 5.15 | COMPLIANT | NON_COMPLIANT | FAIL | True | 341.57 |
| GD-010 | 5.15 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 310.18 |
| GD-011 | 5.23 | COMPLIANT | COMPLIANT | PASS | True | 315.64 |
| GD-012 | 5.23 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 315.48 |
| GD-013 | 6.1 | COMPLIANT | COMPLIANT | PASS | True | 334.49 |
| GD-014 | 6.1 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 314.17 |
| GD-015 | 6.3 | COMPLIANT | COMPLIANT | PASS | True | 406.82 |
| GD-016 | 6.3 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 681.79 |
| GD-017 | 7.1 | COMPLIANT | COMPLIANT | PASS | True | 309.91 |
| GD-018 | 7.1 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 349.46 |
| GD-019 | 7.4 | COMPLIANT | NON_COMPLIANT | FAIL | True | 327.92 |
| GD-020 | 7.4 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 346.77 |
| GD-021 | 8.1 | COMPLIANT | NON_COMPLIANT | FAIL | True | 356.22 |
| GD-022 | 8.1 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 524.88 |
| GD-023 | 8.7 | COMPLIANT | NON_COMPLIANT | FAIL | True | 306.22 |
| GD-024 | 8.7 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 323.95 |
| GD-025 | 8.16 | COMPLIANT | NON_COMPLIANT | FAIL | True | 296.04 |
| GD-026 | 8.16 | NON_COMPLIANT | NON_COMPLIANT | PASS | N/A | 581.58 |
| GD-027 | 8.24 | COMPLIANT | COMPLIANT | PASS | True | 306.43 |
| GD-028 | 8.24 | NON_COMPLIANT | NON_COMPLIANT | PASS | True | 317.16 |