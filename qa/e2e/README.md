# qa/e2e — Playwright UI tests

End-to-end tests against the vanilla HTML/JS frontend in `src/api/static/`. Scoped to this folder —
`package.json` here does not touch the project root (no npm tooling exists there today).

## Setup

```bat
cd qa/e2e
npm install
npx playwright install --with-deps
```

## Run

```bat
:: Full suite (app must already be running, e.g. via run_all.bat)
npx playwright test

:: Single spec
npx playwright test tests/audit-upload.spec.js

:: With browser UI visible, for debugging
npx playwright test --headed
```

## Specs

- `auth.spec.js` — login, forgot-password OTP + QR/2FA flow
- `role-switch.spec.js` — Auditor / Auditee / Admin view switching
- `audit-upload.spec.js` — evidence drop-zone upload, Excel scoping upload, run audit scan
- `findings-review.spec.js` — edit-finding modal (severity, status, recommendation)
- `export.spec.js` — PDF/CSV/DOCX report export
