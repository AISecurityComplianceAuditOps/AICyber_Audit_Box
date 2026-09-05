# qa/monitoring — Sentry setup

Error/crash tracking for the FastAPI backend and the vanilla-JS frontend. Both are wired in as
no-ops — nothing is sent anywhere until you complete the steps below.

## ⚠ Internal/dev use only — never in the customer bundle

Sentry sends error data to an external server (sentry.io) over the internet. `docker-compose.yml`
(your dev/internal stack) is fine to enable this on. **`docker-compose.customer.yml` is the
air-gapped customer deliverable and must never have `SENTRY_DSN` set** — doing so would both break
the "no internet access" guarantee that file documents and risk leaking customer audit data off
their network. This is called out directly in `docker-compose.customer.yml` as well. Only turn
Sentry on for your own dev/staging deployments, never for what ships to a customer.

## Backend (already wired)

`src/api/main.py` calls `sentry_sdk.init(...)` only if the `SENTRY_DSN` env var is set. The
dependency was added to `requirements.txt` (`sentry-sdk[fastapi]`) but not yet installed in your
environment — run `pip install -r requirements.txt` (or `pip install sentry-sdk[fastapi]` directly)
before setting a DSN, otherwise the import will fail at startup.

```bat
set SENTRY_DSN=https://<key>@<org>.ingest.sentry.io/<project>
```

Add it to `run_all.bat` / `run_api.bat` alongside the other env vars (`JWT_SECRET`, `REDIS_URL`,
etc.) once you have a DSN.

## Frontend (already wired, needs one manual step)

`src/api/static/js/config.js` calls `Sentry.init(...)` only if **both** `window.Sentry` and
`window.SENTRY_DSN` are present — otherwise it's a no-op. This app is offline-first, so the SDK is
loaded from a **local file**, not a CDN (same reasoning as bundling `llama-server.exe`/GGUF models
locally instead of fetching them at runtime):

1. Download the Sentry Browser SDK bundle once (from a machine with internet access) —
   `https://browser.sentry-cdn.com/<version>/bundle.min.js` from Sentry's docs — and save it as
   `src/api/static/js/vendor/sentry.bundle.min.js`.
2. Add two lines to `src/api/static/index.html`, **before** the `app.js`/`config.js` script tags:
   ```html
   <script src="/static/js/vendor/sentry.bundle.min.js"></script>
   <script>window.SENTRY_DSN = "https://<key>@<org>.ingest.sentry.io/<project>";</script>
   ```
3. Until step 1–2 are done, `window.Sentry` is undefined and `initSentryIfConfigured()` in
   `config.js` no-ops silently — the app works exactly as before.

## Verifying it works

After setting the DSN(s) and starting the app, trigger a deliberate error (e.g. hit a broken
endpoint, or throw in the browser console) and confirm it shows up in the Sentry dashboard within a
minute or two. Requires your own Sentry account — can't be verified from this environment.
