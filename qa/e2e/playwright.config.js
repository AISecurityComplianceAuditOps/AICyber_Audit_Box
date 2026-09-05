// @ts-check
const { defineConfig, devices } = require("@playwright/test");

// App must already be running (e.g. via run_all.bat) before these tests execute.
// All three launch scripts (run_all.bat, run_api.bat, run_api_llamacpp.bat) start
// uvicorn as plain HTTP on port 8000 -- none pass --ssl-certfile/--ssl-keyfile, so
// cert.pem/key.pem are generated but never actually used locally. Default to HTTP
// to match; ignoreHTTPSErrors stays harmless if E2E_BASE_URL is ever pointed at a
// real HTTPS deployment (e.g. the Azure VM setup, which does terminate TLS).
module.exports = defineConfig({
  testDir: "./tests",
  fullyParallel: false, // audit sessions/uploads are stateful; run serially to avoid cross-test interference
  retries: process.env.CI ? 1 : 0,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:8000",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
