const { TOTP, Secret } = require("otpauth");

// A registered auditor test account is required, with its TOTP secret shared here.
// Register one via the "Create Account" flow once, then set these env vars:
//   E2E_USERNAME, E2E_PASSWORD, E2E_TOTP_SECRET
const USERNAME = process.env.E2E_USERNAME || "";
const PASSWORD = process.env.E2E_PASSWORD || "";
const TOTP_SECRET = process.env.E2E_TOTP_SECRET || "";

function currentOtp() {
  const totp = new TOTP({ secret: Secret.fromBase32(TOTP_SECRET), digits: 6, period: 30 });
  return totp.generate();
}

/**
 * Logs in as the auditor test account and waits for the main app shell to appear.
 * Selectors are the real ids from src/api/static/index.html (auth-overlay form).
 */
async function loginAsAuditor(page) {
  await page.goto("/");
  await page.click("#role-auditor-btn");
  await page.fill("#username-input", USERNAME);
  await page.fill("#password-input", PASSWORD);
  await page.click("#auth-submit-btn");

  await page.waitForSelector("#otp-form", { state: "visible" });
  await page.fill("#otp-input", currentOtp());
  await page.click('#otp-form button[type="submit"]');

  await page.waitForSelector("#app-shell", { state: "visible" });
}

module.exports = { loginAsAuditor, currentOtp, USERNAME, PASSWORD, TOTP_SECRET };
