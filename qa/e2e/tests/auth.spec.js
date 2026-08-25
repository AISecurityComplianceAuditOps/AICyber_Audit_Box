const { test, expect } = require("@playwright/test");
const { loginAsAuditor, currentOtp } = require("./helpers");

test.describe("Authentication", () => {
  test("auditor can log in with username/password + TOTP", async ({ page }) => {
    await loginAsAuditor(page);
    await expect(page.locator("#app-shell")).toBeVisible();
    await expect(page.locator("#auth-overlay")).not.toBeVisible();
  });

  test("wrong password shows an error, not a silent failure", async ({ page }) => {
    await page.goto("/");
    await page.click("#role-auditor-btn");
    await page.fill("#username-input", "nobody@example.com");
    await page.fill("#password-input", "definitely-wrong");
    await page.click("#auth-submit-btn");

    await expect(page.locator("#auth-error")).toBeVisible();
  });

  test("wrong OTP code is rejected", async ({ page }) => {
    const { USERNAME, PASSWORD } = require("./helpers");
    await page.goto("/");
    await page.click("#role-auditor-btn");
    await page.fill("#username-input", USERNAME);
    await page.fill("#password-input", PASSWORD);
    await page.click("#auth-submit-btn");

    await page.waitForSelector("#otp-form", { state: "visible" });
    await page.fill("#otp-input", "000000");
    await page.click('#otp-form button[type="submit"]');

    await expect(page.locator("#auth-error")).toBeVisible();
    await expect(page.locator("#app-shell")).not.toBeVisible();
  });

  test("forgot-password flow reaches the OTP reset step", async ({ page }) => {
    await page.goto("/");
    await page.click("#forgot-password-btn");
    await expect(page.locator("#forgot-password-modal")).toBeVisible();
    // Filling the actual reset requires a mailbox/QR scan step that can't be
    // automated here — this test only verifies the modal opens and exposes the
    // expected fields (fp-otp-input, fp-qr-img) from src/api/static/index.html.
    await expect(page.locator("#fp-otp-input")).toBeAttached();
  });
});
