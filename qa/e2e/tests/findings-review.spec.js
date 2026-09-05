const { test, expect } = require("@playwright/test");
const { loginAsAuditor } = require("./helpers");

test.describe("Findings review", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAuditor(page);
    // Assumes at least one finding already exists from a prior completed audit in
    // this test account's session history — see qa/README.md for seeding notes.
    // The Audit Records Workspace (#tab-audit-records) is part of the main app
    // shell, not behind a separate nav tab, so no extra navigation click is needed.
  });

  test("opens a finding, edits severity/status, and saves", async ({ page }) => {
    const modifyBtn = page.locator("#findings-container").getByText("✏️ Modify").first();
    await modifyBtn.waitFor({ state: "visible", timeout: 15000 });
    await modifyBtn.click();

    await expect(page.locator("#edit-finding-modal")).toBeVisible();

    await page.selectOption("#edit-finding-status", "Partially Compliant");
    await page.selectOption("#edit-finding-severity", "P2 High");
    await page.fill("#edit-finding-recommendation", "E2E test: recommendation updated by Playwright.");

    await page.click('#edit-finding-form button[type="submit"]');

    await expect(page.locator("#edit-finding-modal")).not.toBeVisible();
  });

  test("cancel closes the modal without saving", async ({ page }) => {
    const modifyBtn = page.locator("#findings-container").getByText("✏️ Modify").first();
    await modifyBtn.waitFor({ state: "visible", timeout: 15000 });
    await modifyBtn.click();

    await page.click('#edit-finding-form button:has-text("Cancel")');
    await expect(page.locator("#edit-finding-modal")).not.toBeVisible();
  });
});
