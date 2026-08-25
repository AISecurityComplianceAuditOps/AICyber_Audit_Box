const { test, expect } = require("@playwright/test");

test.describe("Role selector on the login screen", () => {
  test("defaults to Auditor and switches to Admin / Auditee", async ({ page }) => {
    await page.goto("/");

    // Default role is Auditor (config.js: localStorage.getItem("shakti_role") || "auditor"),
    // not Admin -- the static HTML and config.js used to disagree on this (a real bug fixed
    // alongside this test), so this assertion is load-bearing, not decorative.
    await expect(page.locator("#role-auditor-btn")).toHaveClass(/active/);

    await page.click("#role-admin-btn");
    await expect(page.locator("#role-admin-btn")).toHaveClass(/active/);
    await expect(page.locator("#role-auditor-btn")).not.toHaveClass(/active/);

    await page.click("#role-auditee-btn");
    await expect(page.locator("#role-auditee-btn")).toHaveClass(/active/);
    await expect(page.locator("#role-admin-btn")).not.toHaveClass(/active/);
  });

  test("role description text updates per role", async ({ page }) => {
    await page.goto("/");
    const before = await page.locator("#role-desc").textContent();

    // Auditor is the default (see the test above), so click a DIFFERENT role --
    // clicking the already-active one is a no-op and the description won't change.
    await page.click("#role-admin-btn");
    const after = await page.locator("#role-desc").textContent();

    expect(after).not.toEqual(before);
  });
});
