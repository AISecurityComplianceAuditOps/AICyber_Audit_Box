const path = require("path");
const { test, expect } = require("@playwright/test");
const { loginAsAuditor } = require("./helpers");

const SAMPLE_EVIDENCE = path.join(__dirname, "..", "..", "..", "samples", "audit_evidence", "dummy_evidence.txt");

test.describe("Evidence upload + audit scan", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAuditor(page);
  });

  test("uploads a file via the evidence file input", async ({ page }) => {
    // #evidence-file-input is a hidden <input type=file> triggered by the drop-zone
    // (src/api/static/index.html) — Playwright can set files on it directly without
    // needing to simulate the drag-and-drop UI interaction.
    await page.setInputFiles("#evidence-file-input", SAMPLE_EVIDENCE);

    // The uploaded filename should surface somewhere in the evidence list UI.
    await expect(page.getByText("dummy_evidence.txt")).toBeVisible({ timeout: 15000 });
  });

  test("selects a framework and control, then runs an audit scan", async ({ page }) => {
    await page.setInputFiles("#evidence-file-input", SAMPLE_EVIDENCE);
    await expect(page.getByText("dummy_evidence.txt")).toBeVisible({ timeout: 15000 });

    await page.selectOption("#framework-select", { index: 1 });

    // Controls are rendered dynamically into #controls-checkbox-container after a
    // framework is chosen — wait for at least one checkbox, then select it.
    const firstControl = page.locator("#controls-checkbox-container input[type=checkbox]").first();
    await firstControl.waitFor({ state: "visible", timeout: 15000 });
    await firstControl.check();

    await page.click("#run-analysis-btn");

    // A running audit should flip the Run/Stop button pair and show progress —
    // asserting the Stop button becomes visible confirms the scan actually started.
    await expect(page.locator("#stop-analysis-btn")).toBeVisible({ timeout: 15000 });
  });
});
