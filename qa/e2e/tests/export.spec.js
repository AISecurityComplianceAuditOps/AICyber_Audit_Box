const { test, expect } = require("@playwright/test");
const { loginAsAuditor } = require("./helpers");

test.describe("Report export", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAuditor(page);
  });

  test("PDF export triggers a download", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download", { timeout: 20000 });
    await page.click("#btn-export-pdf");
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.pdf$/i);
  });

  test("DOCX export triggers a download", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download", { timeout: 20000 });
    await page.click("#btn-export-docx");
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.docx$/i);
  });

  test("CSV export triggers a download", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download", { timeout: 20000 });
    await page.click("#btn-export-csv");
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.csv$/i);
  });
});
