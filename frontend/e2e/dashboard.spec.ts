import { test, expect } from "@playwright/test";

// Smoke: dashboard loads, hero+search render, filter UI is interactive,
// and the URL reflects state changes. Backend may be empty (no ingested
// data yet) — we only assert UI scaffold + URL sync, not actual hits.
test("dashboard renders and search filter syncs to URL", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: /Kestrel/i })).toBeVisible();

  const searchBox = page.getByRole("searchbox").or(page.getByPlaceholder(/검색/));
  await searchBox.first().fill("openssl");

  // Debounce window is 300ms — wait a bit longer to be safe.
  await page.waitForTimeout(450);

  await expect(page).toHaveURL(/[?&]q=openssl/);

  // Either results or empty state should be present (both are acceptable).
  const results = page.locator("article, li, [data-testid='cve-item']");
  const empty = page.getByText(/조건에 맞는|결과가 없|취약점이 없/);
  await expect(results.first().or(empty)).toBeVisible({ timeout: 10_000 });
});
