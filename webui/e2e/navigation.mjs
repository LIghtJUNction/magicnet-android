/** Use the same visible page controls on phones and desktops. */
export async function navigateToPage(page, tab) {
  const rail = page.locator(".desktop-rail");
  if (await rail.isVisible()) {
    const target = rail.locator(`[data-tab="${tab}"]`);
    if (!await target.isVisible()) await rail.locator(".mn-nav-more-toggle").click();
    await target.click();
    return;
  }
  const target = page.locator(`.mobile-nav [data-tab="${tab}"]`);
  if (await target.count()) await target.click();
  else {
    await page.locator('.mobile-nav [aria-haspopup="dialog"]').click();
    await page.locator(`.mn-workspace-sheet [data-page="${tab}"]`).click();
  }
}
