import { expect, test } from '@playwright/test'

test('M and N distinguish RFC derivation evidence from work rerun in-page', async ({ page }) => {
  await page.goto('.')

  const constants = page.locator('.constants')
  await expect(constants.getByText('RFC hash-to-curve derivation seed (shown, not recomputed here)')).toHaveCount(2)
  await expect(constants.getByText('RFC compressed point loaded and curve-checked by this demo')).toHaveCount(2)
  await expect(constants).toContainText('we do not re-run the full hash-to-curve derivation in-page')
  await expect(constants).not.toContainText('derived by hashing the seed')
})
