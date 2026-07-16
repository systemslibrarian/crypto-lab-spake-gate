import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

// Drive the live demo so every dynamic result region is present when axe scans:
// steal the databases, run the offline attack to completion, and step the mask
// animation to its final compute-both-sides panel.
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  })
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true))
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden')
      el.style.display = ''
      el.classList.add('active', 'is-active', 'open')
    })
  })

  // Trigger the compromise flow explicitly (its labels don't match the generic sweep).
  const steal = page.getByRole('button', { name: /steal both server databases/i })
  if (await steal.count()) {
    await steal.first().click().catch(() => {})
    await page.waitForTimeout(150)
  }
  const attack = page.getByRole('button', { name: /run the offline dictionary attack/i })
  if (await attack.count()) {
    await attack.first().click().catch(() => {})
    // Let the (short) real PBKDF2 grind + row rendering finish.
    await page.waitForTimeout(2200)
  }

  // Step the mask animation to the last step so the K-comparison renders.
  // The Next button disables itself at the final step — never wait on it.
  const next = page.getByRole('button', { name: /^Next ›$/ })
  for (let i = 0; i < 5; i++) {
    if (!(await next.count())) break
    if (await next.first().isDisabled()) break
    await next.first().click({ timeout: 2000 }).catch(() => {})
  }

  await page.waitForTimeout(300)
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([])
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await prepare(page)
  await scan(page)
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await prepare(page)
  await scan(page)
})
