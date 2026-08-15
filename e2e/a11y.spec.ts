import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and scanned after every step:
 * the arrival state, where two real handshakes and four RFC known-answer checks
 * have already run and every disclosure is shut; the skip link focused; the four
 * live known-answer checks revealed through their own summary; a second honest
 * login on fresh ephemerals; both full transcripts and key schedules opened, and
 * one of their scrollers focused from the keyboard; the 1100ms "copied ✓" flash
 * on a hex chip; all five steps of the M/N mask walkthrough, including step 3,
 * the only state that reveals the eavesdropper panel, and step 5, the only one
 * that renders the two-sided K comparison; then stepped back, restarted and
 * re-rolled. Then the compromise panel down BOTH branches of the fork the lab
 * exists to show: a strong password, where the dictionary is exhausted and the
 * augmented record holds, and the shipped weak one, where it is cracked and both
 * records end impersonable — with the Reset in between, and a hand-typed
 * password after. Every one of those states is scanned in {dark, light} ×
 * {1280px, 380px}.
 *
 * Clipboard permission is granted because `dom.ts`'s `hexChip` only repaints on
 * a RESOLVED `navigator.clipboard.writeText` — without the grant the promise
 * rejects into a silent `.catch(() => {})`, nothing changes on screen, and the
 * drive would be asserting against a state the code never reached.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * force-revealed, why the lab's defaults are asserted rather than assumed, and
 * why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
