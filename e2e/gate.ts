import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one is a correction of the
 * `e2e/a11y.spec.ts` this replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec opened with
 *     `page.addStyleTag({ content: '*,*::before,*::after{animation:none
 *     !important;transition:none!important}' })`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it —
 *     and this lab has a second, invisible reason to care: `compromise.ts`'s
 *     `stepDelay()` reads `matchMedia('(prefers-reduced-motion: reduce)')` in
 *     JavaScript and returns 0 instead of 110ms per dictionary candidate. A
 *     stylesheet injection cannot reach that. `boot` asks for the preference for
 *     real and then ASSERTS it took effect, so both the CSS block and the JS
 *     branch are the ones a reader with the preference set actually gets.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. The old spec set `open` on every `<details>`
 *     from script, then stripped `hidden` from every element carrying it and
 *     added `active is-active open` to each. On this page that assembles a
 *     document no visitor can reach: `.attack-wrap` (the dictionary-attack
 *     controls and log) revealed while no database has been stolen, the
 *     `.observer-box` from step 3 of the mask walkthrough revealed while the
 *     stepper is on step 1, and the Reset button revealed beside an un-armed
 *     Steal button. This gate never touches `hidden` or `open`; every panel is
 *     revealed by the control that reveals it, and every disclosure is opened by
 *     clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE, AFTER THE WHOLE DRIVE, AT ONE VIEWPORT. Everything it
 *     built — the stolen-database state, the offline attack, the stepped mask —
 *     was overwritten by the next step before anything measured it, and the
 *     380px column was never scanned at all. This drive scans after every single
 *     step, in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: the three
 *     panels that carry the lab's conclusions (`.cl-hero-why`, `.rule-box`,
 *     `.goodday-takeaway`) are `color-mix(in oklab, …)` surfaces that axe files
 *     under `incomplete` rather than measuring; and an `aria-label` on a
 *     role-less element is PROHIBITED and lands in `incomplete` too, never in
 *     `violations`.
 *
 *  5. IT HAD NO REFLOW, NO KEYBOARD-SCROLLER AND NO NON-TEXT ORACLE, and this
 *     page needs all three. `.cmp-table` is `min-width: 40rem` inside a
 *     `.table-scroll`; `.attack-log` only overflows its 15rem cap once the
 *     fourteen-candidate grind has actually been run; and every button on the
 *     page drew its edge from a SURFACE divider while the palette's real
 *     `--border-control` token sat on one text input.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `style.css` declares no `@keyframes`
 * and no `animation` at all, and its reduced-motion block contains exactly two
 * declarations, `animation: none` and `transition: none`, neither of which can
 * strand anything. The check runs in every state regardless, because all of that
 * is a property of the current stylesheet rather than of the page, and this is
 * the cheapest place to catch the first exception.
 *
 * `aria-hidden` subtrees are excluded — see the note on `ariaHidden` in
 * `contrast.ts` for what this lab hides and why each member of that set is a
 * status glyph whose words sit beside it.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page has two `<header>` elements — the shared `.cl-topbar` and the lab's
 * own `.cl-hero`, which `main.ts` appends directly into the `<div id="app">`
 * wrapper rather than inside `<main>`. So the hero is NOT scoped out of the
 * banner role by its nesting, and the page depends on `index.html`'s
 * `dedupeBanner()` demoting it to `role="group"` at load. Asserting the OUTCOME
 * rather than the mechanism means both a change to that script and a change to
 * the nesting are caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * `[hidden]` has specificity (0,1,0) — identical to a class — so ANY later
 * `.foo { display: … }` rule silently beats it and the attribute does nothing.
 * Seven labs in this fleet shipped that bug.
 *
 * It cannot be settled by reading the CSS, because the answer depends on rule
 * order across the whole cascade. So it is measured: set `hidden` on a probe
 * element carrying each class this lab hides that way, and read back the
 * computed `display`. The three are `.attack-wrap` (the dictionary-attack
 * controls, hidden until a database is stolen), `.observer-box` (the
 * eavesdropper panel, hidden except on step 3 of the mask walkthrough) and
 * `.btn` (the Reset button, hidden until there is something to reset).
 */
async function assertHiddenAttributeWorks(page: Page): Promise<void> {
  const leaks = await page.evaluate(() => {
    const out: string[] = [];
    for (const cls of ['attack-wrap', 'observer-box', 'btn']) {
      const probe = document.createElement('div');
      probe.className = cls;
      probe.hidden = true;
      probe.textContent = 'probe';
      document.body.append(probe);
      const display = getComputedStyle(probe).display;
      if (display !== 'none') out.push(`.${cls} → display: ${display}`);
      probe.remove();
    }
    return out;
  });
  expect(leaks, '[hidden] must win the cascade for every class this lab hides').toEqual([]);
}

/**
 * An explicit `role` on a `<ul>`/`<ol>` REPLACES its implicit `list` role and
 * orphans every `<li>` inside it — a defect a markup grep structurally cannot
 * find when the role is assigned as a JS property, which is how this lab builds
 * its DOM (`el('ul', { role: 'list' }, …)` in `main.ts` and `matter.ts`).
 *
 * `role="list"` is the one benign value: redundant, but the same role the
 * element already had. It is allowed here WITH a companion assertion, because
 * the redundancy is not free — it makes axe apply `aria-required-children`,
 * which fails the moment such a list is empty. Both of this lab's lists are
 * static prose that is never emptied, and that is asserted rather than assumed.
 */
async function assertListSemanticsIntact(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list')
      .map((e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}]`)
  );
  expect(broken, 'an explicit role on a list deletes its list semantics').toEqual([]);

  const emptyLists = await page.$$eval('[role="list"], ul:not([role]), ol:not([role])', (els) =>
    els
      .filter((e) => (e as HTMLElement).checkVisibility?.())
      .filter((e) => e.querySelectorAll(':scope > li, :scope > [role="listitem"]').length === 0)
      .map((e) => `${e.tagName.toLowerCase()}.${(e.getAttribute('class') ?? '').trim()}`)
  );
  expect(emptyLists, 'a visible list with no items fails aria-required-children').toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. It is not cosmetic here: `compromise.ts`
 * reads the same media query from JavaScript to decide whether to pace the
 * dictionary grind at 110ms per candidate, so an emulation that quietly failed
 * would change the code path under test, not just the frame rate.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab's arrival state is NOT
 * empty and NOT obvious. Two full handshakes have already run and rendered
 * before a visitor touches anything; the four RFC known-answer checks have
 * already been computed; the mask stepper is parked on step 1 of 5 with Back
 * disabled and the observer panel absent; the compromise panel ships preloaded
 * with the WEAK example password, which is the branch where the offline attack
 * SUCCEEDS. A gate that assumed the strong-password branch would have scanned
 * the wrong half of this lab's whole argument.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertHiddenAttributeWorks(page);

  // Everything below `#app` is built by `src/main.ts`, so a navigation that
  // resolves proves nothing at all.
  await expect(page.locator('h1.cl-hero-title')).toHaveText('SPAKE Gate');
  await expect(page.locator('#app section.card')).toHaveCount(8);

  // ── The four RFC known-answer checks, computed on mount ──────────────────
  await expect(page.locator('.kat-badge')).toHaveClass(/\bok\b/);
  await expect(page.locator('.kat-badge')).toContainText('reproduce the RFC 9382 and RFC 9383 test vectors bit-for-bit');

  // ── Both handshakes have already run and agreed ──────────────────────────
  await expect(page.locator('.goodday-col')).toHaveCount(2);
  await expect(page.locator('.agree.ok')).toHaveCount(2);
  await expect(page.locator('.agree.bad')).toHaveCount(0);

  // ── The mask stepper ships on step 1, with Back locked ───────────────────
  await expect(page.locator('.step-counter')).toHaveText('Step 1 of 5');
  await expect(page.locator('.step-title')).toHaveText(/^1 · /);
  await expect(page.getByRole('button', { name: '‹ Back' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Next ›' })).toBeEnabled();
  await expect(page.locator('.observer-box')).toBeHidden();
  await expect(page.locator('.k-compare')).toBeEmpty();

  // ── The compromise panel ships loaded with the WEAK password, unstolen ────
  await expect(page.locator('#pw-input')).toHaveValue('password123');
  await expect(page.locator('.btn-danger')).toHaveText('🔓 Steal both server databases');
  await expect(page.locator('.btn-danger')).toBeEnabled();
  await expect(page.locator('.compromise-col.is-stolen')).toHaveCount(0);
  await expect(page.locator('.outcome')).toHaveCount(0);
  await expect(page.locator('.attack-wrap')).toBeHidden();
  await expect(page.locator('.steal-bar .btn:not(.btn-danger)')).toBeHidden();
  // Both server records are rendered before anything is stolen — that side-by-
  // side "what each server wrote down" is the premise, not a result.
  await expect(page.locator('.store-box')).toHaveCount(2);

  // ── Three disclosures, all shut ──────────────────────────────────────────
  await expect(page.locator('details')).toHaveCount(3);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * the shape that breaks it: a `min-width: 40rem` comparison table, four
 * `auto-fit` grids whose tracks have `minmax(15rem–18rem, 1fr)` floors, and
 * 130-character uncompressed P-256 points printed in a monospace face.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has exactly that decoy: `.cmp-table` is 40rem wide by declaration and is
    // ALWAYS the widest rect on the page at 380px, while being entirely
    // innocent.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * Three regions on this page scroll and hold no focusable content: `.attack-log`
 * (the dictionary grind, which only overflows its 15rem cap once fourteen rows
 * have been rendered — a state a drive has to go and build), `.tt-dump` (the
 * full length-prefixed transcript, behind a shut disclosure) and `.table-scroll`
 * (the comparison table, which only overflows below ~40rem). All three are
 * written with `tabindex="0"` today; this assertion is what keeps that true, and
 * what catches the next scroller added without one.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls, under the STRICTER of
 * the two models this gate runs.
 *
 * `nontext.ts` scores a control as `max(fill-vs-surround, border-vs-surround)`.
 * This one scores `max(fill-vs-surround, min(border-vs-surround,
 * border-vs-fill))`: a drawn edge only counts as a delineator if it is
 * distinguishable from BOTH sides of itself. The two agree on every control that
 * has no border, and on every control whose fill already carries the boundary;
 * they differ only for a bordered control sitting on a surface close to its own
 * fill, which is precisely this lab's shape — `.btn` is `--surface-2` on a
 * `--surface` card, 1.11:1 apart, so the border is doing all the work and it had
 * better be visible against the button as well as against the page.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it (how `.btn-primary` works: a
 *     solid `--accent-fill`), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how `.btn` and every `.hex` chip work).
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    `‹ Back` disabled on step 1 and disables the Steal button once armed.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and it is measured
 *    all the same by `nontext.ts`, ratcheted in `nontext-baseline.ts` and
 *    reported upward. The exclusion here is a decision, not an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette uses
    // `color-mix()` for its tinted panels and an 8-digit hex (`#47506180`) for
    // `--border-strong`, and `getComputedStyle` reports the first unchanged.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0]!, g: d[1]!, b: d[2]!, a: d[3]! / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * FAILS at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function softly(
  fn: (page: Page, label: string) => Promise<void>,
  page: Page,
  label: string
): Promise<void> {
  if (!COLLECTING) return fn(page, label);
  try {
    await fn(page, label);
  } catch (e) {
    record(String(e).slice(0, 4000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle inside `<main>`: axe has no rule for
 * non-text contrast, and the arithmetic text walk cannot reach a control's
 * boundary or a `::before` glyph, because a pseudo-element is not an element and
 * owns no text node.
 *
 * This is called from `scan()`, at every driven state. That placement is the
 * repair of a bug that made the identical check DEAD fleet-wide: it used to be
 * called from inside `expectScrollersReachableSoft`, AFTER that function's
 * `if (!COLLECTING) return …` guard, so in a strict run — which is every run in
 * CI and every run anyone reads as a pass — it never executed at all, and the
 * baselines it "verified" had been captured by a check that never looked.
 *
 * It ratchets rather than blocking on a backlog: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and a capture run
  // is left failing by `expectBaselineNotStale` so it cannot be mistaken for a
  // passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Eight assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters here, since the hero aside, the M/N
 *    requirement box and the eavesdropper takeaway are all
 *    `color-mix(in oklab, …)` surfaces axe declines to resolve. Everything else
 *    in that bucket is a real result axe simply could not finish — including
 *    `aria-prohibited-attr`, which is where an `aria-label` on a role-less
 *    element hides, a defect that never reaches the violations array at all.
 *    That one is live on this page: `goodday.ts` puts an `aria-label` on the
 *    `.tt-dump` transcript `<div>` and makes it legal with `role="region"`, and
 *    `compromise.ts` does the same on `.attack-log` with `role="log"` — either
 *    role is easy to drop by accident.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast, twice: the strict boundary model over `#app`, and the
 *    ratcheted `nontext.ts` over the whole document including the shared bar.
 *  - list semantics — see `assertListSemanticsIntact`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // exactly the shape they catch: a shared sticky <header role="banner"> above a
  // second <header> holding an <aside role="complementary">, with <main> a
  // sibling of both.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await softly(expectNoNewNonTextFailures, page, label);
  await softly(assertListSemanticsIntact, page, label);
  await softly(expectScrollersReachable, page, label);
  await softly(expectNoHorizontalOverflow, page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Move focus with a REAL Tab press, then hand it to `target`.
 *
 * Chromium only applies `:focus-visible` styling after a keyboard interaction,
 * so a programmatic `.focus()` on a freshly-loaded page matches `:focus` but NOT
 * `:focus-visible` — and every one of this lab's focus indicators is written
 * `:focus-visible`. A gate that focused programmatically would therefore find no
 * visible indicator on any of them and invent one 2.4.7 defect per focusable
 * region. Priming with a genuine `page.keyboard.press('Tab')` first puts the
 * browser into keyboard mode for the rest of the document's life, which is the
 * mode a keyboard user is in; the assertion below is what proves it worked
 * rather than assuming it.
 */
async function focusByKeyboard(page: Page, selector: string): Promise<void> {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await page.locator(selector).focus();
  await expect(page.locator(selector)).toBeFocused();
  expect(
    await page.locator(selector).evaluate((el) => el.matches(':focus-visible')),
    `${selector} must match :focus-visible after a real keyboard interaction`
  ).toBe(true);
}

/** Open one shut `<details>` by clicking its summary, and assert it opened. */
async function openDisclosure(page: Page, selector: string): Promise<void> {
  const d = page.locator(selector);
  await d.locator('> summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/** Steal both databases, and assert the whole stolen state actually arrived. */
async function steal(page: Page): Promise<void> {
  await page.locator('.btn-danger').click();
  await expect(page.locator('.btn-danger')).toHaveText('🔓 Databases stolen');
  await expect(page.locator('.btn-danger')).toBeDisabled();
  await expect(page.locator('.compromise-col.is-stolen')).toHaveCount(2);
  await expect(page.locator('.steal-bar .btn:not(.btn-danger)')).toBeVisible();
  await expect(page.locator('.attack-wrap')).toBeVisible();
  // Balanced: impersonated with no cracking. Augmented: held, attack forced.
  await expect(page.locator('.verdict.is-compromised')).toHaveCount(1);
  await expect(page.locator('.verdict.is-degraded')).toHaveCount(1);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS NOT EMPTY. Two real
 *    handshakes and four RFC known-answer checks have already run and rendered
 *    before a visitor touches anything. The gate this replaces force-opened
 *    every `<details>` and stripped `hidden` from every panel before its only
 *    scan, so the state a reader actually arrives in was never measured once.
 *
 *  - BOTH BRANCHES OF THE FORK THE LAB EXISTS TO SHOW. The compromise panel
 *    ships loaded with the WEAK password, where the offline dictionary attack
 *    SUCCEEDS and the augmented verdict ends `IMPERSONATED (after offline
 *    crack)`. The strong password is the other branch: the dictionary is
 *    exhausted, `spake2PlusHeldOutcome` renders, and `.verdict.is-secure` — a
 *    whole ink — is painted nowhere else on the page. Driving one and not the
 *    other scans half of the lab's argument.
 *
 *  - EVERY STEP OF THE MASK WALKTHROUGH, FORWARD AND BACK. Step 3 is the only
 *    state that reveals `.observer-box`, which is the only place `--warn-text`
 *    is painted on the `--surface-3` fill; step 5 is the only state that renders
 *    `.k-compare` and its verdict. Both are reachable only by clicking through.
 *
 *  - PREREQUISITE STATES ARE SCANNED BEFORE THEIR UNLOCK. `‹ Back` is asserted
 *    disabled on step 1 and `Next ›` disabled on step 5; the attack controls are
 *    asserted absent before the databases are stolen. The "before" rendering is
 *    what a reader meets, so it is measured too.
 *
 *  - THE TRANSIENT STATES ARE SCANNED WHILE THEY ARE UP. The `.hex.copied`
 *    flash lasts 1100ms and is the only state in which a chip paints `--ok-text`
 *    on `--ok`; clipboard permission is granted by the spec so the resolved path
 *    runs rather than a silently-caught rejection.
 *
 *  - NO FIXED TIMEOUTS. Every step has a DOM completion signal — a row count, a
 *    button returning from `disabled`, a class arriving on a column — and the
 *    drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint: both handshakes run, nothing stolen, every disclosure shut');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── The live known-answer checks ─────────────────────────────────────────
  await openDisclosure(page, '.kat-details');
  await expect(page.locator('.kat-row')).toHaveCount(4);
  await expect(page.locator('.kat-row.ok')).toHaveCount(4);
  await expect(page.locator('.kat-row.bad')).toHaveCount(0);
  await scanAt('the four live RFC known-answer checks shown');

  // ── A fresh honest login, and the expert transcripts ─────────────────────
  await page.locator('.goodday > .btn-primary').click();
  await expect(page.locator('.agree.ok')).toHaveCount(2);
  await scanAt('a second honest login on fresh ephemerals');

  await openDisclosure(page, '.goodday-col:nth-child(1) .expert-details');
  await openDisclosure(page, '.goodday-col:nth-child(2) .expert-details');
  await expect(page.locator('.tt-dump')).toHaveCount(2);
  await expect(page.locator('.tt-dump').first()).toBeVisible();
  await scanAt('both full transcripts and key schedules open');

  await focusByKeyboard(page, '.tt-dump >> nth=0');
  await scanAt('a transcript scroller focused from the keyboard');

  // The 1100ms "copied ✓" flash — the only state a hex chip paints --ok-text.
  const chip = page.locator('.goodday .hex').first();
  const chipText = (await chip.textContent()) ?? '';
  await chip.click();
  await expect(chip).toHaveText('copied ✓');
  await expect(chip).toHaveClass(/\bcopied\b/);
  await scanAt('a hex chip flashing its copy confirmation');
  await expect(chip).toHaveText(chipText, { timeout: 5_000 });

  // ── The mask walkthrough, all five steps ─────────────────────────────────
  const next = page.getByRole('button', { name: 'Next ›' });
  const back = page.getByRole('button', { name: '‹ Back' });
  for (const step of [2, 3, 4, 5]) {
    await next.click();
    await expect(page.locator('.step-counter')).toHaveText(`Step ${step} of 5`);
    await expect(page.locator('.step-title')).toHaveText(new RegExp(`^${step} · `));
    if (step === 3) {
      // The only state that reveals the eavesdropper panel.
      await expect(page.locator('.observer-box')).toBeVisible();
      await expect(page.locator('.observer-box .hex')).toHaveCount(1);
    } else {
      await expect(page.locator('.observer-box')).toBeHidden();
    }
    if (step === 5) {
      await expect(page.locator('.k-verdict.ok')).toHaveCount(1);
      await expect(page.locator('.k-row')).toHaveCount(2);
      await expect(next).toBeDisabled();
    }
    await scanAt(`mask walkthrough step ${step} of 5`);
  }

  await back.click();
  await expect(page.locator('.step-counter')).toHaveText('Step 4 of 5');
  await expect(page.locator('.k-compare')).toBeEmpty();
  await scanAt('stepped back to the unmasking step');

  await page.getByRole('button', { name: '↺ Start over' }).click();
  await expect(page.locator('.step-counter')).toHaveText('Step 1 of 5');
  await expect(back).toBeDisabled();
  await scanAt('mask walkthrough restarted');

  await page.getByRole('button', { name: '↻ Fresh ephemerals (x, y)' }).click();
  await expect(page.locator('.step-counter')).toHaveText('Step 1 of 5');
  await scanAt('fresh ephemerals rolled, back at step 1');

  // ── The compromise panel, STRONG password: the attack is defeated ────────
  await page.getByRole('button', { name: 'Try a strong one' }).click();
  await expect(page.locator('#pw-input')).toHaveValue('coral-anchor-7395-VELVET-tide');
  await expect(page.locator('.attack-wrap')).toBeHidden();
  await scanAt('a strong password registered on both servers, nothing stolen yet');

  await steal(page);
  await scanAt('both databases stolen, strong password, attack not yet run');

  await page.locator('.attack-controls .btn-primary').click();
  await expect(page.locator('.attack-controls .btn-primary')).toBeEnabled();
  await expect(page.locator('.attack-controls .btn-primary')).toHaveText('Re-run the attack');
  await expect(page.locator('.log-row')).toHaveCount(15); // 14 candidates + "exhausted"
  await expect(page.locator('.log-row.exhausted')).toHaveCount(1);
  await expect(page.locator('.log-row.hit')).toHaveCount(0);
  // `.verdict.is-secure` is painted nowhere else on this page.
  await expect(page.locator('.verdict.is-secure')).toHaveCount(1);
  await scanAt('dictionary exhausted: the augmented record held');

  await focusByKeyboard(page, '.attack-log');
  await scanAt('the overflowing attack log focused from the keyboard');

  // ── Reset, then the WEAK password: the attack succeeds ───────────────────
  await page.locator('.steal-bar .btn:not(.btn-danger)').click();
  await expect(page.locator('.compromise-col.is-stolen')).toHaveCount(0);
  await expect(page.locator('.outcome')).toHaveCount(0);
  await expect(page.locator('.attack-wrap')).toBeHidden();
  await expect(page.locator('.btn-danger')).toBeEnabled();
  await scanAt('reset: the stolen state cleared back to the premise');

  await page.getByRole('button', { name: 'Try a weak one' }).click();
  await expect(page.locator('#pw-input')).toHaveValue('password123');
  await steal(page);
  await page.locator('.attack-controls .btn-primary').click();
  await expect(page.locator('.attack-controls .btn-primary')).toBeEnabled();
  await expect(page.locator('.log-row.hit')).toHaveCount(1);
  await expect(page.locator('.log-row.exhausted')).toHaveCount(0);
  // Both columns now compromised: stolen w on the left, cracked halves on the right.
  await expect(page.locator('.verdict.is-compromised')).toHaveCount(2);
  await expect(page.locator('.crypto.is-valid')).toHaveCount(2);
  await scanAt('weak password cracked: both records now impersonable');

  // A typed password is the third input route, and it resets the stolen state.
  await page.locator('#pw-input').fill('hunter2');
  await expect(page.locator('.compromise-col.is-stolen')).toHaveCount(0);
  await expect(page.locator('.attack-wrap')).toBeHidden();
  await scanAt('a hand-typed password re-derives both server records');

  await focusByKeyboard(page, '#pw-input');
  await scanAt('the password field focused from the keyboard');

  // ── The comparison table's scroller ──────────────────────────────────────
  await expect(page.locator('.cmp-table tbody tr')).toHaveCount(4);
  await focusByKeyboard(page, '.table-scroll');
  await scanAt('the comparison table scroller focused from the keyboard');
}
