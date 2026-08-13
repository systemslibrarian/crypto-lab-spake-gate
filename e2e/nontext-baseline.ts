/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  // What the live oracle finds over {dark, light} × {1280, 380} and every state
  // the drive builds is exactly these two — both in the SHARED Crypto Lab top
  // bar, and neither one this repo's to fix. Everything inside `#app`, the hero
  // and the footer is audited with no exemption and comes back clean.
  //
  // `.cl-btn` draws its edge as
  // `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)`
  // over the bar's fixed `#0b1512`, IDENTICALLY IN BOTH THEMES — the bar is
  // always dark and the page theme does not move it.
  //
  // WORTH REPORTING UPWARD, because 1.28:1 is markedly worse than the 2.45:1
  // the same markup measures in labs that define no `--accent` and fall back to
  // teal. The difference is this lab's accent: `#6d28d9`, a DARK violet. Two
  // lines above that border, the same stylesheet handles exactly this case for
  // TEXT — `--cl-ink` is `color-mix(in srgb, var(--accent) 60%, #eafff8)`, with
  // a comment saying it mixes toward near-white "so contrast stays >=4.5:1 on
  // the bar even when a lab's accent is dark". The border got no such
  // correction, so the shared bar's SC 1.4.11 gap is accent-dependent and worst
  // in exactly the labs whose brand colour is dark. `CLAUDE.md` is explicit that
  // a change every lab should get is a reviewed fleet-wide pass and never an
  // overwrite driven from one repo, so it is measured here, ratcheted here, and
  // reported up.
  'control-boundary|a.cl-btn': { ratio: 1.28, required: 3, unverified: false },
  'control-boundary|button#cl-theme-toggle.cl-btn.cl-icon': {
    ratio: 1.28,
    required: 3,
    unverified: false,
  },
};
