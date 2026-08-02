// Why M and N must be "nothing-up-my-sleeve" — and what breaks if they aren't.
//
// M and N are fixed public points. The security proof requires that NOBODY knows
// the discrete logarithm of M or N with respect to the base point P — i.e. no
// scalar m* with M = m*·P (nor n* with N = n*·P) may be known to anyone. If a
// party who chose the constants knew such a discrete log, a malicious server (or
// MITM) could turn its single online password guess per session into an offline
// dictionary attack — the guarantee SPAKE2 exists to provide would collapse. So
// the RFC derives M and N by hashing a fixed, boring seed string (hash-to-curve),
// which yields points whose discrete log to P is unknown even to the authors.

import { el, hexChip } from './dom.ts'
import {
  M,
  N,
  M_COMPRESSED,
  N_COMPRESSED,
  M_SEED,
  N_SEED,
  encodePoint,
  bytesToHex,
} from '../spake/group.ts'

export function buildConstantsPanel(): HTMLElement {
  const row = (
    name: string,
    seed: string,
    compressed: string,
    uncompressed: string,
  ) =>
    el('div', { class: 'const-card' }, [
      el('h3', { class: 'const-name', text: name }),
      el('div', { class: 'const-field' }, [
        el('span', { class: 'const-label', text: 'RFC hash-to-curve derivation seed (shown, not recomputed here)' }),
        el('code', { class: 'seed', text: seed }),
      ]),
      el('div', { class: 'const-field' }, [
        el('span', { class: 'const-label', text: 'RFC compressed point loaded and curve-checked by this demo' }),
        hexChip(compressed, `${name} compressed`),
      ]),
      el('div', { class: 'const-field' }, [
        el('span', { class: 'const-label', text: 'uncompressed, as it appears in the transcript' }),
        hexChip(uncompressed, `${name} uncompressed`),
      ]),
    ])

  return el('div', { class: 'constants' }, [
    el('div', { class: 'const-grid' }, [
      row('M', M_SEED, M_COMPRESSED, bytesToHex(encodePoint(M))),
      row('N', N_SEED, N_COMPRESSED, bytesToHex(encodePoint(N))),
    ]),
    el('div', { class: 'rule-box' }, [
      el('span', { class: 'rule-tag', text: 'THE REQUIREMENT' }),
      el('p', {
        html:
          'No one may know the discrete log of <code>M</code> or <code>N</code> with respect to the base point <code>P</code> — ' +
          'no scalar <code>m*</code> with <code>M = m*·P</code> (nor <code>n*</code> with <code>N = n*·P</code>). ' +
          'The seed strings above (the P-256 object identifier plus a label) are fixed and public, and hash-to-curve turns them into points ' +
          'whose discrete log to <code>P</code> is unknown even to the spec authors — leaving nowhere to hide a trapdoor. ' +
          'If someone <em>did</em> know such a discrete log, a malicious server or man-in-the-middle could convert its one online guess ' +
          'per session into an unlimited <em>offline</em> dictionary attack on the password.',
      }),
    ]),
    el('p', {
      class: 'scope-note',
    }, [
      el('span', { class: 'scope-note-tag', text: 'WHAT THIS ISN’T' }),
      el('span', {
        text: ' We display the RFC constants and verify they are valid curve points; we do not re-run the full hash-to-curve derivation in-page.',
      }),
    ]),
  ])
}
