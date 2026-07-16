// Why M and N must be "nothing-up-my-sleeve" — and what breaks if they aren't.
//
// M and N are fixed public points. The security proof needs that NOBODY knows a
// scalar relating them (no m with N = m·M). If an attacker picked M and N with a
// known discrete-log link, they could unmask shares and recover the password.
// So the RFC derives them by hashing a fixed, boring seed string — leaving no
// room to embed a secret. This panel shows the real constants and states the rule.

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
        el('span', { class: 'const-label', text: 'derived by hashing the seed' }),
        el('code', { class: 'seed', text: seed }),
      ]),
      el('div', { class: 'const-field' }, [
        el('span', { class: 'const-label', text: 'compressed point (from the RFC)' }),
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
          'No one may know a scalar <code>m</code> with <code>N = m·M</code>. ' +
          'The seed strings above (the P-256 object identifier plus a label) are fixed and public, ' +
          'so the derivation is auditable and leaves nowhere to hide a trapdoor. ' +
          'If someone <em>did</em> know such an <code>m</code>, they could strip the mask and recover the password — the protocol would break.',
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
