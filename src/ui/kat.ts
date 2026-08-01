// In-page proof that the crypto is real: run the RFC known-answer vectors live
// in the browser and show they reproduce bit-for-bit. Teaching honesty (§2)
// should be SHOWN, not just asserted in a test file the visitor never opens.

import { el, hexChip } from './dom.ts'
import { spake2Run } from '../spake/spake2.ts'
import { spake2PlusRun } from '../spake/spake2plus.ts'
import { bytesToHex, hexToBytes, bytesToScalar, encodePoint } from '../spake/group.ts'

const scalar = (hex: string) => bytesToScalar(hexToBytes(hex))

// RFC 9382 Appendix B, vector 1 (A=server, B=client).
const V9382 = {
  idA: 'server',
  idB: 'client',
  w: '2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f',
  x: '43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729',
  y: 'dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be',
  pA: '04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c',
  confirmA:
    '58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0',
}

// RFC 9383 Appendix C.
const V9383 = {
  context: 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors',
  idProver: 'client',
  idVerifier: 'server',
  w0: 'bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3',
  w1: '7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba',
  x: 'd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539',
  y: '717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3',
  shareP:
    '04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727',
  confirmP:
    '926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527',
}

interface Check {
  label: string
  expected: string
  computed: string
}

function verdictRow(c: Check): HTMLElement {
  const ok = c.expected === c.computed
  return el('div', { class: `kat-row ${ok ? 'ok' : 'bad'}` }, [
    el('span', { class: 'kat-icon', 'aria-hidden': 'true', text: ok ? '✓' : '✗' }),
    el('span', { class: 'kat-field', text: c.label }),
    hexChip(c.computed, c.label),
    el('span', { class: 'kat-tag', text: ok ? 'matches RFC' : 'MISMATCH' }),
  ])
}

export function buildKatPanel(): HTMLElement {
  const r2 = spake2Run({
    idA: V9382.idA,
    idB: V9382.idB,
    w: scalar(V9382.w),
    x: scalar(V9382.x),
    y: scalar(V9382.y),
  })
  const r3 = spake2PlusRun({
    context: V9383.context,
    idProver: V9383.idProver,
    idVerifier: V9383.idVerifier,
    w0: scalar(V9383.w0),
    w1: scalar(V9383.w1),
    x: scalar(V9383.x),
    y: scalar(V9383.y),
  })

  const checks: Check[] = [
    { label: 'SPAKE2 pA (RFC 9382)', expected: V9382.pA, computed: bytesToHex(encodePoint(r2.pA)) },
    { label: 'SPAKE2 confirmation MAC', expected: V9382.confirmA, computed: bytesToHex(r2.confirmA) },
    { label: 'SPAKE2+ shareP (RFC 9383)', expected: V9383.shareP, computed: bytesToHex(encodePoint(r3.shareP)) },
    { label: 'SPAKE2+ confirmP MAC', expected: V9383.confirmP, computed: bytesToHex(r3.confirmP) },
  ]
  const allOk = checks.every((c) => c.expected === c.computed)

  const badge = el('div', {
    class: `kat-badge ${allOk ? 'ok' : 'bad'}`,
    role: 'status',
    'aria-live': 'polite',
  }, [
    el('span', { class: 'kat-badge-icon', 'aria-hidden': 'true', text: allOk ? '✓' : '✗' }),
    el('span', {
      text: allOk
        ? 'Verified live in your browser: this page’s SPAKE2 and SPAKE2+ reproduce the RFC 9382 and RFC 9383 test vectors bit-for-bit.'
        : 'A known-answer check did not match — the crypto is not behaving as specified.',
    }),
  ])

  const details = el('details', { class: 'kat-details' }, [
    el('summary', { text: 'Show the four live known-answer checks' }),
    el('div', { class: 'kat-rows' }, checks.map(verdictRow)),
    el('p', {
      class: 'kat-note',
      text: 'These four run every page load. The full suite (all 4 RFC 9382 vectors, the RFC 9383 vector, and the attack tests — 18 in total) runs under `npm test` and in CI before deploy.',
    }),
  ])

  return el('div', { class: 'kat' }, [badge, details])
}
