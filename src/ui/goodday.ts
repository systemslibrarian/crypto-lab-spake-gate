// THE CORE "AHA" (from the brief): on a good day, balanced and augmented look
// IDENTICAL from the outside — same handshake shape, both succeed, both derive a
// working session key. An eavesdropper cannot tell which protocol is running or
// learn the password. The difference is only in what the server wrote down, and
// that difference stays invisible until the database leaks (next section).
//
// This runs BOTH real handshakes on the same password so the sameness is shown,
// not asserted. Expert detail (full transcript + key schedule) is behind a
// <details> so the newcomer path stays clean.

import { el, hexChip, shortHex } from './dom.ts'
import { spake2Run } from '../spake/spake2.ts'
import { spake2PlusRun } from '../spake/spake2plus.ts'
import {
  deriveSpake2W,
  deriveSpake2PlusHalves,
  DEMO_PBKDF2_ITERS,
} from '../spake/password.ts'
import {
  randomScalar,
  encodePoint,
  bytesToHex,
  bytesEqual,
  type Point,
} from '../spake/group.ts'

const PW = 'correct-horse-battery-staple'
const ID_CLIENT = 'client'
const ID_SERVER = 'server'
const SALT = 'good-day-salt'
const CONTEXT = 'crypto-lab-spake-gate honest handshake'

function wireRow(label: string, bytes: Uint8Array, hint: string): HTMLElement {
  return el('div', { class: 'wire-row' }, [
    el('div', { class: 'wire-head' }, [
      el('span', { class: 'wire-label', text: label }),
      el('span', { class: 'wire-size', text: `${bytes.length} bytes` }),
    ]),
    hexChip(bytesToHex(bytes), label),
    el('span', { class: 'wire-hint', text: hint }),
  ])
}

function agreeVerdict(agree: boolean, text: string): HTMLElement {
  return el('div', { class: `agree ${agree ? 'ok' : 'bad'}` }, [
    el('span', { class: 'agree-icon', 'aria-hidden': 'true', text: agree ? '✓' : '✗' }),
    el('span', { text }),
  ])
}

function transcriptDetails(summary: string, tt: Uint8Array, schedule: [string, Uint8Array][]): HTMLElement {
  return el('details', { class: 'expert-details' }, [
    el('summary', { text: summary }),
    el('div', { class: 'expert-body' }, [
      el('div', { class: 'expert-field' }, [
        el('span', { class: 'expert-label', text: `Transcript TT (${tt.length} bytes, length-prefixed, 8-byte little-endian framing)` }),
        el('div', {
          class: 'tt-dump',
          role: 'region',
          'aria-label': `${summary} transcript bytes`,
          tabindex: '0',
        }, [el('code', { text: bytesToHex(tt) })]),
      ]),
      ...schedule.map(([label, val]) =>
        el('div', { class: 'expert-field expert-kv' }, [
          el('span', { class: 'expert-label', text: label }),
          hexChip(bytesToHex(val), label),
        ]),
      ),
    ]),
  ])
}

export function buildGoodDayPanel(): HTMLElement {
  const root = el('div', { class: 'goodday' })

  const runBtn = el('button', {
    class: 'btn btn-primary',
    type: 'button',
    text: '▶ Run one honest login (fresh randomness)',
  })
  const columns = el('div', { class: 'goodday-grid' })
  const takeaway = el('div', {
    class: 'goodday-takeaway',
    role: 'status',
    'aria-live': 'polite',
  })

  function render(): void {
    // Same password, both protocols.
    const w = deriveSpake2W(PW, ID_SERVER, ID_CLIENT, SALT, DEMO_PBKDF2_ITERS)
    const { w0, w1 } = deriveSpake2PlusHalves(PW, ID_CLIENT, ID_SERVER, SALT, DEMO_PBKDF2_ITERS)

    const r2 = spake2Run({ idA: ID_CLIENT, idB: ID_SERVER, w, x: randomScalar(), y: randomScalar() })
    const r3 = spake2PlusRun({
      context: CONTEXT,
      idProver: ID_CLIENT,
      idVerifier: ID_SERVER,
      w0,
      w1,
      x: randomScalar(),
      y: randomScalar(),
    })

    const eq = (a: Point, b: Point) => bytesEqual(encodePoint(a), encodePoint(b))

    columns.textContent = ''
    columns.append(
      el('div', { class: 'goodday-col' }, [
        el('h3', { class: 'col-title', text: 'SPAKE2 · balanced' }),
        el('p', { class: 'goodday-sub', text: 'Both sides hold w.' }),
        el('div', { class: 'wire' }, [
          wireRow('client → server (pA)', encodePoint(r2.pA), 'masked DH share: x·P + w·M'),
          wireRow('server → client (pB)', encodePoint(r2.pB), 'masked DH share: y·P + w·N'),
          wireRow('confirmation MAC (cA)', r2.confirmA, 'proves the client derived the key'),
        ]),
        agreeVerdict(eq(r2.K, r2.Kverifier), 'Both sides derived the same shared point K.'),
        el('div', { class: 'sess-key' }, [
          el('span', { class: 'sess-label', text: 'session key Ke' }),
          hexChip(bytesToHex(r2.Ke), 'SPAKE2 session key'),
        ]),
        transcriptDetails('Show SPAKE2 transcript & key schedule (RFC 9382 §3.3–§4)', r2.TT, [
          ['Hash(TT)', r2.hashTT],
          ['Ke ‖ Ka split → Ke', r2.Ke],
          ['Ka', r2.Ka],
          ['KcA (client confirm key)', r2.KcA],
          ['KcB (server confirm key)', r2.KcB],
        ]),
      ]),
      el('div', { class: 'goodday-col' }, [
        el('h3', { class: 'col-title', text: 'SPAKE2+ · augmented' }),
        el('p', { class: 'goodday-sub', text: 'Client holds w0 & w1; server holds w0 & L.' }),
        el('div', { class: 'wire' }, [
          wireRow('client → server (shareP)', encodePoint(r3.shareP), 'masked DH share: x·P + w0·M'),
          wireRow('server → client (shareV)', encodePoint(r3.shareV), 'masked DH share: y·P + w0·N'),
          wireRow('confirmation MAC (confirmP)', r3.confirmP, 'proves knowledge of w0 and w1'),
        ]),
        agreeVerdict(
          eq(r3.Zprover, r3.Zverifier) && eq(r3.Vprover, r3.Vverifier),
          'Both sides agreed on Z and the augmentation element V.',
        ),
        el('div', { class: 'sess-key' }, [
          el('span', { class: 'sess-label', text: 'session key K_shared' }),
          hexChip(bytesToHex(r3.Kshared), 'SPAKE2+ session key'),
        ]),
        transcriptDetails('Show SPAKE2+ transcript & key schedule (RFC 9383 §3.3–§3.4)', r3.TT, [
          ['K_main = Hash(TT)', r3.Kmain],
          ['K_confirmP', r3.KconfirmP],
          ['K_confirmV', r3.KconfirmV],
          ['K_shared', r3.Kshared],
        ]),
      ]),
    )

    takeaway.textContent = ''
    takeaway.append(
      el('span', { class: 'takeaway-tag', text: 'WHAT AN EAVESDROPPER SEES' }),
      el('p', {
        html:
          `Same shape both times: two curve points (65 bytes each: <code>${shortHex(bytesToHex(encodePoint(r2.pA)))}</code> vs <code>${shortHex(bytesToHex(encodePoint(r3.shareP)))}</code>) and a 32-byte confirmation MAC. ` +
          'Both handshakes succeed; both sides agree on a key. Nothing on the wire reveals which protocol ran, or the password. ' +
          'The two session keys differ because they’re different protocols — but that’s internal. ' +
          'The <strong>only externally meaningful difference is what each server wrote down</strong> — and that stays invisible until the database leaks.',
      }),
    )
  }

  runBtn.addEventListener('click', render)
  render()

  root.append(runBtn, columns, takeaway)
  return root
}
