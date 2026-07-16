// THE SERVER-COMPROMISE PANEL — the whole reason for the lab, and the
// break-it-yourself interaction (non-negotiable D: the learner CAUSES the
// failure against the real primitive and the real verifier).
//
// One password, two servers. Steal both databases. Watch what each leak buys:
//   • SPAKE2  → the stored w IS the client. Instant impersonation, no cracking.
//   • SPAKE2+ → the stored (w0, L) only verifies. To impersonate you must run a
//               real offline dictionary attack — which succeeds on a weak
//               password and fails on a strong one.
//
// VERDICT SEPARATION (non-negotiable A): the cryptographic RESULT and the
// security VERDICT are rendered as two independent indicators. Color tracks
// system integrity, so a forged-but-accepted login shows ALARM, not green.

import { el, hexChip } from './dom.ts'
import {
  deriveSpake2W,
  deriveSpake2PlusRecord,
  DEMO_PBKDF2_ITERS,
  type Spake2PlusServerRecord,
} from '../spake/password.ts'
import { scalarToBytes32, bytesToHex, encodePoint, randomScalar } from '../spake/group.ts'
import {
  offlineDictionaryAttack,
  recoveredKeyImpersonates,
  spake2ImpersonateWithStolenW,
} from '../attack/offline.ts'
import {
  spake2LeakOutcome,
  spake2PlusCrackedOutcome,
  spake2PlusHeldOutcome,
  spake2PlusLeakOutcome,
  type SeparatedOutcome,
} from '../attack/verdict.ts'

const ID_PROVER = 'client'
const ID_VERIFIER = 'server'

// A small, real common-password dictionary. The attacker grinds these.
const DICTIONARY = [
  '123456',
  'password',
  'qwerty',
  'letmein',
  'password123',
  'iloveyou',
  'admin',
  'welcome',
  'monkey',
  'abc123',
  'football',
  'dragon',
  'sunshine',
  'trustno1',
]

const WEAK_EXAMPLE = 'password123'
const STRONG_EXAMPLE = 'coral-anchor-7395-VELVET-tide'

function cryptoStateMeta(state: SeparatedOutcome['crypto']['state']): {
  icon: string
  cls: string
} {
  if (state === 'valid') return { icon: '✓', cls: 'is-valid' }
  if (state === 'invalid') return { icon: '✗', cls: 'is-invalid' }
  return { icon: '—', cls: 'is-notrun' }
}

function integrityMeta(state: SeparatedOutcome['verdict']['state']): {
  icon: string
  cls: string
} {
  if (state === 'secure') return { icon: '🛡', cls: 'is-secure' }
  if (state === 'degraded') return { icon: '⚠', cls: 'is-degraded' }
  return { icon: '⛔', cls: 'is-compromised' }
}

/** Two independently-rendered indicators — never collapsed into one. */
function renderOutcome(outcome: SeparatedOutcome): HTMLElement {
  const c = cryptoStateMeta(outcome.crypto.state)
  const v = integrityMeta(outcome.verdict.state)
  return el('div', { class: 'outcome', role: 'status', 'aria-live': 'polite' }, [
    el('div', { class: `indicator crypto ${c.cls}` }, [
      el('span', { class: 'indicator-kind', text: 'CRYPTOGRAPHIC RESULT' }),
      el('span', { class: 'indicator-headline' }, [
        el('span', { class: 'indicator-icon', 'aria-hidden': 'true', text: c.icon }),
        el('span', { class: 'indicator-label', text: outcome.crypto.label }),
      ]),
      el('p', { class: 'indicator-detail', text: outcome.crypto.detail }),
    ]),
    el('div', { class: `indicator verdict ${v.cls}` }, [
      el('span', { class: 'indicator-kind', text: 'SECURITY VERDICT' }),
      el('span', { class: 'indicator-headline' }, [
        el('span', { class: 'indicator-icon', 'aria-hidden': 'true', text: v.icon }),
        el('span', { class: 'indicator-label', text: outcome.verdict.label }),
      ]),
      el('p', { class: 'indicator-detail', text: outcome.verdict.detail }),
    ]),
  ])
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export function buildCompromisePanel(): HTMLElement {
  const salt = bytesToHex(scalarToBytes32(randomScalar())).slice(0, 16)
  let password = WEAK_EXAMPLE
  let stolen = false

  const input = el('input', {
    class: 'pw-input',
    type: 'text',
    id: 'pw-input',
    value: WEAK_EXAMPLE,
    autocomplete: 'off',
    spellcheck: false,
  }) as HTMLInputElement

  const balancedStore = el('div', { class: 'store-box' })
  const augmentedStore = el('div', { class: 'store-box' })
  const balancedOutcome = el('div', { class: 'outcome-slot' })
  const augmentedOutcome = el('div', { class: 'outcome-slot' })
  const attackLog = el('div', {
    class: 'attack-log',
    role: 'log',
    'aria-label': 'Offline dictionary attack progress',
    tabindex: '0',
  })
  const attackWrap = el('div', { class: 'attack-wrap', hidden: true })

  const stealBtn = el('button', {
    class: 'btn btn-danger',
    type: 'button',
  })
  const attackBtn = el('button', {
    class: 'btn btn-primary',
    type: 'button',
    text: 'Run the offline dictionary attack',
  })
  let attackRunning = false

  function currentRecords(): {
    w: bigint
    plus: Spake2PlusServerRecord
  } {
    const w = deriveSpake2W(password, ID_VERIFIER, ID_PROVER, salt, DEMO_PBKDF2_ITERS)
    const plus = deriveSpake2PlusRecord(
      password,
      ID_PROVER,
      ID_VERIFIER,
      salt,
      DEMO_PBKDF2_ITERS,
    )
    return { w, plus }
  }

  function renderStores(): void {
    const { w, plus } = currentRecords()
    balancedStore.textContent = ''
    balancedStore.append(
      el('span', { class: 'store-tag', text: 'SPAKE2 server stores' }),
      el('div', { class: 'store-row' }, [
        el('span', { class: 'store-key', text: 'w' }),
        hexChip(bytesToHex(scalarToBytes32(w)), 'stored w'),
      ]),
      el('p', {
        class: 'store-note',
        text: 'w is the password-equivalent. Whoever holds it can be the client.',
      }),
    )
    augmentedStore.textContent = ''
    augmentedStore.append(
      el('span', { class: 'store-tag', text: 'SPAKE2+ server stores' }),
      el('div', { class: 'store-row' }, [
        el('span', { class: 'store-key', text: 'w0' }),
        hexChip(bytesToHex(scalarToBytes32(plus.w0)), 'stored w0'),
      ]),
      el('div', { class: 'store-row' }, [
        el('span', { class: 'store-key', text: 'L' }),
        hexChip(bytesToHex(encodePoint(plus.L)), 'stored L = w1·P'),
      ]),
      el('p', {
        class: 'store-note',
        text: 'w0 verifies a login; L = w1·P is public. Neither reveals w1, so neither can impersonate the client.',
      }),
    )
  }

  function resetAfterEdit(): void {
    stolen = false
    balancedOutcome.textContent = ''
    augmentedOutcome.textContent = ''
    attackLog.textContent = ''
    attackWrap.hidden = true
    stealBtn.textContent = '🔓 Steal both server databases'
    stealBtn.classList.remove('armed')
    renderStores()
  }

  function doSteal(): void {
    stolen = true
    stealBtn.textContent = '🔓 Databases stolen — records are now the attacker’s'
    stealBtn.classList.add('armed')

    // SPAKE2 (balanced): the stolen w is the client. Prove impersonation now.
    const { w, plus } = currentRecords()
    const imp = spake2ImpersonateWithStolenW(
      w,
      w, // attacker stole exactly this w
      ID_VERIFIER,
      ID_PROVER,
      randomScalar(),
      randomScalar(),
    )
    balancedOutcome.textContent = ''
    balancedOutcome.append(
      el('p', { class: 'attack-headline' }, [
        el('span', { 'aria-hidden': 'true', text: '→ ' }),
        el('span', {
          text: `Attacker replays the protocol as the client with the stolen w. Verifier accepts: ${imp.handshakeAccepted ? 'yes' : 'no'}. Cracking needed: none.`,
        }),
      ]),
      renderOutcome(spake2LeakOutcome()),
    )

    // SPAKE2+ (augmented): cannot impersonate yet. Offer the offline attack.
    augmentedOutcome.textContent = ''
    augmentedOutcome.append(renderOutcome(spake2PlusLeakOutcome()))
    attackWrap.hidden = false
    attackLog.textContent = ''
    // stash the record for the attack handler
    ;(attackBtn as HTMLButtonElement & { _record?: Spake2PlusServerRecord })._record =
      plus
  }

  async function runAttack(): Promise<void> {
    if (attackRunning || !stolen) return
    const record = (attackBtn as HTMLButtonElement & {
      _record?: Spake2PlusServerRecord
    })._record
    if (!record) return
    attackRunning = true
    attackBtn.toggleAttribute('disabled', true)
    attackLog.textContent = ''
    attackLog.append(
      el('p', {
        class: 'attack-headline',
        text: `Grinding ${DICTIONARY.length} common passwords through the same PBKDF2 the server used (${DEMO_PBKDF2_ITERS} iterations each) and comparing against the stolen w0…`,
      }),
    )

    let matchedRow: HTMLElement | null = null
    // We drive the real attack but render one row per candidate for visibility.
    for (let i = 0; i < DICTIONARY.length; i++) {
      const single = offlineDictionaryAttack(
        record,
        ID_PROVER,
        ID_VERIFIER,
        salt,
        [DICTIONARY[i]],
        DEMO_PBKDF2_ITERS,
      )
      const attempt = single.attempts[0]
      const row = el('div', { class: `log-row ${attempt.matched ? 'hit' : 'miss'}` }, [
        el('span', { class: 'log-icon', 'aria-hidden': 'true', text: attempt.matched ? '★' : '·' }),
        el('code', { class: 'log-guess', text: attempt.password }),
        el('span', {
          class: 'log-status',
          text: attempt.matched ? 'w0 matches — password recovered' : 'no match',
        }),
      ])
      attackLog.append(row)
      attackLog.scrollTop = attackLog.scrollHeight
      await sleep(110)
      if (attempt.matched) {
        matchedRow = row
        // Confirm the recovered w1 truly impersonates: w1·P === stolen L.
        const impersonates = recoveredKeyImpersonates(single.recoveredW1!, record)
        augmentedOutcome.textContent = ''
        augmentedOutcome.append(
          el('p', { class: 'attack-headline' }, [
            el('span', { 'aria-hidden': 'true', text: '→ ' }),
            el('span', {
              text: `Recovered w1. It reconstructs the stored L (w1·P = L): ${impersonates ? 'confirmed' : 'no'}. The attacker can now impersonate the client.`,
            }),
          ]),
          renderOutcome(spake2PlusCrackedOutcome(attempt.password)),
        )
        break
      }
    }

    if (!matchedRow) {
      attackLog.append(
        el('div', { class: 'log-row exhausted' }, [
          el('span', { class: 'log-icon', 'aria-hidden': 'true', text: '∅' }),
          el('span', {
            text: 'Dictionary exhausted — no match. w1 was never recovered.',
          }),
        ]),
      )
      augmentedOutcome.textContent = ''
      augmentedOutcome.append(renderOutcome(spake2PlusHeldOutcome()))
    }

    attackBtn.toggleAttribute('disabled', false)
    attackRunning = false
  }

  input.addEventListener('input', () => {
    password = input.value || WEAK_EXAMPLE
    resetAfterEdit()
  })
  stealBtn.addEventListener('click', () => {
    if (stolen) return
    doSteal()
  })
  attackBtn.addEventListener('click', () => {
    void runAttack()
  })

  const useWeak = el('button', { class: 'chip-btn', type: 'button', text: 'Try a weak one' })
  const useStrong = el('button', {
    class: 'chip-btn',
    type: 'button',
    text: 'Try a strong one',
  })
  useWeak.addEventListener('click', () => {
    input.value = WEAK_EXAMPLE
    password = WEAK_EXAMPLE
    resetAfterEdit()
  })
  useStrong.addEventListener('click', () => {
    input.value = STRONG_EXAMPLE
    password = STRONG_EXAMPLE
    resetAfterEdit()
  })

  const panel = el('div', { class: 'compromise' }, [
    el('div', { class: 'pw-controls' }, [
      el('label', { class: 'pw-label', for: 'pw-input', text: 'The user’s password' }),
      input,
      el('div', { class: 'chip-row' }, [useWeak, useStrong]),
    ]),
    el('p', {
      class: 'pw-hint',
      text: 'Both servers register this exact password. Then steal both databases and see what the thief can do.',
    }),
    el('div', { class: 'compromise-grid' }, [
      el('div', { class: 'compromise-col' }, [
        el('h3', { class: 'col-title', text: 'SPAKE2 · balanced' }),
        balancedStore,
        balancedOutcome,
      ]),
      el('div', { class: 'compromise-col' }, [
        el('h3', { class: 'col-title', text: 'SPAKE2+ · augmented' }),
        augmentedStore,
        augmentedOutcome,
        attackWrap,
      ]),
    ]),
    el('div', { class: 'steal-bar' }, [stealBtn]),
  ])

  attackWrap.append(
    el('div', { class: 'attack-controls' }, [attackBtn]),
    attackLog,
  )
  stealBtn.textContent = '🔓 Steal both server databases'
  renderStores()

  return panel
}
