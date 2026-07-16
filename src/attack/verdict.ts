// VERDICT SEPARATION (this lab's non-negotiable A).
//
// The cryptographic RESULT and the security VERDICT are two different questions
// and get two independent indicators. "Signature: valid ✓" sitting next to
// "Verdict: REJECT ✗" is the whole teaching moment: a forged login can be
// cryptographically valid AND a total system compromise at the same time.
//
// Color tracks SYSTEM INTEGRITY, never the raw return value. A forged-but-
// accepted handshake is ALARM, not green — even though the math "succeeded."

/** The math's answer. Neutral by design — a green MAC proves nothing about safety. */
export type CryptoState = 'valid' | 'invalid' | 'not-run'

/** System integrity. This is what drives alarm coloring. */
export type IntegrityState = 'secure' | 'degraded' | 'compromised'

export interface CryptoResult {
  state: CryptoState
  label: string
  detail: string
}

export interface SecurityVerdict {
  state: IntegrityState
  label: string
  detail: string
}

export interface SeparatedOutcome {
  crypto: CryptoResult
  verdict: SecurityVerdict
}

/** SPAKE2 database leak: attacker holds w and logs in with no cracking. */
export function spake2LeakOutcome(): SeparatedOutcome {
  return {
    crypto: {
      state: 'valid',
      label: 'Handshake valid',
      detail:
        'The confirmation MAC verifies. The math is correct — the attacker ran the real protocol with the stolen w.',
    },
    verdict: {
      state: 'compromised',
      label: 'IMPERSONATED',
      detail:
        'The server stored w, and w is everything the client uses on this service. The thief is now indistinguishable from the user — no password was cracked. (The plaintext password stays behind PBKDF2, so reuse elsewhere still needs a crack; but impersonation here needs none.)',
    },
  }
}

/** SPAKE2+ database leak, before/without any offline cracking. */
export function spake2PlusLeakOutcome(): SeparatedOutcome {
  return {
    crypto: {
      state: 'not-run',
      label: 'No forged handshake',
      detail:
        'The stolen record is (w0, L). It verifies logins but cannot produce a client login — that needs w1, which the server never held.',
    },
    verdict: {
      state: 'degraded',
      label: 'HELD — offline attack forced',
      detail:
        'Integrity holds for now, but the leak is not harmless: the attacker can now grind the password offline against the record. SPAKE2+ does not prevent that — it forces it.',
    },
  }
}

/** SPAKE2+ leak where the offline dictionary attack SUCCEEDED (weak password). */
export function spake2PlusCrackedOutcome(password: string): SeparatedOutcome {
  return {
    crypto: {
      state: 'valid',
      label: 'Handshake valid',
      detail: `After recovering w1 by cracking "${password}", the attacker can run the client side. The MAC verifies.`,
    },
    verdict: {
      state: 'compromised',
      label: 'IMPERSONATED (after offline crack)',
      detail:
        'The password was weak enough to fall to the dictionary. Augmentation bought work, not safety — a bad password loses either way.',
    },
  }
}

/** SPAKE2+ leak where the offline dictionary attack FAILED (strong password). */
export function spake2PlusHeldOutcome(): SeparatedOutcome {
  return {
    crypto: {
      state: 'not-run',
      label: 'No forged handshake',
      detail:
        'The dictionary was exhausted without recovering w1. With no w1 there is no client login to forge.',
    },
    verdict: {
      state: 'secure',
      label: 'HELD',
      detail:
        'A strong password outran the offline attack. This is exactly what augmentation is for: the leak is survivable when the password is not guessable.',
    },
  }
}
