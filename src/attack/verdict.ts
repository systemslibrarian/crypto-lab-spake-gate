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

/**
 * SPAKE2 database leak: attacker holds w and logs in with no cracking.
 *
 * `accepted` MUST be the real return value of the honest verifier's
 * confirmation-MAC comparison (offline.ts `spake2ImpersonateWithStolenW`), not a
 * constant. If the MAC ever failed to verify, this banner has to say so — a
 * verdict that reads the same either way is decoration, not a result.
 */
export function spake2LeakOutcome(accepted: boolean): SeparatedOutcome {
  if (!accepted) {
    return {
      crypto: {
        state: 'invalid',
        label: 'Handshake rejected',
        detail:
          'The verifier recomputed the client confirmation MAC over the received share and it did NOT match. The forged login was refused.',
      },
      verdict: {
        state: 'secure',
        label: 'NOT IMPERSONATED',
        detail:
          'The stolen w did not open the account. In SPAKE2 this should never happen for a correctly-stolen record — seeing it here means the protocol code on this page is broken, not that SPAKE2 is safe.',
      },
    }
  }
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

/**
 * SPAKE2+ leak where the offline dictionary attack SUCCEEDED (weak password).
 *
 * `impersonates` MUST be the real result of `recoveredKeyImpersonates` — the
 * check that w1'·P equals the stolen L — and `handshakeAccepted` the real result
 * of running the client side with the recovered halves against the honest
 * verifier. Recovering a password is not the same claim as being able to log in;
 * the banner only gets to say IMPERSONATED when both actually held.
 */
export function spake2PlusCrackedOutcome(
  password: string,
  impersonates: boolean,
  handshakeAccepted: boolean,
): SeparatedOutcome {
  if (!impersonates || !handshakeAccepted) {
    return {
      crypto: {
        state: 'invalid',
        label: 'Forged handshake rejected',
        detail: !impersonates
          ? `A candidate matched the stolen w0, but the recovered w1 does not reconstruct the stored L (w1·P ≠ L), so it is not the client's key.`
          : `The recovered w1 reconstructs L, but the verifier still rejected the forged login's confirmation MAC.`,
      },
      verdict: {
        state: 'degraded',
        label: 'NOT IMPERSONATED',
        detail:
          'The dictionary produced a hit that did not turn into a login. For a genuinely-cracked password both checks pass; seeing this means the page’s own code disagrees with itself.',
      },
    }
  }
  return {
    crypto: {
      state: 'valid',
      label: 'Handshake valid',
      detail: `After recovering w1 by cracking "${password}", the attacker ran the client side against the honest verifier and the confirmation MAC verified.`,
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
