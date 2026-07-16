// The server-compromise attacks — the whole reason this lab exists.
//
// Two databases leak. Same password behind both. The outcomes are NOT the same,
// and the difference is the entire point of augmented PAKE.
//
//   SPAKE2  (balanced):  server stored w.        Attacker HAS w → IS the client.
//                        No cracking. Instant, permanent impersonation.
//   SPAKE2+ (augmented): server stored (w0, L).  Attacker can verify a guess but
//                        cannot impersonate without w1. To get w1 they must run
//                        an OFFLINE DICTIONARY ATTACK on the password itself.
//
// PRECISION (RFC-honest): SPAKE2+ does NOT make offline attack impossible. It
// FORCES one. A weak password still falls; a strong one holds. Say exactly that.

import { bytesEqual, scalarToBytes32, mul, P, M, N } from '../spake/group.ts'
import {
  deriveSpake2PlusHalves,
  type Spake2PlusServerRecord,
} from '../spake/password.ts'
import { spake2Transcript, spake2Confirmations } from '../spake/spake2.ts'

// ---------------------------------------------------------------------------
// SPAKE2 (balanced) — stolen w means instant impersonation, no cracking.
// ---------------------------------------------------------------------------

export interface Spake2ImpersonationResult {
  /** The crypto RESULT: did the verifier's confirmation check pass? */
  handshakeAccepted: boolean
  /** True — no password cracking was required to get here. */
  requiredCracking: boolean
}

/**
 * The attacker holds `attackerW` (whatever they stole) and runs the client side.
 * The honest verifier holds `storedW` and, on receiving the attacker's blinded
 * share pA, independently recomputes the client's expected confirmation MAC.
 * Acceptance is a REAL comparison: a matching w passes, a wrong w fails.
 *
 * When `attackerW === storedW` (a leaked balanced record), the attacker is
 * accepted with no cracking whatsoever — that is the SPAKE2 failure.
 */
export function spake2ImpersonateWithStolenW(
  storedW: bigint,
  attackerW: bigint,
  idA: string,
  idB: string,
  attackerX: bigint,
  honestY: bigint,
): Spake2ImpersonationResult {
  // Verifier generates its share pB from its own y and the password it stores.
  const pB = mul(P, honestY).add(mul(N, storedW))

  // Attacker (holding attackerW) builds pA and completes DH from the received pB,
  // then produces the client confirmation MAC.
  const pA = mul(P, attackerX).add(mul(M, attackerW))
  const Kattacker = mul(pB.subtract(mul(N, attackerW)), attackerX)
  const attackerTT = spake2Transcript(idA, idB, pA, pB, Kattacker, attackerW)
  const attackerConfirmA = spake2Confirmations(attackerTT).confirmA

  // Verifier receives pA, completes DH from ITS y and the password IT stores,
  // and recomputes the client's expected MAC over the received pA. If attackerW
  // does not equal storedW, K and the transcript diverge and the MAC mismatches.
  const Kverifier = mul(pA.subtract(mul(M, storedW)), honestY)
  const verifierTT = spake2Transcript(idA, idB, pA, pB, Kverifier, storedW)
  const verifierExpectA = spake2Confirmations(verifierTT).confirmA

  const handshakeAccepted = bytesEqual(attackerConfirmA, verifierExpectA)
  return { handshakeAccepted, requiredCracking: false }
}

// ---------------------------------------------------------------------------
// SPAKE2+ (augmented) — must run an offline dictionary attack to get w1.
// ---------------------------------------------------------------------------

export interface DictionaryAttempt {
  password: string
  matched: boolean
}

export interface OfflineAttackResult {
  found: boolean
  password: string | null
  /** The recovered prover secret w1 (the impersonation key) — only if found. */
  recoveredW1: bigint | null
  /** How many candidates were tested before stopping. */
  tried: number
  attempts: DictionaryAttempt[]
}

/**
 * Run a REAL offline dictionary attack against a stolen SPAKE2+ record.
 *
 * For each candidate password we re-derive (w0', w1') exactly as registration
 * did, then compare w0' against the stolen w0. A match means we have found the
 * password — and therefore w1, the secret that lets us finally impersonate the
 * client. This is genuine crypto: change the dictionary or the real password and
 * the outcome changes accordingly.
 *
 * @param onAttempt optional per-candidate callback for live UI stepping.
 */
export function offlineDictionaryAttack(
  record: Spake2PlusServerRecord,
  idProver: string,
  idVerifier: string,
  salt: string,
  dictionary: string[],
  iters: number,
  onAttempt?: (attempt: DictionaryAttempt, index: number) => void,
): OfflineAttackResult {
  const stolenW0 = scalarToBytes32(record.w0)
  const attempts: DictionaryAttempt[] = []

  for (let i = 0; i < dictionary.length; i++) {
    const candidate = dictionary[i]
    const { w0, w1 } = deriveSpake2PlusHalves(
      candidate,
      idProver,
      idVerifier,
      salt,
      iters,
    )
    const matched = bytesEqual(scalarToBytes32(w0), stolenW0)
    const attempt: DictionaryAttempt = { password: candidate, matched }
    attempts.push(attempt)
    onAttempt?.(attempt, i)
    if (matched) {
      return {
        found: true,
        password: candidate,
        recoveredW1: w1,
        tried: i + 1,
        attempts,
      }
    }
  }

  return {
    found: false,
    password: null,
    recoveredW1: null,
    tried: dictionary.length,
    attempts,
  }
}

/**
 * Confirm a recovered w1 really is the impersonation key: L' = w1·P must equal
 * the stolen L. This is the check that turns "found the password" into "can now
 * impersonate the client."
 */
export function recoveredKeyImpersonates(
  recoveredW1: bigint,
  record: Spake2PlusServerRecord,
): boolean {
  const Lprime = mul(P, recoveredW1)
  return bytesEqual(Lprime.toRawBytes(false), record.L.toRawBytes(false))
}
