// Password stretching → protocol scalars.
//
// Real deployments feed the password through a slow, salted Memory-Hard Function
// (PBKDF2 / scrypt / Argon2) before it becomes a scalar. RFC 9382/9383's own
// test vectors SKIP this step and hand w / w0 / w1 over directly — so this file
// is NOT exercised by the KATs. It exists so the live demo derives records from
// real typed passwords, and so the offline-attack panel has something real to
// grind against.
//
// HONEST SCOPING: the iteration count here is deliberately LOW so the offline
// attack visibly runs in a browser tab. Production Matter/Thread uses PBKDF2
// with 1,000–100,000 iterations and a per-record salt. A low count makes the
// dictionary attack faster for BOTH the demo and a real attacker — it does not
// change what is being taught (which side can crack, and that it must).

import { pbkdf2 } from '@noble/hashes/pbkdf2'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToScalarMod, ORDER, mul, P, type Point } from './group.ts'
import { lenLE, utf8 } from './transcript.ts'
import { concatBytes } from './group.ts'

/** Iterations used in-page. Low on purpose — see the file header. */
export const DEMO_PBKDF2_ITERS = 2000

/** Length-prefixed password + identities, per RFC 9383 §3.2.1. */
function pwInput(pw: string, idProver: string, idVerifier: string): Uint8Array {
  return concatBytes(
    lenLE(utf8(pw).length),
    utf8(pw),
    lenLE(utf8(idProver).length),
    utf8(idProver),
    lenLE(utf8(idVerifier).length),
    utf8(idVerifier),
  )
}

/**
 * SPAKE2 (balanced): w = PBKDF2(pw, ...) mod p.
 * A single scalar. This is exactly what a SPAKE2 server must store.
 */
export function deriveSpake2W(
  pw: string,
  idA: string,
  idB: string,
  salt: string,
  iters = DEMO_PBKDF2_ITERS,
): bigint {
  // 48 bytes → reduces modular bias before reduction (RFC guidance: >= log2(p)+64 bits).
  const out = pbkdf2(sha256, pwInput(pw, idA, idB), utf8(salt), {
    c: iters,
    dkLen: 48,
  })
  return bytesToScalarMod(out)
}

export interface Spake2PlusHalves {
  w0: bigint
  w1: bigint
}

/**
 * SPAKE2+ (augmented) registration halves.
 * PBKDF2 output is split into w0s || w1s, each reduced mod p (RFC 9383 §3.2.1).
 * The server keeps w0 and L=w1·P; the client keeps w0 and w1.
 */
export function deriveSpake2PlusHalves(
  pw: string,
  idProver: string,
  idVerifier: string,
  salt: string,
  iters = DEMO_PBKDF2_ITERS,
): Spake2PlusHalves {
  // 80 bytes = two 40-byte halves (RFC 9383 recommends >= 80 bytes for P-256).
  const out = pbkdf2(sha256, pwInput(pw, idProver, idVerifier), utf8(salt), {
    c: iters,
    dkLen: 80,
  })
  const w0 = bytesToScalarMod(out.slice(0, 40))
  const w1 = bytesToScalarMod(out.slice(40, 80))
  return { w0, w1 }
}

export interface Spake2PlusServerRecord {
  w0: bigint
  L: Point // w1·P
}

/** What a SPAKE2+ server actually stores for a user. */
export function deriveSpake2PlusRecord(
  pw: string,
  idProver: string,
  idVerifier: string,
  salt: string,
  iters = DEMO_PBKDF2_ITERS,
): Spake2PlusServerRecord {
  const { w0, w1 } = deriveSpake2PlusHalves(pw, idProver, idVerifier, salt, iters)
  return { w0, L: mul(P, w1) }
}

export { ORDER }
