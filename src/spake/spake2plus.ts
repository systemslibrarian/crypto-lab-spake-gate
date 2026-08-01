// SPAKE2+ — the AUGMENTED PAKE (RFC 9383), hand-rolled.
//
// Registration splits the password into two scalars:
//   w0  — a "verifier half" the server keeps in the clear.
//   w1  — a "prover half" only the client keeps.
// The server also stores L = w1·P (a public point), NOT w1 itself.
//
// The live handshake looks identical to SPAKE2 from the wire. The difference is
// what the server database holds: (w0, L). With those you can VERIFY a login but
// you cannot IMPERSONATE the client, because you'd need w1 — and L only lets you
// check a guess, forcing an OFFLINE DICTIONARY ATTACK on the password.

import {
  M,
  N,
  P,
  mul,
  encodePoint,
  scalarToBytes32,
  type Point,
} from './group.ts'
import {
  element,
  utf8,
  sha256Bytes,
  hmacSha256,
  hkdfExpandNoSalt,
} from './transcript.ts'
import { concatBytes } from './group.ts'

/** The server's stored registration record for one user. */
export interface Spake2PlusRecord {
  w0: bigint
  /** L = w1·P — a public point. Lets the server verify but not impersonate. */
  L: Point
}

export interface Spake2PlusInputs {
  /** Application context string (RFC 9383 §3.3). May be empty. */
  context: string
  idProver: string
  idVerifier: string
  w0: bigint
  /** w1 — held only by the prover (client). */
  w1: bigint
  /** Prover ephemeral scalar x. */
  x: bigint
  /** Verifier ephemeral scalar y. */
  y: bigint
}

export interface Spake2PlusResult {
  /** L = w1·P — the record point. */
  L: Point
  /** shareP = x·P + w0·M — the prover's blinded share. */
  shareP: Point
  maskP: Point // w0·M
  /** shareV = y·P + w0·N — the verifier's blinded share. */
  shareV: Point
  maskV: Point // w0·N
  /** Shared DH element (prover view): Z = x·(shareV − w0·N). */
  Zprover: Point
  /** Shared DH element (verifier view): Z = y·(shareP − w0·M). */
  Zverifier: Point
  /** Augmentation element (prover view): V = w1·(shareV − w0·N). */
  Vprover: Point
  /** Augmentation element (verifier view): V = y·L. */
  Vverifier: Point
  TT: Uint8Array
  Kmain: Uint8Array
  KconfirmP: Uint8Array
  KconfirmV: Uint8Array
  Kshared: Uint8Array
  /** confirmP = HMAC(K_confirmP, shareV) — prover proves knowledge. */
  confirmP: Uint8Array
  /** confirmV = HMAC(K_confirmV, shareP) — verifier proves knowledge. */
  confirmV: Uint8Array
}

/** Compute the server registration record (w0, L=w1·P) from the two halves. */
export function spake2PlusRegister(w0: bigint, w1: bigint): Spake2PlusRecord {
  return { w0, L: mul(P, w1) }
}

export interface Spake2PlusSchedule {
  Kmain: Uint8Array
  KconfirmP: Uint8Array
  KconfirmV: Uint8Array
  Kshared: Uint8Array
}

/**
 * The SPAKE2+ key schedule (RFC 9383 §3.4):
 *   K_main = Hash(TT)
 *   K_confirmP ‖ K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
 *   K_shared               = KDF(nil, K_main, "SharedKey")
 * Shared by the honest run and by the attack code, so the two can never drift.
 */
export function spake2PlusSchedule(TT: Uint8Array): Spake2PlusSchedule {
  const Kmain = sha256Bytes(TT)
  const kc = hkdfExpandNoSalt(Kmain, 'ConfirmationKeys', 64)
  return {
    Kmain,
    KconfirmP: kc.slice(0, 32),
    KconfirmV: kc.slice(32, 64),
    Kshared: hkdfExpandNoSalt(Kmain, 'SharedKey', 32),
  }
}

/** Build the SPAKE2+ transcript TT (RFC 9383 §3.3). */
export function spake2PlusTranscript(
  context: string,
  idProver: string,
  idVerifier: string,
  shareP: Point,
  shareV: Point,
  Z: Point,
  V: Point,
  w0: bigint,
): Uint8Array {
  return concatBytes(
    element(utf8(context)),
    element(utf8(idProver)),
    element(utf8(idVerifier)),
    element(encodePoint(M)), // M, N appear UNCOMPRESSED in the transcript
    element(encodePoint(N)),
    element(encodePoint(shareP)),
    element(encodePoint(shareV)),
    element(encodePoint(Z)),
    element(encodePoint(V)),
    element(scalarToBytes32(w0)),
  )
}

/**
 * Run a full SPAKE2+ exchange with deterministic inputs, returning every
 * intermediate value for animation and known-answer testing.
 */
export function spake2PlusRun(input: Spake2PlusInputs): Spake2PlusResult {
  const { context, idProver, idVerifier, w0, w1, x, y } = input

  const L = mul(P, w1)

  // Prover share and verifier share (both blinded by w0).
  const maskP = mul(M, w0)
  const shareP = mul(P, x).add(maskP) // x·P + w0·M
  const maskV = mul(N, w0)
  const shareV = mul(P, y).add(maskV) // y·P + w0·N

  // Prover unmasks the verifier's share, then derives Z and V.
  const unmaskedV = shareV.subtract(maskV) // = y·P
  const Zprover = mul(unmaskedV, x) // x·y·P
  const Vprover = mul(unmaskedV, w1) // w1·y·P

  // Verifier does the mirror: unmask the prover's share, use L for V.
  const unmaskedP = shareP.subtract(maskP) // = x·P
  const Zverifier = mul(unmaskedP, y) // y·x·P
  const Vverifier = mul(L, y) // y·(w1·P) = w1·y·P

  const TT = spake2PlusTranscript(
    context,
    idProver,
    idVerifier,
    shareP,
    shareV,
    Zprover,
    Vprover,
    w0,
  )
  const { Kmain, KconfirmP, KconfirmV, Kshared } = spake2PlusSchedule(TT)
  const confirmP = hmacSha256(KconfirmP, encodePoint(shareV))
  const confirmV = hmacSha256(KconfirmV, encodePoint(shareP))

  return {
    L,
    shareP,
    maskP,
    shareV,
    maskV,
    Zprover,
    Zverifier,
    Vprover,
    Vverifier,
    TT,
    Kmain,
    KconfirmP,
    KconfirmV,
    Kshared,
    confirmP,
    confirmV,
  }
}
