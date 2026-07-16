// SPAKE2 — the BALANCED PAKE (RFC 9382), hand-rolled.
//
// Both parties share the same secret scalar w (derived from the password). Each
// blinds a fresh Diffie-Hellman share by adding w·M (prover) or w·N (verifier).
// An observer sees a point that is uniformly random — the mask hides the share.
// The peer, who also knows w, subtracts the mask back off and completes the DH.
//
// THE PROPERTY THIS LAB IS ABOUT: the server stores w. w is all you need to be
// the client. Steal the database and you don't crack anything — you ARE the user.

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

export interface Spake2Inputs {
  /** Identity of party A (the prover). May be empty. */
  idA: string
  /** Identity of party B (the verifier). May be empty. */
  idB: string
  /** Shared password scalar w (both parties hold it). */
  w: bigint
  /** Prover ephemeral scalar x. */
  x: bigint
  /** Verifier ephemeral scalar y. */
  y: bigint
}

export interface Spake2Result {
  /** x·P — the raw (unblinded) prover DH share. */
  X: Point
  /** w·M — the prover's mask. */
  maskA: Point
  /** pA = x·P + w·M — the blinded value that goes on the wire. */
  pA: Point
  /** y·P — the raw verifier DH share. */
  Y: Point
  /** w·N — the verifier's mask. */
  maskB: Point
  /** pB = y·P + w·N — blinded, on the wire. */
  pB: Point
  /** Shared group element K = x·y·P, computed independently by both sides. */
  K: Point
  /** K as recomputed by the verifier (must equal K) — proves agreement. */
  Kverifier: Point
  /** Full transcript bytes. */
  TT: Uint8Array
  hashTT: Uint8Array
  Ke: Uint8Array
  Ka: Uint8Array
  KcA: Uint8Array
  KcB: Uint8Array
  /** Confirmation MAC sent by A over the transcript. */
  confirmA: Uint8Array
  /** Confirmation MAC sent by B over the transcript. */
  confirmB: Uint8Array
}

export interface Spake2Confirmations {
  hashTT: Uint8Array
  Ke: Uint8Array
  Ka: Uint8Array
  KcA: Uint8Array
  KcB: Uint8Array
  confirmA: Uint8Array
  confirmB: Uint8Array
}

/** Derive the SPAKE2 key schedule and both confirmation MACs from a transcript. */
export function spake2Confirmations(TT: Uint8Array): Spake2Confirmations {
  const hashTT = sha256Bytes(TT)
  const Ke = hashTT.slice(0, 16)
  const Ka = hashTT.slice(16, 32)
  const kc = hkdfExpandNoSalt(Ka, 'ConfirmationKeys', 32)
  const KcA = kc.slice(0, 16)
  const KcB = kc.slice(16, 32)
  const confirmA = hmacSha256(KcA, TT)
  const confirmB = hmacSha256(KcB, TT)
  return { hashTT, Ke, Ka, KcA, KcB, confirmA, confirmB }
}

/** Build the SPAKE2 transcript TT (RFC 9382 §3.3). */
export function spake2Transcript(
  idA: string,
  idB: string,
  pA: Point,
  pB: Point,
  K: Point,
  w: bigint,
): Uint8Array {
  return concatBytes(
    element(utf8(idA)),
    element(utf8(idB)),
    element(encodePoint(pA)),
    element(encodePoint(pB)),
    element(encodePoint(K)),
    element(scalarToBytes32(w)), // w: big-endian, 32-byte padded
  )
}

/**
 * Run a full SPAKE2 exchange with the given (deterministic) inputs and return
 * every intermediate value, so the UI can animate the masking and the tests can
 * check the RFC known-answer vectors.
 */
export function spake2Run(input: Spake2Inputs): Spake2Result {
  const { idA, idB, w, x, y } = input

  // Prover side.
  const X = mul(P, x)
  const maskA = mul(M, w)
  const pA = X.add(maskA) // pA = x·P + w·M

  // Verifier side.
  const Y = mul(P, y)
  const maskB = mul(N, w)
  const pB = Y.add(maskB) // pB = y·P + w·N

  // Prover unmasks the verifier's share and completes DH: K = x·(pB − w·N).
  const K = mul(pB.subtract(maskB), x)
  // Verifier unmasks the prover's share: K = y·(pA − w·M). Must match.
  const Kverifier = mul(pA.subtract(maskA), y)

  const TT = spake2Transcript(idA, idB, pA, pB, K, w)
  const c = spake2Confirmations(TT)

  return {
    X,
    maskA,
    pA,
    Y,
    maskB,
    pB,
    K,
    Kverifier,
    TT,
    hashTT: c.hashTT,
    Ke: c.Ke,
    Ka: c.Ka,
    KcA: c.KcA,
    KcB: c.KcB,
    confirmA: c.confirmA,
    confirmB: c.confirmB,
  }
}
