// P-256 group layer for SPAKE2 / SPAKE2+.
//
// The elliptic-curve field and point arithmetic come from @noble/curves — an
// audited, constant-time library. That is the "named, justified library" the
// template allows for primitive operations. What this lab HAND-ROLLS on top of
// it is the SPAKE2 / SPAKE2+ masking protocol itself (spake2.ts, spake2plus.ts,
// transcript.ts) — the M/N blinding is the teaching subject, so it must be
// inspectable, not hidden inside a dependency.

import { p256 } from '@noble/curves/p256'

export type Point = InstanceType<typeof p256.ProjectivePoint>

/** The prime order of the P-256 group. Scalars live in [0, ORDER). */
export const ORDER: bigint = p256.CURVE.n

/** The standard generator P of the P-256 group. */
export const P: Point = p256.ProjectivePoint.BASE

// ---------------------------------------------------------------------------
// The M and N "nothing-up-my-sleeve" constants (RFC 9382 §6, reused by RFC 9383).
//
// These are FIXED public points, identical across both protocols. They are the
// output of hashing the P-256 object identifier with a fixed seed string, so no
// one — not even the spec authors — knows the discrete log of M or N with
// respect to the base point P (no m* with M = m*·P, no n* with N = n*·P). A known
// such discrete log would let a malicious server/MITM turn one online guess into
// an offline dictionary attack, breaking the protocol. The compressed encodings
// below are copied verbatim from the RFCs; we decode and immediately re-check
// they are valid curve points at module load.
// ---------------------------------------------------------------------------

export const M_SEED = '1.2.840.10045.3.1.7 point generation seed (M)'
export const N_SEED = '1.2.840.10045.3.1.7 point generation seed (N)'

export const M_COMPRESSED =
  '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f'
export const N_COMPRESSED =
  '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49'

export const M: Point = decodePoint(M_COMPRESSED)
export const N: Point = decodePoint(N_COMPRESSED)

// Fail loudly at load time if the copied constants are ever corrupted.
M.assertValidity()
N.assertValidity()

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/** Decode a hex-encoded (compressed or uncompressed) point onto the curve. */
export function decodePoint(hex: string): Point {
  return p256.ProjectivePoint.fromHex(hex)
}

/** Encode a point as SEC1 uncompressed bytes (0x04 || X || Y), 65 bytes. */
export function encodePoint(pt: Point): Uint8Array {
  return pt.toRawBytes(false)
}

/** Multiply a point by a scalar (mod ORDER). Rejects the zero scalar. */
export function mul(pt: Point, k: bigint): Point {
  const s = mod(k, ORDER)
  if (s === 0n) throw new Error('scalar reduces to zero')
  return pt.multiply(s)
}

/** True modulo (never negative). */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m
  return r >= 0n ? r : r + m
}

// ---------------------------------------------------------------------------
// Byte / scalar utilities used throughout the protocol code
// ---------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

/** Length-checked, then constant-time over equal-length inputs. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Big-endian scalar → fixed 32-byte encoding (P-256 field/scalar width). */
export function scalarToBytes32(k: bigint): Uint8Array {
  const s = mod(k, ORDER)
  const out = new Uint8Array(32)
  let v = s
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

export function bytesToScalar(bytes: Uint8Array): bigint {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

/** Reduce arbitrary bytes to a scalar in [0, ORDER) (big-endian interpret). */
export function bytesToScalarMod(bytes: Uint8Array): bigint {
  return mod(bytesToScalar(bytes), ORDER)
}

/** A cryptographically-random nonzero scalar in [1, ORDER). */
export function randomScalar(): bigint {
  // 48 bytes then reduce, to keep bias below the group order (RFC guidance).
  const buf = new Uint8Array(48)
  crypto.getRandomValues(buf)
  const s = bytesToScalarMod(buf)
  return s === 0n ? 1n : s
}
