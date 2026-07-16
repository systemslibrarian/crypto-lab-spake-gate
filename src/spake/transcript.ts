// Transcript (TT) construction and key schedule, hand-rolled from the RFCs.
//
// Both protocols hash a length-prefixed transcript of everything public, then
// derive the session and confirmation keys from that hash. The length prefix is
// an 8-byte LITTLE-endian integer (RFC 9382 §3.1, RFC 9383 §3.3). Scalars that
// appear inside the transcript (w, w0) are encoded BIG-endian, padded to 32
// bytes. Getting these two endiannesses right is the whole game for the KATs.

import { sha256 } from '@noble/hashes/sha256'
import { hmac } from '@noble/hashes/hmac'
import { hkdf } from '@noble/hashes/hkdf'
import { concatBytes } from './group.ts'

const enc = new TextEncoder()

/** 8-byte little-endian length prefix. */
export function lenLE(n: number): Uint8Array {
  const out = new Uint8Array(8)
  let v = n
  for (let i = 0; i < 8; i++) {
    out[i] = v & 0xff
    v = Math.floor(v / 256)
  }
  return out
}

/** A single transcript element: len(bytes) || bytes. */
export function element(bytes: Uint8Array): Uint8Array {
  return concatBytes(lenLE(bytes.length), bytes)
}

/** UTF-8 encode a string (identities, context, info labels). */
export function utf8(s: string): Uint8Array {
  return enc.encode(s)
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data)
}

export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha256, key, msg)
}

/**
 * HKDF with an EMPTY salt over `ikm`, expanding `info` to `length` bytes.
 * Both RFCs specify a nil salt for the confirmation-key derivation; only the
 * argument order of their KDF() notation differs (9382: KDF(ikm,salt,info,L);
 * 9383: KDF(salt,ikm,info)). The operation is identical: extract with no salt,
 * then expand.
 */
export function hkdfExpandNoSalt(
  ikm: Uint8Array,
  info: string,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, new Uint8Array(0), utf8(info), length)
}
