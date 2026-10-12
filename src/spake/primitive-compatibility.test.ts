import { describe, expect, it } from 'vitest'
import { createECDH, ECDH, createHash, createHmac, hkdfSync, pbkdf2Sync } from 'node:crypto'
import { P, M, N, M_COMPRESSED, N_COMPRESSED, ORDER, decodePoint, encodePoint, mul, bytesToHex } from './group.ts'
import { sha256Bytes, hmacSha256, hkdfExpandNoSalt } from './transcript.ts'
import { deriveSpake2W, deriveSpake2PlusHalves } from './password.ts'

const hex = (bytes: Uint8Array | ArrayBuffer) => Buffer.from(bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes).toString('hex')
const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')
const scalar = (bytes: Uint8Array) => BigInt('0x' + hex(bytes)) % order

// Build the registration input independently using Node Buffer's LE integer
// writer, rather than this lab's transcript helpers.
function passwordInput(password: string, prover: string, verifier: string): Buffer {
  return Buffer.concat([password, prover, verifier].flatMap(text => {
    const bytes = Buffer.from(text, 'utf8')
    const length = Buffer.alloc(8)
    length.writeBigUInt64LE(BigInt(bytes.length))
    return [length, bytes]
  }))
}

describe('P-256 codec and scalar compatibility', () => {
  it('preserves the group order and uncompressed generator against native ECDH', () => {
    const native = createECDH('prime256v1')
    native.setPrivateKey(Buffer.from('01'.padStart(64, '0'), 'hex'))
    expect(ORDER).toBe(order)
    expect(hex(encodePoint(P))).toBe(native.getPublicKey('hex', 'uncompressed'))
    expect(encodePoint(P)).toHaveLength(65)
    expect(encodePoint(P)[0]).toBe(4)
  })

  it('keeps the RFC M/N compressed and uncompressed encodings interoperable', () => {
    for (const [compressed, point] of [[M_COMPRESSED, M], [N_COMPRESSED, N]] as const) {
      const native = ECDH.convertKey(compressed, 'prime256v1', 'hex', 'hex', 'uncompressed')
      expect(bytesToHex(encodePoint(point))).toBe(native)
      expect(decodePoint(native).equals(point)).toBe(true)
    }
  })

  it('rejects malformed, off-curve and infinity encodings', () => {
    for (const encoded of ['', '00', '04' + '00'.repeat(64), '02' + 'ff'.repeat(32), M_COMPRESSED.slice(0, -2), 'gg'.repeat(33)]) {
      expect(() => decodePoint(encoded)).toThrow()
    }
  })

  it('retains reduction and zero-scalar rejection', () => {
    expect(mul(P, ORDER + 1n).equals(P)).toBe(true)
    expect(mul(P, -1n).equals(P.negate())).toBe(true)
    expect(() => mul(P, 0n)).toThrow('scalar reduces to zero')
    expect(() => mul(P, ORDER)).toThrow('scalar reduces to zero')
  })
})

describe('key schedule against an independent native provider', () => {
  const message = new TextEncoder().encode('SPAKE transcript fixture — λ')
  const key = Uint8Array.from({ length: 32 }, (_, i) => i)

  it('preserves SHA-256 without introducing an extra prehash', () => {
    expect(hex(sha256Bytes(message))).toBe(createHash('sha256').update(message).digest('hex'))
  })

  it('preserves HMAC key/message ordering and rejects changed transcript equality', () => {
    expect(hex(hmacSha256(key, message))).toBe(createHmac('sha256', key).update(message).digest('hex'))
    expect(hex(hmacSha256(key, message))).not.toBe(hex(hmacSha256(key, Uint8Array.of(1))))
  })

  it('preserves empty-salt HKDF, info and requested output length', () => {
    for (const length of [16, 32, 64]) {
      expect(hex(hkdfExpandNoSalt(key, 'ConfirmationKeys', length))).toBe(hex(hkdfSync('sha256', key, Buffer.alloc(0), 'ConfirmationKeys', length)))
    }
    expect(hex(hkdfExpandNoSalt(key, 'ConfirmationKeys', 32))).not.toBe(hex(hkdfExpandNoSalt(key, 'SharedKey', 32)))
  })
})

describe('password derivation against independent native PBKDF2', () => {
  const password = 'fixture-password-λ'
  const prover = 'client-α'
  const verifier = 'server'
  const salt = 'fixture-salt'
  const iterations = 20

  it('preserves the balanced 48-byte derivation and identity/salt binding', () => {
    const native = pbkdf2Sync(passwordInput(password, prover, verifier), salt, iterations, 48, 'sha256')
    const actual = deriveSpake2W(password, prover, verifier, salt, iterations)
    expect(actual).toBe(scalar(native))
    expect(actual).not.toBe(deriveSpake2W(password, verifier, prover, salt, iterations))
    expect(actual).not.toBe(deriveSpake2W(password, prover, verifier, 'other-salt', iterations))
  })

  it('preserves both augmented 40-byte halves in their original order', () => {
    const native = pbkdf2Sync(passwordInput(password, prover, verifier), salt, iterations, 80, 'sha256')
    expect(deriveSpake2PlusHalves(password, prover, verifier, salt, iterations)).toEqual({
      w0: scalar(native.subarray(0, 40)),
      w1: scalar(native.subarray(40, 80)),
    })
  })
})
