import { describe, it, expect } from 'vitest'
import {
  offlineDictionaryAttack,
  recoveredKeyImpersonates,
  spake2ImpersonateWithStolenW,
  spake2PlusImpersonateWithRecoveredHalves,
} from './offline.ts'
import {
  deriveSpake2PlusRecord,
  deriveSpake2PlusHalves,
  deriveSpake2W,
} from '../spake/password.ts'

const ITERS = 200 // fast for tests; still a real PBKDF2 grind
const idP = 'client'
const idV = 'server'
const salt = 'demo-salt'
const DICT = ['123456', 'letmein', 'password123', 'qwerty', 'dragon']

describe('SPAKE2+ offline dictionary attack (augmented)', () => {
  it('cracks a weak password that is present in the dictionary', () => {
    const record = deriveSpake2PlusRecord('password123', idP, idV, salt, ITERS)
    const res = offlineDictionaryAttack(record, idP, idV, salt, DICT, ITERS)
    expect(res.found).toBe(true)
    expect(res.password).toBe('password123')
    expect(res.recoveredW1).not.toBeNull()
    // The recovered w1 really is the impersonation key: w1·P === stolen L.
    expect(recoveredKeyImpersonates(res.recoveredW1!, record)).toBe(true)
  })

  it('FAILS against a strong password absent from the dictionary', () => {
    const strong = 'Tr0ub4dor&3-x9$correct-horse-battery'
    const record = deriveSpake2PlusRecord(strong, idP, idV, salt, ITERS)
    const res = offlineDictionaryAttack(record, idP, idV, salt, DICT, ITERS)
    expect(res.found).toBe(false)
    expect(res.password).toBeNull()
    expect(res.recoveredW1).toBeNull()
    expect(res.tried).toBe(DICT.length)
  })

  it('reports every attempt for the live UI stepping', () => {
    const record = deriveSpake2PlusRecord('qwerty', idP, idV, salt, ITERS)
    const seen: string[] = []
    const res = offlineDictionaryAttack(record, idP, idV, salt, DICT, ITERS, (a) =>
      seen.push(a.password),
    )
    expect(res.found).toBe(true)
    expect(res.password).toBe('qwerty')
    // Stops as soon as it matches — does not try 'dragon'.
    expect(seen).toEqual(['123456', 'letmein', 'password123', 'qwerty'])
  })
})

describe('SPAKE2+ forged login with cracked halves (the verdict the UI prints)', () => {
  const ctx = 'crypto-lab-spake-gate compromise panel'
  const x = 0x1234567890abcdefn
  const y = 0xfedcba0987654321n

  it('an honest verifier holding only (w0, L) ACCEPTS the cracked halves', () => {
    const record = deriveSpake2PlusRecord('password123', idP, idV, salt, ITERS)
    const res = offlineDictionaryAttack(record, idP, idV, salt, DICT, ITERS)
    expect(res.found).toBe(true)
    expect(
      spake2PlusImpersonateWithRecoveredHalves(
        record, res.recoveredW0!, res.recoveredW1!, ctx, idP, idV, x, y,
      ),
    ).toBe(true)
  })

  it('REJECTS wrong halves — the acceptance check is genuine', () => {
    const record = deriveSpake2PlusRecord('password123', idP, idV, salt, ITERS)
    const wrong = deriveSpake2PlusHalves('letmein', idP, idV, salt, ITERS)
    expect(
      spake2PlusImpersonateWithRecoveredHalves(
        record, wrong.w0, wrong.w1, ctx, idP, idV, x, y,
      ),
    ).toBe(false)
  })

  it('REJECTS the right w0 with a wrong w1 — L is load-bearing, not decoration', () => {
    const record = deriveSpake2PlusRecord('password123', idP, idV, salt, ITERS)
    const right = deriveSpake2PlusHalves('password123', idP, idV, salt, ITERS)
    const wrong = deriveSpake2PlusHalves('letmein', idP, idV, salt, ITERS)
    expect(
      spake2PlusImpersonateWithRecoveredHalves(
        record, right.w0, wrong.w1, ctx, idP, idV, x, y,
      ),
    ).toBe(false)
  })
})

describe('SPAKE2 balanced leak — stolen w impersonates with no cracking', () => {
  const stored = deriveSpake2W('hunter2', 'server', 'client', salt, ITERS)

  it('the verifier accepts the attacker holding the correct stolen w', () => {
    const res = spake2ImpersonateWithStolenW(
      stored,
      stored, // attacker stole exactly this
      'server',
      'client',
      0x1234567890abcdefn,
      0xfedcba0987654321n,
    )
    expect(res.handshakeAccepted).toBe(true)
    expect(res.requiredCracking).toBe(false)
  })

  it('the verifier REJECTS an attacker with the wrong w (check is genuine)', () => {
    const wrong = deriveSpake2W('not-the-password', 'server', 'client', salt, ITERS)
    const res = spake2ImpersonateWithStolenW(
      stored,
      wrong,
      'server',
      'client',
      0x1234567890abcdefn,
      0xfedcba0987654321n,
    )
    expect(res.handshakeAccepted).toBe(false)
  })
})
