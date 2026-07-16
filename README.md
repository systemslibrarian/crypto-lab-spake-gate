# SPAKE Gate

**SPAKE2 (RFC 9382) & SPAKE2+ (RFC 9383) over P-256 — a balanced and an augmented PAKE on the same password, side by side, so you can see exactly what each server keeps and what an attacker gets when the database leaks.**

A browser teaching demo in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite. Real crypto, no backend, everything in memory.

## What It Is

A **PAKE** (Password-Authenticated Key Exchange) turns a shared password into a strong shared key without ever putting the password on the wire and without leaking anything an eavesdropper could grind offline.

- **SPAKE2** is a *balanced* PAKE: both parties hold the same secret scalar `w` (derived from the password). The server stores `w`.
- **SPAKE2+** is an *augmented* PAKE: registration splits the password into `w0` and `w1`. The client keeps both; the server stores only `w0` and the point `L = w1·P`. That record can *verify* a login but cannot *perform* one.

On a good day the two are indistinguishable — same handshake, same session key. The difference only appears when the server's database leaks:

- Steal a **SPAKE2** database → you have `w`, and `w` is everything the client uses on this service. You **are** the client, permanently, with **no cracking**. (The plaintext password isn't directly exposed — `w` is a PBKDF2 image — so reuse on *other* sites still needs an offline crack; but impersonation *here* needs none.)
- Steal a **SPAKE2+** database → you have `(w0, L)`. You cannot impersonate the client without `w1`, so you are **forced into an offline dictionary attack** on the password. A weak password falls; a strong one holds.

**Precision that matters:** SPAKE2+ does **not** prevent an offline attack — it *forces* one. Augmentation buys work, not immunity.

The SPAKE2 and SPAKE2+ logic is **hand-rolled** over real P-256 (the elliptic-curve group and hash primitives come from the audited [`@noble/curves`](https://github.com/paulmillr/noble-curves) / `@noble/hashes`). The M/N masking — the actual teaching subject — is written out in full so you can read it. **This is a teaching demo, not production crypto.**

## Exhibits

1. **The M / N mask, stepped** — the headline mechanism. Watch a real Diffie–Hellman share `X = x·P` get blinded to `pA = X + w·M`, see the *observer's view* (a uniformly random point that leaks nothing), then watch the peer subtract `w·M` back off and both sides land on the same key `K` (compared byte-for-byte).
2. **Why M and N are nothing-up-my-sleeve** — the two fixed constants, their derivation seeds, and the exact requirement: no one may know a scalar `m` with `N = m·M`, or the mask can be stripped.
3. **Steal the database** — register one password on a balanced server and an augmented one, steal both, and see what the thief can do. The **cryptographic result** and the **security verdict** are shown as two independent indicators: a forged-but-accepted login reads as **ALARM**, not green. Includes a **real offline dictionary attack** you run against the stolen SPAKE2+ record — it succeeds on `password123` and fails on a strong passphrase.
4. **SPAKE2 vs SPAKE2+ vs OPAQUE** — a three-way table of what each server stores, what breaks on compromise, and how registration differs.
5. **You already run this: Matter / Thread** — SPAKE2+ is what commissions your smart-home devices; the QR code is the password.

## When to Use It

- **Use SPAKE2+** when a server authenticates users by password and you want a database leak to force offline work rather than hand over impersonation — e.g. device commissioning (Matter/Thread), or any augmented login where you cannot assume the server is never breached.
- **Use SPAKE2** only when both endpoints legitimately share the secret and neither is a persistent, breachable store of many users' passwords (e.g. a symmetric pairing between two devices you control).
- **Do NOT use SPAKE2** as a server-side password-authentication scheme for many users. A single database leak is total account takeover with no cracking step. This is the failure the demo exists to show.
- **Do NOT treat any PAKE as a substitute for a strong password.** Augmented PAKEs force offline attacks; they do not survive guessable passwords.

## Live Demo

**https://crypto-lab.systemslibrarian.dev/crypto-lab-spake-gate/** (also served from GitHub Pages for this repo).

Type a password, steal both databases, and run the offline attack. Everything runs client-side; nothing is stored or transmitted.

## What Can Go Wrong

- **Trapdoored M/N.** If anyone knew the discrete log of M or N with respect to the base point P (a scalar `m*` with `M = m*·P`), a malicious server or man-in-the-middle could convert its single online guess per session into an unlimited *offline* dictionary attack. This is why M and N are fixed, seed-derived by hash-to-curve, and public — so no such discrete log is known to anyone.
- **Weak passwords.** Against a stolen SPAKE2+ record, a dictionary word is recovered in milliseconds. The augmented record only raises the cost from *zero* (SPAKE2) to *one offline guess per candidate* (SPAKE2+).
- **Low KDF cost.** This demo uses a deliberately low PBKDF2 iteration count so the attack is visible in a tab. Real deployments use a per-record salt and far more iterations, slowing the attacker — but not changing which side can be impersonated.
- **Balanced storage of many users' `w`.** Using SPAKE2 as a server login scheme means the database *is* the set of every user's credential.

## Real-World Usage

- **Matter / Thread** commissioning uses SPAKE2+ (PASE) with the printed setup code as the password.
- **SPAKE2** is used in some symmetric device-pairing and Kerberos-adjacent contexts where both sides share the secret.
- **OPAQUE** (RFC 9807) is the OPRF-based augmented aPAKE for password logins where the server should never see the password at all — see the sibling demo.

## How to Run Locally

```bash
npm install
npm run dev        # start the Vite dev server
npm test           # run the Vitest known-answer + attack tests
npm run build      # production build to dist/
npm run test:a11y  # WCAG 2.1 AA gate (axe-core via Playwright), both themes
```

Requires Node 18+. The a11y gate needs a Chromium browser: `npx playwright install chromium`.

## Related Demos

- **[OPAQUE Gate](https://crypto-lab.systemslibrarian.dev/crypto-lab-opaque-gate/)** — the OPRF-based augmented aPAKE (RFC 9807).
- **[PAKE Gate](https://crypto-lab.systemslibrarian.dev/crypto-lab-pake-gate/)** — the wider PAKE survey (SRP-6a, J-PAKE, CPace, Dragonfly, and the Dragonblood side-channel).
- **EC Point Arithmetic / Curve Lens** — the elliptic-curve point operations underpinning the mask.

## Build & Verify

- **15 tests** (Vitest), all passing:
  - **10 known-answer tests** reproducing the RFC vectors bit-for-bit:
    - `src/spake/spake2.test.ts` — all **4** RFC 9382 Appendix B SPAKE2 vectors (shares, `K`, transcript, `Ke/Ka`, `KcA/KcB`, both confirmation MACs), plus the M/N constant check.
    - `src/spake/spake2plus.test.ts` — the RFC 9383 Appendix C SPAKE2+ vector (record `L`, shares, `Z`, `V`, transcript, `K_main`, confirmation keys, `K_shared`, both MACs).
  - **5 attack tests** (`src/attack/offline.test.ts`): the offline dictionary attack cracks a weak password and fails on a strong one, the recovered `w1` genuinely reconstructs `L`, and a stolen SPAKE2 `w` is accepted by the real verifier while a wrong `w` is rejected.
- **Accessibility gate:** `@axe-core/playwright` scans the production build for zero WCAG 2.1 A/AA violations in **both** themes; the GitHub Pages deploy is blocked if it fails.

## Performance

The full SPAKE2/SPAKE2+ handshake is a handful of P-256 scalar multiplications — sub-millisecond. The offline attack's cost is dominated by PBKDF2; the demo's low iteration count keeps a full dictionary sweep under a second so it renders live.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
