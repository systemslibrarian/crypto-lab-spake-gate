import './style.css'
import { el, section } from './ui/dom.ts'
import { buildMaskAnimation } from './ui/maskAnim.ts'
import { buildConstantsPanel } from './ui/constants.ts'
import { buildCompromisePanel } from './ui/compromise.ts'
import { buildComparison } from './ui/comparison.ts'
import { buildMatterPanel } from './ui/matter.ts'

const app = document.getElementById('app')!

// ---------------------------------------------------------------------------
// Standardized hero (§3.1): title / spec-subtitle / description on the left,
// "Why it matters" box to the side. Exactly one <h1> on the page.
// ---------------------------------------------------------------------------
const hero = el('header', { class: 'cl-hero' }, [
  el('div', { class: 'cl-hero-main' }, [
    el('h1', { class: 'cl-hero-title', text: 'SPAKE Gate' }),
    el('p', { class: 'cl-hero-sub', text: 'SPAKE2 & SPAKE2+ · RFC 9382 · RFC 9383' }),
    el('p', {
      class: 'cl-hero-desc',
      text: 'Runs real SPAKE2 and SPAKE2+ over P-256 on one password, then steals both server databases so you can watch exactly what a balanced leak hands over versus an augmented one.',
    }),
  ]),
  el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
    el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
    el('p', {
      class: 'cl-hero-why-text',
      text: 'Databases get breached. A balanced PAKE server holds a secret that IS the user; an augmented one holds a verifier that only forces an offline guess. Same login, wildly different blast radius when it leaks.',
    }),
  ]),
])

// ---------------------------------------------------------------------------
// Plain-language on-ramp (§2): what is this / why it matters, zero math.
// ---------------------------------------------------------------------------
const intro = el('section', { id: 'intro', class: 'card intro-card', 'aria-labelledby': 'intro-h' }, [
  el('h2', { id: 'intro-h', class: 'section-title', text: 'What is a PAKE, and why two flavors?' }),
  el('p', { class: 'lead' }, [
    el('span', {
      text: 'A ',
    }),
    el('strong', { text: 'PAKE' }),
    el('span', {
      text: ' (Password-Authenticated Key Exchange) lets two parties turn a shared password into a strong shared key — without ever sending the password, and without a snoop learning anything they could grind offline. ',
    }),
  ]),
  el('p', {
    text: 'A balanced PAKE (SPAKE2) assumes both sides know the password. An augmented PAKE (SPAKE2+) is asymmetric: only the client knows the full password; the server keeps a verifier that can check a login but not perform one. On a good day the two look identical — same handshake, same session key. The difference only shows up on the worst day: when the server’s database leaks.',
  }),
  el('div', { class: 'jargon' }, [
    jargon('Balanced', 'Both parties hold the same secret (here, the scalar w). SPAKE2 is balanced.'),
    jargon('Augmented', 'The server holds a one-way verifier, not the secret itself. SPAKE2+ is augmented.'),
    jargon('w / w0 / w1', 'Scalars derived from the password. SPAKE2 uses one (w). SPAKE2+ splits into w0 (server + client) and w1 (client only).'),
    jargon('Offline dictionary attack', 'Guessing passwords locally against a stolen verifier, as fast as your hardware allows — no server involved.'),
  ]),
])

function jargon(term: string, def: string): HTMLElement {
  return el('div', { class: 'jargon-item' }, [
    el('dfn', { class: 'jargon-term', text: term }),
    el('span', { class: 'jargon-def', text: def }),
  ])
}

// honest-scoping banner (§0.2)
const scoping = el('section', { id: 'scope', class: 'card scoping-card', 'aria-labelledby': 'scope-h' }, [
  el('h2', { id: 'scope-h', class: 'section-title', text: 'Honest scope' }),
  el('ul', { class: 'scoping-list', role: 'list' }, [
    el('li', { role: 'listitem', html: '<strong>Real crypto.</strong> SPAKE2 and SPAKE2+ are hand-rolled over real P-256 (via the audited @noble/curves group ops) and pass the RFC 9382 and RFC 9383 known-answer test vectors bit-for-bit.' }),
    el('li', { role: 'listitem', html: '<strong>Not production.</strong> This is a teaching demo. Everything runs in your browser tab, in memory; nothing is persisted or sent anywhere.' }),
    el('li', { role: 'listitem', html: '<strong>What’s simplified.</strong> The PBKDF2 iteration count is deliberately low so the offline attack visibly runs in a tab. A real deployment uses a per-record salt and far more iterations — which slows the attacker too, but does not change which side can be impersonated.' }),
    el('li', { role: 'listitem', html: '<strong>What it does NOT prove.</strong> It does not prove SPAKE2+ (or OPAQUE) makes leaks harmless — a weak password still falls to offline guessing. Augmentation buys work, not immunity.' }),
  ]),
])

// section builders
const mask = section(
  'mask',
  'The M / N mask, stepped',
  'The one idea SPAKE2 exists for: blind a real Diffie–Hellman share with the password so the wire leaks nothing, then let the peer subtract the blind back off. Step through it.',
)
mask.body.append(buildMaskAnimation())

const constants = section(
  'constants',
  'Why M and N are nothing-up-my-sleeve',
  'The mask uses two fixed public points. Security depends on nobody knowing how they relate. Here they are, and here is the rule.',
)
constants.body.append(buildConstantsPanel())

const compromise = section(
  'compromise',
  'Steal the database — the whole point',
  'One password, registered on a balanced server and an augmented one. Take both databases and see what the thief can actually do. This runs against the real primitive: you cause the failure.',
)
compromise.body.append(buildCompromisePanel())

const comparison = section(
  'comparison',
  'SPAKE2 vs SPAKE2+ vs OPAQUE',
  'Three PAKEs, three answers to “what does the server keep, and what breaks when it leaks?”',
)
comparison.body.append(buildComparison())

const matter = section(
  'matter',
  'You already run this: Matter / Thread',
  'SPAKE2+ is what commissions your smart-home devices. The QR code is the password.',
)
matter.body.append(buildMatterPanel())

const main = el('main', { class: 'content' }, [
  intro,
  scoping,
  mask.root,
  constants.root,
  compromise.root,
  comparison.root,
  matter.root,
])

app.append(hero, main)
