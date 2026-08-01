// Three-way comparison: SPAKE2 vs SPAKE2+ vs OPAQUE.
//
// SCOPE GUARD (non-goal C): this is a comparison, not a rebuild. The deep dives
// for SRP/J-PAKE/CPace and for OPAQUE's OPRF live in sibling demos — we link out
// rather than re-implement them here.

import { el } from './dom.ts'

interface Col {
  name: string
  tag: string
  serverStores: string
  onCompromise: string
  compromiseClass: 'is-bad' | 'is-mid' | 'is-good'
  registration: string
  authentication: string
}

const COLS: Col[] = [
  {
    name: 'SPAKE2',
    tag: 'balanced PAKE · RFC 9382',
    serverStores: 'w — the password-equivalent scalar (both sides hold the same secret).',
    onCompromise:
      'Total. w is the client. Instant, permanent impersonation with no cracking.',
    compromiseClass: 'is-bad',
    registration: 'Symmetric — server ends up holding the same secret the client uses.',
    authentication: 'One round trip: masked shares + a key-confirmation MAC.',
  },
  {
    name: 'SPAKE2+',
    tag: 'augmented PAKE · RFC 9383',
    serverStores: 'w0 and L = w1·P. Verifies a login; cannot produce one.',
    onCompromise:
      'Survivable. No direct impersonation — the attacker is forced into an offline dictionary attack, which a strong password defeats.',
    compromiseClass: 'is-mid',
    registration: 'Asymmetric — the client keeps w1; the server never sees it.',
    authentication: 'Same wire shape as SPAKE2, plus the augmentation element V from L.',
  },
  {
    name: 'OPAQUE',
    tag: 'augmented aPAKE · RFC 9807',
    serverStores:
      'An OPRF key + an encrypted envelope. The server never learns the password, even during registration.',
    onCompromise:
      'Survivable, like SPAKE2+: an offline dictionary attack is still forced, but the password is never exposed to the server at any point.',
    compromiseClass: 'is-good',
    registration: 'OPRF-blinded — the password is stretched with a key only the server holds.',
    authentication: 'OPRF evaluation → envelope decryption → an authenticated key exchange.',
  },
]

// Each demo is served from its OWN GitHub Pages site. The
// crypto-lab.systemslibrarian.dev domain serves only the catalog page — per-demo
// subpaths under it return 404, so sibling links must use the github.io form.
function link(text: string, repo: string): HTMLAnchorElement {
  return el('a', {
    class: 'sib-link',
    href: `https://systemslibrarian.github.io/${repo}/`,
    target: '_blank',
    rel: 'noopener',
    text,
  }) as HTMLAnchorElement
}

export function buildComparison(): HTMLElement {
  const table = el('table', { class: 'cmp-table' })

  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, [el('span', { class: 'sr-only', text: 'Property' })]),
  ])
  for (const c of COLS) {
    headRow.append(
      el('th', { scope: 'col' }, [
        el('span', { class: 'cmp-name', text: c.name }),
        el('span', { class: 'cmp-tag', text: c.tag }),
      ]),
    )
  }

  const rows: [string, (c: Col) => Node | string, ((c: Col) => string) | null][] = [
    ['What the server stores', (c) => c.serverStores, null],
    [
      'On database compromise',
      (c) => c.onCompromise,
      (c) => c.compromiseClass,
    ],
    ['Registration', (c) => c.registration, null],
    ['Authentication', (c) => c.authentication, null],
  ]

  const body = el('tbody')
  const thead = el('thead', {}, [headRow])
  table.append(thead)
  for (const [label, get, clsGet] of rows) {
    const tr = el('tr', {}, [el('th', { scope: 'row', text: label })])
    for (const c of COLS) {
      const cls = clsGet ? clsGet(c) : ''
      tr.append(el('td', { class: cls }, [
        typeof get(c) === 'string' ? document.createTextNode(get(c) as string) : (get(c) as Node),
      ]))
    }
    body.append(tr)
  }
  table.append(body)

  return el('div', { class: 'comparison' }, [
    el('div', {
      class: 'table-scroll',
      role: 'region',
      'aria-label': 'Comparison of SPAKE2, SPAKE2+ and OPAQUE',
      tabindex: '0',
    }, [table]),
    el('p', { class: 'cmp-links' }, [
      el('span', { text: 'Deep dives on the siblings: ' }),
      link('OPAQUE ↗', 'crypto-lab-opaque-gate'),
      el('span', { text: ' · ' }),
      link('the PAKE survey (SRP-6a, J-PAKE, CPace, Dragonfly) ↗', 'crypto-lab-pake-gate'),
    ]),
    el('p', {}, [
      el('span', { class: 'scope-note-tag', text: 'WHAT THIS ISN’T' }),
      el('span', {
        text: ' Not a PAKE survey and not an OPAQUE build. The OPRF blinding and the SRP/J-PAKE/CPace/Dragonfly family are built out in the linked siblings, not here.',
      }),
    ]),
  ])
}
