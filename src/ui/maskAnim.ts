// THE HEADLINE MECHANISM (§2 "show, don't tell"): the M/N mask, stepped.
//
// SPAKE2's whole trick in one panel: blind a real Diffie–Hellman share by adding
// w·M, where w comes from the password. An observer sees a uniformly random
// point that leaks nothing. The peer, knowing w, subtracts it back and finishes
// the DH to the same key.
//
// VISUAL HONESTY (§2): P-256 lives in a 256-bit field and cannot be drawn as a
// smooth 2-D curve. So the map below is labeled a SCHEMATIC: each real point is
// placed at a position DERIVED FROM ITS ACTUAL ENCODING (a hash → x,y). Equal
// points land in the same spot; the masked point lands somewhere unpredictable.
// The hex beside every node is the real, computed P-256 value — no faking.

import { el, hexChip } from './dom.ts'
import { spake2Run, type Spake2Result } from '../spake/spake2.ts'
import {
  randomScalar,
  encodePoint,
  bytesToHex,
  type Point,
} from '../spake/group.ts'

const VB = 320 // svg viewbox size

interface Step {
  title: string
  body: string
  show: Set<'X' | 'maskA' | 'pA' | 'recovered' | 'observer' | 'K'>
  observer: boolean
}

const STEPS: Step[] = [
  {
    title: '1 · Alice computes a real Diffie–Hellman share',
    body:
      'She picks a fresh secret scalar x and computes X = x·P on the real P-256 curve. This is an ordinary DH share — no password involved yet.',
    show: new Set(['X']),
    observer: false,
  },
  {
    title: '2 · She blinds it with the password',
    body:
      'w is derived from the password. Alice adds the mask w·M to her share: pA = X + w·M. The addition is real point addition on P-256.',
    show: new Set(['X', 'maskA', 'pA']),
    observer: false,
  },
  {
    title: '3 · Only pA goes on the wire — the observer learns nothing',
    body:
      'An eavesdropper sees pA and nothing else. Because w·M shifts X by a password-dependent amount, pA is uniformly distributed: it is indistinguishable from a random curve point. It reveals neither x nor the password.',
    show: new Set(['pA']),
    observer: true,
  },
  {
    title: '4 · Bob, who also knows w, unmasks it',
    body:
      'Bob subtracts the mask: pA − w·M = X. The blinding vanishes for anyone holding w, and Bob recovers Alice’s true DH share.',
    show: new Set(['pA', 'maskA', 'recovered']),
    observer: false,
  },
  {
    title: '5 · Both sides reach the identical key',
    body:
      'Each side finishes the Diffie–Hellman and derives the same shared point K — computed independently and compared byte-for-byte below.',
    show: new Set(['X', 'K']),
    observer: false,
  },
]

/** Deterministic 2-D position for a real point, from its encoding. */
function place(pt: Point): { x: number; y: number } {
  const enc = encodePoint(pt)
  // FNV-ish fold of the encoding into two coordinates.
  let a = 2166136261 >>> 0
  let b = 1099511628211 & 0xffffffff
  for (let i = 0; i < enc.length; i++) {
    a = (a ^ enc[i]) >>> 0
    a = (a * 16777619) >>> 0
    b = (b ^ enc[enc.length - 1 - i]) >>> 0
    b = (b * 16777619) >>> 0
  }
  const pad = 46
  const span = VB - pad * 2
  return { x: pad + (a % span), y: pad + (b % span) }
}

function node(
  pt: Point,
  cls: string,
  label: string,
): SVGGElement {
  const p = place(pt)
  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g')
  g.setAttribute('class', `pt ${cls}`)
  const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle')
  c.setAttribute('cx', String(p.x))
  c.setAttribute('cy', String(p.y))
  c.setAttribute('r', '9')
  const t = document.createElementNS('http://www.w3.org/2000/svg', 'text')
  t.setAttribute('x', String(p.x))
  t.setAttribute('y', String(p.y - 14))
  t.setAttribute('text-anchor', 'middle')
  t.setAttribute('class', 'pt-label')
  t.textContent = label
  g.append(c, t)
  return g
}

export function buildMaskAnimation(): HTMLElement {
  let run: Spake2Result = fresh()
  let stepIdx = 0

  function fresh(): Spake2Result {
    return spake2Run({
      idA: 'client',
      idB: 'server',
      w: randomScalar(),
      x: randomScalar(),
      y: randomScalar(),
    })
  }

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  svg.setAttribute('viewBox', `0 0 ${VB} ${VB}`)
  svg.setAttribute('class', 'mask-svg')
  svg.setAttribute('role', 'img')

  const observerBox = el('div', {
    class: 'observer-box',
    role: 'status',
    'aria-live': 'polite',
  })
  const stepTitle = el('h3', { class: 'step-title' })
  const stepBody = el('p', { class: 'step-body' })
  const hexRows = el('div', { class: 'hex-rows' })
  const kCompare = el('div', {
    class: 'k-compare',
    role: 'status',
    'aria-live': 'polite',
  })

  const counter = el('span', { class: 'step-counter', 'aria-hidden': 'true' })
  const prev = el('button', { class: 'btn', type: 'button', text: '‹ Back' })
  const next = el('button', { class: 'btn btn-primary', type: 'button', text: 'Next ›' })
  const reroll = el('button', {
    class: 'btn',
    type: 'button',
    text: '↻ Fresh randomness',
  })

  function render(): void {
    const step = STEPS[stepIdx]
    svg.textContent = ''

    // schematic curve backdrop (explicitly labeled illustrative)
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute(
      'd',
      `M 20 ${VB - 40} C ${VB * 0.3} ${VB * 0.1}, ${VB * 0.7} ${VB * 1.0}, ${VB - 20} 40`,
    )
    path.setAttribute('class', 'curve-hint')
    svg.append(path)

    const svgTitle = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'title',
    )
    svgTitle.textContent =
      'Schematic map of real P-256 points (positions are a hash of each point’s encoding, not curve geometry).'
    svg.append(svgTitle)

    const drawMaskVector = (from: Point, to: Point, cls: string) => {
      const a = place(from)
      const b = place(to)
      const line = document.createElementNS(
        'http://www.w3.org/2000/svg',
        'line',
      )
      line.setAttribute('x1', String(a.x))
      line.setAttribute('y1', String(a.y))
      line.setAttribute('x2', String(b.x))
      line.setAttribute('y2', String(b.y))
      line.setAttribute('class', `mask-vec ${cls}`)
      line.setAttribute('marker-end', 'url(#arrow)')
      svg.append(line)
    }

    // arrow marker
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs')
    defs.innerHTML =
      '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="currentColor"/></marker>'
    svg.append(defs)

    const s = step.show
    if (s.has('maskA') && (s.has('pA') || s.has('recovered'))) {
      drawMaskVector(run.X, run.pA, s.has('recovered') ? 'undo' : 'add')
    }
    if (s.has('X')) svg.append(node(run.X, 'x', 'X = x·P'))
    if (s.has('pA')) svg.append(node(run.pA, 'pa', 'pA = X + w·M'))
    if (s.has('recovered')) svg.append(node(run.X, 'x recovered', 'recovered X'))
    if (s.has('K')) svg.append(node(run.K, 'k', 'K (shared)'))

    stepTitle.textContent = step.title
    stepBody.textContent = step.body
    counter.textContent = `Step ${stepIdx + 1} of ${STEPS.length}`

    // observer view
    observerBox.textContent = ''
    if (step.observer) {
      observerBox.append(
        el('span', { class: 'observer-tag', text: '👁 OBSERVER’S VIEW' }),
        el('p', {
          class: 'observer-text',
          text: 'Everything the eavesdropper has:',
        }),
        hexChip(bytesToHex(encodePoint(run.pA)), 'pA on the wire'),
        el('p', {
          class: 'observer-note',
          text: 'No x. No w. No password. Just a point that could be any point.',
        }),
      )
      observerBox.hidden = false
    } else {
      observerBox.hidden = true
    }

    // hex rows for the current step
    hexRows.textContent = ''
    const rows: [string, string][] = []
    if (s.has('X')) rows.push(['X = x·P', bytesToHex(encodePoint(run.X))])
    if (s.has('maskA')) rows.push(['w·M (mask)', bytesToHex(encodePoint(run.maskA))])
    if (s.has('pA')) rows.push(['pA = X + w·M', bytesToHex(encodePoint(run.pA))])
    if (s.has('recovered'))
      rows.push(['pA − w·M', bytesToHex(encodePoint(run.pA.subtract(run.maskA)))])
    for (const [label, hex] of rows) {
      hexRows.append(
        el('div', { class: 'hex-row' }, [
          el('span', { class: 'hex-label', text: label }),
          hexChip(hex, label),
        ]),
      )
    }

    // K comparison (compute-both-sides-and-compare)
    kCompare.textContent = ''
    if (s.has('K')) {
      const alice = bytesToHex(encodePoint(run.K))
      const bob = bytesToHex(encodePoint(run.Kverifier))
      const match = alice === bob
      kCompare.append(
        el('div', { class: 'k-row' }, [
          el('span', { class: 'k-side', text: 'Alice’s K' }),
          hexChip(alice, 'Alice K'),
        ]),
        el('div', { class: 'k-row' }, [
          el('span', { class: 'k-side', text: 'Bob’s K' }),
          hexChip(bob, 'Bob K'),
        ]),
        el('div', { class: `k-verdict ${match ? 'ok' : 'bad'}` }, [
          el('span', { class: 'k-icon', 'aria-hidden': 'true', text: match ? '✓' : '✗' }),
          el('span', {
            text: match
              ? 'Byte-for-byte equal — both sides derived the same key.'
              : 'Mismatch — keys disagree.',
          }),
        ]),
      )
    }

    prev.toggleAttribute('disabled', stepIdx === 0)
    next.toggleAttribute('disabled', stepIdx === STEPS.length - 1)
  }

  prev.addEventListener('click', () => {
    if (stepIdx > 0) stepIdx--
    render()
  })
  next.addEventListener('click', () => {
    if (stepIdx < STEPS.length - 1) stepIdx++
    render()
  })
  reroll.addEventListener('click', () => {
    run = fresh()
    render()
  })

  const wrap = el('div', { class: 'mask-anim' }, [
    el('div', { class: 'mask-grid' }, [
      el('div', { class: 'mask-visual' }, [
        svg,
        el('p', {
          class: 'schematic-label',
          text: 'Schematic — positions are a hash of each real P-256 point, not curve geometry. The hex values are the true computed points.',
        }),
        observerBox,
      ]),
      el('div', { class: 'mask-explain' }, [
        stepTitle,
        stepBody,
        hexRows,
        kCompare,
      ]),
    ]),
    el('div', { class: 'stepper-controls' }, [
      prev,
      counter,
      next,
      el('span', { class: 'spacer' }),
      reroll,
    ]),
  ])

  render()
  return wrap
}
