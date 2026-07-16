// Tiny DOM helpers. No framework — the whole app is a few hundred lines of
// vanilla TS so the crypto stays the star and the bundle stays trivial.

type Attrs = Record<string, string | boolean | number | undefined>

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'text') node.textContent = String(v)
    else if (k === 'html') node.innerHTML = String(v)
    else if (v === true) node.setAttribute(k, '')
    else node.setAttribute(k, String(v))
  }
  for (const c of children) {
    node.append(typeof c === 'string' ? document.createTextNode(c) : c)
  }
  return node
}

/** Truncate a hex string for display with a middle ellipsis. */
export function shortHex(hex: string, head = 10, tail = 8): string {
  if (hex.length <= head + tail + 1) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}

/** A monospace hex chip that shows the full value on hover/focus. */
export function hexChip(hex: string, label?: string): HTMLElement {
  const chip = el('code', {
    class: 'hex',
    title: hex,
    tabindex: '0',
    'aria-label': label ? `${label}: ${hex}` : hex,
  })
  chip.textContent = shortHex(hex)
  return chip
}

/** A titled section wrapper (semantic <section> with a heading). */
export function section(
  id: string,
  title: string,
  intro: string,
): { root: HTMLElement; body: HTMLElement } {
  const body = el('div', { class: 'section-body' })
  const root = el('section', { id, class: 'card', 'aria-labelledby': `${id}-h` }, [
    el('h2', { id: `${id}-h`, class: 'section-title', text: title }),
    el('p', { class: 'section-intro', text: intro }),
    body,
  ])
  return { root, body }
}

/** A "what this isn't" scope note (SCOPE GUARD, non-goals). */
export function scopeNote(text: string): HTMLElement {
  return el('p', { class: 'scope-note' }, [
    el('span', { class: 'scope-note-tag', text: 'WHAT THIS ISN’T' }),
    el('span', { text: ` ${text}` }),
  ])
}
