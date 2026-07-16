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

/**
 * A monospace hex chip: shows a truncated value, the full value on hover/focus,
 * and copies the full value to the clipboard on click or Enter/Space. It is a
 * real <button> so it is keyboard-operable and announced correctly.
 */
export function hexChip(hex: string, label?: string): HTMLElement {
  const shown = shortHex(hex)
  const chip = el('button', {
    type: 'button',
    class: 'hex',
    title: `${hex}\n(click to copy)`,
    'aria-label': `Copy ${label ? label + ': ' : ''}${hex}`,
  })
  chip.textContent = shown
  let resetTimer: ReturnType<typeof setTimeout> | undefined
  chip.addEventListener('click', () => {
    const restore = () => {
      chip.textContent = shown
      chip.classList.remove('copied')
    }
    const ok = () => {
      chip.textContent = 'copied ✓'
      chip.classList.add('copied')
      if (resetTimer) clearTimeout(resetTimer)
      resetTimer = setTimeout(restore, 1100)
    }
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(hex).then(ok).catch(() => {})
    } else {
      ok()
    }
  })
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
