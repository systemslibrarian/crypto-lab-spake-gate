// Where you already run SPAKE2+ without knowing it: Matter / Thread.
//
// When you commission a smart-home device, the QR code / 11-digit setup code IS
// the password. The device and your controller run SPAKE2+ to agree on a session
// key over the local network — augmented, so a leak of the device's stored
// record does not hand over impersonation for free.

import { el } from './dom.ts'

export function buildMatterPanel(): HTMLElement {
  return el('div', { class: 'matter' }, [
    el('div', { class: 'matter-grid' }, [
      el('div', { class: 'matter-qr', 'aria-hidden': 'true' }, [
        el('div', { class: 'qr-face' }, [
          el('span', { class: 'qr-emoji', text: '🔳' }),
        ]),
        el('span', { class: 'qr-cap', text: 'setup code = password' }),
      ]),
      el('div', { class: 'matter-text' }, [
        el('p', {
          text: 'SPAKE2+ is not just a spec exercise — it is what your smart-home gear runs at commissioning. In Matter (and Thread-based Matter devices), the printed QR code or 11-digit manual pairing code is the password that seeds SPAKE2+.',
        }),
        el('ul', { class: 'matter-list', role: 'list' }, [
          el('li', { role: 'listitem', text: 'The device stores a SPAKE2+ verifier (w0, L) — derived from the setup code with PBKDF2.' }),
          el('li', { role: 'listitem', text: 'Your phone/hub, holding the code, runs the client side and proves knowledge of w1.' }),
          el('li', { role: 'listitem', text: 'Augmentation matters here: a device you physically hand off cannot leak an impersonation-ready password.' }),
        ]),
      ]),
    ]),
    el('p', {}, [
      el('span', { class: 'scope-note-tag', text: 'WHAT THIS ISN’T' }),
      el('span', {
        text: ' We do not implement the Matter commissioning protocol (PASE session establishment, certificate exchange, etc.) — only the SPAKE2+ core it is built on.',
      }),
    ]),
  ])
}
