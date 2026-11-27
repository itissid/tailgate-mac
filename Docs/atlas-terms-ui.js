/* Offline enhancement. Definitions are text, never markup or executable input. */
(() => {
  'use strict';
  const dictionaryNode = document.getElementById('atlas-dictionary');
  if (!dictionaryNode || document.getElementById('atlas-term-popup')) return;
  let dictionary;
  try { dictionary = JSON.parse(dictionaryNode.textContent); } catch (_) { return; }
  const triggers = [...document.querySelectorAll('[data-atlas-term="1"][data-term]')]
    .filter(node => Object.prototype.hasOwnProperty.call(dictionary, node.dataset.term));
  if (!triggers.length) return;
  const popup = document.createElement('div');
  popup.id = 'atlas-term-popup';
  popup.setAttribute('role', 'tooltip');
  popup.hidden = true;
  const heading = document.createElement('strong');
  const definition = document.createElement('span');
  const source = document.createElement('span');
  source.className = 'atlas-term-source';
  source.textContent = 'Definition: CONTEXT.md · Escape or tap outside to close';
  popup.append(heading, definition, source);
  document.body.append(popup);
  let active = null;
  let pinned = false;
  let timer = null;
  const cancelClose = () => { clearTimeout(timer); timer = null; };
  const close = () => {
    cancelClose();
    if (active) {
      active.removeAttribute('aria-describedby');
      active.setAttribute('aria-expanded', 'false');
    }
    active = null;
    pinned = false;
    popup.hidden = true;
  };
  const position = () => {
    if (!active) return;
    const rect = active.getBoundingClientRect();
    // VisualViewport also handles zoom and the mobile on-screen keyboard.
    const viewport = window.visualViewport;
    const left = viewport ? viewport.offsetLeft : 0;
    const top = viewport ? viewport.offsetTop : 0;
    const width = viewport ? viewport.width : document.documentElement.clientWidth;
    const height = viewport ? viewport.height : document.documentElement.clientHeight;
    popup.style.maxWidth = `${Math.max(1, width - 24)}px`;
    popup.style.maxHeight = `${Math.max(1, height - 24)}px`;
    const box = popup.getBoundingClientRect();
    const clamp = (value, min, max) => Math.max(min, Math.min(value, Math.max(min, max)));
    let y = rect.bottom + 8;
    if (y + box.height > top + height - 12) y = rect.top - box.height - 8;
    popup.style.left = `${clamp(rect.left, left + 12, left + width - box.width - 12)}px`;
    popup.style.top = `${clamp(y, top + 12, top + height - box.height - 12)}px`;
  };
  const open = node => {
    cancelClose();
    if (active === node) return;
    close();
    const entry = dictionary[node.dataset.term];
    if (!entry || typeof entry.term !== 'string' || typeof entry.definition !== 'string') return;
    active = node;
    heading.textContent = entry.term;
    definition.textContent = entry.definition;
    popup.hidden = false;
    node.setAttribute('aria-describedby', popup.id);
    node.setAttribute('aria-expanded', 'true');
    position();
  };
  const scheduleClose = () => {
    cancelClose();
    timer = setTimeout(() => {
      if (!pinned && active !== document.activeElement && !popup.matches(':hover') &&
          !(active && active.matches(':hover'))) close();
    }, 250);
  };
  for (const node of triggers) {
    // SVG role=img hides descendants from accessibility trees. Preserve its
    // accessible title/description while exposing enhanced text as a group.
    const svg = node.closest('svg');
    if (svg && svg.getAttribute('role') === 'img') svg.setAttribute('role', 'group');
    node.removeAttribute('title');
    node.setAttribute('tabindex', '0');
    node.setAttribute('role', 'button');
    node.setAttribute('aria-expanded', 'false');
    node.addEventListener('pointerenter', event => {
      if (event.pointerType === 'touch' || pinned) return;
      open(node);
    });
    node.addEventListener('pointerleave', scheduleClose);
    node.addEventListener('focus', () => open(node));
    node.addEventListener('blur', scheduleClose);
    const activate = () => {
      if (active === node && pinned) close();
      else { open(node); pinned = true; }
    };
    node.addEventListener('click', activate);
    node.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        activate();
      }
    });
  }
  popup.addEventListener('pointerenter', cancelClose);
  popup.addEventListener('pointerleave', scheduleClose);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && active) {
      // Focus stays on its trigger, so Escape does not reopen the tooltip.
      close();
      event.preventDefault();
    }
  });
  document.addEventListener('pointerdown', event => {
    if (active && !active.contains(event.target) && !popup.contains(event.target)) close();
  });
  window.addEventListener('resize', position);
  document.addEventListener('scroll', position, { capture: true, passive: true });
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', position);
    window.visualViewport.addEventListener('scroll', position);
  }
  document.documentElement.classList.add('atlas-terms-ready');
})();
