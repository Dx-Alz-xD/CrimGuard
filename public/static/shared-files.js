'use strict';

// Files shared with this account, and a clipboard integrity check.
//
// What leaves this page, and what does not:
//
//   sent      when something copied or pasted contains a string whose SHA-256 starts with one of
//             the prefixes the server lists, the full SHA-256 of that string - nothing else.
//   not sent  the clipboard text, or any hash that doesn't match a listed prefix. With 8-hex-digit
//             prefixes, an ordinary string has about a one-in-four-billion chance of matching.

(() => {
  // Strings shaped like a secret. Must stay identical to the server's copy (a test checks).
  const CANDIDATE_PATTERNS = [
    /\bAKIA[A-Z2-7]{16}\b/g,
    /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g,
    /\b(?:sk_live|whsec)_[A-Za-z0-9]{32}\b/g,
    /\bghp_[A-Za-z0-9]{36}\b/g,
    /\bxoxb-\d{12}-\d{13}-[A-Za-z0-9]{24}\b/g,
    /\bpostgres:\/\/[^\s:@/]+:[A-Za-z0-9]{24}@[^\s/:]+:\d+\/[A-Za-z0-9_]+/g,
    /(?<![A-Za-z0-9])[A-Za-z0-9]{24}(?![A-Za-z0-9])/g,
    /(?<![A-Za-z0-9!#%*])[A-Za-z0-9!#%*]{22}(?![A-Za-z0-9!#%*])/g,
    /(?<![A-Za-z0-9])[A-Za-z0-9]{26}(?![A-Za-z0-9])/g,
    /https:\/\/files\.[a-z0-9-]+\.internal\/s\/[A-Za-z0-9]{26}/g,
  ];
  const MAX_CANDIDATES = 200;

  function extractCandidates(text) {
    if (typeof text !== 'string' || text.length < 20) return [];
    const found = new Set();
    for (const pattern of CANDIDATE_PATTERNS) {
      for (const match of text.matchAll(pattern)) {
        found.add(match[0]);
        if (found.size >= MAX_CANDIDATES) return [...found];
      }
    }
    return [...found];
  }

  window.CrimGuardSharedFiles = { CANDIDATE_PATTERNS, extractCandidates };

  const page = document.body && document.body.dataset ? document.body.dataset.page : null;
  if (page !== 'dashboard' && page !== 'admin' && page !== 'risk') return;

  const REFRESH_MS = 5 * 60_000;
  let watch = new Set();

  const signedOut = (res) => {
    if (res.status === 401) {
      location.href = '/login';
      return true;
    }
    return false;
  };

  // ---- the clipboard check -----------------------------------------------------------------------

  async function sha256(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function check(action, text) {
    if (!watch.size || !globalThis.crypto || !crypto.subtle) return;
    const matches = [];
    for (const candidate of extractCandidates(text)) {
      const hash = await sha256(candidate);
      if (watch.has(hash.slice(0, 8))) matches.push(hash);
    }
    if (!matches.length) return;
    const res = await fetch('/api/files/shared/integrity', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, fingerprints: matches }),
    }).catch(() => null);
    if (res) signedOut(res);
  }

  for (const type of ['copy', 'cut']) {
    addEventListener(type, () => { check(type, String(getSelection() || '')); }, { capture: true });
  }
  addEventListener('paste', (event) => {
    let text = '';
    try { text = event.clipboardData ? event.clipboardData.getData('text') : ''; } catch { /* blocked */ }
    check('paste', text);
  }, { capture: true });

  // ---- the files ---------------------------------------------------------------------------------

  // Shared files are drawn with the same classes as the project list and dialogs in app.js, so
  // they read as part of the page rather than something added to it.
  let section = null;

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === 'class') el.className = value;
      else if (key === 'style') el.style.cssText = value;
      else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, value);
    }
    el.append(...children.filter((child) => child !== null && child !== undefined && child !== false));
    return el;
  }

  const formatSize = (bytes) => (bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`);
  const formatDate = (value) => new Date(value).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });

  function render(files) {
    if (!files.length) {
      if (section) section.remove();
      section = null;
      return;
    }
    if (!section) {
      section = h('section', { 'aria-labelledby': 'shared-files-title', style: 'display:grid;gap:14px' });
      (document.querySelector('main') || document.body).append(section);
    }
    section.replaceChildren(
      h('header', { class: 'page-header' },
        h('div', {},
          h('h2', { id: 'shared-files-title', style: 'font-size:19px;font-weight:650;font-stretch:104%' }, 'Shared with you'),
          h('p', {}, 'Files other teams have shared with your account.'))),
      h('div', { class: 'surface' },
        h('ul', { class: 'project-list' }, ...files.map((file) => h('li', { class: 'project-row' },
          h('span', { class: 'status status-idle' }, formatSize(file.size)),
          h('div', { class: 'project-main' },
            h('p', { class: 'project-name' }, file.name),
            h('p', { class: 'project-desc' }, `${file.fileName} · ${file.description}`)),
          h('span', { class: 'project-updated' }, `Updated ${formatDate(file.updatedAt)}`),
          h('div', { class: 'row-actions' },
            h('button', { class: 'btn btn-quiet btn-sm', type: 'button', 'aria-label': `Open ${file.name}`, onclick: () => show(file.id) }, 'Open')))))),
    );
  }

  async function show(id) {
    const res = await fetch(`/api/files/shared/${id}`).catch(() => null);
    if (!res || signedOut(res) || !res.ok) return;
    const { file } = await res.json();

    const dialog = h('dialog', { class: 'dialog', 'aria-labelledby': 'shared-file-title', style: 'width:min(640px, calc(100% - 32px))' },
      h('div', { class: 'dialog-head' },
        h('h2', { class: 'dialog-title', id: 'shared-file-title' }, file.name),
        h('p', { class: 'dialog-note' }, file.fileName)),
      h('div', { class: 'dialog-body' },
        h('pre', { style: 'margin:0;padding:14px;max-height:55vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--canvas);border:1px solid var(--line);border-radius:8px' }, file.body)),
      h('div', { class: 'dialog-actions' },
        h('button', { class: 'btn btn-secondary', type: 'button', onclick: () => dialog.close() }, 'Close')));
    dialog.addEventListener('close', () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
  }

  async function refresh() {
    const res = await fetch('/api/files/shared').catch(() => null);
    if (!res || signedOut(res) || !res.ok) return;
    const data = await res.json();
    watch = new Set(Array.isArray(data.watch) ? data.watch : []);
    render(Array.isArray(data.files) ? data.files : []);
  }

  refresh();
  setInterval(refresh, REFRESH_MS);
})();
