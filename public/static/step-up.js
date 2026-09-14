'use strict';

// "Please confirm it's you": the page side of the identity throttle's step-up.
//
// A step-up can be opened by the risk score crossing a policy or by biometrics noticing someone
// else at the keyboard. Either way the server refuses other API calls with 403 step_up_required
// until the password is confirmed, so this script shows the dialog when:
//   - the page loads with a step-up already open,
//   - biometrics.js reports one (the crimguard:step-up event), or
//   - any request on the page is refused for that reason.
// The dialog can't be dismissed: the only ways out are the password or signing out.

(() => {
  const page = document.body && document.body.dataset ? document.body.dataset.page : null;
  if (page !== 'dashboard' && page !== 'admin' && page !== 'risk') return;

  let dialog = null;

  function element(tag, className, attrs = {}) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'text') el.textContent = value;
      else el.setAttribute(key, value);
    }
    return el;
  }

  function show() {
    if (dialog) return;
    dialog = element('dialog', 'dialog', { 'aria-labelledby': 'step-up-title' });
    // Typing a password is not typing evidence.
    dialog.setAttribute('data-no-biometrics', '');
    const form = element('form', 'dialog-form');
    const head = element('div', 'dialog-head');
    head.append(
      element('h2', 'dialog-title', { id: 'step-up-title', text: 'Please confirm it’s you' }),
      element('p', 'dialog-note', { text: 'Something about this session looks different from usual. Enter your password to carry on.' }),
    );
    const body = element('div', 'dialog-body');
    const field = element('div', 'field');
    const input = element('input', '', { id: 'step-up-password', type: 'password', autocomplete: 'current-password', maxlength: '256', required: '' });
    field.append(element('label', 'field-label', { for: 'step-up-password', text: 'Password' }), input);
    const error = element('p', 'form-error', { role: 'alert' });
    error.hidden = true;
    body.append(field, error);
    const actions = element('div', 'dialog-actions');
    const signOut = element('button', 'btn btn-secondary', { type: 'button', text: 'Sign out' });
    const button = element('button', 'btn btn-primary', { type: 'submit', text: 'Confirm' });
    actions.append(signOut, button);
    form.append(head, body, actions);
    dialog.append(form);
    document.body.append(dialog);

    dialog.addEventListener('cancel', (event) => event.preventDefault());
    signOut.addEventListener('click', () => {
      pageFetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
        .finally(() => { location.href = '/login'; });
    });
    dialog.showModal();
    input.focus();

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      button.disabled = true;
      error.hidden = true;
      try {
        const res = await pageFetch('/api/identity/step-up', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: input.value }),
        });
        if (res.status === 401) {
          location.href = '/login';
          return;
        }
        if (res.ok) {
          // Whatever the page asked for while the step-up was open was refused; start it over.
          location.reload();
          return;
        }
        const reply = await res.json().catch(() => ({}));
        error.textContent = reply.error || 'That didn’t work. Try again.';
        error.hidden = false;
        input.value = '';
      } finally {
        button.disabled = false;
      }
    });
  }

  const pageFetch = window.fetch.bind(window);
  window.fetch = function fetchWatchingForStepUp(...args) {
    return pageFetch(...args).then((res) => {
      if (res.status === 403) {
        res.clone().json().then((body) => { if (body && body.code === 'step_up_required') show(); }).catch(() => {});
      }
      return res;
    });
  };

  addEventListener('crimguard:step-up', show);

  pageFetch('/api/identity/status')
    .then((res) => (res.ok ? res.json() : null))
    .then((status) => { if (status && status.stepUp) show(); })
    .catch(() => {});
})();
