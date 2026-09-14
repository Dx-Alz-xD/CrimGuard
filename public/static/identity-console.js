'use strict';

// The identity-throttle panel on the admin risk console (/admin/risk): accounts CrimGuard has
// stepped up or frozen and why, actions waiting for an analyst, the response policies, and for
// any one person their typing and pointer profile and the decoys planted for them.

(() => {
  if (document.body.dataset.page !== 'risk') return;
  const root = document.getElementById('identity-console');
  if (!root) return;

  const ACTION_LABELS = {
    step_up_mfa: 'Step-up', session_freeze: 'Freeze', session_revoke: 'Sessions ended', account_suspend: 'Suspend',
    force_password_reset: 'Password reset', restore_access: 'Access restored',
  };
  const SOURCE_LABELS = {
    risk_policy: 'risk policy', biometrics: 'typing & pointer', honeytrap: 'honeytrap', decoy_project: 'decoy project',
    step_up_failed: 'failed step-ups', analyst: 'analyst',
  };

  function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (key === 'class') el.className = value;
      else if (key === 'value') el.value = value;
      else el.setAttribute(key, value === true ? '' : value);
    }
    el.append(...children.flat().filter((child) => child != null && child !== false));
    return el;
  }

  async function api(method, url, body) {
    const options = { method, headers: { Accept: 'application/json' } };
    if (method !== 'GET') {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body || {});
    }
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Something went wrong (${res.status}).`);
    return data;
  }

  const toast = (message) => {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 3500);
  };
  // Inline, so this panel needs nothing added to styles.css.
  const LIST_STYLE = 'margin:6px 0 0;padding-left:18px;display:grid;gap:4px;font-size:13px';
  const when = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' }) : '');
  const initials = (name) => (name || '?').split(/\s+/).slice(0, 2).map((word) => word[0]?.toUpperCase() || '').join('');

  function standing(person) {
    if (person.frozen) return h('span', { class: 'status status-alert' }, 'Frozen');
    if (person.pending) return h('span', { class: 'status status-warn' }, 'Awaiting approval');
    if (person.stepUp) return h('span', { class: 'status status-warn' }, 'Step-up open');
    return h('span', { class: 'status status-ok' }, 'Clear');
  }

  const describe = (action) => h('div', {},
    h('div', {}, `${ACTION_LABELS[action.action] || action.action} · ${SOURCE_LABELS[action.source] || action.source || 'unknown'}`,
      action.status === 'pending' ? ' · waiting' : '', action.downgradedFrom ? ' · downgraded from a freeze (last admin)' : ''),
    h('div', { class: 'muted' }, [when(action.createdAt), ...(action.reasons || []).slice(0, 3)].filter(Boolean).join(' · ')));

  async function act(label, request) {
    try {
      await request();
      toast(label);
      await load();
    } catch (err) {
      toast(err.message);
    }
  }

  // ---- one person's evidence ---------------------------------------------------------------

  async function evidence(person, cell) {
    cell.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
    const [bio, trap] = await Promise.all([
      api('GET', `/api/admin/biometrics/people/${person.crimUserId}`).catch(() => null),
      api('GET', `/api/admin/honeytrap/people/${person.crimUserId}`).catch(() => null),
    ]);
    const blocks = [];
    if (bio) {
      const modes = [bio.enrolment.keys && 'typing', bio.enrolment.pointer && 'pointer'].filter(Boolean);
      blocks.push(h('div', {},
        h('strong', {}, 'Typing & pointer'),
        h('p', { class: 'muted' }, modes.length ? `Profile learnt for ${modes.join(' and ')}.`
          : `Still learning: ${bio.enrolment.needed?.windows ?? 0} more windows over ${bio.enrolment.needed?.days ?? 0} more days.`),
        bio.recent.length ? h('ul', { style: LIST_STYLE }, bio.recent.slice(0, 6).map((w) => h('li', {},
          `${when(w.at)} · ${w.verdict}${w.z === null ? '' : ` · ${w.z > 0 ? '+' : ''}${w.z}σ`}`
          + `${w.keys ? ` · ${w.keys} keys` : ''}${w.strokes ? ` · ${w.strokes} pointer strokes` : ''}${w.decision && w.decision !== 'ok' ? ` · ${w.decision}` : ''}`)))
          : h('p', { class: 'muted' }, 'No windows yet.')));
    }
    if (trap) {
      blocks.push(h('div', {},
        h('strong', {}, 'Decoys'),
        trap.plantings.length ? h('ul', { style: LIST_STYLE }, trap.plantings.slice(-5).reverse().map((p) => h('li', {},
          `${p.title} · tier ${p.tier} · ${p.active ? 'active' : p.retireReason || 'retired'} · ${(p.reasons || []).join('; ')}`)))
          : h('p', { class: 'muted' }, 'None planted.'),
        trap.trips.length ? h('p', {}, `${trap.trips.length} trip${trap.trips.length === 1 ? '' : 's'}, last ${when(trap.trips[0].at)} (${trap.trips[0].interaction}).`) : null));
    }
    cell.replaceChildren(h('div', { style: 'display:grid;gap:16px;padding:4px 0' }, blocks));
  }

  // ---- the panel ----------------------------------------------------------------------------

  async function load() {
    let data;
    try {
      data = await api('GET', '/api/admin/identity');
    } catch (err) {
      root.replaceChildren(h('p', { class: 'muted' }, err.message));
      return;
    }

    const people = data.people.length
      ? h('div', { class: 'surface table-wrap' }, h('table', { class: 'table' },
        h('thead', {}, h('tr', {},
          h('th', { scope: 'col' }, 'Person'), h('th', { scope: 'col' }, 'Standing'), h('th', { scope: 'col' }, 'Latest response'),
          h('th', { scope: 'col' }, h('span', { class: 'sr-only' }, 'Actions')))),
        h('tbody', {}, data.people.flatMap((person) => {
          const detail = h('td', { colspan: 4 });
          const detailRow = h('tr', { hidden: true }, detail);
          const pending = person.actions.find((a) => a.status === 'pending');
          return [h('tr', {},
            h('td', {}, h('div', { class: 'person' },
              h('span', { class: person.role === 'admin' ? 'avatar is-admin' : 'avatar', 'aria-hidden': 'true' }, initials(person.name)),
              h('div', { class: 'person-text' },
                h('span', { class: 'person-name' }, person.name),
                h('span', { class: 'person-email' }, person.risk ? `${person.email} · score ${person.risk.score.toFixed(1)}` : person.email)))),
            h('td', {}, standing(person)),
            h('td', { class: 'wrap' }, person.actions[0] ? describe(person.actions[0]) : '—'),
            h('td', {}, h('div', { class: 'row-actions' },
              pending && h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => act('Approved', () => api('POST', `/api/admin/identity/actions/${pending.id}/approve`)) }, 'Approve'),
              pending && h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => act('Declined', () => api('POST', `/api/admin/identity/actions/${pending.id}/decline`)) }, 'Decline'),
              (person.frozen || person.stepUp) && h('button', {
                class: 'btn btn-quiet btn-sm', type: 'button',
                onclick: () => {
                  const note = prompt(`Restore access for ${person.name}? Add a note for the record:`, '');
                  if (note !== null) act('Access restored', () => api('POST', `/api/admin/identity/people/${person.crimUserId}/restore`, { note }));
                },
              }, 'Restore'),
              h('button', {
                class: 'btn btn-quiet btn-sm', type: 'button', 'aria-expanded': 'false',
                onclick: (event) => {
                  detailRow.hidden = !detailRow.hidden;
                  event.currentTarget.setAttribute('aria-expanded', String(!detailRow.hidden));
                  if (!detailRow.hidden) evidence(person, detail);
                },
              }, 'Evidence')))),
          detailRow];
        }))))
      : h('div', { class: 'surface' }, h('div', { class: 'empty' }, h('h2', {}, 'Nobody is under a response'),
        h('p', {}, 'Step-ups and freezes appear here when a policy, biometrics or a honeytrap acts on an account.')));

    const policies = h('div', { class: 'surface table-wrap' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Policy'), h('th', { scope: 'col' }, 'Action'), h('th', { scope: 'col' }, 'From score'),
        h('th', { scope: 'col' }, h('span', { class: 'sr-only' }, 'Settings')))),
      h('tbody', {}, data.policies.map((policy) => {
        const threshold = h('input', {
          type: 'number', min: 0, max: 100, step: 1, value: policy.minFinalScore ?? '', placeholder: 'any',
          'aria-label': `Minimum score for ${policy.name}`, style: 'width:6.5rem;height:34px',
          onchange: (event) => act('Policy saved', () => api('PATCH', `/api/admin/identity/policies/${policy.id}`, {
            minFinalScore: event.target.value === '' ? null : Number(event.target.value),
          })),
        });
        return h('tr', {},
          h('td', {}, h('div', {}, policy.name), policy.scenario ? h('div', { class: 'muted' }, `scenario: ${policy.scenario.replace(/_/g, ' ')}`) : null),
          h('td', {}, ACTION_LABELS[policy.action] || policy.action),
          h('td', {}, threshold),
          h('td', {}, h('div', { class: 'row-actions' },
            h('button', {
              class: 'btn btn-quiet btn-sm', type: 'button', 'aria-pressed': String(policy.requiresApproval),
              onclick: () => act('Policy saved', () => api('PATCH', `/api/admin/identity/policies/${policy.id}`, { requiresApproval: !policy.requiresApproval })),
            }, policy.requiresApproval ? 'Needs approval' : 'Automatic'),
            h('button', {
              class: `btn btn-quiet btn-sm${policy.isEnabled ? '' : ' btn-danger'}`, type: 'button', 'aria-pressed': String(policy.isEnabled),
              onclick: () => act('Policy saved', () => api('PATCH', `/api/admin/identity/policies/${policy.id}`, { isEnabled: !policy.isEnabled })),
            }, policy.isEnabled ? 'On' : 'Off'))));
      }))));

    root.replaceChildren(
      h('header', { class: 'page-header' }, h('div', {},
        h('h2', {}, 'Identity responses'),
        h('p', {}, 'Step-ups and freezes CrimGuard has applied, from risk policies, typing and pointer dynamics, and honeytraps.'))),
      people,
      h('header', { class: 'page-header' }, h('div', {},
        h('h2', {}, 'Response policies'),
        h('p', {}, 'When a score or scenario triggers a step-up or a freeze. The strongest matching policy wins.'))),
      policies,
    );
  }

  load();
  // Refresh in the background, but not while someone is reading a person's evidence.
  setInterval(() => { if (!root.querySelector('tr:not([hidden]) > td[colspan]')) load(); }, 30_000);
})();
