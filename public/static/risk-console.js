'use strict';

// The admin risk console at /admin/risk: everyone Red scores, and for one person at a time all
// 100 variables behind the score, plus the HR context the engine's amplifier runs on.

(() => {
  if (document.body.dataset.page !== 'risk') return;

  const CATEGORY_LABELS = {
    access_resource: 'Access & resources',
    temporal: 'Timing',
    data_movement: 'Data movement',
    authentication_identity: 'Authentication & identity',
    device_network: 'Device & network',
    behavioral_biometrics: 'Behavioural biometrics',
    hr_org_context: 'HR & organisation',
    communication_collaboration: 'Communication',
    privilege_permission: 'Privilege & permission',
    physical_environmental: 'Physical & environmental',
  };
  const LEVEL_CLASS = { low: 'status-ok', medium: 'status-warn', high: 'status-alert', critical: 'status-alert' };
  const COLLECTION_LABELS = { measured: 'measured', derived: 'derived', 'no-source': 'no source' };
  const HR_EVENTS = [
    ['performance_review', 'Negative performance review'],
    ['disciplinary_action', 'Disciplinary action'],
    ['manager_change', 'Manager change'],
    ['compensation_change', 'Compensation change'],
    ['resignation_notice', 'Resignation notice'],
  ];
  const EMPLOYMENT = [['full_time', 'Full time'], ['contractor', 'Contractor'], ['temp', 'Temporary']];

  const $ = (selector) => document.querySelector(selector);

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
    const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Something went wrong (${res.status}).`);
    return data;
  }

  let toastTimer;
  function toast(message, kind = 'ok') {
    const el = $('#toast');
    el.textContent = message;
    el.dataset.kind = kind;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  const formatValue = (value) => {
    if (value === null || value === undefined) return '—';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (typeof value === 'number') {
      if (Number.isInteger(value)) return String(value);
      return Math.abs(value) >= 1 ? value.toFixed(2) : value.toFixed(3);
    }
    return String(value).replace(/_/g, ' ');
  };

  const rows = $('#risk-rows');
  const summary = $('#risk-summary');
  const detail = $('#risk-detail');
  const footnote = $('#risk-footnote');
  let selected = null;

  // ---- the people table --------------------------------------------------------------

  async function loadOverview() {
    const data = await api('GET', '/api/admin/risk/overview');
    const scored = data.people.filter((person) => person.score !== null);
    summary.textContent = `${data.people.length} people · ${scored.length} scored · `
      + `${data.alerts.length} open ${data.alerts.length === 1 ? 'alert' : 'alerts'}`;
    footnote.textContent = `Red collects ${data.coverage.collected} of the ${data.coverage.total} variables in the catalog: `
      + `${data.coverage.measured} observed directly, ${data.coverage.derived} derived. `
      + `The other ${data.coverage['no-source']} need a system Red isn't connected to and stay empty.`;

    if (!data.people.length) {
      rows.replaceChildren(h('tr', {}, h('td', { colspan: 5 },
        h('div', { class: 'empty' }, h('h2', {}, 'Nobody scored yet'), h('p', {}, 'Scores appear once people have used Red.')))));
      return;
    }

    rows.replaceChildren(...data.people.map((person) => h('tr', {},
      h('td', {}, h('div', { class: 'person' },
        h('span', { class: person.role === 'admin' ? 'avatar is-admin' : 'avatar', 'aria-hidden': 'true' },
          (person.name || '?').split(/\s+/).slice(0, 2).map((word) => word[0].toUpperCase()).join('')),
        h('div', { class: 'person-text' },
          h('span', { class: 'person-name' }, person.name),
          h('span', { class: 'person-email' }, person.email)))),
      h('td', {}, person.score === null
        ? h('span', { class: 'status status-idle' }, 'Not scored')
        : h('span', { class: `status ${LEVEL_CLASS[person.level] || 'status-idle'}` }, `${person.score.toFixed(1)} ${person.level}`)),
      h('td', { class: 'muted' }, person.scenario ? person.scenario.replace(/_/g, ' ') : '—'),
      h('td', { class: 'date' }, person.lastSnapshot || '—'),
      h('td', {}, h('div', { class: 'row-actions' },
        h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => showPerson(person.id) }, 'Variables'))))));
  }

  // ---- one person's 100 variables -------------------------------------------------------

  async function showPerson(id) {
    selected = id;
    const data = await api('GET', `/api/admin/risk/people/${id}`);
    detail.hidden = false;
    $('#detail-name').textContent = data.person.full_name;

    const score = data.score;
    $('#detail-meta').textContent = score
      ? `${data.date} · ${Number(score.final_score).toFixed(1)} ${score.risk_level}`
        + `${score.scenario ? ` · ${score.scenario.replace(/_/g, ' ')}` : ''}`
        + ` · context ×${Number(score.context_multiplier).toFixed(2)} · HR ×${Number(score.hr_amplifier).toFixed(2)}`
      : `${data.date || 'No snapshot'} · not scored yet`;

    const points = new Map((score?.dashboard_payload?.contributions || []).map((item) => [item.feature, item.points]));
    const groups = new Map();
    for (const feature of data.features) {
      if (!groups.has(feature.category)) groups.set(feature.category, []);
      groups.get(feature.category).push(feature);
    }

    $('#detail-features').replaceChildren(...[...groups].map(([category, features]) => {
      const filled = features.filter((feature) => feature.value !== null).length;
      return h('div', { class: 'risk-group' },
        h('div', { class: 'risk-group-head' },
          h('h3', {}, CATEGORY_LABELS[category] || category),
          h('span', { class: 'count' }, `${filled}/${features.length}`)),
        h('ul', { class: 'risk-rows' }, features.map((feature) => {
          const contribution = points.get(feature.key);
          return h('li', {
            class: `risk-row${feature.value === null ? ' is-empty' : ''}${contribution ? ' is-flagged' : ''}`,
            title: feature.note,
          },
          h('span', { class: 'risk-key' }, feature.key.replace(/_/g, ' ')),
          h('span', { class: 'risk-value' }, formatValue(feature.value)),
          contribution
            ? h('span', { class: 'risk-points' }, `+${contribution}`)
            : h('span', { class: `risk-tag risk-tag-${feature.collection}` }, COLLECTION_LABELS[feature.collection]));
        })));
    }));
    detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ---- HR context ------------------------------------------------------------------------

  async function editHr() {
    if (selected === null) return;
    const data = await api('GET', `/api/admin/risk/people/${selected}/hr`);
    const person = data.person;

    const employment = h('select', { name: 'employmentType' },
      EMPLOYMENT.map(([value, label]) => h('option', { value, selected: value === person.employment_type }, label)));
    const hireDate = h('input', { type: 'date', name: 'hireDate', value: person.hire_date || '' });
    const leaving = h('input', { type: 'date', name: 'terminationDate', value: person.termination_date || '' });
    const eventType = h('select', { name: 'eventType' }, HR_EVENTS.map(([value, label]) => h('option', { value }, label)));
    const eventDate = h('input', { type: 'date', name: 'eventDate', value: new Date().toISOString().slice(0, 10) });

    const field = (label, control) => h('div', { class: 'field' }, h('span', { class: 'field-label' }, label), control);
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });

    const dialog = h('dialog', { class: 'dialog' },
      h('form', { class: 'dialog-form', method: 'dialog' },
        h('div', { class: 'dialog-head' },
          h('h2', { class: 'dialog-title' }, `HR context for ${person.full_name}`),
          h('p', { class: 'dialog-note' }, 'Red has no HR system, so these are kept here. They drive the amplifier: a leaving date, a bad review or a disciplinary action raises existing risk but never creates it.')),
        h('div', { class: 'dialog-body' },
          h('div', { class: 'field-pair' }, field('Employment type', employment), field('Hire date', hireDate)),
          field('Leaving date', leaving),
          h('div', { class: 'field-pair' }, field('Record an event', eventType), field('Effective', eventDate)),
          data.events.length
            ? h('ul', { class: 'risk-rows' }, data.events.slice(0, 6).map((event) => h('li', { class: 'risk-row' },
              h('span', { class: 'risk-key' }, event.event_type.replace(/_/g, ' ')),
              h('span', { class: 'risk-value' }, event.effective_date))))
            : h('p', { class: 'field-hint' }, 'Nothing on file.'),
          error),
        h('div', { class: 'dialog-actions' },
          h('button', { class: 'btn btn-secondary', type: 'button', onclick: () => dialog.close() }, 'Close'),
          h('button', { class: 'btn btn-quiet', type: 'button', onclick: () => run(addEvent) }, 'Add event'),
          h('button', { class: 'btn btn-primary', type: 'button', onclick: () => run(saveDetails) }, 'Save details'))));

    async function saveDetails() {
      await api('PATCH', `/api/admin/risk/people/${selected}`, {
        employmentType: employment.value,
        hireDate: hireDate.value || null,
        terminationDate: leaving.value || null,
      });
      toast('HR details saved');
    }
    async function addEvent() {
      await api('POST', `/api/admin/risk/people/${selected}/hr-events`, {
        type: eventType.value, effectiveDate: eventDate.value, isNegative: true,
      });
      toast('Event recorded');
    }
    async function run(action) {
      error.hidden = true;
      try {
        await action();
        dialog.close();
        await api('POST', '/api/admin/risk/run', {});
        await Promise.all([loadOverview(), showPerson(selected)]);
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
      }
    }

    dialog.addEventListener('close', () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
  }

  // ---- wiring -------------------------------------------------------------------------

  $('#detail-hr').addEventListener('click', () => editHr().catch((err) => toast(err.message, 'error')));
  $('#recompute').addEventListener('click', async (event) => {
    event.target.disabled = true;
    try {
      const result = await api('POST', '/api/admin/risk/run', {});
      toast(`Scored ${result.scored} of ${result.snapshots} snapshots`);
      await loadOverview();
      if (selected !== null) await showPerson(selected);
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      event.target.disabled = false;
    }
  });

  loadOverview().catch((err) => {
    summary.textContent = err.message;
  });
})();
