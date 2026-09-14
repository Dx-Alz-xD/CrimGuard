# Keystroke biometrics and dynamic honeytrapping

These two features were built while other people were editing Red at the same time. So they
**only add files and never change an existing one**, and a merge can't conflict. This page covers
what was added, how to run it today, and the few edits that wire it into Red once branches are combined.

## What was added

| Path | What it is |
| --- | --- |
| `src/biometrics/keystroke-features.js` | The 18-number typing vector: hold and between-key times by hand, rollover, pauses, corrections, shift habits, speed |
| `src/biometrics/keystroke-model.js` | Pure model: robust per-person profile, scaled Manhattan distance, leave-one-out calibration, session trust |
| `src/biometrics/keystroke-store.js` | `keystroke_windows` table in the CrimGuard database (created on first use) |
| `src/biometrics/keystroke-ingest.js` | Validates and clamps a window from the browser |
| `src/biometrics/keystrokes.js` | Judges windows, keeps session trust, asks for step-up (`identity_actions.step_up_mfa`, `auth_events.mfa_*`) or freezes the session when the risk score is already high |
| `src/biometrics/keystroke-routes.js` | `POST /api/biometrics/keystrokes`, `GET /api/biometrics/keystrokes/status`, `POST /api/biometrics/step-up`, `GET /api/admin/biometrics/people/:id` |
| `src/honeytrap/policy.js` | When to plant, raise the tier, rotate (14 days), stand down (score < 25), cool off after a trip |
| `src/honeytrap/lures.js` | Picks the decoy this person would reach for (searches, job title, scenario, top risk features, role) and records why |
| `src/honeytrap/canaries.js` | Fresh fake secrets for every planting (AWS, Stripe, GitHub, Slack, DB URL, break-glass, document link) and the patterns that find them again |
| `src/honeytrap/honeytrap.js` | Plants and retires decoys in `resources`/`honeytokens`. Trips on copy, exfiltration or key use into `honeytoken_triggers`, which already floors the next score at 100 |
| `src/honeytrap/routes.js` | `GET /api/files/shared[/:id]`, `POST /api/files/shared/integrity`, trap endpoints under `/api/internal/v1/…`, `GET /api/admin/honeytrap/people/:id`, `POST /api/admin/honeytrap/run` |
| `src/features/index.js` | `registerFeatureRoutes()`: both route groups in one call |
| `src/features/attach.js` | **Temporary.** Mounts everything on a running Red server from outside |
| `src/features/server.js` | **Temporary.** `src/server.js` with the features attached |
| `public/static/keystroke-biometrics.js` | Browser collector and "confirm it's you" dialog |
| `public/static/shared-files.js` | "Shared with you" list and the clipboard canary check |
| `test/keystroke-biometrics.test.js`, `test/honeytrap.test.js`, `test/features-attach.test.js` | 34 tests; `test/keystroke-typists.js` and `test/feature-harness.js` support them |

The honeytrap's own browser-facing paths are called "shared files" and "internal API". Nothing
the browser can see says "honeytrap"; only the admin endpoints use that name.

## Running it now

```sh
node --env-file-if-exists=.env src/features/server.js
```

This is the normal server with both features switched on. Everything else stays the same: same
configuration, same databases, same pages. `node --test "test/**/*.test.js"` runs the new tests
along with the existing ones.

Docker still starts `src/server.js`. To try the features in a container, override the command
with `node src/features/server.js`. This hasn't been tested, because there's no Docker on the dev
machine.

## Combining with main

Once the branches are merged, do these steps and then delete `src/features/attach.js`,
`src/features/server.js` and `test/features-attach.test.js`.

### 1. `src/app.js`: register the routes

```js
const { registerFeatureRoutes, allowedWhileChallenged } = require('./features');
// ...
  registerTelemetryRoutes(router, deps);
  const features = registerFeatureRoutes(router, deps);
```

### 2. `src/app.js`: hold the API while a keystroke challenge is open

In `route()`, after the same-origin check:

```js
    if (!allowedWhileChallenged(pathname)) {
      const user = sessions.current(req);
      if (user && features.keystrokes.isChallenged(user, req.sessionTokenHash)) {
        throw Object.assign(new HttpError(403, 'Please confirm it’s you to carry on.'), { code: 'step_up_required' });
      }
    }
```

### 3. `src/app.js`: re-evaluate decoys after scoring

In `runRisk()`, after the two `telemetry.runDay(...)` calls:

```js
      await features.honeytrap.evaluateAll();
```

### 4. `src/routes/projects.js`: check saved text for canaries

`registerProjectRoutes` needs `features.honeytrap` passed in through `deps`, and
`const { createRevoker } = require('../honeytrap/routes');`. Then in the POST and PATCH handlers,
next to `telemetry.onText(...)`:

```js
    const trips = await honeytrap.inspectText({ user, text: `${fields.name}\n${fields.description}`, channel: 'project_text', client });
    if (trips.length) { createRevoker(stores)(trips, client, user); throw new HttpError(401, 'Your session has ended. Please sign in again.'); }
```

Checked inline like this, the request that carries the canary is refused. The temporary
attach.js can only check after the response, so it signs the person out on their next request.

### 5. Pages: load the scripts

Add these to `public/dashboard.html`, `public/admin.html` and `public/risk.html`, after `app.js`:

```html
  <script src="/static/keystroke-biometrics.js"></script>
  <script src="/static/shared-files.js"></script>
```

Both scripts call server endpoints, so add them to `SERVER_ONLY_SCRIPTS` in
`scripts/demo/build.js`. That keeps them out of the static demo.

### 6. Schema: make `keystroke_windows` a real schema file

Right now `keystroke-store.js` creates the table on first use. Move the DDL from `ddl()` into
`database/crimguard/09_keystroke_windows.sql` (and the SQLite copy), then drop `ensureSchema()`.
The honeytrap uses only tables that already exist.

### 7. Risk engine: use the biometric deviation

`src/telemetry/features.js` currently computes `keystroke_cadence_deviation` from the mean key
interval that `telemetry.js` sends. `keystrokes.dailyDeviation(crimUserId, date)` returns the same
thing in sigma, measured against the person's own enrolled profile. Use it when it isn't `null`,
and fall back to the current value otherwise.

### 8. Privacy page: needs a decision

`public/privacy.html` becomes inaccurate once these ship:

- **Typing:** it says only per-minute averages are recorded. Biometrics sends per-hand hold and
  between-key statistics (still no key identity or text) and keeps a per-person profile.
- **Clipboard:** it says only a category name is sent. The canary check also sends a string's
  SHA-256 when it matches the watch list (never the text).
- **Decoys:** whether and how to disclose that decoy files may be shown is a policy call for the
  team. Disclosing it in general terms doesn't reveal who has one: every account gets the same watch list.

## Behaviour worth knowing

- **Keystroke enrolment** needs 8 windows of 40+ keys over at least 2 days. Until then nothing is
  judged. Calibrated on 30 simulated typists, 1.3% of an owner's sessions get challenged, and 87% of
  impostors are challenged by their second window (92% by the fourth). The tests enforce at most
  3% for owners, and at least 80% and 88% for impostors. These rates come from simulation, not
  real people; tune `MODEL` in `keystroke-model.js` on real data.
- **Session trust is kept in memory.** A restart clears open challenges; the profile itself is in
  the database. With more than one Red process, a challenge only applies on the process that raised it.
- **Step-up is the account password**, because Red has no second factor. Three wrong attempts end
  every session. A mismatch on an account whose latest score is already high or critical freezes
  the session straight away.
- **The browser never learns** its trust, distance or profile. It only learns whether it has to
  confirm, so an impostor gets nothing to tune against.
- **Decoys go only to people with a score of 40+** and are withdrawn below 25. Each planting
  records why that decoy was chosen for that person, so it can be reviewed later. Opening a decoy
  is logged as a restricted-file read but isn't a trip; add `'opened'` to `POLICY.tripOn` for the
  strict reading.
- **A canary stays armed after its decoy is rotated or withdrawn**, because a copy taken earlier
  is just as telling later. The same canary seen twice within an hour counts as one incident.
- **The existing decoy projects** (`src/telemetry/honeytokens.js`, trip on edit or delete) are
  untouched and still work. Both kinds share the `honeytokens` table, with separate URI prefixes
  (`red:honeytoken/` and `red:honeytrap/`) and separate id ranges (900,000,000+ and 800,000,000+).
- While attach.js is in use, feature API requests don't go through app.js's bandwidth counter or
  refusal telemetry. Once registered in app.js (step 1) they do.
