# Red

A project workspace with two separate logins: one for interns and employees, and the
admin console for admins and the CEO. Every account has its own projects and files, and
admins and the CEO decide who holds which role and who can open which file.

- **User login** (`/login`): create, edit and track your own projects, upload files to
  them, open files shared with you under **Shared with me**, edit your profile, and
  change your own password.
- **Admin login** (`/admin/login`): your own projects, plus **People & roles**, where
  you add people, change roles, reset passwords and delete accounts, and the CEO creates
  roles; **Activity**, a log of sign-ins and account changes; **CrimGuard**, a live
  dashboard of everyone's projects, files, devices and activity; and **Risk**, the
  insider-risk console described below.

Red also scores how each account behaves against the 100 variables in the CrimGuard
feature catalog, to catch data being taken out of it. Everyone can read their own score
from the **Risk** button in the bottom-left corner of any signed-in page; see
[Insider risk](#insider-risk).

No npm dependencies. Red uses Node's built-in `node:sqlite` and `crypto.argon2`, so it
only needs **Node.js 24.7 or newer** (developed on Node 26).

---

## Run locally

```bash
npm start
```

Open <http://localhost:3000>.

On first start Red creates `data/` with the database and a development password pepper,
and prints a **one-time password** for the admin account `admin@red.local` and another
for the CEO account `ceo@red.local`. Sign in with either at `/admin/login`, and you'll be
asked to choose your own password straight away.

```bash
npm test
```

To see the risk console with something in it, give an account a history:

```bash
npm run db:seed-risk
```

## Static demo

`demo/` is a copy of Red's pages that runs without the server. Open
`demo/index.html` in a browser, or publish the folder on a static host such as
GitHub Pages. A small script stands in for the API and keeps everything in the
browser's local storage, so it is for trying Red out, never for real accounts.
Both login pages show the demo sign-ins.

Rebuild it after changing anything in `public/`:

```bash
npm run build:demo
```

---

## How roles work

Every role has a **clearance** from 1 to 5, and every file a **confidentiality** on the
same scale: 1 Open, 2 Internal, 3 Confidential, 4 Restricted, 5 Secret.

| Role     | Clearance | Signs in at    | Can do |
| -------- | --------- | -------------- | ------ |
| Intern   | 1         | `/login`       | Their own projects and files, files shared with them, their profile and password |
| Employee | 2         | `/login`       | The same |
| Admin    | 4         | `/admin/login` | All of the above, plus add people and give them any role up to Admin, reset passwords, delete accounts, read the activity log, open anyone's files up to Restricted and choose who can see them, and use CrimGuard |
| CEO      | 5         | `/admin/login` | Everything an admin can do, for every file including Secret ones, plus create, change and delete roles and make someone CEO |

- **The CEO account is created on first start**, the same way as the first admin (see
  [Run locally](#run-locally) and the `RED_CEO_*` variables).
- **Sign-up always creates an Intern.** Admins and the CEO give out roles up to their own
  clearance, so only the CEO can make someone CEO.
- **Nobody can act on an account with more clearance than their own.** An admin can't
  change the CEO's role, reset the CEO's password or delete the CEO.
- **The CEO can add roles**, such as Contractors at clearance 1 or Analysts at 3. Roles
  the CEO adds are for sharing files and never open the admin console. Built-in roles
  can't be changed, and a role can only be deleted once nobody holds it.
- **Each portal only accepts its own roles.** Admins and the CEO sign in at the admin
  login and everyone else at the user login; the wrong one says which to use.
- **Role changes apply immediately**, including to people who are already signed in.
- **Nobody can change their own role or delete their own account**, so there is always
  at least one admin and one CEO.
- **Passwords an admin chooses are temporary.** Someone added by an admin, or whose
  password an admin reset, must choose their own password when they next sign in.
  Until they do, the API refuses everything except changing the password or logging out.
- **Changing your password** asks for the current one, gives this device a new
  session, and signs out your other devices.
- **When an admin resets someone's password, that person is signed out everywhere.**
- **Deleting a person also deletes their profile, projects, files and sessions.** It can't be undone.
- **Projects hold files.** Open a project to upload files, as many at once as you like
  (drag and drop works), then download, rename, replace with a new version, or delete
  them. Each file can be up to 10 MB (set `RED_MAX_FILE_MB` to change it), names are
  unique within a project, and the contents are stored in the database, so the data
  volume holds everything.

## Who can open a file

- **Its owner always can, and so can the CEO.** Admins can open any file up to
  Restricted. Everyone else needs the file shared with them.
- **Admins and the CEO share files** from the **Access** button on a file, in a project
  or in CrimGuard. Sharing with a **role** lets everyone in it open the file while the
  role's clearance covers the file's confidentiality: a Confidential file shared with
  Employees stays closed to them until it is lowered to Internal. Sharing with a
  **person** lets them open it at any confidentiality.
- **New files are Internal and shared with nobody.** Existing files became Internal
  when roles arrived.
- **Only the CEO can mark a file Secret**, or change who can see a Secret file. An admin
  the CEO shares a Secret file with can open it, but not change who else can.
- **A file someone can't see is "not found"** to them, so its existence isn't given away.
- **The rule is written once**, as SQL in `src/db/files.js`; every list, download and
  dashboard goes through it. The rest of the access rules are in `src/security/access.js`.
- **Changing who can see a file, and downloading someone else's file, go in the
  activity log.** File names never do.

## CrimGuard dashboard

`/crimguard`, for admins and the CEO, carries CrimGuard's own name. It lists everyone
with an account, with their role, projects, files, storage, whether they are online and,
when the risk database is connected, their latest risk score. Choosing someone opens their
record: profile, every project and file with its confidentiality and sharing, files shared
with them, the devices they are signed in on, their activity and their risk trend.

- **It stays live.** The list refreshes every 15 seconds and the open record every 5,
  while the tab is visible; a record only redraws when something in it changed.
- **Files above your clearance are counted, never named**, so an admin can see that
  someone holds Secret files without learning what they are.
- **Looking is recorded.** Opening someone's record goes in the activity log, at most
  once every ten minutes per viewer and person, so leaving the page open doesn't flood it.

---

## Security

| Area | What Red does |
| ---- | ------------- |
| Password storage | HMAC-SHA-256 with a secret pepper, then Argon2id (64 MiB, t=3, p=4). Hashes sit in their own table. Older scrypt hashes are upgraded at sign-in. See [`database/README.md`](database/README.md#how-passwords-are-stored). |
| Password policy | 12 to 256 characters, no composition rules, common and sequential passwords rejected, can't be based on your name or email. |
| Brute force | After 5 failed sign-ins for one email in 15 minutes, that email is paused for 15 minutes. Limits also apply per IP address, to sign-ups, and to wrong current passwords. Unknown emails get the same response and timing as wrong passwords. |
| Sessions | 256-bit random tokens, stored only as SHA-256. New token at every sign-in and password change. Intern and employee sessions last 24 hours idle / 7 days total; admin and CEO sessions 2 hours idle / 12 hours total. At most 10 per account. |
| Cookies | `HttpOnly`, `SameSite=Strict`. Over HTTPS: `Secure` with the `__Host-` prefix, and cookies without the prefix are ignored. |
| CSRF | Writes must be JSON, and requests whose `Origin` or `Sec-Fetch-Site` is another site are refused. |
| Headers | Strict CSP (`default-src 'none'`), HSTS over HTTPS, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP/CORP, Permissions-Policy. |
| Input | Size-limited JSON bodies, validated fields, control and bidi-override characters removed from names and text. All user text is rendered with `textContent`, never as HTML. |
| Audit | Security events in `audit_log`, visible to admins and the CEO under **Activity**: sign-ins, role and password changes, roles created or changed, changes to who can see a file, downloads of other people's files, and records opened in CrimGuard. No secrets or file names are logged. |
| Access | Roles with clearance and files with confidentiality, checked on the server for every list and download (see [Who can open a file](#who-can-open-a-file)). |
| Server | Request and header timeouts, database and pepper files readable by the server's user only, no default admin or CEO password. |

---

## Deploy

Red runs as a single Docker container with its SQLite database on a volume at
`/data`. **Attach persistent storage at `/data`**, or every redeploy wipes all
accounts and projects.

### Environment variables

| Variable                   | Default                 | Notes |
| -------------------------- | ----------------------- | ----- |
| `RED_PASSWORD_PEPPER`      | none (required in prod) | Secret mixed into every password hash, at least 32 characters. Generate with `openssl rand -base64 48`. **Keep it out of database backups, and never change or lose it:** doing so invalidates every password. |
| `RED_PASSWORD_PEPPER_FILE` | none                    | Read the pepper from a file instead, e.g. a Docker secret. |
| `RED_ADMIN_EMAIL`          | `admin@red.local`       | First admin's email. Only used when no admin exists yet. |
| `RED_ADMIN_PASSWORD`       | none (required in prod) | First admin's password, at least 12 characters. |
| `RED_ADMIN_NAME`           | `Red Admin`             | |
| `RED_CEO_EMAIL`            | `ceo@red.local`         | The CEO's email. Only used when no CEO exists yet, and must differ from `RED_ADMIN_EMAIL`. |
| `RED_CEO_PASSWORD`         | none (required in prod) | The CEO's password, at least 12 characters. |
| `RED_CEO_NAME`             | `Red CEO`               | |
| `RED_TRUST_PROXY`          | off                     | Set to `1` behind exactly one reverse proxy, so rate limits and the activity log use the client address from `X-Forwarded-For`. Leave off otherwise, or clients could spoof it. |
| `RED_MAX_FILE_MB`    | `10`                     | Largest file someone can upload to a project, in megabytes (up to 100). |
| `RED_SECURE_COOKIES`       | off                     | Set to `1` to always mark cookies Secure. Behind an HTTPS proxy Red detects this on its own. |
| `PORT`                     | `3000`                  | Most platforms set this for you. |
| `HOST`                     | `0.0.0.0` in the image  | `127.0.0.1` when run with `npm start` outside production. |
| `RED_DB`                   | `/data/red.db` in image | Path to the SQLite file. `data/red.db` locally. |
| `CRIMGUARD_DATABASE_URL`   | none                    | PostgreSQL for the risk database. Without it, the SQLite copy at `database/crimguard.db` is used. |
| `CRIMGUARD_DB`             | `auto`                  | `postgres` to refuse the SQLite fallback, `sqlite` to skip PostgreSQL entirely. |
| `CRIMGUARD_SQLITE_PATH`    | `database/crimguard.db` | Where the SQLite copy of the risk database lives. |
| `RED_HONEYTOKEN_SCORE`     | `40`                    | Risk score at which a decoy project is planted for an account. |

The admin and CEO variables only matter until someone holds that role. After that,
manage people from **People & roles** in the admin console.

### Any server with Docker

```bash
RED_ADMIN_EMAIL=you@example.com \
RED_ADMIN_PASSWORD='a-long-admin-password' \
RED_CEO_EMAIL=ceo@example.com \
RED_CEO_PASSWORD='a-different-long-password' \
RED_PASSWORD_PEPPER="$(openssl rand -base64 48)" \
docker compose up -d --build
```

Save the pepper somewhere safe (a password manager or secrets store) before you
run this. Put Red behind HTTPS (Caddy, nginx, or your platform's proxy). Session
cookies become `Secure` and `__Host-` prefixed when the proxy sends
`X-Forwarded-Proto: https`.

### Railway, Render, Fly.io and similar

1. Point the service at the folder containing the `Dockerfile`. It builds from that.
2. Add a persistent volume or disk mounted at `/data`.
3. Set `RED_PASSWORD_PEPPER`, `RED_ADMIN_EMAIL`, `RED_ADMIN_PASSWORD`, `RED_CEO_EMAIL`
   and `RED_CEO_PASSWORD` as secrets.
4. Set `RED_TRUST_PROXY=1`.
5. Set the health check path to `/healthz`.

Run a single instance. SQLite lives on one machine's disk, so scaling to
several replicas would give each one its own separate database.

### Upgrading from an earlier Red

Start the new version against your existing database. Migrations move password
hashes into `user_credentials`, add profiles, the activity log and throttling, and
rebuild the sessions table, which signs everyone out once. Existing passwords keep
working and are upgraded to Argon2id as people sign in. In production, set
`RED_PASSWORD_PEPPER` first.

Moving to roles with clearance (migration 007) turns every existing User into an
Employee, keeps admins as admins and marks existing files Internal, without signing
anyone out. The next start creates the CEO account, so in production set
`RED_CEO_EMAIL` and `RED_CEO_PASSWORD` before upgrading.

---

## Insider risk

`database/crimguard/05_feature_catalog.sql` defines 100 risk variables, and
[`crimguard/risk/`](crimguard/risk/README.md) turns them into a 0-100 score. The website
feeds them: `src/telemetry/` records what people do, aggregates it into a daily snapshot per
account, and runs the engine over it. Everything lands in the CrimGuard database - PostgreSQL
when `CRIMGUARD_DATABASE_URL` points at one, otherwise the SQLite copy at
`database/crimguard.db`. Without either, Red behaves exactly as it did before.

### What is collected, and what isn't

Red fills in **64 of the 100** variables. The other 36 need a system a website is not part of -
badge readers, an EDR agent, MDM enrolment, a mail gateway, a DLP proxy, an IdP with MFA - and
are written as `NULL`, which `06_feature_snapshots.sql` defines as *not collected*. They are
never written as `0` or `false`, because "no badge system" and "nobody entered the building"
are not the same fact. `src/telemetry/coverage.js` records the decision for every variable and
fails to load if it and the catalog ever disagree.

| Category | Filled | Where it comes from |
| --- | --- | --- |
| Access & resources | 10/10 | Which projects, pages and account records were opened, and what was searched for |
| Timing | 10/10 | When people work, against their own pattern and the org's hours |
| Data movement | 4/10 | Project exports, printing, clipboard size. No USB, personal cloud or mail |
| Authentication & identity | 6/10 | Sign-ins, failures, new devices, networks and countries, replayed session cookies |
| Device & network | 5/10 | Browser fingerprint, address ranges, impossible travel, bytes served |
| Behavioural biometrics | 9/10 | Typing and pointer rhythm, scrolling, idle time, focus changes, clipboard |
| HR & organisation | 10/10 | Role changes Red makes itself, plus employment details admins record |
| Communication | 2/10 | Sensitive terms and secret patterns in project text. Red has no messaging |
| Privilege & permission | 7/10 | Red's own admin actions, and refusals that show someone reaching past their role |
| Physical & environmental | 1/10 | Printing a page with confidential material on screen |

### What the browser sends

`public/static/telemetry.js` batches up the signals a server cannot see, once a minute:

- **Sent**: timing statistics over each one-minute window (the gaps between keystrokes, how
  long keys are held, pointer and scroll speed, idle time, focus changes), counts of events,
  how many characters were copied, and the *names* of any secret-shaped patterns matched.
- **Never sent**: which keys were pressed, where the pointer went, what was selected, and the
  text of anything copied or pasted. Classification happens in the page; only the category
  name ("api_key") survives it.

Everything the server can see for itself - which resources were opened, what was searched for,
who signed in, who changed a role - is recorded in the route handlers instead, where a page
cannot forge it. `/api/telemetry` takes the account from the session, so a batch can only ever
describe the person who sent it. `/privacy` says all of this to the people being scored.

### Seeing a score

Every signed-in page has a **Risk** button in the bottom-left corner. It opens a movable
window with the account's own score and all 100 variables, live. People can read their own
assessment because the alternative - scoring people and hiding it from them - is worse.

Admins get `/admin/risk`: everyone's latest score, open alerts, and one person's full variable
list with each one's contribution to the score. It is also where the HR context lives
(employment type, hire and leaving dates, reviews, disciplinary actions, leave), since Red has
no HR system to sync from. Those are the engine's amplifier: they raise existing risk and
cannot create it.

Snapshots are rebuilt and rescored every 15 minutes, and on demand from the console.

### Impossible travel

Two sign-ins from places further apart than the time between them allows. `src/telemetry/geo.js`
resolves each one to coordinates, takes the great-circle distance, and divides by the elapsed
time: over **900 km/h** across at least **400 km** is not a journey anyone made.

It is judged in kilometres per hour rather than hours of UTC offset, which matters both ways.
Paris and Lagos share an offset and are 4,700 km apart — an offset comparison never sees it.
Berlin to New York in ten hours is a real flight at 639 km/h — an offset comparison flags it
every time.

```
Berlin → Lagos, 20 min apart       5,196 km   15,589 km/h   impossible
Paris  → Lagos, 45 min apart       4,709 km    6,279 km/h   impossible  (same UTC offset)
Berlin → New York, 2 h apart       6,386 km    3,193 km/h   impossible
Berlin → New York, 10 h apart      6,386 km      639 km/h   a real flight
Amsterdam → Brussels, 1 min apart    173 km   10,394 km/h   under 400 km, not judged
```

The network has to have changed too. A VPN moves the address without moving the person, and
changing a laptop's region setting moves neither — neither fires this, though a new address
range is still noticed on its own. Two sign-ins at the *same instant* from different cities
give an infinite speed, which is the correct answer: one of them is not where it claims to be.

On a clean account this one flag takes the score from **3.0 to 32.3** — the engine weights it
1.0 as a strong precursor, and the catalog marks it `context_explainable: false`, so no ticket
can excuse it.

**Where the location comes from.** Red carries no GeoIP database — that is a licensed binary
this project deliberately doesn't ship — so a sign-in is placed by the IANA time zone the
browser reports, which is named after a real city. `geo.js` holds coordinates for the ~140
zones in real use, and stores them in the `latitude`, `longitude` and `country_code` columns
the schema already has. To use real IP geolocation instead, hand `setIpLookup` a function
returning `{ latitude, longitude, country }` and everything above it keeps working:

```js
const { setIpLookup } = require('./src/telemetry/geo');
setIpLookup((ip) => myGeoIpReader.city(ip));   // a GeoIP hit wins; the time zone is the fallback
```

The time zone arrives with the collector's first batch rather than at sign-in, so a location is
attached within a window (15 seconds with the panel open, otherwise a minute). A sign-in where
the collector never ran has no location and is not compared.

### Networks and VPNs

The three address checks answer three different questions, and the catalog's own source tables
say which is which:

| Variable | Source table | Fires on |
| --- | --- | --- |
| `unusual_ip_range_flag` | `network_events` | **any** address seen that day outside the usual ones, including one moved to mid-session |
| `new_geolocation_login_flag` | `auth_events` | a **sign-in** from a network, time zone or country not used before |
| `impossible_travel_flag` | `auth_events` | two **sign-ins** further apart than the time between them allows |

So switching a VPN on while already signed in raises the score, without pretending anyone
signed in from there. On an account settled on one network for a month:

```
30 days on the home network              2.99 low
VPN switched on mid-session, no sign-in  5.50 low   unusual_ip_range_flag  +3.05
signs out and back in over the VPN       8.41 low   + new_geolocation_login_flag
```

A mid-session address change is common and usually innocent — phones hand off wifi to cellular,
leases renew, people tether. No threshold is needed for that, because the engine baselines every
flag on how often it fires over 90 days: an account whose address changes daily builds a rate
near 1 and earns nothing from it, while one that has sat still for months and suddenly moves is
strong evidence. The noisy case calibrates itself away.

A VPN never fires `impossible_travel_flag`, because it moves the address without moving the
browser's time zone, and distance is what that check is made of.

### Decoys

Once an account's score reaches **40**, a fake project appears in its list, named like the
thing someone hoarding data would reach for. Only that account can see it, and nothing
legitimate ever needs to touch it. *Reading* it proves nothing. *Changing or deleting* it is
the trip, and it:

1. records a `honeytoken_triggers` row, which floors the next score at 100 (critical),
2. revokes every session the account has, signing the person out everywhere, and logs the
   revocation in `identity_actions`,
3. prints the account, its score at that moment, the decoy and the action to the server console.

Set `RED_HONEYTOKEN_SCORE` to change the threshold. A decoy id with no live decoy behind it is
just a missing project: guessing the number does nothing.

### Seeding a history

```bash
npm run db:seed-risk                      # the first admin, 210 days
npm run db:seed-risk -- --email a@b.c     # a particular account
npm run db:seed-risk -- --profile spike   # one loud day instead of a slow creep
npm run db:seed-risk -- --reset           # clear that account's history first
```

The default is the deck's Case B: four quiet months, then a creep from ~15 to ~70 files a day
with nothing on file to explain it. No single day looks wrong, and a 3-sigma rule never fires;
the drift detector reports it as `slow_exfiltration` about seven weeks in.

---

## Layout

```
src/
  server.js              startup: config checks, migrations, first admin and CEO, graceful shutdown
  app.js                 HTTP server: security headers, CSRF checks, routing, housekeeping
  config.js              environment variables, session lifetimes, rate limits
  validation.js          input cleaning and validation shared by the routes
  routes/                auth.js (sign-up, login, password), profile.js, projects.js,
                         files.js (files, sharing, access), admin.js (people, roles, activity),
                         crimguard.js (the dashboard's data), pages.js (HTML, static, health)
  security/              access.js (roles, clearance, who may change access),
                         passwords.js (pepper + Argon2id), password-policy.js, sessions.js,
                         throttle.js, tokens.js, headers.js
  http/                  router, request parsing, responses, cookies, errors
  db/                    index.js (open, pragmas), migrate.js, and one query module per area:
                         users.js, sessions.js, projects.js, files.js (and who can see
                         a file), roles.js, people.js (the dashboard), audit.js
  telemetry/             the risk pipeline: coverage.js (how each of the 100 variables is
                         collected), subjects.js, events.js, ingest.js, features.js,
                         snapshots.js, scoring.js, honeytokens.js, patterns.js, geo.js
database/
  web/migrations/        SQLite schema for the website, applied on start
  crimguard/             PostgreSQL schema for the CrimGuard detection platform
crimguard/risk/          the scoring formula (see its own README)
public/                  pages and static/: app.js, crimguard.js (the dashboard),
                         telemetry.js (the collector), risk-panel.js, risk-console.js,
                         styles.css, icons
test/                    node --test suites: auth, passwords, profile, projects, files, admin,
                         roles, access, crimguard,
                         security, migrations, telemetry, client-scripts
scripts/demo/            build.js and demo-api.js, which make the static demo
scripts/db/              status.js, build-sqlite.js, seed-risk.js
demo/                    the generated static demo (npm run build:demo)
data/                    local database and development pepper (git-ignored)
Dockerfile               production image, runs as non-root, health check
docker-compose.yml       one-command self-hosting with a data volume
```

### API

| Method & path                          | Who |
| -------------------------------------- | --- |
| `POST /api/signup`                     | anyone, creates an Intern |
| `POST /api/login` `{portal}`           | anyone |
| `POST /api/logout`, `GET /api/me`      | signed in |
| `PATCH /api/me/password` `{currentPassword, newPassword}` | signed in; new session here, signs out other devices |
| `GET/PATCH /api/me/profile` `{name, jobTitle, organization, bio}` | signed in, own profile |
| `GET/POST /api/projects`               | signed in, own projects only |
| `PATCH/DELETE /api/projects/:id`       | signed in, own projects only |
| `GET /api/projects/:id/files`          | signed in, own projects only |
| `POST /api/projects/:id/files`         | own projects; raw bytes with `X-File-Name` (URL-encoded) |
| `GET /api/projects/:id/files/:fileId/download` | own projects; always sent as a download |
| `PATCH /api/projects/:id/files/:fileId` `{name}` | own projects; rename |
| `PUT /api/projects/:id/files/:fileId/content` | own projects; raw bytes, replaces the contents |
| `DELETE /api/projects/:id/files/:fileId` | own projects |
| `GET /api/files/shared`                | signed in, files other people shared with you or your role |
| `GET /api/files/:fileId/download`      | anyone who may see the file; otherwise 404 |
| `GET /api/files/:fileId/access`        | the owner, admins and the CEO |
| `PUT /api/files/:fileId/access` `{confidentiality, roles, people}` | admin or CEO, files up to their clearance; replaces the whole list |
| `GET /api/roles`                       | signed in; admins and the CEO also get member counts |
| `POST /api/admin/roles` `{label, clearance}` | CEO |
| `PATCH/DELETE /api/admin/roles/:id`    | CEO, roles the CEO added; delete only when nobody holds it |
| `GET /api/admin/users`                 | admin or CEO |
| `POST /api/admin/users` `{role}`       | admin or CEO, roles up to their clearance; the person must then choose a password |
| `PATCH /api/admin/users/:id/role`      | admin or CEO, not their own account or anyone with more clearance |
| `PATCH /api/admin/users/:id/password`  | the same; signs that account out everywhere |
| `DELETE /api/admin/users/:id`          | the same |
| `GET /api/admin/audit?limit&before`    | admin or CEO, newest first |
| `GET /api/crimguard/overview`          | admin or CEO, everyone with their counts, presence and score |
| `GET /api/crimguard/people/:id`        | admin or CEO, one person's record; file names above your clearance left out |
| `POST /api/telemetry`                  | signed in, own behaviour only |
| `GET /api/me/risk`                     | signed in, own score and all 100 variables |
| `GET /api/admin/risk/overview`         | admin, everyone's latest score and open alerts |
| `GET /api/admin/risk/people/:id`       | admin, one person's 100 variables |
| `GET /api/admin/risk/catalog`          | admin, the catalog and how Red collects each entry |
| `POST /api/admin/risk/run` `{date}`    | admin, recompute and rescore a day |
| `PATCH /api/admin/risk/people/:id`     | admin, employment type, hire and leaving dates |
| `POST /api/admin/risk/people/:id/hr-events` | admin, records a review, action or notice |
| `POST/DELETE /api/admin/risk/people/:id/leave` | admin, leave periods |
| `GET /healthz`                         | anyone |

Errors are `{ "error": "message" }`, plus a `code` for `password_change_required` (403),
`not_privileged` (403, the account no longer has the admin console) and `rate_limited`
(429, with `Retry-After`).
