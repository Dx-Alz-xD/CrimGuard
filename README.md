# Red

A project workspace with two separate logins, one for users and one for admins.
Every account has its own private projects, and admins decide who gets which role.

- **User login** (`/login`): create, edit and track your own projects, edit your
  profile, and change your own password.
- **Admin login** (`/admin/login`): your own projects, plus **People & roles**, where
  you can add people with a role, change roles, reset passwords and delete accounts,
  and **Activity**, a log of sign-ins and account changes.

No npm dependencies. Red uses Node's built-in `node:sqlite` and `crypto.argon2`, so it
only needs **Node.js 24.7 or newer** (developed on Node 26).

---

## Run locally

```bash
npm start
```

Open <http://localhost:3000>.

On first start Red creates `data/` with the database and a development password pepper,
and prints a **one-time password** for the admin account `admin@red.local`. Sign in at
`/admin/login` with it, and you'll be asked to choose your own password straight away.

```bash
npm test
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

| Role  | Signs in at    | Can do                                                          |
| ----- | -------------- | --------------------------------------------------------------- |
| User  | `/login`       | Manage their own projects and profile, change their own password |
| Admin | `/admin/login` | All of the above, plus add people, assign roles, reset passwords, delete accounts, read the activity log |

- **Sign-up always creates a User.** Only an admin can make someone an Admin,
  either by adding them with that role or by changing their role later.
- **Each portal only accepts its own role.** A User signing in at the admin
  login, or an Admin at the user login, is told to use the other one.
- **Role changes apply immediately**, including to people who are already signed in.
- **Admins can't change their own role or delete their own account**, so there
  is always at least one admin.
- **Passwords an admin chooses are temporary.** Someone added by an admin, or whose
  password an admin reset, must choose their own password when they next sign in.
  Until they do, the API refuses everything except changing the password or logging out.
- **Changing your password** asks for the current one, gives this device a new
  session, and signs out your other devices.
- **When an admin resets someone's password, that person is signed out everywhere.**
- **Deleting a person also deletes their profile, projects and sessions.** It can't be undone.
- **Projects are private.** Admins manage roles, not other people's projects,
  and see only how many projects each person has.

---

## Security

| Area | What Red does |
| ---- | ------------- |
| Password storage | HMAC-SHA-256 with a secret pepper, then Argon2id (64 MiB, t=3, p=4). Hashes sit in their own table. Older scrypt hashes are upgraded at sign-in. See [`database/README.md`](database/README.md#how-passwords-are-stored). |
| Password policy | 12 to 256 characters, no composition rules, common and sequential passwords rejected, can't be based on your name or email. |
| Brute force | After 5 failed sign-ins for one email in 15 minutes, that email is paused for 15 minutes. Limits also apply per IP address, to sign-ups, and to wrong current passwords. Unknown emails get the same response and timing as wrong passwords. |
| Sessions | 256-bit random tokens, stored only as SHA-256. New token at every sign-in and password change. User sessions last 24 hours idle / 7 days total; admin sessions 2 hours idle / 12 hours total. At most 10 per account. |
| Cookies | `HttpOnly`, `SameSite=Strict`. Over HTTPS: `Secure` with the `__Host-` prefix, and cookies without the prefix are ignored. |
| CSRF | Writes must be JSON, and requests whose `Origin` or `Sec-Fetch-Site` is another site are refused. |
| Headers | Strict CSP (`default-src 'none'`), HSTS over HTTPS, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP/CORP, Permissions-Policy. |
| Input | Size-limited JSON bodies, validated fields, control and bidi-override characters removed from names and text. All user text is rendered with `textContent`, never as HTML. |
| Audit | Security events in `audit_log`, visible to admins under **Activity**. No secrets are logged. |
| Server | Request and header timeouts, database and pepper files readable by the server's user only, no default admin password. |

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
| `RED_TRUST_PROXY`          | off                     | Set to `1` behind exactly one reverse proxy, so rate limits and the activity log use the client address from `X-Forwarded-For`. Leave off otherwise, or clients could spoof it. |
| `RED_SECURE_COOKIES`       | off                     | Set to `1` to always mark cookies Secure. Behind an HTTPS proxy Red detects this on its own. |
| `PORT`                     | `3000`                  | Most platforms set this for you. |
| `HOST`                     | `0.0.0.0` in the image  | `127.0.0.1` when run with `npm start` outside production. |
| `RED_DB`                   | `/data/red.db` in image | Path to the SQLite file. `data/red.db` locally. |

The admin variables only matter on the very first start. After that, manage
people from **People & roles** in the admin console.

### Any server with Docker

```bash
RED_ADMIN_EMAIL=you@example.com \
RED_ADMIN_PASSWORD='a-long-admin-password' \
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
3. Set `RED_PASSWORD_PEPPER`, `RED_ADMIN_EMAIL` and `RED_ADMIN_PASSWORD` as secrets.
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

---

## Layout

```
src/
  server.js              startup: config checks, migrations, first admin, graceful shutdown
  app.js                 HTTP server: security headers, CSRF checks, routing, housekeeping
  config.js              environment variables, session lifetimes, rate limits
  validation.js          input cleaning and validation shared by the routes
  routes/                auth.js (sign-up, login, password), profile.js, projects.js,
                         admin.js (people, roles, activity), pages.js (HTML, static, health)
  security/              passwords.js (pepper + Argon2id), password-policy.js, sessions.js,
                         throttle.js, tokens.js, headers.js
  http/                  router, request parsing, responses, cookies, errors
  db/                    index.js (open, pragmas), migrate.js, and one query module per area:
                         users.js, sessions.js, projects.js, audit.js
database/
  web/migrations/        SQLite schema for the website, applied on start
  crimguard/             PostgreSQL schema for the CrimGuard detection platform
public/                  pages and static/ (app.js, styles.css, favicon)
test/                    node --test suites: auth, passwords, profile, projects, admin,
                         security, migrations
scripts/demo/            build.js and demo-api.js, which make the static demo
demo/                    the generated static demo (npm run build:demo)
data/                    local database and development pepper (git-ignored)
Dockerfile               production image, runs as non-root, health check
docker-compose.yml       one-command self-hosting with a data volume
```

### API

| Method & path                          | Who |
| -------------------------------------- | --- |
| `POST /api/signup`                     | anyone, creates a User |
| `POST /api/login` `{portal}`           | anyone |
| `POST /api/logout`, `GET /api/me`      | signed in |
| `PATCH /api/me/password` `{currentPassword, newPassword}` | signed in; new session here, signs out other devices |
| `GET/PATCH /api/me/profile` `{name, jobTitle, organization, bio}` | signed in, own profile |
| `GET/POST /api/projects`               | signed in, own projects only |
| `PATCH/DELETE /api/projects/:id`       | signed in, own projects only |
| `GET /api/admin/users`                 | admin |
| `POST /api/admin/users` `{role}`       | admin, adds a person who must then choose a password |
| `PATCH /api/admin/users/:id/role`      | admin, not their own account |
| `PATCH /api/admin/users/:id/password`  | admin; signs that account out everywhere |
| `DELETE /api/admin/users/:id`          | admin, not their own account |
| `GET /api/admin/audit?limit&before`    | admin, newest first |
| `GET /healthz`                         | anyone |

Errors are `{ "error": "message" }`, plus a `code` for `password_change_required` (403)
and `rate_limited` (429, with `Retry-After`).
