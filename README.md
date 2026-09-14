# Red

A project workspace with two separate logins, one for users and one for admins.
Every account has its own private projects, and admins decide who gets which role.

- **User login** (`/login`): create, edit and track your own projects, and change
  your own password.
- **Admin login** (`/admin/login`): your own projects, plus **Users & roles**, where
  you can add people with a role, change roles, set passwords and delete accounts.

No npm dependencies. Red uses Node's built-in `node:sqlite`, so it only needs
**Node.js 22.13 or newer** (developed on Node 24).

---

## Run locally

From the folder containing `package.json`:

```bash
npm start
```

Open <http://localhost:3000>.

On first start Red creates an admin account and prints it:

| Email             | Password     |
| ----------------- | ------------ |
| `admin@red.local` | `admin12345` |

That default exists only for local use. Change it from the account menu in the
admin console's top bar. In production (`NODE_ENV=production`) Red refuses to
start until you set `RED_ADMIN_PASSWORD`.

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
| User  | `/login`       | Manage their own projects, change their own password            |
| Admin | `/admin/login` | Manage their own projects, add people, assign roles, set passwords, delete accounts |

- **Sign-up always creates a User.** Only an admin can make someone an Admin,
  either by adding them with that role or by changing their role later.
- **Each portal only accepts its own role.** A User signing in at the admin
  login, or an Admin at the user login, is told to use the other one.
- **Role changes apply immediately**, including to people who are already signed
  in. Nobody needs to log out and back in.
- **Admins can't change their own role or delete their own account**, so there
  is always at least one admin.
- **Everyone can change their own password** from the account menu in the top
  bar. It asks for the current password first, keeps you signed in on that
  device, and signs out your other devices.
- **When an admin sets someone else's password, that person is signed out
  everywhere** and needs the new password to get back in.
- **Deleting a person also deletes their projects, files and sessions.** It can't be undone.
- **Projects hold files.** Open a project to upload files (drag and drop works), then
  download, rename, replace with a new version, or delete them. Files are as private
  as the project: nobody else can reach them, admins included. Each file can be up to
  10 MB (set `RED_MAX_FILE_MB` to change it), and names are unique within a project.
  Files are stored in the SQLite database, so the `/data` volume holds everything.
- **Projects are private.** Admins manage roles, not other people's projects,
  and see only how many projects each person has.

---

## Deploy

Red runs as a single Docker container with its SQLite database on a volume at
`/data`. **Attach persistent storage at `/data`**, or every redeploy wipes all
accounts and projects.

### Environment variables

| Variable             | Default                  | Notes                                                                 |
| -------------------- | ------------------------ | --------------------------------------------------------------------- |
| `RED_ADMIN_EMAIL`    | `admin@red.local`        | First admin's email. Only used when no admin exists yet.              |
| `RED_ADMIN_PASSWORD` | none (required in prod)  | First admin's password, at least 8 characters.                        |
| `RED_ADMIN_NAME`     | `Red Admin`              |                                                                       |
| `PORT`               | `3000`                   | Most platforms set this for you.                                      |
| `HOST`               | `0.0.0.0` in the image   | `127.0.0.1` when run with `npm start` outside production.             |
| `RED_DB`             | `/data/red.db` in image  | Path to the SQLite file.                                              |
| `RED_SECURE_COOKIES` | off                      | Set to `1` to always mark cookies Secure. Behind an HTTPS proxy Red detects this on its own. |

The admin variables only matter on the very first start. After that, manage
people from **Users & roles** in the admin console.

### Any server with Docker

```bash
RED_ADMIN_EMAIL=you@example.com RED_ADMIN_PASSWORD='a-long-password' docker compose up -d --build
```

Put it behind HTTPS (Caddy, nginx, or your platform's proxy). Session cookies
are marked `Secure` automatically when the proxy sends `X-Forwarded-Proto: https`.

### Railway, Render, Fly.io and similar

1. Point the service at the folder containing the `Dockerfile`. It builds from that.
2. Add a persistent volume or disk mounted at `/data`.
3. Set `RED_ADMIN_EMAIL` and `RED_ADMIN_PASSWORD`.
4. Set the health check path to `/healthz`.

Run a single instance. SQLite lives on one machine's disk, so scaling to
several replicas would give each one its own separate database.

---

## Layout

```
src/server.js        startup: config checks, first admin, graceful shutdown
src/app.js           HTTP server: pages, JSON API, sessions, role checks, files
src/security/        scrypt password hashing, session tokens, cookies
src/db/              SQLite schema (users, sessions, projects, project_files)
public/*.html        landing, both logins, sign-up, dashboard, admin console
public/static/       app.js (all client code), styles.css, favicon
test/helpers.js      end-to-end API tests (node --test)
scripts/demo/        build.js and demo-api.js, which make the static demo
demo/                the generated static demo (npm run build:demo)
database/crimguard/  CrimGuard PostgreSQL schema (separate design, not used by the app)
Dockerfile           production image, runs as non-root, health check
docker-compose.yml   one-command self-hosting with a data volume
```

### API

| Method & path                        | Who   |
| ------------------------------------ | ----- |
| `POST /api/signup`                   | anyone, creates a User |
| `POST /api/login` `{portal}`         | anyone |
| `POST /api/logout`, `GET /api/me`    | signed in |
| `PATCH /api/me/password` `{currentPassword, newPassword}` | signed in, own account; signs out other devices |
| `GET/POST /api/projects`             | signed in, own projects only |
| `PATCH/DELETE /api/projects/:id`     | signed in, own projects only |
| `GET /api/admin/users`               | admin |
| `POST /api/admin/users` `{role}`     | admin, adds a person |
| `PATCH /api/admin/users/:id/role`    | admin, not their own account |
| `PATCH /api/admin/users/:id/password`| admin, any account; signs that account out elsewhere |
| `DELETE /api/admin/users/:id`        | admin, not their own account |
| `GET /api/projects/:id/files`        | signed in, own projects only |
| `POST /api/projects/:id/files`       | own projects; raw bytes, `X-File-Name` (URL-encoded) |
| `GET /api/projects/:id/files/:fileId/download` | own projects; always sent as a download |
| `PATCH /api/projects/:id/files/:fileId` `{name}` | own projects; rename |
| `PUT /api/projects/:id/files/:fileId/content` | own projects; raw bytes, replaces the contents |
| `DELETE /api/projects/:id/files/:fileId` | own projects |
| `GET /healthz`                       | anyone |

### Security notes

Passwords are hashed with scrypt. Only a SHA-256 hash of each session token is
stored, and cookies are `HttpOnly` and `SameSite=Strict`. All writes must be
JSON, which blocks cross-site form posts. A strict Content-Security-Policy is
set, and all user text is rendered with `textContent`, never as HTML.
