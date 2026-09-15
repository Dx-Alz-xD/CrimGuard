# Databases

This folder holds two separate schemas.

| Folder       | Engine        | Used by                 | How it's applied                        |
| ------------ | ------------- | ----------------------- | --------------------------------------- |
| `web/`       | SQLite        | the Red website         | automatically, every time the server starts |
| `crimguard/` | PostgreSQL 15+, or SQLite | the CrimGuard risk pipeline | `psql -f` in numeric order for PostgreSQL; `npm run db:sqlite` builds the SQLite copy from the same files |

## `web/`: the website database

`web/migrations/NNN_name.sql` files run in order, once each, inside a transaction. The
server records applied versions in `schema_migrations`, so starting it on an existing
`red.db` upgrades that file in place. To change the schema, add a new numbered file.
Never edit a migration that has already shipped.

| Area       | Tables                                         | What's in them |
| ---------- | ---------------------------------------------- | -------------- |
| Sign-up    | `users`, `user_credentials`, `user_profiles`   | An account is created in all three at once. |
| Login      | `user_credentials`, `sessions`, `auth_throttle` | Password hashes, signed-in devices, failed-attempt counters. |
| User data  | `users`, `user_profiles`                       | Name, email, role, job title, team, bio, last sign-in. |
| Projects   | `projects`, `project_files`                    | Each project belongs to one account (`owner_id`); files live in the database beside it. |
| Roles      | `roles`                                        | The four built-in roles and any the CEO adds, each with a clearance from 1 to 5. |
| File access | `file_role_grants`, `file_user_grants`, `project_role_grants` | Who a file or a whole project is shared with, by role or by name. |
| Risk limiting | `user_risk_state`, `risk_limit_exemptions`  | The score access is narrowed from, and the accounts an admin has exempted. |
| Leaving    | `user_departure_state`, `file_access_requests` | Leaving dates, and the queue of requests the departure gate produces. |
| Step-up    | `risk_adjustments`, `email_reputation`, `mfa_verifications`, `download_verifications` | What a passed challenge is worth, address reputation, and codes owed or already answered. |
| Security   | `audit_log`                                    | Sign-ins, failures, password and role changes, deletions. |

What each table stores:

- **`users`**: who someone is and their role, which is a row in `roles` carrying a clearance
  from 1 to 5. No secrets.
- **`user_credentials`**: one row per account. `password_hash` is an Argon2id PHC string
  (see below). `must_change_password` is set when an admin chose the password.
- **`user_profiles`**: optional details the person edits themselves.
- **`sessions`**: `token_hash` is the SHA-256 of the cookie token. The token itself is never
  stored. `created_at`, `last_seen_at` and `expires_at` drive the idle and absolute timeouts.
- **`auth_throttle`**: failure counts per email, per IP address and per account.
- **`audit_log`**: security events, kept for 12 months. Emails are copied in so entries stay
  readable after an account is deleted. Passwords, tokens and emails typed for accounts that
  don't exist are never written.

Deleting a user cascades to their credentials, profile, sessions and projects. Audit entries
keep the email but lose the link to the account.

### How passwords are stored

```
stored = Argon2id( HMAC-SHA-256(pepper, NFKC(password)), 16-byte random salt )
         memory 64 MiB, 3 passes, 4 lanes, 32-byte output   (RFC 9106)
```

- **HMAC-SHA-256 with a pepper.** The pepper (`RED_PASSWORD_PEPPER`) is a secret that lives
  outside the database, so a stolen database or backup alone can't be cracked offline.
- **Argon2id** is the slow, memory-hard step that makes each guess expensive.
- Hashes are written as `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`, with the parameters
  included. When the parameters are raised, older hashes still verify and are rehashed at
  the next sign-in. Accounts from before this change (`scrypt$…`) are upgraded the same way.

SHA-256 on its own is never used for passwords. It is fast by design, which makes
brute-forcing cheap.

The database file is created with `0600` permissions. The server also turns on SQLite's
`secure_delete`, so deleted hashes and sessions are overwritten on disk.

## `crimguard/`: the detection platform schema

PostgreSQL schema for insider-risk detection: tenants and people, the context ledger
(projects, tickets, HR events), raw activity events, the 100-variable feature catalog, daily
feature snapshots, and anomaly/alert/response tables.

The website fills it as people use Red. `src/telemetry/` writes the events and the daily
snapshots, `src/db/crimguard.js` opens the connection, and Red carries on unchanged if that
connection is not there.

The risk formula that fills `risk_scores` lives in [`crimguard/risk/`](../crimguard/risk/README.md).

```bash
for f in database/crimguard/0*.sql; do psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"; done
```

Without a PostgreSQL server, the same schema is used as SQLite. `src/db/sqlite-schema.js`
translates these files rather than keeping a second copy, so the two cannot drift apart, and
throws on anything it does not recognise instead of quietly producing a different schema.
The few views and triggers that need PostgreSQL-only syntax have hand-written SQLite versions
in `crimguard/sqlite/`, and each one keeps the same output columns.
