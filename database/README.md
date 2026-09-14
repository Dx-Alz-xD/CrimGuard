# Databases

This folder holds two separate schemas.

| Folder       | Engine        | Used by                 | How it's applied                        |
| ------------ | ------------- | ----------------------- | --------------------------------------- |
| `web/`       | SQLite        | the Red website         | automatically, every time the server starts |
| `crimguard/` | PostgreSQL 15+ | the CrimGuard detection platform | by hand, `psql -f` in numeric order |

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
| Projects   | `projects`                                     | Each project belongs to one account (`owner_id`). |
| Security   | `audit_log`                                    | Sign-ins, failures, password and role changes, deletions. |

What each table stores:

- **`users`**: who someone is and their role (`user` or `admin`). No secrets.
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
feature snapshots, and anomaly/alert/response tables. It is not used by the website yet.

The risk formula that fills `risk_scores` lives in [`crimguard/risk/`](../crimguard/risk/README.md).

```bash
for f in database/crimguard/0*.sql; do psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"; done
```

`crimguard/archive/trustline_risk_variables.sql` is the earlier single-table draft that
`06_feature_snapshots.sql` replaced. It's kept for reference only.
