# OnePass mailbox

The sync server of OnePass: a Supabase project that stores opaque, end-to-end
encrypted records for each mailbox. It never sees a key or a plaintext; the
OnePass core verifies everything it reads (spec 4.4, 4.15). Soma Labs hosts an
instance ([RUNBOOK.md](RUNBOOK.md)); anyone can run their own on self-hosted
Supabase with the same migrations and functions.

```
supabase/migrations/   schema onepass_mailbox, SQL API, maintenance, pg_cron jobs
supabase/functions/    mailbox (the only HTTP entry), mailbox-push, mailbox-gc
supabase/seed.sql      plans free and selfhost
scripts/               local stack helpers, SQL tests, hosted-admin.sh
```

## Self-hosting

You need the official self-hosted Supabase stack (Docker: Postgres 17, Kong,
Realtime, Storage, edge runtime, with `pg_cron`, `pg_net` and Vault) and the
Supabase CLI pinned in `supabase/config.toml` (`npx --yes supabase@2.122.0`,
written `supabase` below). The steps are those of the hosted instance in
[RUNBOOK.md](RUNBOOK.md) without creating a project:

1. Migrations: `supabase db push --db-url <postgres URL of your stack>`.
2. Plans: run `supabase/seed.sql` as `postgres` (`psql -f`).
3. Roles: give `onepass_mailbox_api` and `onepass_mailbox_janitor` generated
   passwords (`alter role ... login password '...'`, from a file, not a
   command line).
4. Vault: `mailbox_cron_key` (random, 32 characters or more) and
   `mailbox_functions_url` (your functions base URL as the database container
   reaches it, for example `http://kong:8000/functions/v1`).
5. Function secrets, in the edge runtime's environment:

   | Variable | Value |
   | --- | --- |
   | `MAILBOX_DB_URL`, `MAILBOX_JANITOR_DB_URL` | Postgres URLs of the two roles |
   | `MAILBOX_IP_HMAC_SECRET` | random, 32 characters or more |
   | `MAILBOX_CRON_KEY` | the Vault's `mailbox_cron_key` |
   | `MAILBOX_CLIENT_IP_HEADER` | required; `x-forwarded-for` behind Kong |
   | `MAILBOX_TRUSTED_HOPS` | proxies appending to `X-Forwarded-For` (1 for Kong alone, 2 with a reverse proxy in front) |
   | `MAILBOX_PUSH_PROVIDERS` | required; `none` (clients poll and use Realtime) or `log` |
   | `MAILBOX_PUBLISHABLE_KEY`, `MAILBOX_REALTIME_URL` | your stack's anon key and `wss://<host>/realtime/v1` |
   | `MAILBOX_OPEN_SIGNUP` | `true` to allow creation without an invite (see below) |
   | `MAILBOX_STORAGE_PUBLIC_URL` | only when `SUPABASE_URL` is an address clients cannot reach |

6. Functions: `supabase functions deploy mailbox mailbox-push mailbox-gc
   --no-verify-jwt` (requests are signed by the client, never a Supabase JWT).
7. Check `GET <functions base>/mailbox/v1/config` and run the end-to-end suite
   (`ONEPASS_MAILBOX_E2E_URL=... cargo test -p onepass-mailbox --features
   testing --test conformance_e2e` from `core/`).

Behind a reverse proxy, set `MAILBOX_CLIENT_IP_HEADER` and
`MAILBOX_TRUSTED_HOPS` to what reaches the function: send a request with a
forged `X-Forwarded-For` and check which entry your proxies append. A wrong
value rate limits a proxy instead of clients.

### Signup and plans

A self-host usually opens signup: new mailboxes then get plan `selfhost` (high
limits). Signup is open only when two things say so: `MAILBOX_OPEN_SIGNUP=true`
in the function's environment and the row `open_signup = 'on'` in
`onepass_mailbox.settings`, which an operator writes in maintenance mode:

```sql
begin;
select set_config('onepass.maintenance', 'on', true);
insert into onepass_mailbox.settings (name, value) values ('open_signup', 'on')
on conflict (name) do update set value = excluded.value;
commit;
```

Two optional rows in the same table, written the same way: `open_signup_plan`
(an existing plan name; absent means `selfhost`) and `daily_create_cap` (an
integer: open signups this instance accepts per UTC day, then `503 retry`;
absent means no cap). A valid invite keeps its own plan and is exempt from the cap.

Without the `open_signup` row, creation needs an invite (`onepass_mailbox.invites`, token
stored as its SHA-256), as on the hosted instance.

### Private certificate authority

Clients take any base URL and, for a certificate signed by your own authority,
its PEM (the "My server" choice in the apps). Connections are TLS 1.3 only.

## Development

`scripts/local-env.sh` sets up a local stack (`supabase start` from this
folder), `scripts/sql-test.sh` runs the SQL tests on a scratch Postgres 17, and
`deno test` runs the function tests in each `supabase/functions/*` folder.
