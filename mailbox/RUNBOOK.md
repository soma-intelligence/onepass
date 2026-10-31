# Hosted mailbox runbook

The OnePass mailbox hosted by Soma Labs: one Supabase project, schema
`onepass_mailbox`, three edge functions, one private Storage bucket, three
pg_cron jobs. Self-hosting is in [README.md](README.md).

| | |
| --- | --- |
| Project | `one pass`, ref `aixgegcostjptashxlzf`, us-east-2, Postgres 17 |
| Client base URL | `https://aixgegcostjptashxlzf.supabase.co/functions/v1/mailbox` |
| Functions | `mailbox`, `mailbox-push`, `mailbox-gc`, all `verify_jwt = false` |
| Bucket | `onepass-mailbox`, private, 900 KiB per object |
| pg_cron | `onepass-mailbox-maintenance` (every minute), `onepass-mailbox-push` (10 s), `onepass-mailbox-gc` (hourly at :17) |
| Signup | closed: creating a mailbox needs an invite |
| Push | disabled (`MAILBOX_PUSH_PROVIDERS=none`): clients wake through Realtime and poll |

Every command runs from `mailbox/` with the CLI pinned in `supabase/config.toml`
(`npx --yes supabase@2.122.0`, written `supabase` below). Local secrets live in
`supabase/.env.hosted` (git ignored, mode 600); this page names its variables,
never their values.

## Access

`supabase login` once, then `supabase link --project-ref aixgegcostjptashxlzf`.
`db push --linked` and `db query --linked` then go through the Management API
with a temporary login role: no database password is typed or stored.
`scripts/hosted-admin.sh` wraps the operator gestures below on top of that.

The direct host `db.<ref>.supabase.co` is IPv6 only. From an IPv4 network use
the pooler `aws-0-us-east-2.pooler.supabase.com`: port 6543 (transaction mode)
for the functions, 5432 (session mode) for psql. Pooler users are
`<role>.<ref>`.

## First setup (done 2026-10-31)

1. Migrations, in order: `supabase db push --linked` (all files of
   `supabase/migrations/`).
2. Plans: `seed.sql` is not run by `db push`. Run its `insert into
   onepass_mailbox.plans` in a maintenance transaction (`begin; select
   set_config('onepass.maintenance', 'on', true); ...; commit;`) with
   `supabase db query --linked -f <file>`. Plans `free` and `selfhost` must
   exist before the first invite.
3. Roles: the schema migration creates `onepass_mailbox_api` and
   `onepass_mailbox_janitor` as `LOGIN` without a password. Generate two
   passwords (`openssl rand -hex 24`), keep them as `MAILBOX_API_DB_PASSWORD`
   and `MAILBOX_JANITOR_DB_PASSWORD` in `.env.hosted`, and set them with
   `alter role ... login password '...'` from a mode 600 file passed to
   `db query -f` (never on a command line).
4. Vault (same way): `select vault.create_secret('<MAILBOX_CRON_KEY>',
   'mailbox_cron_key')` and `select
   vault.create_secret('https://<ref>.supabase.co/functions/v1',
   'mailbox_functions_url')`. The pg_cron jobs read both at each run and send
   nothing while either is missing.
5. Function secrets, from a mode 600 env file
   (`supabase secrets set --project-ref <ref> --env-file <file>`, then delete
   the file):

   | Secret | Value |
   | --- | --- |
   | `MAILBOX_DB_URL` | `postgresql://onepass_mailbox_api.<ref>:<MAILBOX_API_DB_PASSWORD>@aws-0-us-east-2.pooler.supabase.com:6543/postgres?sslmode=require` |
   | `MAILBOX_JANITOR_DB_URL` | the same with `onepass_mailbox_janitor` and `MAILBOX_JANITOR_DB_PASSWORD` |
   | `MAILBOX_IP_HMAC_SECRET` | `openssl rand -hex 32`, kept in `.env.hosted` |
   | `MAILBOX_CRON_KEY` | `openssl rand -hex 32`, the same value as the Vault's `mailbox_cron_key` |
   | `MAILBOX_CLIENT_IP_HEADER` | `sb-forwarded-for` (see below) |
   | `MAILBOX_TRUSTED_HOPS` | `1` (unused for a single-value header) |
   | `MAILBOX_PUSH_PROVIDERS` | `none` |
   | `MAILBOX_PUBLISHABLE_KEY` | the project's `sb_publishable_...` key (public) |
   | `MAILBOX_REALTIME_URL` | `wss://<ref>.supabase.co/realtime/v1` |

   `MAILBOX_OPEN_SIGNUP` stays unset. `SUPABASE_URL` and
   `SUPABASE_SERVICE_ROLE_KEY` come from the platform. Every function refuses
   to boot without its required secrets: `mailbox` without
   `MAILBOX_CLIENT_IP_HEADER`, `mailbox-push` without an explicit
   `MAILBOX_PUSH_PROVIDERS`.
6. Functions: `supabase functions deploy mailbox mailbox-push mailbox-gc
   --project-ref <ref> --no-verify-jwt --use-api`.
7. Checks: `curl <base>/v1/config` answers 200; `POST` to `mailbox-push` or
   `mailbox-gc` without the key answers 401; `net._http_response` shows the
   push job's 200 summaries every 10 s; run the gc job's command once (as in
   `scripts/cron-check.sh`) and look for a 200 summary.
8. Realtime: the wake-up uses a public Broadcast channel, so "Allow public
   access" must stay on in Realtime settings. `realtime.messages` partitions
   appear only once Realtime has served a client; until then the maintenance
   logs a `WARNING` per missing day and wake-ups are lost (clients poll).
9. Advisors: `get_advisors` security and performance show nothing above INFO
   on `onepass_mailbox`.

### Client address

Probed on 2026-10-31 with real requests: the gateway drops any client
`X-Forwarded-For` and sends `x-forwarded-for: <client>,<client>, <internal
load balancer>`, so the rightmost entry is a Supabase address, never the
client. `sb-forwarded-for` and `cf-connecting-ip` carry the client address
alone, and a client-sent `sb-forwarded-for` is overwritten (a client-sent
`CF-Connecting-IP` is refused by Cloudflare). Hence
`MAILBOX_CLIENT_IP_HEADER=sb-forwarded-for`. If Supabase changes its gateway,
repeat the probe (a throwaway function echoing those headers, called with
spoofed values) before changing the setting.

## Invites and signup

- New invite: `scripts/hosted-admin.sh invite free <uses> <days>` prints the
  token once; only its SHA-256 is stored.
- Signup is open only when both the function's `MAILBOX_OPEN_SIGNUP=true` and
  the database row `onepass_mailbox.settings (name 'open_signup', value 'on')`
  say so. The row is written by an operator in maintenance mode, never by the
  API role, so whoever holds only the function's environment cannot open the
  instance. `scripts/hosted-admin.sh signup on|off` writes or deletes the row.
  Keep it off on the hosted instance unless the founder decides otherwise (spec
  D.6 plans open hosted signup with per-IP limits; not enabled yet). The
  default is closed and nothing below turns it on by itself.
- Opening signup, once decided: `scripts/hosted-admin.sh signup-plan free`
  (plan open signup gives; `default` = selfhost), `create-cap <n>` (global
  mailboxes per UTC day, `none` = no cap), then `signup on` and
  `MAILBOX_OPEN_SIGNUP=true` on the function. Per-IP limits (60 a minute, 5 a
  day) use the client IP from `MAILBOX_CLIENT_IP_HEADER`, HMAC'd with
  `MAILBOX_IP_HMAC_SECRET`. At the cap, creation answers `503 retry` (no
  retry-after) until the next UTC day or a higher cap. A refused creation is
  not counted. A valid invite always keeps its own plan, and the cap counts
  invite creations too. An `open_signup_plan` naming no plan makes creation
  fail with 503 until fixed. Closing again: `signup off`.

## Freezing a mailbox

`scripts/hosted-admin.sh freeze <mailbox hex>` (and `unfreeze`) sets
`mailboxes.frozen`: reads and writes answer `403 frozen`, nothing is deleted,
wake-ups stop. Write down who froze which mailbox, when and why in the
operations log.

## Rotating `MAILBOX_IP_HMAC_SECRET`

The secret only keys the per-IP rate windows (no address is stored), so a
rotation resets them and costs nothing else. Generate a new value, replace it
in `.env.hosted`, `supabase secrets set MAILBOX_IP_HMAC_SECRET=...` from an env
file, then redeploy `mailbox` so running workers pick it up. Old windows age
out within two days. Rotate the cron key the same way, Vault and function
secret together (`mailbox_cron_key` and `MAILBOX_CRON_KEY`); role passwords
with `alter role` then `MAILBOX_DB_URL` or `MAILBOX_JANITOR_DB_URL`.

## Backup and restore

- The database is covered by the project's Supabase backups (daily on paid
  plans; the Free plan has none, so take `supabase db dump --linked
  --data-only -s onepass_mailbox` yourself until the project is on Pro).
  Storage objects are not in database backups: list and copy the bucket
  separately.
- After a restore, every mailbox must get a new `incarnation` so clients
  reset their zone instead of trusting cursors the server forgot:
  `update onepass_mailbox.mailboxes set incarnation = (('x' ||
  encode(extensions.gen_random_bytes(8), 'hex'))::bit(64)::bigint &
  9223372036854775807)` in a maintenance transaction.

## Dashboard

Supabase dashboard of the project: Edge Functions (logs and invocations of the
three functions; alert on bursts of `503`), Database > Cron (job runs),
Logs > Postgres (maintenance `WARNING`s, `OP` SQLSTATEs), Advisors, Storage
(bucket size). `net._http_response` keeps the janitor functions' answers.

## End-to-end run against the hosted instance

```
scripts/hosted-admin.sh e2e-setup        # plan conformance + a 2 h invite, prints it
cd ../core && ONEPASS_MAILBOX_E2E_URL=<client base URL> \
  ONEPASS_MAILBOX_E2E_INVITE=<invite> \
  ONEPASS_MAILBOX_E2E_ADMIN="$PWD/../mailbox/scripts/hosted-admin.sh" \
  cargo test -p onepass-mailbox --features testing --test conformance_e2e
cd ../mailbox && scripts/hosted-admin.sh e2e-teardown   # mailboxes, objects, plan, invites
```

`reset-rate`, called by the suite before every case, empties all rate windows:
run the suite only while nobody else uses the instance.
