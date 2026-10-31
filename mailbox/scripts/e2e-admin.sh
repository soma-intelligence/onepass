#!/usr/bin/env bash
# Operator steps the end-to-end conformance run needs on the LOCAL stack
# (core/onepass-mailbox/tests/conformance_e2e.rs), done in the database
# container the way an operator would. Never points at a hosted project.
#
#   mailbox/scripts/e2e-admin.sh setup
#       Plan `conformance` (64 MiB, 3 000 records, 16 credentials, 6 000
#       requests a minute, 20 000 operations a batch: the limits of
#       tests/conformance_fake.rs), an invite for it with 1 000 uses, and
#       open signup switched off in the database (with it on, a create
#       ignores the invite and takes plan selfhost). Prints the invite, for
#       ONEPASS_MAILBOX_E2E_INVITE.
#   mailbox/scripts/e2e-admin.sh reset-rate
#       Empties the rate windows. Every conformance case creates mailboxes,
#       and one address gets 5 creations a day (spec 4.9).
#   mailbox/scripts/e2e-admin.sh purge <mailbox hex>
#       Ages that mailbox's tombstones past 90 days, then runs the
#       maintenance as postgres (as pg_cron does): they are purged, their
#       quota cost freed, min_cursor raised.
#
# Writes go through supabase_admin (a superuser: it passes the row level
# security like the migrations do); the maintenance needs session user
# postgres (onepass_mailbox.in_maintenance).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="$root/mailbox/supabase/config.toml"
project="$(awk -F'"' '/^project_id *=/ { print $2; exit }' "$config")"
db="supabase_db_${project}"

if ! docker inspect -f '{{.State.Running}}' "$db" 2>/dev/null | grep -q true; then
    echo "$db is not running: start the local stack first" >&2
    exit 1
fi

sql() {
    local user="$1"
    shift
    docker exec -i "$db" psql -q -X -t -A -v ON_ERROR_STOP=1 -U "$user" -d postgres "$@"
}

case "${1:-}" in
    setup)
        invite="e2e-$(openssl rand -hex 16)"
        sql supabase_admin >/dev/null <<SQL
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('conformance', 67108864, 3000, 16, 6000, 20000)
on conflict (plan) do update set
    max_bytes = excluded.max_bytes, max_records = excluded.max_records,
    max_credentials = excluded.max_credentials, req_per_min = excluded.req_per_min,
    max_commit_ops = excluded.max_commit_ops;
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest(convert_to('${invite}', 'UTF8'), 'sha256'), 'conformance', 1000, now() + interval '1 day');
delete from onepass_mailbox.settings where name = 'open_signup';
SQL
        echo "$invite"
        ;;
    reset-rate)
        sql supabase_admin -c 'delete from onepass_mailbox.rate' >/dev/null
        ;;
    purge)
        hex="${2:-}"
        if ! printf '%s' "$hex" | grep -Eq '^[0-9a-f]{32}$'; then
            echo "usage: $0 purge <32 hex mailbox id>" >&2
            exit 2
        fi
        sql supabase_admin -c "update onepass_mailbox.records set deleted_at = deleted_at - interval '91 days'
            where mailbox_id = decode('${hex}', 'hex') and deleted" >/dev/null
        sql postgres -c 'select onepass_mailbox.maintenance()' >/dev/null
        ;;
    *)
        echo "usage: $0 setup | reset-rate | purge <mailbox hex>" >&2
        exit 2
        ;;
esac
