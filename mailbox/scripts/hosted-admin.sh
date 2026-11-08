#!/usr/bin/env bash
# Operator steps on the HOSTED mailbox (mailbox/RUNBOOK.md), through the
# Supabase CLI's Management API access (`supabase login` once, then
# `supabase link --project-ref <ref>` from mailbox/): SQL runs as postgres,
# in maintenance mode, and no database password is needed or shown.
#
#   mailbox/scripts/hosted-admin.sh invite <plan> <uses> <days>
#       Creates an invite of that plan and prints its token (give it to the
#       person; only its SHA-256 is stored).
#   mailbox/scripts/hosted-admin.sh freeze <mailbox hex> | unfreeze <mailbox hex>
#       Sets or clears mailboxes.frozen (a frozen mailbox refuses writes).
#   mailbox/scripts/hosted-admin.sh signup on|off
#       The open_signup row of onepass_mailbox.settings. Keep it off on the
#       hosted instance: creation then needs an invite.
#   mailbox/scripts/hosted-admin.sh signup-plan <plan>|default
#       The open_signup_plan row: the plan open signup gives (default deletes
#       the row: selfhost). The plan must exist; it changes nothing while
#       signup is off.
#   mailbox/scripts/hosted-admin.sh create-cap <n>|none
#       The daily_create_cap row: mailboxes the whole instance creates per
#       UTC day (none deletes the row: no cap). Over it creation answers 503.
#   mailbox/scripts/hosted-admin.sh e2e-setup
#       Plan `conformance` and one invite for a conformance run (2 hours,
#       1 000 uses: every case creates mailboxes). Prints the invite.
#   mailbox/scripts/hosted-admin.sh reset-rate
#       Empties the rate windows. Only while plan `conformance` exists (an
#       e2e run): on a live instance this lifts every client's limits.
#   mailbox/scripts/hosted-admin.sh purge <mailbox hex>
#       Ages that mailbox's tombstones past 90 days and runs the maintenance
#       (the conformance suite's purge step).
#   mailbox/scripts/hosted-admin.sh e2e-teardown
#       Deletes every mailbox of plan `conformance` and their children (rows
#       in one transaction, then their Storage objects), its invites and the
#       plan. Run it again if it fails: it picks up where it stopped.
#
# This file is ONEPASS_MAILBOX_E2E_ADMIN for a conformance run against the
# hosted URL (it answers reset-rate and purge like e2e-admin.sh).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workdir="$root/mailbox"
cli=(npx --yes supabase@2.122.0)
bucket="onepass-mailbox"

if [ ! -s "$workdir/supabase/.temp/project-ref" ]; then
    echo "not linked: run npx --yes supabase@2.122.0 link --project-ref <ref> from mailbox/" >&2
    exit 1
fi
ref="$(cat "$workdir/supabase/.temp/project-ref")"

# Runs SQL from stdin as postgres; prints the rows as JSON.
sql() {
    local f
    f="$(mktemp)"
    trap 'rm -f "$f"' RETURN
    chmod 600 "$f"
    cat >"$f"
    "${cli[@]}" db query --linked --workdir "$workdir" -o json -f "$f"
}

# One column of the rows, one value a line.
column() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
for r in d.get("rows", d if isinstance(d, list) else []):
    print(r[sys.argv[1]])
' "$1"
}

hex_arg() {
    if ! printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{32}$'; then
        echo "expected a 32 hex mailbox id" >&2
        exit 2
    fi
}

conformance_present() {
    [ "$(sql <<<"select count(*) as n from onepass_mailbox.plans where plan = 'conformance'" | column n)" = "1" ]
}

case "${1:-}" in
    invite)
        plan="${2:-}" uses="${3:-}" days="${4:-}"
        printf '%s' "$plan" | grep -Eq '^[a-z][a-z0-9_]{0,31}$' || { echo "bad plan" >&2; exit 2; }
        printf '%s' "$uses" | grep -Eq '^[1-9][0-9]{0,5}$' || { echo "bad uses" >&2; exit 2; }
        printf '%s' "$days" | grep -Eq '^[1-9][0-9]{0,2}$' || { echo "bad days" >&2; exit 2; }
        token="inv-$(openssl rand -hex 16)"
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest(convert_to('${token}', 'UTF8'), 'sha256'), '${plan}', ${uses}, now() + interval '${days} days');
commit;
SQL
        echo "$token"
        ;;
    freeze | unfreeze)
        hex_arg "${2:-}"
        value=$([ "$1" = freeze ] && echo true || echo false)
        sql <<SQL | column n
begin;
select set_config('onepass.maintenance', 'on', true);
with u as (update onepass_mailbox.mailboxes set frozen = ${value} where id = decode('${2}', 'hex') returning 1)
select count(*) as n from u;
commit;
SQL
        ;;
    signup)
        case "${2:-}" in
            on) stmt="insert into onepass_mailbox.settings (name, value) values ('open_signup', 'on')
                      on conflict (name) do update set value = excluded.value;" ;;
            off) stmt="delete from onepass_mailbox.settings where name = 'open_signup';" ;;
            *) echo "usage: $0 signup on|off" >&2; exit 2 ;;
        esac
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
${stmt}
commit;
SQL
        ;;
    signup-plan)
        case "${2:-}" in
            default) stmt="delete from onepass_mailbox.settings where name = 'open_signup_plan';" ;;
            *)
                printf '%s' "${2:-}" | grep -Eq '^[a-z][a-z0-9_]{0,31}$' || { echo "bad plan" >&2; exit 2; }
                stmt="insert into onepass_mailbox.settings (name, value) values ('open_signup_plan', '${2}')
                      on conflict (name) do update set value = excluded.value;" ;;
        esac
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
${stmt}
commit;
SQL
        ;;
    create-cap)
        case "${2:-}" in
            none) stmt="delete from onepass_mailbox.settings where name = 'daily_create_cap';" ;;
            *)
                printf '%s' "${2:-}" | grep -Eq '^[1-9][0-9]{0,8}$' || { echo "bad cap" >&2; exit 2; }
                stmt="insert into onepass_mailbox.settings (name, value) values ('daily_create_cap', '${2}')
                      on conflict (name) do update set value = excluded.value;" ;;
        esac
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
${stmt}
commit;
SQL
        ;;
    e2e-setup)
        invite="e2e-$(openssl rand -hex 16)"
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops,
                                   max_children_shared, max_children_contact)
values ('conformance', 67108864, 3000, 16, 6000, 20000, 16, 16)
on conflict (plan) do update set
    max_bytes = excluded.max_bytes, max_records = excluded.max_records,
    max_credentials = excluded.max_credentials, req_per_min = excluded.req_per_min,
    max_commit_ops = excluded.max_commit_ops,
    max_children_shared = excluded.max_children_shared,
    max_children_contact = excluded.max_children_contact;
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest(convert_to('${invite}', 'UTF8'), 'sha256'), 'conformance', 1000, now() + interval '2 hours');
delete from onepass_mailbox.settings where name = 'open_signup';
commit;
SQL
        echo "$invite"
        ;;
    reset-rate)
        conformance_present || { echo "no plan conformance: reset-rate is for an e2e run only" >&2; exit 1; }
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
delete from onepass_mailbox.rate;
commit;
SQL
        ;;
    purge)
        hex_arg "${2:-}"
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
update onepass_mailbox.records set deleted_at = deleted_at - interval '91 days'
where mailbox_id = decode('${2}', 'hex') and deleted;
commit;
select onepass_mailbox.maintenance();
SQL
        ;;
    e2e-teardown)
        conformance_present || { echo "no plan conformance: nothing to tear down"; exit 0; }
        # The conformance mailboxes and their children (sharing creates them
        # on plans shared and contact).
        set_sql="with recursive s (id) as (
    select id from onepass_mailbox.mailboxes where plan = 'conformance'
    union
    select m.id from onepass_mailbox.mailboxes m join s on m.parent_id = s.id
)
select id from s"
        # Their ids are kept in a file until their Storage objects are gone:
        # a run that fails after the database step finds them there again.
        pending="$workdir/supabase/.temp/e2e-teardown-mailboxes"
        touch "$pending"
        sql <<<"select encode(id, 'hex') as h from (${set_sql}) x" | column h >>"$pending"
        sort -u -o "$pending" "$pending"
        mailboxes=()
        while IFS= read -r line; do
            if printf '%s' "$line" | grep -Eq '^[0-9a-f]{32}$'; then mailboxes+=("$line"); fi
        done <"$pending"
        echo "conformance mailboxes (children included): ${#mailboxes[@]}"
        # Database first, in one transaction: every row that references
        # them, then children before parents. A failure leaves every row in
        # place.
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
create temporary table t_gone on commit drop as
${set_sql};
delete from onepass_mailbox.push_queue where mailbox_id in (select id from t_gone);
-- push_targets exists only from 20261101120100 on (its rows also go with
-- their credentials, on delete cascade).
do \$\$
begin
    if to_regclass('onepass_mailbox.push_targets') is not null then
        delete from onepass_mailbox.push_targets where mailbox_id in (select id from t_gone);
    end if;
end
\$\$;
delete from onepass_mailbox.locators where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.nonces where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.used_tickets where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.records where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.blob_graves where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.blobs where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.credentials where mailbox_id in (select id from t_gone);
delete from onepass_mailbox.mailboxes where id in (select id from t_gone) and parent_id is not null;
delete from onepass_mailbox.mailboxes where id in (select id from t_gone);
commit;
SQL
        # Then Storage, once the rows are gone: the objects under those
        # mailboxes' prefixes (announced or not), removed through the
        # Storage API with the service key (never printed).
        if [ "${#mailboxes[@]}" -gt 0 ]; then
            prefixes="$(printf "'%s/'," "${mailboxes[@]}")"
            prefixes="${prefixes%,}"
            objects=()
            while IFS= read -r line; do objects+=("$line"); done < <(sql <<<"select name as n from storage.objects
                where bucket_id = '${bucket}' and left(name, 33) in (${prefixes})" | column n)
            echo "Storage objects: ${#objects[@]}"
            if [ "${#objects[@]}" -gt 0 ]; then
                key="$("${cli[@]}" projects api-keys --workdir "$workdir" --project-ref "$ref" -o json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
d = d if isinstance(d, list) else d.get("keys", [])
print(next(k["api_key"] for k in d if k.get("name") == "service_role"))
')"
                for ((i = 0; i < ${#objects[@]}; i += 500)); do
                    body="$(python3 -c 'import json, sys; print(json.dumps({"prefixes": sys.argv[1:]}))' "${objects[@]:i:500}")"
                    curl -sS -f -o /dev/null -X DELETE "https://${ref}.supabase.co/storage/v1/object/${bucket}" \
                        -H "authorization: Bearer ${key}" -H "apikey: ${key}" -H 'content-type: application/json' \
                        --data-binary @- <<<"$body"
                done
            fi
        fi
        rm -f "$pending"
        sql >/dev/null <<SQL
begin;
select set_config('onepass.maintenance', 'on', true);
delete from onepass_mailbox.invites where plan = 'conformance';
delete from onepass_mailbox.plans where plan = 'conformance';
delete from onepass_mailbox.rate;
delete from onepass_mailbox.settings where name = 'open_signup';
commit;
SQL
        echo "conformance plan, invites and mailboxes removed; open signup off"
        ;;
    *)
        echo "usage: $0 invite <plan> <uses> <days> | freeze|unfreeze <hex> | signup on|off | e2e-setup | reset-rate | purge <hex> | e2e-teardown" >&2
        exit 2
        ;;
esac
