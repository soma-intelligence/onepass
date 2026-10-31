#!/usr/bin/env bash
# Checks the pg_cron -> pg_net -> edge function path on the LOCAL stack:
#
#   mailbox/scripts/cron-check.sh <functions URL seen from the database>
#   e.g. mailbox/scripts/cron-check.sh http://kong:8000/functions/v1
#
# Run after commits (the end-to-end conformance run leaves push_queue
# entries), with mailbox-push and mailbox-gc served and
# mailbox/scripts/local-env.sh run (it stores mailbox_cron_key in Vault).
#
# 1. Stores the URL as the Vault secret mailbox_functions_url, which the
#    jobs of migration 20261031120400 read at each run.
# 2. mailbox-push: waits for the pg_cron job (every 10 s) to post to the
#    function with the cron key and get a 200 summary, and for push_queue
#    to be drained by it.
# 3. mailbox-gc: runs the command of its pg_cron job (hourly, at :17) once
#    by hand, the same net.http_post, and waits for a 200 summary.
#
# Exits non-zero, with the last responses, when a step does not happen in
# time. Never points at a hosted project.
set -euo pipefail

url="${1:-}"
case "$url" in
    http://*|https://*) ;;
    *)
        echo "usage: $0 <functions base URL as the database container reaches it>" >&2
        exit 2
        ;;
esac
url="${url%/}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="$root/mailbox/supabase/config.toml"
project="$(awk -F'"' '/^project_id *=/ { print $2; exit }' "$config")"
db="supabase_db_${project}"

sql() {
    docker exec -i "$db" psql -q -X -t -A -v ON_ERROR_STOP=1 -U supabase_admin -d postgres "$@"
}

if [ "$(sql -c "select count(*) from vault.decrypted_secrets where name = 'mailbox_cron_key'")" != "1" ]; then
    echo "no mailbox_cron_key in Vault: run mailbox/scripts/local-env.sh first" >&2
    exit 1
fi
queued="$(sql -c 'select count(*) from onepass_mailbox.push_queue')"
if [ "$queued" = "0" ]; then
    echo "push_queue is empty: run this after commits (the e2e conformance run)" >&2
    exit 1
fi
echo "push_queue: $queued entries"

before="$(sql -c 'select coalesce(max(id), 0) from net._http_response')"
sql >/dev/null <<SQL
delete from vault.secrets where name = 'mailbox_functions_url';
select vault.create_secret('${url}', 'mailbox_functions_url');
SQL

# A 200 answer of the function, posted by pg_net after $before, whose JSON
# summary has the given key.
answered() {
    sql -c "select count(*) from net._http_response
            where id > ${before} and status_code = 200 and content like '%\"$1\":%'"
}

dump() {
    echo "last pg_net responses:" >&2
    sql -c "select id, status_code, left(coalesce(content, error_msg, ''), 200) from net._http_response
            where id > ${before} order by id desc limit 5" >&2 || true
    echo "last cron runs:" >&2
    sql -c "select j.jobname, d.status, left(coalesce(d.return_message, ''), 120) from cron.job_run_details d
            join cron.job j on j.jobid = d.jobid order by d.runid desc limit 5" >&2 || true
}

wait_for() {
    local what="$1" check="$2"
    for _ in $(seq 1 60); do
        if [ "$(eval "$check")" != "0" ]; then
            echo "ok $what"
            return 0
        fi
        sleep 2
    done
    echo "FAILED $what" >&2
    dump
    exit 1
}

# mailbox-push answers {"taken":..,"sent":..,...}; the job runs every 10 s.
wait_for "pg_cron posted to mailbox-push" "answered sent"
wait_for "push_queue drained by mailbox-push" \
    "sql -c 'select (count(*) = 0)::int from onepass_mailbox.push_queue'"

# mailbox-gc answers {"taken":..,"deleted":..,...}; its job is hourly: run
# the job's own command now.
sql >/dev/null <<'SQL'
do $$
declare
    v_command text;
begin
    select command into strict v_command from cron.job where jobname = 'onepass-mailbox-gc';
    execute v_command;
end
$$;
SQL
wait_for "the mailbox-gc job's net.http_post reached mailbox-gc" "answered deleted"

# Leave the jobs idle again, as local-env.sh leaves them.
sql -c "delete from vault.secrets where name = 'mailbox_functions_url'" >/dev/null
