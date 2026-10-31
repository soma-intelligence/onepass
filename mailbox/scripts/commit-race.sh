#!/usr/bin/env bash
# Concurrent commits on one mailbox, on a throwaway Postgres 17 set up like
# mailbox/scripts/sql-test.sh (shims, migrations, seed).
#
#   mailbox/scripts/commit-race.sh
#
# 1. commit_concurrent_sessions_serialize: session A commits a put with
#    expected NULL and holds its transaction open; session B sends the same
#    put, waits on A's mailbox lock (seen in pg_stat_activity), then gets a
#    conflict carrying A's row. next_seq ends at 2.
# 2. commit_parallel_sessions_take_every_seq_once: four sessions commit 50
#    batches each at the same time (their own keys plus one shared key, so
#    some batches conflict). Every applied seq is logged in the transaction
#    that took it; the logged seqs must be exactly 1..N, next_seq N + 1, the
#    counters must match the rows, and no session may fail (a deadlock or a
#    unique violation stops it).
# 3. commit_frozen_while_waiting_is_refused: a freeze that commits while a
#    batch waits on the mailbox lock stops that batch (frozen is read again
#    under the lock).
# 4. purge_and_commit_serialize: maintenance purges a 90 day tombstone and
#    holds its transaction; a batch that puts on the same key waits on the
#    mailbox lock, then inserts a fresh row. The counters must match the
#    rows (a batch that planned against the tombstone would count it twice).
# 5. collector_never_takes_a_blob_a_commit_checked: a blob put waits on a
#    record row another session holds, after it checked the blob; meanwhile
#    the janitor runs maintenance and drains every grave (deleting each
#    object). When the batch applies, its blob row must be the one it
#    checked (same generation, refs 1) and that object must still exist.
#
# Prints `ok <name>` per check; exits non-zero on the first failure.
set -euo pipefail

export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
supa="$root/mailbox/supabase"

if [ -z "${PG_BIN:-}" ]; then
    if [ -x /opt/homebrew/opt/postgresql@17/bin/postgres ]; then
        PG_BIN=/opt/homebrew/opt/postgresql@17/bin
    elif [ -x /usr/lib/postgresql/17/bin/postgres ]; then
        PG_BIN=/usr/lib/postgresql/17/bin
    else
        PG_BIN="$(dirname "$(command -v postgres)")"
    fi
fi
major="$("$PG_BIN/postgres" --version | sed -E 's/.* ([0-9]+)\..*/\1/')"
if [ "$major" != "17" ]; then
    echo "need Postgres 17, $PG_BIN/postgres is $major" >&2
    exit 1
fi

tmp="$(mktemp -d "${SQL_TEST_TMP:-${TMPDIR:-/tmp}}/onepass-race.XXXXXX")"
data="$tmp/data"
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    "$PG_BIN/pg_ctl" -D "$data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$data" -U postgres --auth=trust -E UTF8 --no-locale >"$tmp/initdb.log" 2>&1 || {
    cat "$tmp/initdb.log" >&2
    exit 1
}
"$PG_BIN/pg_ctl" -D "$data" -l "$tmp/server.log" -w \
    -o "-c listen_addresses=127.0.0.1 -c port=$port -c unix_socket_directories= -c fsync=off -c deadlock_timeout=100ms" \
    start >/dev/null || {
    cat "$tmp/server.log" >&2
    exit 1
}

# psql as postgres; extra arguments pass through. `name` sets application_name.
q() {
    local name="$1"
    shift
    PGAPPNAME="$name" PGOPTIONS='--client-min-messages=warning' \
        "$PG_BIN/psql" -X -q -h 127.0.0.1 -p "$port" -U postgres -d postgres \
        -v ON_ERROR_STOP=1 -v VERBOSITY=terse "$@"
}
val() {
    q race-check -At -c "$1"
}
ok() {
    if [ "$1" = "t" ]; then
        echo "ok $2"
    else
        echo "not ok $2 (got $1)" >&2
        exit 1
    fi
}

q setup -o /dev/null -f "$supa/tests/shims.sql"
for m in "$supa"/migrations/*.sql; do
    q setup -o /dev/null -f "$m"
done
q setup -o /dev/null -f "$supa/seed.sql"

# One open-signup mailbox, committed, its ids kept in race.fixture.
q setup -o /dev/null <<'SQL'
create schema race;
create table race.fixture (mailbox bytea, credential bytea);
create table race.applied (session integer, seq bigint);
with k as (select extensions.digest('onepass-race-key', 'sha256') as pk)
insert into race.fixture
select c.mailbox_id, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || k.pk, 'sha256') from 1 for 16)
from k, onepass_mailbox.api_create_mailbox(k.pk, extensions.gen_random_bytes(16), now(), null, '\x',
    extensions.gen_random_bytes(32), true) c;
-- A put of one inline byte on (kind 1, id) with `expected`.
create function race.put(p_id bytea, p_expected bigint)
returns table (status text, seq bigint)
language sql
as $$
    select c.status, c.seq
    from race.fixture f,
         onepass_mailbox.api_commit(f.credential, extensions.gen_random_bytes(16), now(), f.mailbox,
             array[1]::smallint[], array[p_id], array[1]::bigint[], array[1]::smallint[],
             array[p_expected], array['\x01']::bytea[], array[null]::bytea[], array[1]) c
$$;
SQL

# ------------------------------------------------------------- phase 1

key="'\\x000000000000000000000000000000aa'::bytea"

q race-a -At >"$tmp/a.out" <<SQL &
begin;
select status || '|' || coalesce(seq::text, '') from race.put($key, null);
select pg_sleep(3);
commit;
SQL
pid_a=$!

# A holds the lock once it sleeps inside its transaction.
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-a' and query like '%pg_sleep%'")" = "1" ] && break
    sleep 0.05
done
ok "$(val "select count(*) = 1 from pg_stat_activity where application_name = 'race-a' and state = 'active' and query like '%pg_sleep%'")" \
    commit_race_first_session_holds_its_transaction

q race-b -At >"$tmp/b.out" <<SQL &
select status || '|' || coalesce(seq::text, '') from race.put($key, null);
SQL
pid_b=$!

waited=f
for _ in $(seq 1 40); do
    if [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-b' and wait_event_type = 'Lock'")" = "1" ]; then
        waited=t
        break
    fi
    sleep 0.05
done
ok "$waited" commit_race_second_session_waits_on_the_mailbox_lock

wait "$pid_a"
wait "$pid_b"
ok "$(grep -c '^ok|1$' "$tmp/a.out" | sed 's/^1$/t/')" commit_race_first_session_applies_seq_1
ok "$(grep -c '^conflict|1$' "$tmp/b.out" | sed 's/^1$/t/')" commit_race_second_session_conflicts_on_the_first_row
ok "$(val "select next_seq = 2 and records_count = 1 from onepass_mailbox.mailboxes")" \
    commit_concurrent_sessions_serialize

# ------------------------------------------------------------- phase 2

batches=50
sessions=4
for s in $(seq 1 "$sessions"); do
    q "race-p$s" -o /dev/null <<SQL &
do \$\$
declare
    b integer;
    cur bigint;
    r record;
begin
    for b in 1 .. $batches loop
        -- The shared key, with the expectation read just before: another
        -- session may write it first, and this batch then conflicts.
        select seq into cur from onepass_mailbox.records
        where kind = 1 and id = '\\x000000000000000000000000000000bb'::bytea and not deleted;
        for r in
            select c.status, c.seq
            from race.fixture f,
                 onepass_mailbox.api_commit(f.credential, extensions.gen_random_bytes(16), now(), f.mailbox,
                     array[2, 2, 1]::smallint[],
                     array[decode(lpad(to_hex($s * 100000 + b * 10 + 1), 32, '0'), 'hex'),
                           decode(lpad(to_hex($s * 100000 + b * 10 + 2), 32, '0'), 'hex'),
                           '\\x000000000000000000000000000000bb'::bytea],
                     array[b, b, b]::bigint[], array[1, 1, 1]::smallint[], array[null, null, cur]::bigint[],
                     array['\\x0102', '\\x03', '\\x040404']::bytea[], array[null, null, null]::bytea[], array[2, 1, 3]) c
        loop
            if r.status = 'ok' then
                insert into race.applied values ($s, r.seq);
            elsif r.status <> 'conflict' then
                raise exception 'session $s batch %: %', b, r.status;
            end if;
        end loop;
        commit;
    end loop;
end
\$\$;
SQL
    eval "pid_p$s=\$!"
done
for s in $(seq 1 "$sessions"); do
    eval "wait \$pid_p$s"
done
echo "ok commit_parallel_sessions_finish_without_error"

ok "$(val "select count(*) = count(distinct seq) from race.applied")" commit_parallel_seqs_never_duplicated
ok "$(val "select array_agg(seq order by seq) = array(select generate_series(2, (select count(*) + 1 from race.applied)))
           from race.applied")" \
    commit_parallel_seqs_have_no_gap
ok "$(val "select m.next_seq = (select max(seq) + 1 from race.applied) from onepass_mailbox.mailboxes m")" \
    commit_parallel_next_seq_follows_the_last_seq
ok "$(val "select m.bytes_used = (select sum(case when deleted then 128 else size end) from onepass_mailbox.records)
                 and m.records_count = (select count(*) from onepass_mailbox.records)
                 and (select count(*) from onepass_mailbox.records where kind = 2) = (select count(*) * 2 / 3 from race.applied)
           from onepass_mailbox.mailboxes m")" \
    commit_parallel_counters_match_the_rows
ok "$(val "select (select seq from onepass_mailbox.records where kind = 1 and id = '\\x000000000000000000000000000000bb'::bytea)
                 = (select max(seq) from race.applied)")" \
    commit_parallel_shared_key_holds_the_last_write
echo "# $(val "select count(*) from race.applied") seqs applied, $(val "select $sessions * $batches - count(distinct seq) / 3 from race.applied") batches conflicted"

# ------------------------------------------------------------- phase 3

# commit_frozen_while_waiting_is_refused: A holds the mailbox lock, the
# operator's freeze queues behind it, then B authenticates (not frozen yet)
# and queues too. When A commits, the freeze lands first, and B, reading
# frozen again under the lock, is refused and writes nothing.
key3="'\\x000000000000000000000000000000cc'::bytea"
before="$(val "select next_seq from onepass_mailbox.mailboxes")"

q race-a3 -At >"$tmp/a3.out" <<SQL &
begin;
select status from race.put($key3, null);
select pg_sleep(2);
commit;
SQL
pid_a3=$!
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-a3' and query like '%pg_sleep%'")" = "1" ] && break
    sleep 0.05
done

q race-freeze -o /dev/null -c "set onepass.maintenance = 'on'; update onepass_mailbox.mailboxes set frozen = true" &
pid_f=$!
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-freeze' and wait_event_type = 'Lock'")" = "1" ] && break
    sleep 0.05
done
ok "$(val "select count(*) = 1 from pg_stat_activity where application_name = 'race-freeze' and wait_event_type = 'Lock'")" \
    commit_race_freeze_waits_behind_the_batch

q race-b3 -At >"$tmp/b3.out" 2>&1 <<SQL &
select status from race.put('\\x000000000000000000000000000000dd'::bytea, null);
SQL
pid_b3=$!
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-b3' and wait_event_type = 'Lock'")" = "1" ] && break
    sleep 0.05
done
ok "$(val "select count(*) = 1 from pg_stat_activity where application_name = 'race-b3' and wait_event_type = 'Lock'")" \
    commit_race_second_batch_waits_after_authenticating

wait "$pid_a3"
wait "$pid_f"
wait "$pid_b3" || true
ok "$(grep -c '^ok$' "$tmp/a3.out" | sed 's/^1$/t/')" commit_race_batch_before_the_freeze_applies
ok "$(grep -c 'ERROR:  frozen' "$tmp/b3.out" | sed 's/^1$/t/')" commit_race_batch_after_the_freeze_is_refused
ok "$(val "select frozen and next_seq = $before + 1
                 and not exists (select 1 from onepass_mailbox.records where id = '\\x000000000000000000000000000000dd'::bytea)
           from onepass_mailbox.mailboxes")" \
    commit_frozen_while_waiting_is_refused

# ------------------------------------------------------------- phase 4

key4="'\\x000000000000000000000000000000ee'::bytea"
q setup -o /dev/null <<SQL
set onepass.maintenance = 'on';
update onepass_mailbox.mailboxes set frozen = false;
reset onepass.maintenance;
select status from race.put($key4, null);
select c.status
from race.fixture f,
     onepass_mailbox.api_commit(f.credential, extensions.gen_random_bytes(16), now(), f.mailbox,
         array[1]::smallint[], array[$key4], array[2]::bigint[], array[2]::smallint[],
         array[null]::bigint[], array[null]::bytea[], array[null]::bytea[], array[null]::integer[]) c;
update onepass_mailbox.records set deleted_at = now() - interval '100 days' where id = $key4;
SQL
tomb="$(val "select seq from onepass_mailbox.records where id = $key4 and deleted")"

q race-m4 -o /dev/null <<SQL &
begin;
select onepass_mailbox.maintenance();
select pg_sleep(2);
commit;
SQL
pid_m4=$!
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-m4' and query like '%pg_sleep%'")" = "1" ] && break
    sleep 0.05
done

q race-b4 -At >"$tmp/b4.out" <<SQL &
select status from race.put($key4, null);
SQL
pid_b4=$!
waited=f
for _ in $(seq 1 40); do
    if [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-b4' and wait_event_type = 'Lock'")" = "1" ]; then
        waited=t
        break
    fi
    sleep 0.05
done
ok "$waited" purge_race_batch_waits_behind_the_purge

wait "$pid_m4"
wait "$pid_b4"
ok "$(grep -c '^ok$' "$tmp/b4.out" | sed 's/^1$/t/')" purge_race_batch_applies_after_the_purge
ok "$(val "select m.bytes_used = (select sum(case when deleted then 128 else size end) from onepass_mailbox.records)
                 and m.records_count = (select count(*) from onepass_mailbox.records)
                 and m.min_cursor = $tomb
                 and (select not deleted from onepass_mailbox.records where id = $key4)
           from onepass_mailbox.mailboxes m")" \
    purge_and_commit_serialize

# ------------------------------------------------------------- phase 5

q setup -o /dev/null <<'SQL'
set onepass.maintenance = 'on';
insert into onepass_mailbox.blobs (mailbox_id, sha256, size, state, refs, orphaned_at)
select mailbox, extensions.digest('X', 'sha256'), 20000, 2, 0, now() - interval '2 days' from race.fixture;
insert into storage.objects (bucket_id, name, metadata)
select 'onepass-mailbox', onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen), '{"size": 20000}'::jsonb
from onepass_mailbox.blobs b where b.sha256 = extensions.digest('X', 'sha256');
SQL
gen5="$(val "select gen from onepass_mailbox.blobs where sha256 = extensions.digest('X', 'sha256')")"

# S holds the record row the batch will write.
q race-s5 -o /dev/null <<'SQL' &
begin;
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, size, data)
select mailbox, 1, '\x000000000000000000000000000000c5'::bytea, 1, 999999, 1, '\x01' from race.fixture;
select pg_sleep(3);
rollback;
SQL
pid_s5=$!
for _ in $(seq 1 100); do
    [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-s5' and query like '%pg_sleep%'")" = "1" ] && break
    sleep 0.05
done

q race-c5 -At >"$tmp/c5.out" 2>&1 <<'SQL' &
select c.status
from race.fixture f,
     onepass_mailbox.api_commit(f.credential, extensions.gen_random_bytes(16), now(), f.mailbox,
         array[1]::smallint[], array['\x000000000000000000000000000000c5'::bytea], array[1]::bigint[], array[1]::smallint[],
         array[null]::bigint[], array[null]::bytea[], array[extensions.digest('X', 'sha256')], array[20000]) c;
SQL
pid_c5=$!
waited=f
for _ in $(seq 1 40); do
    if [ "$(val "select count(*) from pg_stat_activity where application_name = 'race-c5' and wait_event_type = 'Lock'")" = "1" ]; then
        waited=t
        break
    fi
    sleep 0.05
done
ok "$waited" collector_race_batch_waits_after_checking_its_blob

# The janitor: maintenance (collects due blobs), then drain every grave the
# way mailbox-gc does: delete the object, then confirm.
q race-g5 -o /dev/null <<'SQL'
select onepass_mailbox.maintenance();
create temporary table taken as select * from onepass_mailbox.gc_take(1000);
delete from storage.objects o using taken t where o.name = t.object_name;
select onepass_mailbox.gc_done(t.mailbox_id, t.object_name) from taken t;
SQL

wait "$pid_s5" || true
wait "$pid_c5"
ok "$(grep -c '^ok$' "$tmp/c5.out" | sed 's/^1$/t/')" collector_race_batch_applies
ok "$(val "select b.gen = $gen5 and b.refs = 1 and b.state = 2
                 and exists (select 1 from storage.objects o
                             where o.name = onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen))
           from onepass_mailbox.blobs b where b.sha256 = extensions.digest('X', 'sha256')")" \
    collector_never_takes_a_blob_a_commit_checked
