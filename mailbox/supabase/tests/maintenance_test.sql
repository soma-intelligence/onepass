-- Maintenance (spec 4.5, 4.7, 4.9, 4.10, 4.11): purges, the 90 day
-- tombstone purge and min_cursor, the push queue, the Realtime partition
-- check and the pg_cron schedule.
-- Starts as the harness superuser (pg_cron's role), inside a transaction the
-- harness rolls back. now() is fixed for the whole transaction; maintenance
-- takes the time as a parameter, so ageing is simulated by passing a later
-- p_now or by moving timestamps back.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea, wake_topic bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-maintenance-test-key/' || n, 'sha256') as pk
      from unnest(array['m', 'm2', 'm3', 'm4', 'n', 'o']) as n) k;

create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        (select pk from t_keys where t_keys.name = key), onepass_test.n(), now(), null, '\x',
        decode(md5(name) || md5(name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id, r.wake_topic);
    end if;
    return r.status;
end
$$;
create function onepass_test.put(cred text, mbx text, i integer, body bytea)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[1]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array[body], array[null]::bytea[], array[octet_length(body)])
$$;
create function onepass_test.del(cred text, mbx text, i integer)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[1]::smallint[], array[onepass_test.rid(i)], array[2]::bigint[], array[2]::smallint[],
        array[null]::bigint[], array[null]::bytea[], array[null]::bytea[], array[null]::integer[])
$$;
create function onepass_test.changes(cred text, mbx text, after bigint, full_fetch boolean)
returns table (status text, retry_after integer, incarnation bigint, min_cursor bigint, head bigint,
               seq bigint, kind smallint, id bytea, version bigint, deleted boolean, data bytea,
               blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_changes(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        after, 1000, full_fetch)
$$;
grant execute on all functions in schema onepass_test to public;

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(m, k) = 'ok') from (values ('M', 'm'), ('N', 'n'), ('O', 'o')) v (m, k)),
    'maintenance_fixture_mailboxes_created');
reset role;
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, enrolled_by, push_kind, push_token)
select cid, onepass_test.mbx('M'), pk, onepass_test.cid('m'),
       case name when 'm2' then 2 when 'm3' then 3 end,
       case name when 'm2' then '\x7402'::bytea when 'm3' then '\x7403'::bytea end
from t_keys where name in ('m2', 'm3', 'm4');
update onepass_mailbox.credentials set push_kind = 1, push_token = '\x7401' where id = onepass_test.cid('m');
update onepass_mailbox.credentials set push_kind = 1, push_token = '\x7501' where id = onepass_test.cid('n');
update onepass_mailbox.credentials set push_kind = 1, push_token = '\x7601' where id = onepass_test.cid('o');
-- A revoked credential keeps no token through the API; set one anyway.
update onepass_mailbox.credentials set revoked_at = now() where id = onepass_test.cid('m3');

-- ------------------------------------------------- 90 day tombstone purge

-- M: rid 1..4 live (seq 1..4), then rid 1 and rid 2 deleted (seq 5, 6).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(s = 'ok') from (
        select (select status from onepass_test.put('m', 'M', i, '\x01')) as s from generate_series(1, 4) i
        union all select (select status from onepass_test.del('m', 'M', 1))
        union all select (select status from onepass_test.del('m', 'M', 2))) x),
    'tombstone_fixture_written');
-- A full fetch that started before the purge keeps the head of its first page.
select onepass_test.ok(
    (select head = 6 and min_cursor = 0 from onepass_test.changes('m', 'M', 0, true) limit 1),
    'full_fetch_head_before_the_purge');
reset role;
select onepass_test.ok(
    (select records_count = 6 - 2 and bytes_used = 2 + 2 * 128 and min_cursor = 0 and next_seq = 7
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('M')),
    'tombstones_count_until_purged');

update onepass_mailbox.records set deleted_at = now() - interval '91 days'
where mailbox_id = onepass_test.mbx('M') and id = onepass_test.rid(1);
update onepass_mailbox.records set deleted_at = now() - interval '89 days'
where mailbox_id = onepass_test.mbx('M') and id = onepass_test.rid(2);

select onepass_mailbox.maintenance();

select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('M') and id = onepass_test.rid(1))
    and exists (select 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('M') and id = onepass_test.rid(2)),
    'tombstone_of_91_days_purged_and_of_89_days_kept');
select onepass_test.ok(
    (select records_count = 3 and bytes_used = 2 + 128 and min_cursor = 5 and next_seq = 7
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('M')),
    'purge_frees_the_tombstone_cost_and_raises_min_cursor_to_its_seq');
select onepass_test.ok(
    coalesce(current_setting('onepass.maintenance', true), '') <> 'on',
    'maintenance_leaves_no_maintenance_setting_behind');

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'cursor_expired' from onepass_test.changes('m', 'M', 4, false) limit 1),
    'incremental_fetch_from_before_the_purged_seq_is_cursor_expired');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and seq = 6 and deleted and min_cursor = 5)
     from onepass_test.changes('m', 'M', 5, false)),
    'incremental_fetch_from_the_purged_seq_still_works');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and seq is null and head = 6)
     from onepass_test.changes('m', 'M', 6, false)),
    'incremental_fetch_from_the_full_fetch_head_still_works');
select onepass_test.ok(
    (select count(*) = 2 and bool_and(status = 'ok' and not deleted) from onepass_test.changes('m', 'M', 0, true)),
    'full_fetch_after_the_purge_sees_the_live_rows');
reset role;

-- Much later: the second tombstone goes, live rows never do.
select onepass_mailbox.maintenance(now() + interval '1000 days');
select onepass_test.ok(
    (select count(*) = 2 and bool_and(not deleted) from onepass_mailbox.records where mailbox_id = onepass_test.mbx('M'))
    and (select records_count = 2 and bytes_used = 2 and min_cursor = 6 from onepass_mailbox.mailboxes where id = onepass_test.mbx('M')),
    'old_live_rows_are_never_purged');
select onepass_mailbox.maintenance(now() + interval '2000 days');
select onepass_test.ok(
    (select min_cursor = 6 from onepass_mailbox.mailboxes where id = onepass_test.mbx('M')),
    'min_cursor_stays_when_nothing_is_purged');

-- ------------------------------------------------------- short lived rows

insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce, seen_at) values
    (onepass_test.cid('m'), onepass_test.mbx('M'), onepass_test.nonce(900001), now() - interval '601 seconds'),
    (onepass_test.cid('m'), onepass_test.mbx('M'), onepass_test.nonce(900002), now() - interval '599 seconds');
insert into onepass_mailbox.used_tickets (ticket_hash, mailbox_id, used_at) values
    (extensions.digest('t1', 'sha256'), onepass_test.mbx('M'), now() - interval '61 minutes'),
    (extensions.digest('t2', 'sha256'), onepass_test.mbx('M'), now() - interval '59 minutes');
insert into onepass_mailbox.rdv_sessions (session_id, created_at) values
    (onepass_test.nonce(800001), now() - interval '601 seconds'),
    (onepass_test.nonce(800002), now() - interval '200 seconds'),
    (onepass_test.nonce(800003), now() - interval '24 hours 1 second');
insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data, written_at) values
    (onepass_test.nonce(800001), 0, 0, '\x01', now() - interval '500 seconds'),
    (onepass_test.nonce(800002), 0, 0, '\x01', now() - interval '121 seconds'),
    (onepass_test.nonce(800002), 0, 1, '\x01', now() - interval '119 seconds');

select onepass_mailbox.maintenance();

select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.nonces where nonce = onepass_test.nonce(900001))
    and exists (select 1 from onepass_mailbox.nonces where nonce = onepass_test.nonce(900002)),
    'nonces_older_than_600_s_purged');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.used_tickets where ticket_hash = extensions.digest('t1', 'sha256'))
    and exists (select 1 from onepass_mailbox.used_tickets where ticket_hash = extensions.digest('t2', 'sha256')),
    'used_tickets_older_than_an_hour_purged');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.rdv_sessions where session_id = onepass_test.nonce(800003))
    and exists (select 1 from onepass_mailbox.rdv_sessions where session_id = onepass_test.nonce(800001))
    and exists (select 1 from onepass_mailbox.rdv_sessions where session_id = onepass_test.nonce(800002)),
    'rdv_session_rows_purged_after_a_day');
select onepass_test.ok(
    (select array_agg(n order by n) = array[1] from onepass_mailbox.rdv_chunks where session_id = onepass_test.nonce(800002))
    and not exists (select 1 from onepass_mailbox.rdv_chunks where session_id = onepass_test.nonce(800001)),
    'rdv_frames_older_than_120_s_purged');

-- Rate windows, against a fixed clock at 10:17:30 UTC on some later day.
create temporary table t_clock on commit drop as
select date_trunc('day', now() + interval '3000 days', 'UTC') + interval '10 hours 17 minutes 30 seconds' as t;
insert into onepass_mailbox.rate (key, window_start, count)
select extensions.digest(k, 'sha256'), (select t from t_clock) - w, 1
from (values ('minute_3_ago', interval '3 minutes 30 seconds'),
             ('minute_1_ago', interval '1 minute 30 seconds'),
             ('minute_on_the_hour', interval '17 minutes 30 seconds'),
             ('hour_1_ago', interval '1 hour 17 minutes 30 seconds'),
             ('hour_3_ago', interval '3 hours 17 minutes 30 seconds'),
             ('day_today', interval '10 hours 17 minutes 30 seconds'),
             ('day_1_ago', interval '1 day 10 hours 17 minutes 30 seconds'),
             ('day_3_ago', interval '3 days 10 hours 17 minutes 30 seconds')) v (k, w);
select onepass_mailbox.maintenance((select t from t_clock));
select onepass_test.ok(
    (select array_agg(k order by k) from (values ('minute_3_ago'), ('minute_1_ago'), ('minute_on_the_hour'),
         ('hour_1_ago'), ('hour_3_ago'), ('day_today'), ('day_1_ago'), ('day_3_ago')) v (k)
     where exists (select 1 from onepass_mailbox.rate r where r.key = extensions.digest(v.k, 'sha256')))
    = array['day_1_ago', 'day_today', 'hour_1_ago', 'minute_1_ago', 'minute_on_the_hour'],
    'rate_windows_purged_by_their_length');

-- -------------------------------------------------------------- push queue

-- One author: the others hear of it, the author and a revoked credential
-- do not, a credential without a token has nothing to receive.
set local role onepass_mailbox_api;
select onepass_test.ok((select status = 'ok' from onepass_test.put('m', 'M', 10, '\x01')), 'push_fixture_commit_by_m');
reset role;
set local role onepass_mailbox_janitor;
create temporary table t_push on commit drop as select * from onepass_mailbox.push_take(100);
reset role;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(mailbox_id = onepass_test.mbx('M') and credential_id = onepass_test.cid('m2')
                                      and push_kind = 2 and push_token = '\x7402')
     from t_push),
    'push_take_returns_the_tokens_without_the_author');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.push_queue),
    'push_take_empties_the_queue');
set local role onepass_mailbox_janitor;
select onepass_test.ok((select count(*) = 0 from onepass_mailbox.push_take(100)), 'push_take_of_an_empty_queue_is_empty');
reset role;

-- Two authors: both hear of it.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put('m', 'M', 11, '\x01'))
    and (select status = 'ok' from onepass_test.put('m2', 'M', 12, '\x01')),
    'push_fixture_commits_by_m_and_m2');
reset role;
set local role onepass_mailbox_janitor;
select onepass_test.ok(
    (select array_agg(credential_id order by credential_id)
            = (select array_agg(x order by x) from unnest(array[onepass_test.cid('m'), onepass_test.cid('m2')]) x)
     from onepass_mailbox.push_take(100)),
    'push_take_after_two_authors_returns_both');
reset role;

-- A frozen mailbox is not woken; its entry still leaves the queue. A limit
-- takes that many mailboxes.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put('n', 'N', 1, '\x01'))
    and (select status = 'ok' from onepass_test.put('o', 'O', 1, '\x01')),
    'push_fixture_commits_in_n_and_o');
reset role;
update onepass_mailbox.mailboxes set frozen = true where id = onepass_test.mbx('N');
update onepass_mailbox.push_queue set exclude_credential = null;
set local role onepass_mailbox_janitor;
select onepass_test.ok(
    (select count(*) <= 1 from onepass_mailbox.push_take(1)),
    'push_take_with_limit_one');
reset role;
select onepass_test.ok((select count(*) = 1 from onepass_mailbox.push_queue), 'push_take_limit_takes_one_mailbox');
set local role onepass_mailbox_janitor;
create temporary table t_push2 on commit drop as select * from onepass_mailbox.push_take(100);
reset role;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.push_queue)
    and not exists (select 1 from t_push2 where mailbox_id = onepass_test.mbx('N')),
    'frozen_mailbox_is_not_woken_and_leaves_the_queue');
set local role onepass_mailbox_janitor;
select onepass_test.throws($$select * from onepass_mailbox.push_take(0)$$, '22023', 'push_take_limit_zero_refused');

-- A token the provider calls stale is forgotten, unless it changed since.
select onepass_mailbox.push_forget(onepass_test.cid('m2'), '\x7402');
select onepass_mailbox.push_forget(onepass_test.cid('m'), '\x9999');
reset role;
select onepass_test.ok(
    (select push_kind is null and push_token is null from onepass_mailbox.credentials where id = onepass_test.cid('m2'))
    and (select push_kind = 1 and push_token = '\x7401' from onepass_mailbox.credentials where id = onepass_test.cid('m')),
    'push_forget_clears_only_the_stale_token');

-- ------------------------------------------------- Realtime partitions

-- No realtime.messages here: both days are reported.
select onepass_test.ok(
    (select array_agg(d order by d) from onepass_mailbox.wake_partitions_missing(now()) d)
    = array[(now() at time zone 'UTC')::date, (now() at time zone 'UTC')::date + 1],
    'missing_wake_partitions_reported_without_the_table');
-- Partitioned by day like the Realtime service does it, today only.
create table realtime.messages (topic text, inserted_at timestamp not null) partition by range (inserted_at);
do $$
declare
    d date := (now() at time zone 'UTC')::date;
begin
    execute format('create table realtime.%I partition of realtime.messages for values from (%L) to (%L)',
        'messages_' || to_char(d, 'YYYY_MM_DD'), d, d + 1);
end
$$;
select onepass_test.ok(
    (select array_agg(d) from onepass_mailbox.wake_partitions_missing(now()) d)
    = array[(now() at time zone 'UTC')::date + 1],
    'missing_wake_partition_of_tomorrow_reported');
-- Maintenance warns and goes on.
select onepass_mailbox.maintenance();
select onepass_test.ok(true, 'maintenance_runs_with_a_missing_wake_partition');

-- ------------------------------------------------------------------ roles

select onepass_test.throws(
    $$set local role onepass_mailbox_api; select onepass_mailbox.maintenance()$$, '42501',
    'api_cannot_run_maintenance');
select onepass_test.throws(
    $$set local role onepass_mailbox_api; select * from onepass_mailbox.push_take(10)$$, '42501',
    'api_cannot_take_the_push_queue');
select onepass_test.throws(
    $$set local role onepass_mailbox_api; select * from onepass_mailbox.gc_take(10)$$, '42501',
    'api_cannot_take_orphaned_blobs');
select onepass_test.throws(
    $$set local role onepass_mailbox_janitor; select onepass_mailbox.maintenance()$$, '42501',
    'janitor_cannot_run_maintenance');

-- ---------------------------------------------------------------- pg_cron

select onepass_test.ok(
    (select count(*) = 3 from cron.job where jobname like 'onepass-mailbox-%'),
    'three_cron_jobs_scheduled');
select onepass_test.ok(
    (select schedule = '* * * * *' and command = 'select onepass_mailbox.maintenance()'
     from cron.job where jobname = 'onepass-mailbox-maintenance'),
    'maintenance_runs_every_minute');
select onepass_test.ok(
    (select schedule = '10 seconds' and command like '%/mailbox-push%' from cron.job where jobname = 'onepass-mailbox-push'),
    'push_is_called_every_10_seconds');
select onepass_test.ok(
    (select schedule ~ '^[0-9]+ \* \* \* \*$' and command like '%/mailbox-gc%' from cron.job where jobname = 'onepass-mailbox-gc'),
    'gc_is_called_every_hour');

-- Without the Vault secrets the jobs send nothing; with them, one POST.
do $$
begin
    execute (select command from cron.job where jobname = 'onepass-mailbox-push');
end
$$;
select onepass_test.ok((select count(*) = 0 from net.sent), 'push_job_without_secrets_sends_nothing');
insert into vault.decrypted_secrets (name, decrypted_secret) values
    ('mailbox_functions_url', 'https://mailbox.test/functions/v1'),
    ('mailbox_cron_key', 'k-test');
do $$
begin
    execute (select command from cron.job where jobname = 'onepass-mailbox-push');
    execute (select command from cron.job where jobname = 'onepass-mailbox-gc');
end
$$;
select onepass_test.ok(
    (select array_agg(url order by id) = array['https://mailbox.test/functions/v1/mailbox-push',
                                               'https://mailbox.test/functions/v1/mailbox-gc']
            and bool_and(headers ->> 'Authorization' = 'Bearer k-test')
     from net.sent),
    'jobs_post_to_the_functions_with_the_cron_key');
