-- Pairing rendezvous (spec 4.6, 4.9, 5.3): frames written once, readable
-- 120 s, 66 MiB a session and direction, sessions closed 600 s after they
-- start, per-IP limits shared with create and enroll.
-- Starts as the harness superuser, inside a transaction the harness rolls
-- back; calls run as onepass_mailbox_api, state is read back as the
-- superuser. now() is fixed for the whole transaction; time passing is
-- simulated by moving written_at and created_at back.
--
-- Contract under test: a malformed IP key raises (OP400); every other
-- outcome is in band (`status`): 'ok', 'malformed', 'too_large',
-- 'conflict', 'not_found', 'rate_limited' (retry_after). The per-IP minute
-- hit stays even when the call fails; anything else a refused put wrote is
-- rolled back.

create function onepass_test.ip(name text) returns bytea language sql immutable as $$
    select decode(md5(name) || md5(name || '/'), 'hex') $$;
create function onepass_test.sid(i integer) returns bytea language sql immutable as $$
    select onepass_test.nonce(1000000 + i) $$;
create function onepass_test.rput(s integer, dir integer, n integer, data bytea, ip text default 'ip')
returns table (status text, retry_after integer)
language sql volatile as $$
    select * from onepass_mailbox.rdv_put(onepass_test.sid(s), dir::smallint, n, data, onepass_test.ip(ip)) $$;
create function onepass_test.rget(s integer, dir integer, n integer, ip text default 'ip')
returns table (status text, retry_after integer, data bytea)
language sql volatile as $$
    select * from onepass_mailbox.rdv_get(onepass_test.sid(s), dir::smallint, n, onepass_test.ip(ip)) $$;
grant execute on all functions in schema onepass_test to public;

-- -------------------------------------------------------------- frames

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_mailbox.rdv_put(onepass_test.sid(1), 0::smallint, 0, '\x01', '\x0102')$$,
    'OP400', 'malformed', 'rdv_put_with_malformed_ip_key_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.rdv_put(onepass_test.sid(1), 0::smallint, 0, '\x01', null)$$,
    'OP400', 'malformed', 'rdv_put_without_ip_key_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.rdv_close(onepass_test.sid(1), null)$$,
    'OP400', 'malformed', 'rdv_close_without_ip_key_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.rdv_get(onepass_test.sid(1), 0::smallint, 0, '\x01')$$,
    'OP400', 'malformed', 'rdv_get_with_malformed_ip_key_raises');

select onepass_test.answers(format('select * from onepass_mailbox.rdv_put(%s, %s, %s, %s, onepass_test.ip(''ip''))', s, d, n, b),
    'malformed', 'rdv_put_malformed_' || name)
from (values
    ('session_15_bytes', 'substring(onepass_test.sid(1) from 1 for 15)', '0::smallint', '0', '''\x01''::bytea'),
    ('session_null', 'null::bytea', '0::smallint', '0', '''\x01''::bytea'),
    ('dir_2', 'onepass_test.sid(1)', '2::smallint', '0', '''\x01''::bytea'),
    ('dir_null', 'onepass_test.sid(1)', 'null::smallint', '0', '''\x01''::bytea'),
    ('n_negative', 'onepass_test.sid(1)', '0::smallint', '-1', '''\x01''::bytea'),
    ('n_4096', 'onepass_test.sid(1)', '0::smallint', '4096', '''\x01''::bytea'),
    ('data_null', 'onepass_test.sid(1)', '0::smallint', '0', 'null::bytea')) as t (name, s, d, n, b);
select onepass_test.answers(
    $$select * from onepass_test.rput(1, 0, 0, decode(repeat('00', 1048577), 'hex'))$$,
    'too_large', 'rdv_frame_over_1_mib_is_too_large');
select onepass_test.answers(
    $$select * from onepass_mailbox.rdv_get(onepass_test.sid(1), 3::smallint, 0, onepass_test.ip('ip'))$$,
    'malformed', 'rdv_get_dir_3_is_malformed');

reset role;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.rdv_sessions) and (select count(*) = 0 from onepass_mailbox.rdv_chunks),
    'refused_frames_wrote_nothing');
set local role onepass_mailbox_api;

-- A reader polls before the writer started: nothing yet, not an error.
select onepass_test.ok(
    (select status = 'ok' and data is null from onepass_test.rget(1, 0, 0)),
    'rdv_get_before_the_session_exists_is_empty');
select onepass_test.ok(
    (select status = 'ok' and retry_after is null from onepass_test.rput(1, 0, 0, '\x0a0b')),
    'rdv_put_of_a_frame_is_ok');
select onepass_test.ok(
    (select status = 'ok' and data = '\x0a0b' from onepass_test.rget(1, 0, 0)),
    'rdv_get_reads_the_frame');
select onepass_test.ok(
    (select status = 'ok' and data is null from onepass_test.rget(1, 0, 1))
    and (select status = 'ok' and data is null from onepass_test.rget(1, 1, 0)),
    'rdv_get_of_an_absent_frame_is_empty');
select onepass_test.ok(
    (select status = 'conflict' from onepass_test.rput(1, 0, 0, '\x0c')),
    'rdv_put_of_the_same_frame_again_is_a_conflict');
select onepass_test.ok(
    (select data = '\x0a0b' from onepass_test.rget(1, 0, 0)),
    'rdv_conflict_keeps_the_first_frame');
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(1, 1, 0, '\x0d'))
    and (select status = 'ok' from onepass_test.rput(1, 0, 1, '\x0e0e0e')),
    'rdv_frames_in_both_directions');
-- An empty frame is a frame.
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(1, 1, 1, '\x')) and (select data = '\x' from onepass_test.rget(1, 1, 1)),
    'rdv_empty_frame_is_a_frame');

reset role;
select onepass_test.ok(
    (select bytes_0 = 5 and bytes_1 = 1 and closed_at is null and created_at = now()
     from onepass_mailbox.rdv_sessions where session_id = onepass_test.sid(1)),
    'rdv_session_counts_bytes_per_direction');

-- --------------------------------------------------------- isolation

-- The owner, scoped to another session, sees none of session 1.
set local role onepass_mailbox_owner;
select set_config('onepass.rdv', encode(onepass_test.sid(2), 'hex'), true);
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.rdv_chunks) and (select count(*) = 0 from onepass_mailbox.rdv_sessions),
    'rdv_another_session_sees_nothing');
select set_config('onepass.rdv', encode(onepass_test.sid(1), 'hex'), true);
select onepass_test.ok(
    (select count(*) = 4 from onepass_mailbox.rdv_chunks),
    'rdv_its_own_session_sees_its_frames');
select set_config('onepass.rdv', '', true);
reset role;
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' and data is null from onepass_test.rget(2, 0, 0)),
    'rdv_get_of_another_session_returns_nothing');

-- -------------------------------------------------------- frame expiry

reset role;
update onepass_mailbox.rdv_chunks set written_at = now() - interval '121 seconds'
where session_id = onepass_test.sid(1) and dir = 0 and n = 0;
update onepass_mailbox.rdv_chunks set written_at = now() - interval '119 seconds'
where session_id = onepass_test.sid(1) and dir = 0 and n = 1;
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' and data is null from onepass_test.rget(1, 0, 0)),
    'rdv_frame_older_than_120_s_reads_as_absent');
select onepass_test.ok(
    (select data = '\x0e0e0e' from onepass_test.rget(1, 0, 1)),
    'rdv_frame_younger_than_120_s_is_read');

-- ------------------------------------------------- 66 MiB per direction

-- 66 MiB = 69 206 016 bytes. Session 3 has written 66 MiB toward the
-- approver: one more byte that way is refused, the other way is not.
select onepass_test.ok((select status = 'ok' from onepass_test.rput(3, 0, 0, '\x01')), 'rdv_session_3_started');
reset role;
update onepass_mailbox.rdv_sessions set bytes_0 = 69206016 - 1048576 where session_id = onepass_test.sid(3);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(3, 0, 1, decode(repeat('00', 1048576), 'hex'))),
    'rdv_66th_mib_of_a_direction_is_accepted');
select onepass_test.ok(
    (select status = 'too_large' from onepass_test.rput(3, 0, 2, '\x01')),
    'rdv_67th_mib_of_a_direction_is_refused');
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(3, 1, 0, decode(repeat('00', 1048576), 'hex'))),
    'rdv_other_direction_has_its_own_66_mib');
reset role;
select onepass_test.ok(
    (select bytes_0 = 69206016 and bytes_1 = 1048576 from onepass_mailbox.rdv_sessions where session_id = onepass_test.sid(3))
    and not exists (select 1 from onepass_mailbox.rdv_chunks where session_id = onepass_test.sid(3) and dir = 0 and n = 2),
    'rdv_refused_frame_wrote_nothing');

-- ------------------------------------------------------- session expiry

update onepass_mailbox.rdv_sessions set created_at = now() - interval '601 seconds' where session_id = onepass_test.sid(1);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'not_found' from onepass_test.rput(1, 0, 5, '\x01')),
    'rdv_put_into_a_session_older_than_600_s_is_not_found');
select onepass_test.ok(
    (select status = 'not_found' from onepass_test.rget(1, 0, 1)),
    'rdv_get_from_a_session_older_than_600_s_is_not_found');
reset role;
update onepass_mailbox.rdv_sessions set created_at = now() - interval '599 seconds' where session_id = onepass_test.sid(1);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(1, 0, 5, '\x01')),
    'rdv_put_into_a_session_younger_than_600_s_is_ok');

-- ---------------------------------------------------------------- close

select onepass_test.ok(
    (select status = 'ok' from onepass_mailbox.rdv_close(onepass_test.sid(1), onepass_test.ip('ip'))),
    'rdv_close_is_ok');
select onepass_test.ok(
    (select status = 'not_found' from onepass_test.rput(1, 0, 6, '\x01')),
    'rdv_put_after_close_is_not_found');
select onepass_test.ok(
    (select status = 'not_found' from onepass_test.rget(1, 0, 5)),
    'rdv_get_after_close_is_not_found');
select onepass_test.ok(
    (select status = 'ok' from onepass_mailbox.rdv_close(onepass_test.sid(1), onepass_test.ip('ip'))),
    'rdv_close_twice_is_ok');
-- Closing a session nobody started keeps it from starting.
select onepass_test.ok(
    (select status = 'ok' from onepass_mailbox.rdv_close(onepass_test.sid(4), onepass_test.ip('ip')))
    and (select status = 'not_found' from onepass_test.rput(4, 0, 0, '\x01')),
    'rdv_close_of_an_unknown_session_closes_it');
reset role;
select onepass_test.ok(
    (select closed_at = now() from onepass_mailbox.rdv_sessions where session_id = onepass_test.sid(1))
    and not exists (select 1 from onepass_mailbox.rdv_chunks where session_id = onepass_test.sid(1)),
    'rdv_close_drops_the_frames');

-- ------------------------------------------------------- per-IP limits

-- The minute bucket is the one of create and enroll (60 a minute on the raw
-- IP key): 60 hits already this minute, the next call is limited, and
-- counted.
update onepass_mailbox.rate set count = 60
where key = onepass_test.ip('ip') and window_start = date_trunc('minute', now(), 'UTC');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'rate_limited' and retry_after between 1 and 60 from onepass_test.rput(5, 0, 0, '\x01')),
    'rdv_put_over_the_minute_bucket_is_rate_limited');
select onepass_test.ok(
    (select status = 'rate_limited' from onepass_test.rget(5, 0, 0))
    and (select status = 'rate_limited' from onepass_mailbox.rdv_close(onepass_test.sid(5), onepass_test.ip('ip'))),
    'rdv_get_and_close_share_the_minute_bucket');
select onepass_test.ok(
    (select status = 'rate_limited' from onepass_mailbox.api_create_mailbox(
        onepass_test.ip('onepass-rdv-test-key'), onepass_test.nonce(1), now(), null, '\x',
        onepass_test.ip('ip'), true)),
    'rdv_and_create_share_the_minute_bucket');
-- A re-poll of a request already counted carries no IP key and is not limited.
select onepass_test.ok(
    (select status = 'ok' and data is null
     from onepass_mailbox.rdv_get(onepass_test.sid(5), 0::smallint, 0, null)),
    'rdv_get_repoll_without_ip_key_is_not_counted');
reset role;
select onepass_test.ok(
    (select count = 64 from onepass_mailbox.rate
     where key = onepass_test.ip('ip') and window_start = date_trunc('minute', now(), 'UTC'))
    and not exists (select 1 from onepass_mailbox.rdv_sessions where session_id = onepass_test.sid(5)),
    'rdv_limited_calls_are_counted_and_write_nothing_else');

-- 200 MiB an hour per IP key, on its own bucket (SHA-256 of SHA-256 of the
-- IP key, hour windows in UTC): 5 bytes left, a 6 byte frame is limited and
-- writes nothing, a 5 byte frame passes.
insert into onepass_mailbox.rate (key, window_start, count)
values (extensions.digest(extensions.digest(onepass_test.ip('ip2'), 'sha256'), 'sha256'),
        date_trunc('hour', now(), 'UTC'), 209715200 - 5);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'rate_limited' and retry_after between 1 and 3600
     from onepass_test.rput(6, 0, 0, '\x010203040506', 'ip2')),
    'rdv_bytes_over_200_mib_an_hour_are_rate_limited');
reset role;
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.rdv_sessions where session_id = onepass_test.sid(6)),
    'rdv_bytes_limited_frame_wrote_nothing');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.rput(6, 0, 0, '\x0102030405', 'ip2')),
    'rdv_bytes_within_200_mib_an_hour_pass');
reset role;
select onepass_test.ok(
    (select count = 209715200 from onepass_mailbox.rate
     where key = extensions.digest(extensions.digest(onepass_test.ip('ip2'), 'sha256'), 'sha256')
       and window_start = date_trunc('hour', now(), 'UTC')),
    'rdv_bytes_bucket_counts_the_frame');

-- ---------------------------------------------------------------- roles

select onepass_test.throws(
    $$set local role anon; select * from onepass_test.rput(7, 0, 0, '\x01')$$, '42501',
    'anon_cannot_put_a_frame');
select onepass_test.throws(
    $$set local role onepass_mailbox_janitor; select * from onepass_test.rget(7, 0, 0)$$, '42501',
    'janitor_cannot_read_a_frame');
