-- Authenticated SQL entry points and reads (spec 4.5, 4.6, 4.9, 4.12).
-- Starts as the harness superuser, inside a transaction the harness rolls
-- back; every call under test runs as onepass_mailbox_api. now() is fixed for
-- the whole transaction, so time windows (skew, rate minute, day) are exact.

-- Fixtures, readable by the api role.
create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea, incarnation bigint, wake_topic bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-test-key/' || n, 'sha256') as pk
      from unnest(array['a', 'a2', 'a3', 'b', 'e', 'f', 'r', 'o', 'dup', 'n0', 'n1', 'n2', 'n3', 'n4', 'n5',
                        'q0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6'])
          as n
      union all
      select 'q' || i, extensions.digest('onepass-test-key/q' || i, 'sha256') from generate_series(1, 17) i
      union all
      select 'c' || i, extensions.digest('onepass-test-key/c' || i, 'sha256') from generate_series(1, 6) i) k;

create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.ip(text) returns bytea language sql immutable as $$ select decode(md5($1) || md5($1 || '/'), 'hex') $$;
-- One authenticated read with a fresh nonce: the probe for the auth checks.
create function onepass_test.info(cred text, mbx text) returns bigint language sql volatile as $$
    select incarnation from onepass_mailbox.api_mailbox_info(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx))
$$;
create function onepass_test.open(name text, key text, ip text) returns void language sql volatile as $$
    insert into t_mbx (name, id, incarnation, wake_topic)
    select name, c.mailbox_id, c.incarnation, c.wake_topic
    from onepass_mailbox.api_create_mailbox(onepass_test.pk(key), onepass_test.n(), now(), null, '\x', onepass_test.ip(ip), true) c
$$;
grant execute on all functions in schema onepass_test to public;

insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at) values
    (extensions.digest('inv-ok', 'sha256'), 'free', 3, now() + interval '1 day'),
    (extensions.digest('inv-zero', 'sha256'), 'free', 0, now() + interval '1 day'),
    (extensions.digest('inv-expired', 'sha256'), 'free', 5, now() - interval '1 second');

-- ------------------------------------------------------------ creation

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), null, '\x', onepass_test.ip('ip-a'), false)$$,
    'OP400', 'malformed', 'create_without_invite_when_closed_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), 'inv-unknown', '\x', onepass_test.ip('ip-a'), false)$$,
    'OP404', 'not_found', 'create_with_unknown_invite_is_not_found');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), 'inv-zero', '\x', onepass_test.ip('ip-a'), false)$$,
    'OP404', 'not_found', 'create_with_used_up_invite_is_not_found');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), 'inv-expired', '\x', onepass_test.ip('ip-a'), false)$$,
    'OP404', 'not_found', 'create_with_expired_invite_is_not_found');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now() - interval '301 seconds', 'inv-ok', '\x', onepass_test.ip('ip-a'), false)$$,
    'OP401', 'stale_request', 'create_stale_is_refused');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), 'inv-ok', decode(repeat('00', 65), 'hex'), onepass_test.ip('ip-a'), false)$$,
    'OP400', 'malformed', 'create_label_over_64_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_create_mailbox('\x0102', onepass_test.n(), now(), 'inv-ok', '\x', onepass_test.ip('ip-a'), false)$$,
    'OP400', 'malformed', 'create_short_key_is_malformed');

insert into t_mbx (name, id, incarnation, wake_topic)
select 'A', c.mailbox_id, c.incarnation, c.wake_topic
from onepass_mailbox.api_create_mailbox(onepass_test.pk('a'), onepass_test.n(), now(), 'inv-ok', '\x0a0b', onepass_test.ip('ip-a'), false) c;

reset role;

select onepass_test.ok((select uses_left from onepass_mailbox.invites where token_hash = extensions.digest('inv-ok', 'sha256')) = 2,
    'create_with_invite_decrements_uses_left');
select onepass_test.ok(
    (select m.plan = 'free' and m.incarnation = t.incarnation and m.wake_topic = t.wake_topic and not m.frozen
            and m.next_seq = 1 and m.min_cursor = 0
     from onepass_mailbox.mailboxes m join t_mbx t on t.id = m.id where t.name = 'A'),
    'create_with_invite_takes_the_invite_plan');
select onepass_test.ok(
    (select c.mailbox_id = onepass_test.mbx('A') and c.enrolled_by is null and c.revoked_at is null
            and c.public_key = onepass_test.pk('a') and c.label = '\x0a0b'
     from onepass_mailbox.credentials c where c.id = onepass_test.cid('a')),
    'create_enrolls_the_first_credential');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.nonces where credential_id = onepass_test.cid('a')) = 1,
    'create_stores_the_nonce_under_the_new_credential');

set local role onepass_mailbox_api;

-- Open signup: no invite, plan selfhost.
select onepass_test.open('B', 'b', 'ip-b');
reset role;
select onepass_test.ok(
    (select plan from onepass_mailbox.mailboxes where id = onepass_test.mbx('B')) = 'selfhost',
    'open_signup_creates_without_invite_on_selfhost');
set local role onepass_mailbox_api;

-- Five creations a day per IP key, the sixth is refused.
select onepass_test.open('C' || i, 'c' || i, 'ip-six') from generate_series(1, 5) i;
select onepass_test.raises(
    $$select onepass_test.open('C6', 'c6', 'ip-six')$$,
    'OP429', 'rate_limited', 'sixth_creation_of_the_day_per_ip_is_rate_limited');
do $$
declare
    d text;
begin
    perform onepass_test.open('C6', 'c6', 'ip-six');
exception when others then
    get stacked diagnostics d = pg_exception_detail;
    perform onepass_test.ok(d ~ '^[0-9]+$' and d::int between 1 and 86400, 'rate_limited_carries_retry_after');
end
$$;
select onepass_test.open('C6', 'c6', 'ip-other');
select onepass_test.ok((select count(*) from t_mbx where name = 'C6') = 1, 'other_ip_key_still_creates');

-- A key already enrolled anywhere cannot open a second mailbox; the error
-- says nothing about where.
select onepass_test.raises(
    $$select onepass_test.open('A2', 'a', 'ip-dup')$$,
    'OP400', 'malformed', 'create_with_enrolled_key_is_malformed');

-- Small-order and non-canonical Ed25519 encodings are refused.
select onepass_test.raises(
    format('select * from onepass_mailbox.api_create_mailbox(%L, onepass_test.n(), now(), null, %L, onepass_test.ip(%L), true)',
           decode(k, 'hex'), '\x', 'ip-weak-' || k),
    'OP400', 'malformed', 'create_refuses_weak_key_' || left(k, 4) || right(k, 2))
from unnest(array[
    '0100000000000000000000000000000000000000000000000000000000000000',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    '0100000000000000000000000000000000000000000000000000000000000080',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff']) k;

-- Mailboxes for the rest of the file.
select onepass_test.open('E', 'e', 'ip-e');
select onepass_test.open('F', 'f', 'ip-f');
select onepass_test.open('R', 'r', 'ip-r');
select onepass_test.open('N', 'n0', 'ip-n');
select onepass_test.open('Q', 'q0', 'ip-q');
select onepass_test.open('O', 'o', 'ip-o');

reset role;
-- Q and R are on the free plan (16 credentials, 120 requests a minute), like A.
update onepass_mailbox.mailboxes set plan = 'free' where id in (onepass_test.mbx('Q'), onepass_test.mbx('R'));
-- A second and a revoked credential in A, frozen F.
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, enrolled_by)
values (onepass_test.cid('a2'), onepass_test.mbx('A'), onepass_test.pk('a2'), onepass_test.cid('a'));
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, enrolled_by, revoked_at)
values (onepass_test.cid('a3'), onepass_test.mbx('A'), onepass_test.pk('a3'), onepass_test.cid('a'), now());
update onepass_mailbox.mailboxes set frozen = true where id = onepass_test.mbx('F');

select onepass_test.ok(
    exists (select 1 from pg_constraint
            where conrelid = 'onepass_mailbox.credentials'::regclass and contype = 'u'
              and conkey = array[(select attnum from pg_attribute where attrelid = 'onepass_mailbox.credentials'::regclass and attname = 'mailbox_id'),
                                 (select attnum from pg_attribute where attrelid = 'onepass_mailbox.credentials'::regclass and attname = 'id')]::int2[]),
    'credentials_unique_mailbox_and_id');
select onepass_test.throws(
    $$insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
      values (onepass_test.cid('a'), onepass_test.mbx('B'), onepass_test.n())$$,
    '23503', 'nonce_cannot_pair_a_credential_with_another_mailbox');
select onepass_test.throws(
    $$insert into onepass_mailbox.credentials (id, mailbox_id, public_key)
      values (substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || decode(repeat('00', 32), 'hex'), 'sha256') from 1 for 16),
              onepass_test.mbx('B'), decode(repeat('00', 32), 'hex'))$$,
    '23514', 'credentials_refuse_weak_keys_by_constraint');

-- ----------------------------------------------------- authentication

set local role onepass_mailbox_api;

select onepass_test.ok(
    (select mailbox_id = onepass_test.mbx('A') and public_key = onepass_test.pk('a') and not revoked
     from onepass_mailbox.credential_key(onepass_test.mbx('A'), onepass_test.cid('a'))),
    'credential_key_reads_the_key_in_the_path_mailbox');
select onepass_test.ok(
    (select revoked from onepass_mailbox.credential_key(onepass_test.mbx('A'), onepass_test.cid('a3'))),
    'credential_key_flags_a_revoked_credential');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.credential_key(onepass_test.mbx('B'), onepass_test.cid('a'))) = 0,
    'credential_key_finds_nothing_across_mailboxes');
select onepass_test.raises(
    $$select * from onepass_mailbox.credential_key('\x01', onepass_test.cid('a'))$$,
    'OP400', 'malformed', 'credential_key_short_mailbox_is_malformed');

-- Replay: same nonce twice under one credential; the same nonce under
-- another credential is a different request.
select onepass_test.ok(
    (select count(*) from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.nonce(9000001), now(), onepass_test.mbx('A'))) = 1,
    'first_use_of_a_nonce_is_accepted');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.nonce(9000001), now(), onepass_test.mbx('A'))$$,
    'OP401', 'replay', 'second_use_of_a_nonce_is_replay');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.api_mailbox_info(onepass_test.cid('a2'), onepass_test.nonce(9000001), now(), onepass_test.mbx('A'))) = 1,
    'same_nonce_under_another_credential_is_accepted');

-- Clock skew: 300 s either way passes, 301 s does not.
select onepass_test.ok(
    (select count(*) from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), now() - interval '300 seconds', onepass_test.mbx('A'))) = 1,
    'created_300s_ago_is_accepted');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), now() + interval '300 seconds', onepass_test.mbx('A'))) = 1,
    'created_300s_ahead_is_accepted');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), now() - interval '301 seconds', onepass_test.mbx('A'))$$,
    'OP401', 'stale_request', 'created_301s_ago_is_stale');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), now() + interval '301 seconds', onepass_test.mbx('A'))$$,
    'OP401', 'stale_request', 'created_301s_ahead_is_stale');

select onepass_test.raises($$select onepass_test.info('b', 'A')$$,
    'OP403', 'unknown_credential', 'credential_of_another_mailbox_is_unknown');
select onepass_test.raises($$select onepass_test.info('a3', 'A')$$,
    'OP403', 'revoked_credential', 'revoked_credential_is_refused');
select onepass_test.raises($$select onepass_test.info('f', 'F')$$,
    'OP403', 'frozen', 'frozen_mailbox_is_refused');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), '\x01', now(), onepass_test.mbx('A'))$$,
    'OP400', 'malformed', 'short_nonce_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), null, onepass_test.mbx('A'))$$,
    'OP400', 'malformed', 'missing_created_is_malformed');

-- 120 requests a minute on free; the 121st is refused.
select onepass_test.ok((select count(onepass_test.info('r', 'R')) from generate_series(1, 120)) = 120,
    'free_credential_gets_120_requests_a_minute');
select onepass_test.raises($$select onepass_test.info('r', 'R')$$,
    'OP429', 'rate_limited', 'request_121_of_the_minute_is_rate_limited');

-- The api role cannot widen its view by presetting the context: every entry
-- point overwrites it before touching a table.
reset role;
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data) values
    (onepass_test.mbx('B'), 1, decode(repeat('b5', 16), 'hex'), 1, 1, false, 1, '\x0b');
update onepass_mailbox.mailboxes set next_seq = 2 where id = onepass_test.mbx('B');
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data) values
    (onepass_test.mbx('O'), 1, decode(repeat('0a', 16), 'hex'), 1, 1, false, 1, '\x0a');
update onepass_mailbox.mailboxes set next_seq = 2 where id = onepass_test.mbx('O');
set local role onepass_mailbox_api;

select set_config('onepass.mailbox', encode(onepass_test.mbx('B'), 'hex'), false);
select set_config('onepass.maintenance', 'on', false);
select set_config('onepass.invite', repeat('ab', 32), false);
select onepass_test.raises(
    $$select * from onepass_mailbox.api_changes(onepass_test.cid('o'), onepass_test.n(), now(), onepass_test.mbx('B'), 0, 100)$$,
    'OP403', 'unknown_credential', 'preset_context_for_b_with_a_credential_of_o_is_refused');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('o'), onepass_test.n(), now(), onepass_test.mbx('B'), 1::smallint, decode(repeat('b5', 16), 'hex'))$$,
    'OP403', 'unknown_credential', 'preset_context_record_of_b_is_refused');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.credential_key(onepass_test.mbx('O'), onepass_test.cid('b'))) = 0,
    'preset_context_credential_key_stays_in_the_path_mailbox');
select onepass_test.ok(
    (select array_agg(c.data order by c.seq)
     from onepass_mailbox.api_changes(onepass_test.cid('o'), onepass_test.n(), now(), onepass_test.mbx('O'), 0, 100) c) = array['\x0a'::bytea],
    'preset_context_for_b_reads_only_the_authenticated_mailbox');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('o'), onepass_test.n(), now(), onepass_test.mbx('O'), 1::smallint, decode(repeat('b5', 16), 'hex'))$$,
    'OP404', 'not_found', 'preset_context_record_of_b_through_o_is_not_found');
select onepass_test.ok(
    current_setting('onepass.mailbox') = encode(onepass_test.mbx('O'), 'hex')
    and current_setting('onepass.maintenance') = ''
    and current_setting('onepass.invite') = '',
    'entry_points_overwrite_the_context');
select onepass_test.throws($$select * from onepass_mailbox.records$$, '42501', 'api_role_reads_no_table');
select onepass_test.throws(
    $$select onepass_mailbox._authenticate(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'))$$,
    '42501', 'api_role_cannot_call_the_private_authenticate');
select set_config('onepass.mailbox', '', false);
select set_config('onepass.maintenance', '', false);
select set_config('onepass.invite', '', false);

-- ------------------------------------------------------------ info

select onepass_test.ok(
    (select i.incarnation = t.incarnation and i.wake_topic = t.wake_topic and i.min_cursor = 0
            and i.max_bytes = 268435456 and i.max_records = 100000 and i.max_credentials = 16
            and i.req_per_min = 120 and i.max_commit_ops = 20000
            and i.bytes_used = 0 and i.records_count = 0 and i.credentials_count = 2
     from onepass_mailbox.api_mailbox_info(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A')) i, t_mbx t
     where t.name = 'A'),
    'mailbox_info_returns_limits_and_active_credentials');

-- ----------------------------------------------------------- changes

select onepass_test.ok(
    (select count(*) = 1 and bool_and(c.seq is null and c.kind is null and c.id is null)
            and min(c.incarnation) = (select incarnation from t_mbx where name = 'E') and min(c.min_cursor) = 0
     from onepass_mailbox.api_changes(onepass_test.cid('e'), onepass_test.n(), now(), onepass_test.mbx('E'), 0, 1000) c),
    'changes_on_empty_mailbox_is_one_row_without_seq');

reset role;
-- A: live 1, 2, 4, 5; tombstones 3, 6.
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, deleted_at, size, data)
select onepass_test.mbx('A'), 1, decode(lpad(to_hex(s), 32, '0'), 'hex'), 10 + s, s,
       s in (3, 6), case when s in (3, 6) then now() end,
       case when s in (3, 6) then 0 else 1 end, case when s in (3, 6) then null else '\x01'::bytea end
from generate_series(1, 6) s;
update onepass_mailbox.mailboxes set next_seq = 7 where id = onepass_test.mbx('A');
set local role onepass_mailbox_api;

select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[1, 2, 4, 5]::bigint[] and not bool_or(c.deleted)
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 1000) c),
    'changes_after_0_returns_live_rows_only');
select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[6]::bigint[] and bool_and(c.deleted and c.data is null and c.size = 0)
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 5, 1000) c),
    'changes_after_5_returns_the_tombstone');
select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[3, 4]::bigint[]
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 2, 2) c),
    'changes_respects_the_limit_in_seq_order');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(c.seq is null)
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 6, 1000) c),
    'changes_past_the_end_is_one_row_without_seq');
select onepass_test.ok(
    (select bool_and(c.version = 10 + c.seq and c.kind = 1 and c.incarnation = (select incarnation from t_mbx where name = 'A'))
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 1000) c),
    'changes_rows_carry_version_kind_and_incarnation');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), -1, 10)$$,
    'OP400', 'malformed', 'changes_negative_after_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 0)$$,
    'OP400', 'malformed', 'changes_zero_limit_is_malformed');

reset role;
update onepass_mailbox.mailboxes set min_cursor = 3 where id = onepass_test.mbx('A');
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select * from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 2, 10)$$,
    'OP410', 'cursor_expired', 'changes_after_below_min_cursor_is_expired');
select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[4, 5, 6]::bigint[] and bool_and(c.min_cursor = 3)
     from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 3, 10) c),
    'changes_after_equal_to_min_cursor_is_served');
select onepass_test.ok(
    (select count(*) = 4 from onepass_mailbox.api_changes(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 10) c),
    'changes_after_0_ignores_min_cursor');

-- Page caps: 1 000 rows, 4 MiB of inline data.
reset role;
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
select onepass_test.mbx('B'), 2, decode(lpad(to_hex(s), 32, '0'), 'hex'), 1, s, false, 1, '\x02'
from generate_series(2, 1201) s;
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
select onepass_test.mbx('E'), 2, decode(lpad(to_hex(s), 32, '0'), 'hex'), 1, s, false, 16384, decode(repeat('ee', 16384), 'hex')
from generate_series(1, 300) s;
update onepass_mailbox.mailboxes set next_seq = 1202 where id = onepass_test.mbx('B');
update onepass_mailbox.mailboxes set next_seq = 301 where id = onepass_test.mbx('E');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 1000 and max(c.seq) = 1000
     from onepass_mailbox.api_changes(onepass_test.cid('b'), onepass_test.n(), now(), onepass_test.mbx('B'), 0, 5000) c),
    'changes_limit_is_capped_at_1000');
select onepass_test.ok(
    (select count(*) = 256 and sum(octet_length(c.data)) = 4194304 and max(c.seq) = 256
     from onepass_mailbox.api_changes(onepass_test.cid('e'), onepass_test.n(), now(), onepass_test.mbx('E'), 0, 1000) c),
    'changes_page_is_cut_at_4_mib_of_data');

-- ------------------------------------------------------------ record

select onepass_test.ok(
    (select r.seq = 2 and r.version = 12 and not r.deleted and r.data = '\x01' and r.size = 1 and r.blob_sha256 is null
     from onepass_mailbox.api_record(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, decode(lpad(to_hex(2), 32, '0'), 'hex')) r),
    'record_reads_a_live_row');
select onepass_test.ok(
    (select r.seq = 3 and r.deleted and r.data is null
     from onepass_mailbox.api_record(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, decode(lpad(to_hex(3), 32, '0'), 'hex')) r),
    'record_reads_a_tombstone');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 2::smallint, decode(lpad(to_hex(2), 32, '0'), 'hex'))$$,
    'OP404', 'not_found', 'record_missing_is_not_found');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0::smallint, decode(lpad(to_hex(2), 32, '0'), 'hex'))$$,
    'OP400', 'malformed', 'record_kind_0_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, '\x02')$$,
    'OP400', 'malformed', 'record_short_id_is_malformed');

-- ------------------------------------------------------------ enroll

reset role;
create function onepass_test.enroll(key text, mbx text, approver text, ticket text, expires timestamptz default now() + interval '600 seconds')
returns bytea language sql volatile as $$
    select e.credential_id from onepass_mailbox.api_enroll(
        onepass_test.pk(key), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(approver),
        decode(md5(ticket) || md5(ticket || '/'), 'hex'), expires, '\x', onepass_test.ip('ip-enroll-' || mbx)) e
$$;
grant execute on function onepass_test.enroll(text, text, text, text, timestamptz) to public;
set local role onepass_mailbox_api;

select onepass_test.ok(onepass_test.enroll('n1', 'N', 'n0', 't1') = onepass_test.cid('n1'), 'enroll_returns_the_new_credential_id');
reset role;
select onepass_test.ok(
    (select c.mailbox_id = onepass_test.mbx('N') and c.enrolled_by = onepass_test.cid('n0') and c.revoked_at is null
     from onepass_mailbox.credentials c where c.id = onepass_test.cid('n1')),
    'enroll_records_the_approver');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.nonces where credential_id = onepass_test.cid('n1')) = 1,
    'enroll_stores_the_nonce_under_the_new_credential');
select onepass_test.ok(
    exists (select 1 from onepass_mailbox.used_tickets where ticket_hash = decode(md5('t1') || md5('t1/'), 'hex') and mailbox_id = onepass_test.mbx('N')),
    'enroll_marks_the_ticket_used');
set local role onepass_mailbox_api;

select onepass_test.raises($$select onepass_test.enroll('n2', 'N', 'n0', 't1')$$,
    'OP401', 'replay', 'enroll_replayed_ticket_is_refused');
select onepass_test.raises($$select onepass_test.enroll('n2', 'N', 'n0', 't2', now() - interval '1 second')$$,
    'OP401', 'stale_request', 'enroll_expired_ticket_is_refused');
select onepass_test.raises($$select onepass_test.enroll('n2', 'N', 'n0', 't2', now() + interval '901 seconds')$$,
    'OP400', 'malformed', 'enroll_ticket_living_too_long_is_malformed');
select onepass_test.ok(onepass_test.enroll('n2', 'N', 'n0', 't2', now()) = onepass_test.cid('n2'), 'enroll_ticket_expiring_now_is_accepted');
select onepass_test.raises($$select onepass_test.enroll('n1', 'N', 'n0', 't3')$$,
    'OP401', 'replay', 'enroll_already_enrolled_key_is_replay');
select onepass_test.raises($$select onepass_test.enroll('a', 'N', 'n0', 't3')$$,
    'OP400', 'malformed', 'enroll_key_of_another_mailbox_is_malformed');
select onepass_test.raises($$select onepass_test.enroll('n3', 'N', 'a', 't3')$$,
    'OP403', 'unknown_credential', 'enroll_approver_of_another_mailbox_is_unknown');
select onepass_test.raises($$select onepass_test.enroll('n3', 'A', 'a3', 't3')$$,
    'OP403', 'revoked_credential', 'enroll_revoked_approver_is_refused');
select onepass_test.raises($$select onepass_test.enroll('n3', 'F', 'f', 't3')$$,
    'OP403', 'frozen', 'enroll_into_frozen_mailbox_is_refused');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_enroll(onepass_test.pk('n3'), onepass_test.n(), now(), decode(repeat('99', 16), 'hex'),
        onepass_test.cid('n0'), decode(repeat('98', 32), 'hex'), now() + interval '60 seconds', '\x', onepass_test.ip('x'))$$,
    'OP404', 'not_found', 'enroll_into_unknown_mailbox_is_not_found');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_enroll(decode(repeat('00', 32), 'hex'), onepass_test.n(), now(), onepass_test.mbx('N'),
        onepass_test.cid('n0'), decode(repeat('97', 32), 'hex'), now() + interval '60 seconds', '\x', onepass_test.ip('x'))$$,
    'OP400', 'malformed', 'enroll_weak_key_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_enroll(onepass_test.pk('n3'), onepass_test.n(), now() - interval '301 seconds', onepass_test.mbx('N'),
        onepass_test.cid('n0'), decode(repeat('96', 32), 'hex'), now() + interval '60 seconds', '\x', onepass_test.ip('x'))$$,
    'OP401', 'stale_request', 'enroll_stale_request_is_refused');

-- Sixteen active credentials on free: the seventeenth is a quota error; a
-- revoked one frees its place.
select onepass_test.enroll('q' || i, 'Q', 'q0', 'tq' || i) from generate_series(1, 15) i;
select onepass_test.raises($$select onepass_test.enroll('q16', 'Q', 'q0', 'tq16')$$,
    'OP422', 'quota', 'enroll_seventeenth_credential_on_free_is_quota');
select onepass_mailbox.api_revoke_credential(onepass_test.cid('q0'), onepass_test.n(), now(), onepass_test.mbx('Q'), onepass_test.cid('q15'));
select onepass_test.ok(onepass_test.enroll('q16', 'Q', 'q0', 'tq16b') = onepass_test.cid('q16'), 'enroll_after_a_revoke_fits_again');

-- ------------------------------------------------------------ revoke, push

select onepass_test.raises(
    $$select onepass_mailbox.api_revoke_credential(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), onepass_test.cid('b'))$$,
    'OP404', 'not_found', 'revoke_credential_of_another_mailbox_is_not_found');
reset role;
select onepass_test.ok(
    (select revoked_at is null from onepass_mailbox.credentials where id = onepass_test.cid('b')),
    'revoke_across_mailboxes_has_no_effect');
set local role onepass_mailbox_api;

select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 2::smallint, '\xa1a2');
reset role;
select onepass_test.ok(
    (select push_kind = 2 and push_token = '\xa1a2' from onepass_mailbox.credentials where id = onepass_test.cid('a2')),
    'set_push_stores_kind_and_token');
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, '\x')$$,
    'OP400', 'malformed', 'set_push_kind_with_empty_token_is_malformed');
select onepass_test.raises(
    $$select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, null)$$,
    'OP400', 'malformed', 'set_push_kind_with_null_token_is_malformed');
select onepass_test.raises(
    $$select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 0::smallint, '\x01')$$,
    'OP400', 'malformed', 'set_push_none_with_token_is_malformed');
select onepass_test.raises(
    $$select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 4::smallint, '\x01')$$,
    'OP400', 'malformed', 'set_push_unknown_kind_is_malformed');
select onepass_test.raises(
    $$select onepass_mailbox.api_set_push(onepass_test.cid('a2'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, decode(repeat('01', 4097), 'hex'))$$,
    'OP400', 'malformed', 'set_push_token_over_4096_is_malformed');

select onepass_mailbox.api_revoke_credential(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), onepass_test.cid('a2'));
reset role;
select onepass_test.ok(
    (select revoked_at = now() and push_kind is null and push_token is null from onepass_mailbox.credentials where id = onepass_test.cid('a2')),
    'revoke_sets_revoked_at_and_clears_the_push_token');
set local role onepass_mailbox_api;
select onepass_test.raises($$select onepass_test.info('a2', 'A')$$,
    'OP403', 'revoked_credential', 'revoked_credential_can_no_longer_read');
select onepass_mailbox.api_revoke_credential(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), onepass_test.cid('a2'));
select onepass_test.ok(true, 'revoking_twice_is_a_no_op');

reset role;
update onepass_mailbox.credentials set last_used_at = now() - interval '1 day' where id = onepass_test.cid('a');
set local role onepass_mailbox_api;
select onepass_mailbox.api_set_push(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 1::smallint, '\x01');
select onepass_mailbox.api_set_push(onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('A'), 0::smallint, '\x');
reset role;
select onepass_test.ok(
    (select push_kind is null and push_token is null from onepass_mailbox.credentials where id = onepass_test.cid('a')),
    'set_push_none_clears_the_token');
select onepass_test.ok(
    (select last_used_at = now() from onepass_mailbox.credentials where id = onepass_test.cid('a')),
    'authenticated_calls_touch_last_used_at');
