-- Invite drops of 72 hours (Task 25; sharing spec 13.9). Starts as the
-- harness superuser, inside a transaction the harness rolls back; calls run
-- as onepass_mailbox_api, state is read back (and the clock simulated by
-- moving expires_at back) as the superuser.

create function onepass_test.ip(name text) returns bytea language sql immutable as $$
    select decode(md5(name) || md5(name || '/'), 'hex') $$;
create function onepass_test.did(i integer) returns bytea language sql immutable as $$
    select onepass_test.nonce(2000000 + i) $$;
create function onepass_test.dput(d integer, slot integer, data bytea, ip text default 'ip')
returns text language sql volatile as $$
    select p.status from onepass_mailbox.drop_put(onepass_test.did(d), slot::smallint, data, onepass_test.ip(ip)) p $$;
create function onepass_test.dget(d integer, slot integer, ip text default 'ip')
returns table (status text, data bytea) language sql volatile as $$
    select g.status, g.data from onepass_mailbox.drop_get(onepass_test.did(d), slot::smallint, onepass_test.ip(ip)) g $$;
grant execute on all functions in schema onepass_test to public;

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_mailbox.drop_put(onepass_test.did(1), 0::smallint, '\x01', '\x0102')$$,
    'OP400', 'malformed', 'drop_put_with_malformed_ip_key_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.drop_get(onepass_test.did(1), 0::smallint, null)$$,
    'OP400', 'malformed', 'drop_get_without_ip_key_raises');

-- drop_written_once
select onepass_test.ok(onepass_test.dput(1, 0, '\x0a0b') = 'ok', 'drop_written_once_first_write');
select onepass_test.ok(onepass_test.dput(1, 0, '\x0c') = 'conflict', 'drop_written_once_second_write_conflict');
select onepass_test.ok((select data from onepass_test.dget(1, 0)) = '\x0a0b', 'drop_written_once_first_bytes_kept');
select onepass_test.ok(onepass_test.dput(1, 3, '\x03') = 'ok', 'drop_other_slot_written');

-- drop_slot_range
select onepass_test.ok(onepass_test.dput(2, 4, '\x01') = 'malformed', 'drop_slot_range_four_refused');
select onepass_test.ok(onepass_test.dput(2, -1, '\x01') = 'malformed', 'drop_slot_range_negative_refused');
select onepass_test.ok(
    (select status from onepass_mailbox.drop_put('\x0102', 0::smallint, '\x01', onepass_test.ip('ip'))) = 'malformed',
    'drop_short_id_refused');

-- drop_size_cap
select onepass_test.ok(onepass_test.dput(3, 0, convert_to(repeat('a', 65536), 'UTF8')) = 'ok', 'drop_size_cap_exact_ok');
select onepass_test.ok(onepass_test.dput(3, 1, convert_to(repeat('a', 65537), 'UTF8')) = 'too_large', 'drop_size_cap_over_refused');

-- drop_absent_is_not_found
select onepass_test.ok((select status from onepass_test.dget(4, 0)) = 'not_found', 'drop_absent_is_not_found');
select onepass_test.ok((select status from onepass_test.dget(1, 2)) = 'not_found', 'drop_unwritten_slot_is_not_found');

reset role;

-- One expiry for every slot: the first write's plus 72 hours.
select onepass_test.ok(
    (select bool_and(d.expires_at = h.expires_at and h.expires_at = h.created_at + interval '72 hours')
     from onepass_mailbox.drops d join onepass_mailbox.drop_heads h using (drop_id)
     where d.drop_id = onepass_test.did(1)),
    'drop_slots_share_the_first_write_deadline');

-- late_slot_after_expiry_refused: the deadline passes, a new slot is refused.
update onepass_mailbox.drop_heads set expires_at = now() - interval '1 second', created_at = now() - interval '72 hours 1 second'
where drop_id = onepass_test.did(1);
update onepass_mailbox.drops set expires_at = now() - interval '1 second' where drop_id = onepass_test.did(1);
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.dput(1, 1, '\x01') = 'not_found', 'late_slot_after_expiry_refused');
select onepass_test.ok((select status from onepass_test.dget(1, 0)) = 'not_found', 'expired_slot_not_readable');
reset role;

-- drop_expires_after_72h: maintenance 73 hours on drops every slot of drop 3,
-- keeps its head 7 more days, so a write never reopens it.
select onepass_mailbox.maintenance(now() + interval '73 hours');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.drops where drop_id in (onepass_test.did(1), onepass_test.did(3))),
    'drop_expires_after_72h');
select onepass_test.ok(
    exists (select 1 from onepass_mailbox.drop_heads where drop_id = onepass_test.did(3)),
    'drop_head_kept_after_expiry');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.dput(1, 2, '\x01') = 'not_found', 'purged_drop_never_reopens');
reset role;
select onepass_mailbox.maintenance(now() + interval '72 hours' + interval '8 days');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.drop_heads where drop_id = onepass_test.did(3)),
    'drop_head_purged_after_seven_days');

-- drop_delete closes the drop for good.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.dput(5, 0, '\x01', 'ip5') = 'ok', 'drop_delete_setup');
select onepass_test.ok(
    (select status from onepass_mailbox.drop_delete(onepass_test.did(5), onepass_test.ip('ip5'))) = 'ok', 'drop_delete_ok');
select onepass_test.ok((select status from onepass_test.dget(5, 0, 'ip5')) = 'not_found', 'deleted_drop_not_readable');
select onepass_test.ok(onepass_test.dput(5, 1, '\x01', 'ip5') = 'not_found', 'deleted_drop_not_writable');
select onepass_test.ok(
    (select status from onepass_mailbox.drop_delete(onepass_test.did(6), onepass_test.ip('ip5'))) = 'ok',
    'drop_delete_unknown_ok');
select onepass_test.ok(onepass_test.dput(6, 0, '\x01', 'ip5') = 'not_found', 'deleted_unopened_drop_never_opens');

-- RLS: under the owner, another drop id sees nothing.
reset role;
set local role onepass_mailbox_owner;
select set_config('onepass.drop', encode(onepass_test.did(99), 'hex'), true);
select onepass_test.ok((select count(*) from onepass_mailbox.drops) = 0, 'drop_rls_other_id_sees_nothing');
select onepass_test.ok((select count(*) from onepass_mailbox.drop_heads) = 0, 'drop_heads_rls_other_id_sees_nothing');
select set_config('onepass.drop', '', true);
reset role;

-- drop_rate_per_ip_per_day: 50 writes a day per IP key, then rate_limited
-- with retry_after. The minute bucket (60) is not reached first.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.dput(100 + i, 0, '\x01', 'rate') = 'ok') from generate_series(1, 50) i),
    'drop_rate_fifty_writes_ok');
select onepass_test.ok(
    (select status = 'rate_limited' and retry_after > 0
     from onepass_mailbox.drop_put(onepass_test.did(151), 0::smallint, '\x01', onepass_test.ip('rate'))),
    'drop_rate_per_ip_per_day');
select onepass_test.ok(onepass_test.dput(151, 0, '\x01', 'other') = 'ok', 'drop_rate_other_ip_unaffected');
-- The minute bucket is shared with the rendezvous: the 61st call of the
-- minute from one IP key is refused whatever the route.
-- 51 calls so far; 52 to 59 here.
select onepass_test.ok(
    (select bool_and(g.status = 'not_found') from generate_series(52, 59) i,
         lateral onepass_test.dget(1, 0 * i, 'rate') g),
    'drop_minute_bucket_calls_to_59');
select onepass_test.ok(
    (select status from onepass_mailbox.rdv_get(onepass_test.nonce(1), 0::smallint, 0, onepass_test.ip('rate'))) = 'ok',
    'drop_minute_bucket_call_60_on_rdv');
select onepass_test.ok(
    (select status from onepass_test.dget(1, 0, 'rate')) = 'rate_limited', 'drop_minute_bucket_shared_with_rdv');
reset role;
