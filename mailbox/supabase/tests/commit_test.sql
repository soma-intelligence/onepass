-- Atomic conditional commit (spec 4.5, 4.6, 4.9, 4.10).
-- Starts as the harness superuser, inside a transaction the harness rolls
-- back; calls under test run as onepass_mailbox_api, state is read back as
-- the superuser (which row level security does not bind). now() is fixed
-- for the whole transaction.
--
-- Contract under test: authentication refusals raise; every other outcome
-- is in band (`status`): 'ok' (one row per operation, in the order sent),
-- 'conflict' (one row per conflicting key, with the current server row),
-- or one row 'malformed', 'too_large', 'quota', 'rate_limited'. A refused
-- batch writes no record and consumes no seq; its nonce and rate hit stay.
-- Concurrent sessions: mailbox/scripts/commit-race.sh.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea, wake_topic bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-commit-test-key/' || n, 'sha256') as pk
      from unnest(array['a', 'a2', 'b', 'f', 'q', 's', 'r', 'k', 'c']) as n) k;

create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
-- A record id from a number.
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
-- A commit with a fresh nonce.
create function onepass_test.commit(
    cred text, mbx text, kinds smallint[], ids bytea[], versions bigint[], ops smallint[],
    expected bigint[], data bytea[], blob_sha bytea[], sizes integer[])
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        kinds, ids, versions, ops, expected, data, blob_sha, sizes)
$$;
-- One inline put of `body` on (kind 1, rid(i)), version v.
create function onepass_test.put(cred text, mbx text, i integer, expected bigint, body bytea, v bigint default 1)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.commit(cred, mbx, array[1]::smallint[], array[onepass_test.rid(i)], array[v],
        array[1]::smallint[], array[expected], array[body], array[null]::bytea[], array[octet_length(body)])
$$;
-- One delete of (kind 1, rid(i)).
create function onepass_test.del(cred text, mbx text, i integer, v bigint default 9)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.commit(cred, mbx, array[1]::smallint[], array[onepass_test.rid(i)], array[v],
        array[2]::smallint[], array[null]::bigint[], array[null]::bytea[], array[null]::bytea[], array[null]::integer[])
$$;
grant execute on all functions in schema onepass_test to public;

-- Fixture state, read as the superuser.
create function onepass_test.next_seq(mbx text) returns bigint language sql stable as $$
    select next_seq from onepass_mailbox.mailboxes where id = onepass_test.mbx(mbx) $$;
create function onepass_test.nrec(mbx text) returns bigint language sql stable as $$
    select count(*) from onepass_mailbox.records where mailbox_id = onepass_test.mbx(mbx) $$;
create function onepass_test.nonces(cred text) returns bigint language sql stable as $$
    select count(*) from onepass_mailbox.nonces where credential_id = onepass_test.cid(cred) $$;
revoke all on function onepass_test.next_seq(text), onepass_test.nrec(text), onepass_test.nonces(text) from public;

-- Mailboxes: A (selfhost, credentials a and a2), B (another tenant), F
-- (frozen), Q (tiny quotas), S (slow: 3 requests a minute), R (100 random
-- batches).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(m, k) = 'ok')
     from (values ('A', 'a'), ('B', 'b'), ('F', 'f'), ('Q', 'q'), ('S', 's'), ('R', 'r'), ('K', 'k'), ('C', 'c')) v (m, k)),
    'commit_fixture_mailboxes_created');
reset role;

insert into onepass_mailbox.credentials (id, mailbox_id, public_key, enrolled_by)
select cid, onepass_test.mbx('A'), pk, onepass_test.cid('a') from t_keys where name = 'a2';
update onepass_mailbox.mailboxes set frozen = true where id = onepass_test.mbx('F');
set local onepass.maintenance = 'on';
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('t_tiny', 100, 3, 4, 1000, 4), ('t_slow', 1000000, 1000, 4, 3, 20000);
reset onepass.maintenance;
update onepass_mailbox.mailboxes set plan = 't_tiny' where id = onepass_test.mbx('Q');
update onepass_mailbox.mailboxes set plan = 't_slow' where id = onepass_test.mbx('S');
-- C churns on the free plan (100 000 records, 120 requests a minute).
update onepass_mailbox.mailboxes set plan = 'free' where id = onepass_test.mbx('C');

-- ------------------------------------------------------- authentication

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_test.put('a', 'B', 1, null, '\x01')$$,
    'OP403', 'unknown_credential', 'commit_with_credential_of_another_mailbox_raises');
select onepass_test.raises(
    $$select * from onepass_test.put('f', 'F', 1, null, '\x01')$$,
    'OP403', 'frozen', 'commit_into_frozen_mailbox_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_commit(onepass_test.cid('a'), onepass_test.n(), now() - interval '301 seconds',
        onepass_test.mbx('A'), array[1]::smallint[], array[onepass_test.rid(1)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01']::bytea[], array[null]::bytea[], array[1])$$,
    'OP401', 'stale_request', 'stale_commit_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_commit(onepass_test.cid('a'), onepass_test.nonce(1), now(),
        onepass_test.mbx('A'), array[1]::smallint[], array[onepass_test.rid(1)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01']::bytea[], array[null]::bytea[], array[1])$$,
    'OP401', 'replay', 'replayed_commit_nonce_raises');

-- ------------------------------------------------------------- shapes

select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', array[1, 1]::smallint[], array[onepass_test.rid(1)], array[1]::bigint[],
        array[1]::smallint[], array[null]::bigint[], array['\x01']::bytea[], array[null]::bytea[], array[1])$$,
    'malformed', 'arrays_of_different_lengths_are_malformed');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', '{}'::smallint[], '{}'::bytea[], '{}'::bigint[], '{}'::smallint[],
        '{}'::bigint[], '{}'::bytea[], '{}'::bytea[], '{}'::integer[])$$,
    'malformed', 'empty_batch_is_malformed');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', null, array[onepass_test.rid(1)], array[1]::bigint[],
        array[1]::smallint[], array[null]::bigint[], array['\x01']::bytea[], array[null]::bytea[], array[1])$$,
    'malformed', 'null_array_is_malformed');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', '{{1}}'::smallint[], array[[onepass_test.rid(1)]], '{{1}}'::bigint[],
        '{{1}}'::smallint[], '{{NULL}}'::bigint[], '{{"\\x01"}}'::bytea[], '{{NULL}}'::bytea[], '{{1}}'::integer[])$$,
    'malformed', 'two_dimensional_arrays_are_malformed');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', '[0:0]={1}'::smallint[], '[0:0]={"\\x00000000000000000000000000000001"}'::bytea[],
        '[0:0]={1}'::bigint[], '[0:0]={1}'::smallint[], '[0:0]={NULL}'::bigint[], '[0:0]={"\\x01"}'::bytea[],
        '[0:0]={NULL}'::bytea[], '[0:0]={1}'::integer[])$$,
    'malformed', 'arrays_not_starting_at_one_are_malformed');

-- One bad operation among good ones refuses the batch.
select onepass_test.answers(format(
    $$select * from onepass_test.commit('a', 'A', array[1, %s]::smallint[], array[onepass_test.rid(1), %s], array[1, %s]::bigint[],
        array[1, %s]::smallint[], array[null, %s]::bigint[], array['\x01', %s]::bytea[], array[null, %s]::bytea[], array[1, %s])$$,
        k, i, v, op, e, d, b, s),
    'malformed', 'malformed_op_' || name)
from (values
    ('kind_zero', '0', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'null', '1'),
    ('kind_null', 'null', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'null', '1'),
    ('kind_256', '256', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'null', '1'),
    ('id_short', '1', '''\x0102''::bytea', '1', '1', 'null', '''\x02''', 'null', '1'),
    ('id_null', '1', 'null::bytea', '1', '1', 'null', '''\x02''', 'null', '1'),
    ('version_null', '1', 'onepass_test.rid(2)', 'null', '1', 'null', '''\x02''', 'null', '1'),
    ('op_null', '1', 'onepass_test.rid(2)', '1', 'null', 'null', '''\x02''', 'null', '1'),
    ('op_three', '1', 'onepass_test.rid(2)', '1', '3', 'null', '''\x02''', 'null', '1'),
    ('expected_zero', '1', 'onepass_test.rid(2)', '1', '1', '0', '''\x02''', 'null', '1'),
    ('put_without_body', '1', 'onepass_test.rid(2)', '1', '1', 'null', 'null', 'null', '1'),
    ('put_with_data_and_blob', '1', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'decode(repeat(''ab'', 32), ''hex'')', '1'),
    ('inline_size_mismatch', '1', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'null', '2'),
    ('inline_size_null', '1', 'onepass_test.rid(2)', '1', '1', 'null', '''\x02''', 'null', 'null'),
    ('inline_over_16_kib', '1', 'onepass_test.rid(2)', '1', '1', 'null', 'decode(repeat(''00'', 16385), ''hex'')', 'null', '16385'),
    ('blob_until_task_6', '1', 'onepass_test.rid(2)', '1', '1', 'null', 'null', 'decode(repeat(''ab'', 32), ''hex'')', '20000'),
    ('delete_with_expected', '1', 'onepass_test.rid(2)', '1', '2', '1', 'null', 'null', 'null'),
    ('delete_with_data', '1', 'onepass_test.rid(2)', '1', '2', 'null', '''\x02''', 'null', 'null'),
    ('delete_with_size', '1', 'onepass_test.rid(2)', '1', '2', 'null', 'null', 'null', '0'),
    ('duplicate_key', '1', 'onepass_test.rid(1)', '1', '1', 'null', '''\x02''', 'null', '1'))
    as t (name, k, i, v, op, e, d, b, s);

-- The same id under another kind is another key.
select onepass_test.ok(
    (select count(*) = 2 and bool_and(status = 'ok')
     from onepass_test.commit('a', 'A', array[7, 8]::smallint[], array[onepass_test.rid(500), onepass_test.rid(500)],
        array[1, 1]::bigint[], array[1, 1]::smallint[], array[null, null]::bigint[], array['\x07', '\x08']::bytea[],
        array[null, null]::bytea[], array[1, 1])),
    'same_id_under_two_kinds_is_two_keys');

reset role;
select onepass_test.ok(onepass_test.nrec('A') = 2 and onepass_test.next_seq('A') = 3,
    'refused_shapes_wrote_nothing');
set local role onepass_mailbox_api;

-- ----------------------------------------------------------------- limits

-- Q allows 4 operations a batch, every plan at most 20 000; the bytes the
-- batch carries (ids, inline bodies, blob hashes) at most 4 MiB.
select onepass_test.answers(
    $$select * from onepass_test.commit('q', 'Q', array_fill(1::smallint, array[5]),
        array(select onepass_test.rid(i) from generate_series(1, 5) i), array_fill(1::bigint, array[5]),
        array_fill(1::smallint, array[5]), array_fill(null::bigint, array[5]), array_fill('\x01'::bytea, array[5]),
        array_fill(null::bytea, array[5]), array_fill(1, array[5]))$$,
    'too_large', 'more_ops_than_the_plan_allows_is_too_large');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', array_fill(1::smallint, array[20001]),
        array(select onepass_test.rid(i) from generate_series(1, 20001) i), array_fill(1::bigint, array[20001]),
        array_fill(1::smallint, array[20001]), array_fill(null::bigint, array[20001]), array_fill('\x01'::bytea, array[20001]),
        array_fill(null::bytea, array[20001]), array_fill(1, array[20001]))$$,
    'too_large', 'more_than_20000_ops_is_too_large');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', array_fill(1::smallint, array[256]),
        array(select onepass_test.rid(1000 + i) from generate_series(1, 256) i), array_fill(1::bigint, array[256]),
        array_fill(1::smallint, array[256]), array_fill(null::bigint, array[256]),
        array_fill(decode(repeat('00', 16384), 'hex'), array[256]),
        array_fill(null::bytea, array[256]), array_fill(16384, array[256]))$$,
    'too_large', 'batch_over_4_mib_is_too_large');
select onepass_test.ok(
    (select count(*) = 4 and bool_and(status = 'ok')
     from onepass_test.commit('q', 'Q', array_fill(1::smallint, array[4]),
        array(select onepass_test.rid(i) from generate_series(1, 4) i), array_fill(1::bigint, array[4]),
        array[1, 1, 1, 2]::smallint[], array_fill(null::bigint, array[4]), array['\x01', '\x01', '\x01', null]::bytea[],
        array_fill(null::bytea, array[4]), array[1, 1, 1, null])),
    'exactly_the_plan_ops_is_accepted');

reset role;
select onepass_test.ok(onepass_test.nrec('A') = 2 and onepass_test.next_seq('A') = 3,
    'too_large_wrote_nothing');
set local role onepass_mailbox_api;

-- ---------------------------------------------------- conditional writes

select onepass_test.ok(
    (select status = 'ok' and seq = 3 and kind = 1 and id = onepass_test.rid(1) and version = 11 and not deleted
            and size = 2 and data is null and blob_sha256 is null and retry_after is null
     from onepass_test.put('a', 'A', 1, null, '\x0101', 11)),
    'put_expected_none_on_absent_key_is_applied');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'conflict' and seq = 3 and version = 11 and not deleted
                                      and data = '\x0101' and size = 2 and kind = 1 and id = onepass_test.rid(1))
     from onepass_test.put('a', 'A', 1, null, '\x0202', 12)),
    'second_put_expected_none_conflicts_with_the_current_row');
select onepass_test.ok(
    (select status = 'conflict' and seq = 3 from onepass_test.put('a', 'A', 1, 2, '\x0202', 12)),
    'put_with_stale_expected_conflicts');
select onepass_test.ok(
    (select status = 'conflict' and seq is null and version is null and data is null and id = onepass_test.rid(2)
     from onepass_test.put('a', 'A', 2, 1, '\x0202', 12)),
    'put_expected_some_on_absent_key_conflicts_with_seq_null');
select onepass_test.ok(
    (select status = 'ok' and seq = 4 and version = 12 from onepass_test.put('a', 'A', 1, 3, '\x030303', 12)),
    'put_with_current_expected_is_applied');

reset role;
select onepass_test.ok(
    (select r.seq = 4 and r.version = 12 and r.data = '\x030303' and r.size = 3 and not r.deleted
            and r.deleted_at is null and r.blob_sha256 is null
     from onepass_mailbox.records r where r.mailbox_id = onepass_test.mbx('A') and r.kind = 1 and r.id = onepass_test.rid(1)),
    'applied_put_is_stored')
;
select onepass_test.ok(
    (select bytes_used = 2 + 3 and records_count = 3 and next_seq = 5
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'counters_follow_the_puts');
set local role onepass_mailbox_api;

-- ----------------------------------------------------------------- deletes

select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and seq is null and deleted and id = onepass_test.rid(77))
     from onepass_test.del('a', 'A', 77)),
    'delete_of_absent_key_is_ok_with_seq_null');
reset role;
select onepass_test.ok(onepass_test.next_seq('A') = 5 and onepass_test.nrec('A') = 3,
    'delete_of_absent_key_writes_nothing_and_takes_no_seq');
set local role onepass_mailbox_api;

select onepass_test.ok(
    (select status = 'ok' and seq = 5 and deleted and version = 9 and size = 0 from onepass_test.del('a', 'A', 1)),
    'delete_of_live_row_takes_a_new_seq');
reset role;
select onepass_test.ok(
    (select r.deleted and r.deleted_at = now() and r.data is null and r.blob_sha256 is null and r.size = 0
            and r.seq = 5 and r.version = 9
     from onepass_mailbox.records r where r.mailbox_id = onepass_test.mbx('A') and r.kind = 1 and r.id = onepass_test.rid(1)),
    'delete_leaves_a_tombstone');
select onepass_test.ok(
    (select bytes_used = 2 + 128 and records_count = 3 and next_seq = 6
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'delete_swaps_the_row_size_for_the_tombstone_cost');
set local role onepass_mailbox_api;

select onepass_test.ok(
    (select status = 'ok' and seq is null from onepass_test.del('a', 'A', 1)),
    'delete_of_tombstone_is_ok_with_seq_null');
reset role;
select onepass_test.ok(onepass_test.next_seq('A') = 6
    and (select seq = 5 and version = 9 from onepass_mailbox.records
         where mailbox_id = onepass_test.mbx('A') and kind = 1 and id = onepass_test.rid(1)),
    'delete_of_tombstone_changes_nothing');
set local role onepass_mailbox_api;

-- A tombstone takes a put with expected none, not one with its seq.
select onepass_test.ok(
    (select status = 'conflict' and seq = 5 and deleted and data is null and size = 0
     from onepass_test.put('a', 'A', 1, 5, '\x04', 13)),
    'put_expected_some_on_tombstone_conflicts');
select onepass_test.ok(
    (select status = 'ok' and seq = 6 and not deleted from onepass_test.put('a', 'A', 1, null, '\x04', 13)),
    'put_expected_none_on_tombstone_is_applied');
reset role;
select onepass_test.ok(
    (select not r.deleted and r.deleted_at is null and r.data = '\x04' and r.size = 1
     from onepass_mailbox.records r where r.mailbox_id = onepass_test.mbx('A') and r.kind = 1 and r.id = onepass_test.rid(1))
    and (select bytes_used = 3 and records_count = 3 from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'revived_tombstone_is_live_and_counted');
set local role onepass_mailbox_api;

-- --------------------------------------------------------- mixed batches

-- rid(1) live at 6, rid(500) kinds 7 and 8 live at 1 and 2. One stale
-- expected among four operations: nothing is written, only that key comes back.
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'conflict' and kind = 8 and id = onepass_test.rid(500) and seq = 2)
     from onepass_test.commit('a', 'A', array[1, 7, 8, 1]::smallint[],
        array[onepass_test.rid(1), onepass_test.rid(500), onepass_test.rid(500), onepass_test.rid(600)],
        array[2, 2, 2, 2]::bigint[], array[1, 2, 1, 1]::smallint[], array[6, null, 1, null]::bigint[],
        array['\x05', null, '\x05', '\x05']::bytea[], array_fill(null::bytea, array[4]), array[1, null, 1, 1])),
    'mixed_batch_returns_only_the_conflicting_key');
reset role;
select onepass_test.ok(onepass_test.next_seq('A') = 7 and onepass_test.nrec('A') = 3
    and (select bytes_used = 3 and records_count = 3 from onepass_mailbox.mailboxes where id = onepass_test.mbx('A'))
    and (select seq = 6 and data = '\x04' from onepass_mailbox.records
         where mailbox_id = onepass_test.mbx('A') and kind = 1 and id = onepass_test.rid(1))
    and (select not deleted from onepass_mailbox.records
         where mailbox_id = onepass_test.mbx('A') and kind = 7 and id = onepass_test.rid(500)),
    'conflicting_batch_wrote_nothing');
set local role onepass_mailbox_api;

-- Two conflicts come back in the order sent.
select onepass_test.ok(
    (select array_agg(kind order by o) = array[8, 7]::smallint[]
     from (select kind, row_number() over () as o
           from onepass_test.commit('a', 'A', array[8, 1, 7]::smallint[],
               array[onepass_test.rid(500), onepass_test.rid(1), onepass_test.rid(500)],
               array[2, 2, 2]::bigint[], array[1, 1, 1]::smallint[], array[null, 6, null]::bigint[],
               array['\x05', '\x05', '\x05']::bytea[], array_fill(null::bytea, array[3]), array[1, 1, 1])) c),
    'conflicts_come_back_in_the_order_sent');

-- The same batch with right expectations: one row per operation, in order,
-- seqs consecutive; the no-op delete takes none.
select onepass_test.ok(
    (select array_agg(seq order by o) is not distinct from array[7, null, 8, 9]::bigint[]
            and array_agg(kind order by o) = array[1, 1, 8, 1]::smallint[]
            and array_agg(id order by o) = array[onepass_test.rid(1), onepass_test.rid(42), onepass_test.rid(500), onepass_test.rid(600)]
            and bool_and(status = 'ok')
     from (select kind, id, seq, status, row_number() over () as o
           from onepass_test.commit('a', 'A', array[1, 1, 8, 1]::smallint[],
               array[onepass_test.rid(1), onepass_test.rid(42), onepass_test.rid(500), onepass_test.rid(600)],
               array[3, 3, 3, 3]::bigint[], array[1, 2, 1, 1]::smallint[], array[6, null, 2, null]::bigint[],
               array['\x0505', null, '\x05', '\x050505']::bytea[], array_fill(null::bytea, array[4]), array[2, null, 1, 3])) c),
    'applied_batch_returns_one_row_per_op_in_order');
reset role;
select onepass_test.ok(
    (select next_seq = 10 and bytes_used = 2 + 1 + 1 + 3 and records_count = 4
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'applied_batch_updates_counters_once');
set local role onepass_mailbox_api;

-- ----------------------------------------------------------------- quotas

-- Q: 100 bytes, 3 live records; rid(1..3) live at 1 byte each after the
-- batch of 4 above (the delete of rid(4) was a no-op).
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 9, null, '\x01')$$,
    'quota', 'record_over_quota_is_refused');
select onepass_test.answers(
    $$select * from onepass_test.put('q', 'Q', 1, 1, decode(repeat('00', 99), 'hex'))$$,
    'quota', 'bytes_over_quota_are_refused');
reset role;
select onepass_test.ok(onepass_test.nrec('Q') = 3 and onepass_test.next_seq('Q') = 4
    and (select bytes_used = 3 and records_count = 3 and last_write_at is not null
         from onepass_mailbox.mailboxes where id = onepass_test.mbx('Q')),
    'quota_refusal_wrote_nothing');
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put('q', 'Q', 1, 1, decode(repeat('00', 98), 'hex'))$$,
    'ok', 'bytes_up_to_quota_are_accepted');
-- Q now: rid(1) 98 bytes at seq 4, rid(2) and rid(3) 1 byte: 100 bytes, 3 records.
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 2, 2, '\x02')$$,
    'ok', 'rewriting_in_place_within_quota_passes');
-- A tombstone stays a record and costs 128 bytes.
select onepass_test.answers(
    $$select * from onepass_test.commit('q', 'Q', array[1, 1]::smallint[], array[onepass_test.rid(2), onepass_test.rid(9)],
        array[2, 2]::bigint[], array[2, 1]::smallint[], array[null, null]::bigint[], array[null, '\x09']::bytea[],
        array[null, null]::bytea[], array[null, 1])$$,
    'quota', 'tombstone_still_counts_as_a_record');
select onepass_test.answers(
    $$select * from onepass_test.commit('q', 'Q', array[1, 1]::smallint[], array[onepass_test.rid(1), onepass_test.rid(2)],
        array[2, 2]::bigint[], array[1, 2]::smallint[], array[4, null]::bigint[], array['\x01', null]::bytea[],
        array[null, null]::bytea[], array[1, null])$$,
    'quota', 'tombstone_costs_128_bytes');
-- Deletes only always pass, even past the byte limit: a full mailbox can delete.
select onepass_test.answers($$select * from onepass_test.del('q', 'Q', 3)$$, 'ok', 'delete_only_batch_passes_quota');
reset role;
select onepass_test.ok(
    (select bytes_used = 100 - 1 + 128 and records_count = 3 from onepass_mailbox.mailboxes where id = onepass_test.mbx('Q')),
    'delete_only_batch_may_go_over_the_byte_limit');
set local role onepass_mailbox_api;
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 3, null, '\x03')$$,
    'ok', 'reviving_a_tombstone_gives_back_its_cost');
reset role;
select onepass_test.ok(
    (select bytes_used = 100 and records_count = 3 and next_seq = 8 from onepass_mailbox.mailboxes where id = onepass_test.mbx('Q')),
    'quota_counters_at_the_limit');
-- A mailbox over its quota (the plan shrank) may still shrink, never grow.
set local onepass.maintenance = 'on';
update onepass_mailbox.plans set max_bytes = 10, max_records = 1 where plan = 't_tiny';
reset onepass.maintenance;
set local role onepass_mailbox_api;
select onepass_test.answers($$select * from onepass_test.del('q', 'Q', 3)$$, 'ok', 'over_quota_mailbox_may_delete');
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 9, null, '\x0909')$$, 'quota', 'over_quota_mailbox_may_not_add_a_record');
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 2, 5, '\x020202')$$, 'quota', 'over_quota_mailbox_may_not_grow');
select onepass_test.answers($$select * from onepass_test.put('q', 'Q', 1, 4, '')$$, 'ok', 'over_quota_mailbox_may_shrink_a_body');


-- ------------------------------------------------- rate and consumed nonce

select onepass_test.answers($$select * from onepass_test.put('s', 'S', 1, null, '\x01')$$, 'ok', 'slow_first');
select onepass_test.answers($$select * from onepass_test.put('s', 'S', 2, null, '\x01')$$, 'ok', 'slow_second');
select onepass_test.answers($$select * from onepass_test.put('s', 'S', 3, null, '\x01')$$, 'ok', 'slow_third');
select onepass_test.ok(
    (select status = 'rate_limited' and retry_after between 1 and 60 and seq is null
     from onepass_test.put('s', 'S', 4, null, '\x01')),
    'commit_over_rate_is_rate_limited_in_band');
reset role;
select onepass_test.ok(onepass_test.nrec('S') = 3 and onepass_test.next_seq('S') = 4 and onepass_test.nonces('s') = 5,
    'rate_limited_commit_writes_nothing_and_keeps_its_nonce');
create temporary table t_nonce0 on commit drop as select onepass_test.nonces('a') as n;
set local role onepass_mailbox_api;
select onepass_test.answers($$select * from onepass_test.put('a', 'A', 1, 1, '\x01')$$, 'conflict', 'nonce_probe_conflict');
select onepass_test.answers($$select * from onepass_test.put('a', 'A', 1, 0, '\x01')$$, 'malformed', 'nonce_probe_malformed');
select onepass_test.answers(
    $$select * from onepass_test.commit('a', 'A', array_fill(1::smallint, array[20001]),
        array(select onepass_test.rid(i) from generate_series(1, 20001) i), array_fill(1::bigint, array[20001]),
        array_fill(1::smallint, array[20001]), array_fill(null::bigint, array[20001]), array_fill('\x01'::bytea, array[20001]),
        array_fill(null::bytea, array[20001]), array_fill(1, array[20001]))$$,
    'too_large', 'nonce_probe_too_large');
reset role;
select onepass_test.ok(onepass_test.nonces('a') = (select n from t_nonce0) + 3,
    'refused_commits_keep_their_nonces');
set local role onepass_mailbox_api;

-- --------------------------------------------------------------- wake-up

reset role;
delete from onepass_mailbox.push_queue;
update onepass_mailbox.mailboxes set last_write_at = timestamptz '2001-01-01 00:00:00+00' where id = onepass_test.mbx('A');
create temporary table t_sent0 on commit drop as select coalesce(max(n), 0) as n from realtime.sent;
set local role onepass_mailbox_api;

select onepass_test.answers($$select * from onepass_test.put('a', 'A', 600, 3, '\x06')$$, 'conflict', 'wake_probe_conflict');
select onepass_test.answers($$select * from onepass_test.del('a', 'A', 999)$$, 'ok', 'wake_probe_noop_delete');
reset role;
select onepass_test.ok(
    (select count(*) from realtime.sent where n > (select n from t_sent0)) = 0
    and (select count(*) from onepass_mailbox.push_queue) = 0,
    'batch_that_writes_nothing_wakes_nobody');
select onepass_test.ok(
    (select last_write_at = timestamptz '2001-01-01 00:00:00+00' from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'batch_that_writes_nothing_keeps_last_write_at');
set local role onepass_mailbox_api;

select onepass_test.answers($$select * from onepass_test.put('a', 'A', 600, 9, '\x06')$$, 'ok', 'wake_probe_applied');
reset role;
select onepass_test.ok(
    (select count(*) = 1
            and bool_and(event = 'wake' and payload = '{}'::jsonb and not private
                         and topic = 'mbx:' || encode((select wake_topic from t_mbx where name = 'A'), 'hex'))
     from realtime.sent where n > (select n from t_sent0)),
    'applied_batch_sends_one_empty_wake_on_the_mailbox_topic');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(mailbox_id = onepass_test.mbx('A') and exclude_credential = onepass_test.cid('a')
                                      and enqueued_at = now())
     from onepass_mailbox.push_queue),
    'applied_batch_queues_a_push_excluding_the_author');
select onepass_test.ok(
    (select last_write_at = now() from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'applied_batch_sets_last_write_at');
set local role onepass_mailbox_api;

-- The same author again keeps itself excluded; a second author before the
-- push went out means nobody is excluded (each must hear of the other).
select onepass_test.answers($$select * from onepass_test.put('a', 'A', 601, null, '\x06')$$, 'ok', 'wake_same_author');
reset role;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(exclude_credential = onepass_test.cid('a')) from onepass_mailbox.push_queue),
    'same_author_twice_stays_excluded');
set local role onepass_mailbox_api;
select onepass_test.answers($$select * from onepass_test.put('a2', 'A', 602, null, '\x06')$$, 'ok', 'wake_second_author');
reset role;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(exclude_credential is null) from onepass_mailbox.push_queue),
    'two_authors_coalesced_exclude_nobody');
select onepass_test.ok(
    (select count(*) from realtime.sent where n > (select n from t_sent0)) = 3,
    'each_applied_batch_sends_a_wake');
set local role onepass_mailbox_api;

-- Another mailbox's commit leaves A's queue entry alone.
select onepass_test.answers($$select * from onepass_test.put('b', 'B', 1, null, '\x01')$$, 'ok', 'wake_other_mailbox');
reset role;
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.push_queue)
    and (select exclude_credential is null from onepass_mailbox.push_queue where mailbox_id = onepass_test.mbx('A'))
    and (select exclude_credential = onepass_test.cid('b') from onepass_mailbox.push_queue where mailbox_id = onepass_test.mbx('B')),
    'push_queue_is_per_mailbox');
select onepass_test.ok(
    (select count(*) = 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('B')),
    'commit_on_b_writes_only_b');

-- ------------------------------------------------- 100 random batches

-- Deterministic: fixed seed, keys drawn from 40 ids of kind 3. Each
-- batch sets the right expectations (read as the superuser), so all apply.
create temporary table t_applied (batch integer, ord integer, kind smallint, id bytea, seq bigint) on commit drop;
do $$
declare
    b integer;
    n integer;
    j integer;
    k integer;
    ids bytea[];
    vers bigint[];
    ops smallint[];
    exps bigint[];
    dat bytea[];
    sizes integer[];
    cur record;
    used integer[];
    rw record;
    o integer;
begin
    perform setseed(0.4242);
    for b in 1 .. 100 loop
        n := 1 + floor(random() * 12)::integer;
        ids := '{}'; vers := '{}'; ops := '{}'; exps := '{}'; dat := '{}'; sizes := '{}'; used := '{}';
        j := 0;
        while j < n loop
            k := floor(random() * 40)::integer;
            continue when k = any (used);
            used := used || k;
            j := j + 1;
            select r.seq, r.deleted into cur from onepass_mailbox.records r
            where r.mailbox_id = onepass_test.mbx('R') and r.kind = 3 and r.id = onepass_test.rid(k);
            ids := ids || onepass_test.rid(k);
            vers := vers || (b * 100 + j)::bigint;
            if random() < 0.25 then
                ops := ops || 2::smallint; exps := exps || null::bigint; dat := dat || null::bytea; sizes := sizes || null::integer;
            else
                ops := ops || 1::smallint;
                exps := exps || (case when cur.seq is not null and not cur.deleted then cur.seq end);
                dat := dat || decode(repeat('ab', 1 + floor(random() * 64)::integer), 'hex');
                sizes := sizes || octet_length(dat[j]);
            end if;
        end loop;
        o := 0;
        for rw in select * from onepass_mailbox.api_commit(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('R'),
                array_fill(3::smallint, array[n]), ids, vers, ops, exps, dat, array_fill(null::bytea, array[n]), sizes) loop
            o := o + 1;
            if rw.status <> 'ok' then
                raise exception 'random batch % refused: %', b, rw.status;
            end if;
            insert into t_applied values (b, o, rw.kind, rw.id, rw.seq);
        end loop;
        if o <> n then
            raise exception 'random batch % returned % rows for % ops', b, o, n;
        end if;
    end loop;
end
$$;

select onepass_test.ok(
    (select array_agg(seq order by batch, ord) = array(select generate_series(1, count(*)) from t_applied where seq is not null)
     from t_applied where seq is not null),
    'random_batches_seq_strictly_increasing_without_gaps');
select onepass_test.ok(
    (select count(*) filter (where seq is null) > 0 and count(distinct batch) = 100 from t_applied),
    'random_batches_include_noop_deletes');
select onepass_test.ok(
    onepass_test.next_seq('R') = (select max(seq) + 1 from t_applied),
    'random_batches_next_seq_follows_the_last_seq');
select onepass_test.ok(
    (select bytes_used = (select coalesce(sum(case when deleted then 128 else size end), 0)
                          from onepass_mailbox.records where mailbox_id = m.id)
            and records_count = (select count(*) from onepass_mailbox.records where mailbox_id = m.id)
     from onepass_mailbox.mailboxes m where m.id = onepass_test.mbx('R')),
    'random_batches_counters_match_the_rows');

-- The change feed gives each key's last applied seq, in order, nothing else.
set local role onepass_mailbox_api;
create temporary table t_feed on commit drop as
select c.seq, c.kind, c.id, c.head from onepass_mailbox.api_changes(onepass_test.cid('r'), onepass_test.n(), now(),
    onepass_test.mbx('R'), 0, 1000, false) c;
reset role;
select onepass_test.ok(
    (select array_agg(seq order by seq) from t_feed)
    = (select array_agg(s order by s) from (select max(seq) s from t_applied where seq is not null group by kind, id) l),
    'change_feed_gives_the_last_seq_of_each_key');
select onepass_test.ok(
    (select bool_and(head = (select max(seq) from t_applied)) from t_feed),
    'change_feed_head_is_the_last_applied_seq');

-- ------------------------------------------------------ capped conflicts

-- K: 2000 rows of 16 KiB, written 200 at a time (3.2 MiB a batch).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(c.status = 'ok')
     from generate_series(0, 9) b,
          onepass_test.commit('k', 'K', array_fill(1::smallint, array[200]),
              array(select onepass_test.rid(b * 200 + i) from generate_series(1, 200) i), array_fill(1::bigint, array[200]),
              array_fill(1::smallint, array[200]), array_fill(null::bigint, array[200]),
              array_fill(decode(repeat('ee', 16384), 'hex'), array[200]),
              array_fill(null::bytea, array[200]), array_fill(16384, array[200])) c),
    'conflict_fixture_2000_rows_of_16_kib');
-- 2000 puts with expected none on those keys, plus one new key at the end.
create temporary table t_conflict on commit drop as
select row_number() over () as o, c.*
from onepass_test.commit('k', 'K', array_fill(1::smallint, array[2001]),
    array(select onepass_test.rid(i) from generate_series(1, 2001) i), array_fill(2::bigint, array[2001]),
    array_fill(1::smallint, array[2001]), array_fill(null::bigint, array[2001]), array_fill('\x01'::bytea, array[2001]),
    array_fill(null::bytea, array[2001]), array_fill(1, array[2001])) c;
reset role;
select onepass_test.ok(
    (select count(*) = 256 and bool_and(status = 'conflict') and sum(octet_length(data)) = 4194304
            and array_agg(id order by o) = array(select onepass_test.rid(i) from generate_series(1, 256) i)
     from t_conflict),
    'conflict_reply_is_a_prefix_capped_at_4_mib');
select onepass_test.ok(
    onepass_test.nrec('K') = 2000 and onepass_test.next_seq('K') = 2001
    and not exists (select 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('K') and version <> 1),
    'capped_conflict_applied_nothing');
-- Small rows: the cap is 1000 rows.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok')
     from onepass_test.commit('k', 'K', array_fill(2::smallint, array[2000]),
         array(select onepass_test.rid(i) from generate_series(1, 2000) i), array_fill(1::bigint, array[2000]),
         array_fill(1::smallint, array[2000]), array_fill(null::bigint, array[2000]), array_fill('\x01'::bytea, array[2000]),
         array_fill(null::bytea, array[2000]), array_fill(1, array[2000]))),
    'conflict_fixture_2000_small_rows');
select onepass_test.ok(
    (select count(*) = 1000 and bool_and(status = 'conflict' and kind = 2)
     from onepass_test.commit('k', 'K', array_fill(2::smallint, array[2000]),
         array(select onepass_test.rid(i) from generate_series(1, 2000) i), array_fill(1::bigint, array[2000]),
         array_fill(1::smallint, array[2000]), array_fill(null::bigint, array[2000]), array_fill('\x01'::bytea, array[2000]),
         array_fill(null::bytea, array[2000]), array_fill(1, array[2000]))),
    'conflict_reply_is_capped_at_1000_rows');

-- ------------------------------------------- tombstone churn on free

-- Put then delete 20 000 fresh keys a round: the tombstones keep counting,
-- so the fifth round reaches the free plan's 100 000 records and the next
-- put is refused in band.
reset role;
do $$
declare
    rnd integer;
    st text;
begin
    for rnd in 0 .. 4 loop
        select min(c.status) into st
        from onepass_mailbox.api_commit(onepass_test.cid('c'), onepass_test.n(), now(), onepass_test.mbx('C'),
            array_fill(4::smallint, array[20000]),
            array(select onepass_test.rid(rnd * 20000 + i) from generate_series(1, 20000) i), array_fill(1::bigint, array[20000]),
            array_fill(1::smallint, array[20000]), array_fill(null::bigint, array[20000]), array_fill('\x01'::bytea, array[20000]),
            array_fill(null::bytea, array[20000]), array_fill(1, array[20000])) c;
        if st <> 'ok' then
            raise exception 'churn put round %: %', rnd, st;
        end if;
        select min(c.status) into st
        from onepass_mailbox.api_commit(onepass_test.cid('c'), onepass_test.n(), now(), onepass_test.mbx('C'),
            array_fill(4::smallint, array[20000]),
            array(select onepass_test.rid(rnd * 20000 + i) from generate_series(1, 20000) i), array_fill(2::bigint, array[20000]),
            array_fill(2::smallint, array[20000]), array_fill(null::bigint, array[20000]), array_fill(null::bytea, array[20000]),
            array_fill(null::bytea, array[20000]), array_fill(null::integer, array[20000])) c;
        if st <> 'ok' then
            raise exception 'churn delete round %: %', rnd, st;
        end if;
    end loop;
end
$$;
select onepass_test.ok(
    (select records_count = 100000 and bytes_used = 100000 * 128
     from onepass_mailbox.mailboxes where id = onepass_test.mbx('C'))
    and not exists (select 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('C') and not deleted),
    'churned_tombstones_count_against_the_quota');
set local role onepass_mailbox_api;
select onepass_test.answers($$select * from onepass_test.put('c', 'C', 999999, null, '\x01')$$,
    'quota', 'churn_reaches_the_free_plan_quota');
select onepass_test.answers(
    $$select * from onepass_test.commit('c', 'C', array[4]::smallint[], array[onepass_test.rid(1)], array[3]::bigint[],
        array[1]::smallint[], array[null]::bigint[], array['\x01']::bytea[], array[null]::bytea[], array[1])$$,
    'ok', 'reviving_a_churned_tombstone_still_passes');
reset role;
