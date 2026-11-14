-- OnePass Business: plan `org` and the write-once org kinds 29 and 30.
-- Starts as the harness superuser, inside a transaction the harness rolls
-- back; calls under test run as onepass_mailbox_api, state is read back as
-- the superuser. now() is fixed for the whole transaction.
--
-- Contract under test: the org mailbox is created through an invite of plan
-- `org` only. A put on an existing key (live or tombstone, any expected seq)
-- of kind 29 or 30 is 'conflict' carrying the current row; a delete of kind
-- 29 or 30, present or not, is in-band 'forbidden', before the mailbox lock.
-- Other kinds follow the usual rules. A trigger refuses UPDATE and DELETE of
-- those rows (OP403) outside maintenance.

create temporary table og_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table og_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence og_n start 930000;
grant all on og_keys, og_mbx to public;
grant usage on sequence og_n to public;

insert into og_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-org-test-key/' || n, 'sha256') as pk
      from unnest(array['o', 'open']) as n) k;

create function onepass_test.og_n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('og_n')) $$;
create function onepass_test.og_rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
-- A commit as credential o on mailbox o, fresh nonce. Versions are all 1;
-- sizes follow the bodies.
create function onepass_test.og_commit(kinds smallint[], ids integer[], ops smallint[], expected bigint[], bodies bytea[])
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_commit(
        (select cid from og_keys where name = 'o'), onepass_test.og_n(), now(), (select id from og_mbx where name = 'o'),
        kinds, (select array_agg(onepass_test.og_rid(i)) from unnest(ids) i),
        (select array_agg(1::bigint) from unnest(kinds)), ops, expected, bodies,
        (select array_agg(null::bytea) from unnest(kinds)),
        (select array_agg(octet_length(b)) from unnest(bodies) b))
$$;
-- One put of (kind, rid(i)).
create function onepass_test.og_put(k smallint, i integer, expected bigint, body bytea)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.og_commit(array[k], array[i], array[1]::smallint[], array[expected], array[body])
$$;
-- One delete of (kind, rid(i)).
create function onepass_test.og_del(k smallint, i integer)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.og_commit(array[k], array[i], array[2]::smallint[], array[null]::bigint[], array[null]::bytea[])
$$;
create function onepass_test.og_next_seq() returns bigint language sql stable as $$
    select next_seq from onepass_mailbox.mailboxes where id = (select id from og_mbx where name = 'o') $$;
create function onepass_test.og_row(k smallint, i integer) returns onepass_mailbox.records language sql stable as $$
    select r from onepass_mailbox.records r
    where r.mailbox_id = (select id from og_mbx where name = 'o') and r.kind = k and r.id = onepass_test.og_rid(i) $$;
grant execute on all functions in schema onepass_test to public;
revoke all on function onepass_test.og_next_seq(), onepass_test.og_row(smallint, integer) from public;

-- The plan row.
select onepass_test.ok(
    (select max_bytes = 17179869184 and max_records = 200000 and max_credentials = 4096 and req_per_min = 600
            and max_commit_ops = 20000 and max_children_shared = 0 and max_children_contact = 0
     from onepass_mailbox.plans where plan = 'org'),
    'org_plan_row_matches_seed');

-- Creation: through an invite of plan org only.
delete from onepass_mailbox.settings;
insert into onepass_mailbox.settings (name, value) values ('open_signup', 'on');
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest('org-invite', 'sha256'), 'org', 1, now() + interval '1 day');

set local role onepass_mailbox_api;
create temporary table og_made on commit drop as
select * from onepass_mailbox.api_create_mailbox(
    (select pk from og_keys where name = 'o'), onepass_test.og_n(), now(), convert_to('org-invite', 'UTF8'), '\x',
    decode(md5('og-o') || md5('og-o/'), 'hex'), true);
create temporary table og_made_open on commit drop as
select * from onepass_mailbox.api_create_mailbox(
    (select pk from og_keys where name = 'open'), onepass_test.og_n(), now(), null, '\x',
    decode(md5('og-open') || md5('og-open/'), 'hex'), true);
reset role;
insert into og_mbx select 'o', mailbox_id from og_made where status = 'ok';

select onepass_test.ok(
    (select status from og_made) = 'ok'
    and (select plan from onepass_mailbox.mailboxes where id = (select id from og_mbx where name = 'o')) = 'org'
    and (select uses_left from onepass_mailbox.invites where token_hash = extensions.digest('org-invite', 'sha256')) = 0,
    'org_invite_creates_org_mailbox');
select onepass_test.ok(
    (select status from og_made_open) = 'ok'
    and (select m.plan from onepass_mailbox.mailboxes m where m.id = (select mailbox_id from og_made_open)) = 'selfhost',
    'open_signup_does_not_give_org');

-- First puts.
set local role onepass_mailbox_api;
create temporary table og_r1 on commit drop as
select * from onepass_test.og_commit(array[29, 30]::smallint[], array[1, 1], array[1, 1]::smallint[],
    array[null, null]::bigint[], array['\x2901', '\x3001']::bytea[]);
reset role;
select onepass_test.ok(
    (select count(*) from og_r1) = 2 and (select bool_and(status = 'ok') from og_r1)
    and (select seq from og_r1 where kind = 29) = 1 and (select seq from og_r1 where kind = 30) = 2,
    'org_first_puts_apply');

-- Writes on existing immutable keys conflict, whatever the expectation.
set local role onepass_mailbox_api;
create temporary table og_r2 on commit drop as select * from onepass_test.og_put(29::smallint, 1, null, '\x2901');
create temporary table og_r3 on commit drop as select * from onepass_test.og_put(29::smallint, 1, 1, '\x2902');
create temporary table og_r4 on commit drop as select * from onepass_test.og_put(30::smallint, 1, 2, '\x3001');
reset role;
select onepass_test.ok(
    (select count(*) from og_r2) = 1 and (select status from og_r2) = 'conflict'
    and (select seq from og_r2) = 1 and (select data from og_r2) = '\x2901',
    'immutable_put_without_expectation_conflicts');
select onepass_test.ok(
    (select count(*) from og_r3) = 1 and (select status from og_r3) = 'conflict'
    and (select seq from og_r3) = 1 and (select data from og_r3) = '\x2901'
    and (onepass_test.og_row(29::smallint, 1)).data = '\x2901'
    and (onepass_test.og_row(29::smallint, 1)).version = 1
    and (onepass_test.og_row(29::smallint, 1)).seq = 1
    and onepass_test.og_next_seq() = 3,
    'immutable_put_with_current_seq_conflicts');
select onepass_test.ok(
    (select count(*) from og_r4) = 1 and (select status from og_r4) = 'conflict' and (select seq from og_r4) = 2,
    'immutable_put_with_current_seq_same_body_conflicts');

-- All or nothing.
set local role onepass_mailbox_api;
create temporary table og_r5 on commit drop as
select * from onepass_test.og_commit(array[5, 30]::smallint[], array[9, 1], array[1, 1]::smallint[],
    array[null, 2]::bigint[], array['\x05', '\x3002']::bytea[]);
reset role;
select onepass_test.ok(
    (select count(*) from og_r5) = 1 and (select status from og_r5) = 'conflict' and (select kind from og_r5) = 30
    and onepass_test.og_row(5::smallint, 9) is null and onepass_test.og_next_seq() = 3,
    'immutable_conflict_is_all_or_nothing');

-- Deletes are forbidden.
set local role onepass_mailbox_api;
create temporary table og_d1 on commit drop as select * from onepass_test.og_del(29::smallint, 1);
create temporary table og_d2 on commit drop as select * from onepass_test.og_del(30::smallint, 77);
create temporary table og_d3 on commit drop as
select * from onepass_test.og_commit(array[5, 29]::smallint[], array[9, 1], array[2, 2]::smallint[],
    array[null, null]::bigint[], array[null, null]::bytea[]);
reset role;
select onepass_test.ok(
    (select count(*) from og_d1) = 1 and (select status from og_d1) = 'forbidden'
    and not (onepass_test.og_row(29::smallint, 1)).deleted,
    'immutable_delete_forbidden');
select onepass_test.ok((select count(*) from og_d2) = 1 and (select status from og_d2) = 'forbidden',
    'immutable_delete_of_absent_key_forbidden');
select onepass_test.ok(
    (select count(*) from og_d3) = 1 and (select status from og_d3) = 'forbidden'
    and onepass_test.og_row(5::smallint, 9) is null and onepass_test.og_next_seq() = 3,
    'immutable_delete_in_a_mixed_batch_forbidden');

-- Kinds 31 and 32 stay mutable.
set local role onepass_mailbox_api;
create temporary table og_m1 on commit drop as select * from onepass_test.og_put(31::smallint, 1, null, '\x3101');
create temporary table og_m2 on commit drop as select * from onepass_test.og_put(32::smallint, 1, null, '\x3201');
reset role;
create temporary table og_m3 on commit drop as select 31::smallint as k, (onepass_test.og_row(31::smallint, 1)).seq as s;
grant all on og_m3 to public;
set local role onepass_mailbox_api;
create temporary table og_m4 on commit drop as
select * from onepass_test.og_put(31::smallint, 1, (select s from og_m3), '\x3102');
create temporary table og_m5 on commit drop as select * from onepass_test.og_del(32::smallint, 1);
reset role;
select onepass_test.ok(
    (select status from og_m1) = 'ok' and (select status from og_m2) = 'ok' and (select status from og_m4) = 'ok'
    and (select status from og_m5) = 'ok' and (select seq from og_m5) is not null
    and (onepass_test.og_row(32::smallint, 1)).deleted,
    'mutable_org_kinds_still_update');

-- Other kinds are unchanged.
set local role onepass_mailbox_api;
create temporary table og_k1 on commit drop as select * from onepass_test.og_put(1::smallint, 1, null, '\x01');
reset role;
create temporary table og_k1s on commit drop as select (onepass_test.og_row(1::smallint, 1)).seq as s;
grant all on og_k1s to public;
set local role onepass_mailbox_api;
create temporary table og_k2 on commit drop as
select * from onepass_test.og_put(1::smallint, 1, (select s from og_k1s), '\x02');
create temporary table og_k3 on commit drop as select * from onepass_test.og_del(1::smallint, 1);
reset role;
select onepass_test.ok(
    (select status from og_k1) = 'ok' and (select status from og_k2) = 'ok' and (select status from og_k3) = 'ok',
    'other_kinds_unchanged');

-- The trigger.
select onepass_test.throws(
    $$update onepass_mailbox.records set version = version + 1 where kind = 29$$, 'OP403', 'immutable_guard_refuses_update');
select onepass_test.throws(
    $$delete from onepass_mailbox.records where kind = 30$$, 'OP403', 'immutable_guard_refuses_delete');
select set_config('onepass.maintenance', 'on', true);
select onepass_test.ok(onepass_test.row_count($$delete from onepass_mailbox.records where kind = 29$$) = 1,
    'immutable_guard_lets_maintenance_delete');
select set_config('onepass.maintenance', '', true);
