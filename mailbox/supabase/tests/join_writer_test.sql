-- A join request (kind 32) is rewritten only by the credential that wrote it
-- first, when the writer is limited by put_kinds (migration 20261114130000,
-- plan C ruling R38 (a)). Starts as the harness superuser, inside a
-- transaction the harness rolls back; calls under test run as
-- onepass_mailbox_api, state is read back as the superuser.

create temporary table jw_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table jw_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence jw_n start 940000;
grant all on jw_keys, jw_mbx to public;
grant usage on sequence jw_n to public;

insert into jw_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-join-writer-test-key/' || n, 'sha256') as pk
      from unnest(array['m', 'l1', 'l2', 'k', 'w']) as n) k;

create function onepass_test.jw_cid(text) returns bytea language sql stable as $$
    select cid from jw_keys where name = $1 $$;
create function onepass_test.jw_n() returns bytea language sql volatile as $$
    select onepass_test.nonce(nextval('jw_n')) $$;
create function onepass_test.jw_mbx() returns bytea language sql stable as $$ select id from jw_mbx where name = 'A' $$;
-- The 256 bit kind set of `k`.
create function onepass_test.jw_kinds(k integer) returns bytea language sql immutable as $$
    select set_bit(decode(repeat('00', 32), 'hex'), k, 1) $$;
create function onepass_test.jw_grant(target text, role integer, kinds bytea) returns text language sql volatile as $$
    select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.jw_cid('m'), onepass_test.jw_n(), now(), onepass_test.jw_mbx(),
        (select pk from jw_keys where name = target), role::smallint, kinds, '\x') g
$$;
-- One put of `body` on (p_kind, nonce(i)) by `cred`, expecting seq `e`
-- (null: the key is absent or a tombstone).
create function onepass_test.jw_put(cred text, p_kind integer, i integer, e bigint, body bytea) returns text
language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.jw_cid(cred), onepass_test.jw_n(), now(),
        onepass_test.jw_mbx(), array[p_kind]::smallint[], array[onepass_test.nonce(i)], array[1]::bigint[],
        array[1]::smallint[], array[e], array[body], array[null]::bytea[],
        array[octet_length(body)]) c limit 1
$$;
-- Two puts of kind 32 in one batch: a new key i, and key j expecting seq e.
create function onepass_test.jw_put2(cred text, i integer, j integer, e bigint) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.jw_cid(cred), onepass_test.jw_n(), now(),
        onepass_test.jw_mbx(), array[32, 32]::smallint[], array[onepass_test.nonce(i), onepass_test.nonce(j)],
        array[1, 1]::bigint[], array[1, 1]::smallint[], array[null, e]::bigint[],
        array['\x5a'::bytea, '\x5b'::bytea], array[null, null]::bytea[], array[1, 1]) c limit 1
$$;
create function onepass_test.jw_del(cred text, p_kind integer, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.jw_cid(cred), onepass_test.jw_n(), now(),
        onepass_test.jw_mbx(), array[p_kind]::smallint[], array[onepass_test.nonce(i)], array[9]::bigint[],
        array[2]::smallint[], array[null]::bigint[], array[null]::bytea[], array[null]::bytea[],
        array[null]::integer[]) c limit 1
$$;
grant execute on all functions in schema onepass_test to public;

create function onepass_test.jw_row(p_kind integer, p_i integer) returns onepass_mailbox.records language sql stable as $$
    select r from onepass_mailbox.records r
    where r.mailbox_id = onepass_test.jw_mbx() and r.kind = p_kind and r.id = onepass_test.nonce(p_i) $$;
revoke all on function onepass_test.jw_row(integer, integer) from public;

-- Mailbox A, manager m; limited writers l1 and l2 (kind 32), k (kind 14),
-- an unlimited writer w.
set local role onepass_mailbox_api;
create temporary table jw_made on commit drop as
select * from onepass_mailbox.api_create_mailbox(
    (select pk from jw_keys where name = 'm'), onepass_test.jw_n(), now(), null, '\x',
    decode(md5('jw-a') || md5('jw-a/'), 'hex'), true);
reset role;
insert into jw_mbx select 'A', mailbox_id from jw_made where status = 'ok';
set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.jw_grant('l1', 2, onepass_test.jw_kinds(32)) = 'ok'
    and onepass_test.jw_grant('l2', 2, onepass_test.jw_kinds(32)) = 'ok'
    and onepass_test.jw_grant('k', 2, onepass_test.jw_kinds(14)) = 'ok'
    and onepass_test.jw_grant('w', 2, null) = 'ok',
    'join_writer_fixture');
reset role;

-- The first put records its writer, which rewrites at will.
set local role onepass_mailbox_api;
create temporary table jw_r1 on commit drop as
select onepass_test.jw_put('l1', 32, 1, null, '\x01') as a, onepass_test.jw_put('l1', 32, 1, 1, '\x02') as b;
reset role;
select onepass_test.ok(
    (select a = 'ok' and b = 'ok' from jw_r1)
    and (onepass_test.jw_row(32, 1)).data = '\x02'
    and (onepass_test.jw_row(32, 1)).first_writer = onepass_test.jw_cid('l1'),
    'first_writer_rewrites_its_join_request');

-- Another limited writer may not: forbidden, nothing written.
create temporary table jw_seq on commit drop as select next_seq from onepass_mailbox.mailboxes where id = onepass_test.jw_mbx();
grant all on jw_seq to public;
set local role onepass_mailbox_api;
create temporary table jw_r2 on commit drop as select onepass_test.jw_put('l2', 32, 1, 2, '\xff') as s;
create temporary table jw_r3 on commit drop as select onepass_test.jw_put2('l2', 7, 1, 2) as s;
reset role;
select onepass_test.ok(
    (select s from jw_r2) = 'forbidden'
    and (onepass_test.jw_row(32, 1)).data = '\x02'
    and (select next_seq from onepass_mailbox.mailboxes where id = onepass_test.jw_mbx()) = (select next_seq from jw_seq),
    'other_limited_writer_cannot_rewrite_a_join_request');
select onepass_test.ok(
    (select s from jw_r3) = 'forbidden' and onepass_test.jw_row(32, 7) is null,
    'forbidden_rewrite_fails_the_whole_batch');

-- A manager and an unlimited writer are not bound; the first writer stays.
set local role onepass_mailbox_api;
create temporary table jw_r4 on commit drop as
select onepass_test.jw_put('m', 32, 1, 2, '\x03') as a, onepass_test.jw_put('w', 32, 1, 3, '\x04') as b;
create temporary table jw_r5 on commit drop as select onepass_test.jw_put('l2', 32, 1, 4, '\x05') as s;
reset role;
select onepass_test.ok(
    (select a = 'ok' and b = 'ok' from jw_r4) and (select s from jw_r5) = 'forbidden'
    and (onepass_test.jw_row(32, 1)).data = '\x04'
    and (onepass_test.jw_row(32, 1)).first_writer = onepass_test.jw_cid('l1'),
    'manager_and_unlimited_writer_rewrite_first_writer_kept');

-- A new key is anyone's first; after a delete the key starts again.
set local role onepass_mailbox_api;
create temporary table jw_r6 on commit drop as
select onepass_test.jw_put('l2', 32, 2, null, '\x21') as a, onepass_test.jw_put('l1', 32, 2, 5, '\x22') as b,
       onepass_test.jw_del('m', 32, 2) as c, onepass_test.jw_put('l1', 32, 2, null, '\x23') as d,
       onepass_test.jw_put('l2', 32, 2, 7, '\x24') as e;
reset role;
select onepass_test.ok(
    (select a = 'ok' and b = 'forbidden' and c = 'ok' and d = 'ok' and e = 'forbidden' from jw_r6)
    and (onepass_test.jw_row(32, 2)).data = '\x23'
    and (onepass_test.jw_row(32, 2)).first_writer = onepass_test.jw_cid('l1'),
    'put_over_a_tombstone_takes_a_new_first_writer');

-- A row of unknown writer (from before the migration) binds every limited
-- writer.
update onepass_mailbox.records set first_writer = null
where mailbox_id = onepass_test.jw_mbx() and kind = 32 and id = onepass_test.nonce(1);
set local role onepass_mailbox_api;
create temporary table jw_r7 on commit drop as select onepass_test.jw_put('l1', 32, 1, 4, '\x06') as s;
reset role;
select onepass_test.ok((select s from jw_r7) = 'forbidden' and (onepass_test.jw_row(32, 1)).data = '\x04',
    'unknown_first_writer_binds_limited_writers');

-- Other kinds are unchanged: a limited writer rewrites a kind 14 row it did
-- not write.
set local role onepass_mailbox_api;
create temporary table jw_r8 on commit drop as
select onepass_test.jw_put('w', 14, 3, null, '\x31') as a, onepass_test.jw_put('k', 14, 3, 8, '\x32') as b;
reset role;
select onepass_test.ok((select a = 'ok' and b = 'ok' from jw_r8) and (onepass_test.jw_row(14, 3)).data = '\x32',
    'other_kinds_are_not_writer_bound');
