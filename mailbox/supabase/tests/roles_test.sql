-- Credential roles and grants by a manager (Task 22, spec D.4, D.5, D.7,
-- sharing spec 13.4 and 13.8). Starts as the harness superuser, inside a
-- transaction the harness rolls back; calls under test run as
-- onepass_mailbox_api, state is read back as the superuser.
--
-- Roles: 1 read, 2 write (put_kinds, when set, lists the kinds it may put,
-- and it may delete nothing), 3 manage. A refusal by role is the in-band
-- status forbidden, after authentication: the nonce and the rate hit stay.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-roles-test-key/' || n, 'sha256') as pk
      from unnest(array['m', 'm2', 'w', 'r', 'l', 'o', 'x', 'b', 'e', 'e2', 'g1', 'g2', 'g3', 'g4',
                        's', 's2', 'raw', 'n', 't1', 't2']) as n) k;

create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
-- The 256 bit kind set: bit k (byte k / 8, bit k % 8 from the least
-- significant) is kind k.
create function onepass_test.kinds(k integer[]) returns bytea language plpgsql immutable as $$
declare
    b bytea := decode(repeat('00', 32), 'hex');
    i integer;
begin
    foreach i in array k loop
        b := set_bit(b, i, 1);
    end loop;
    return b;
end
$$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        onepass_test.pk(key), onepass_test.n(), now(), null, '\x',
        decode(md5('roles/' || name) || md5('roles/' || name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
create function onepass_test.grant(cred text, mbx text, pk bytea, role integer, kinds bytea default null,
                                   label bytea default '\x')
returns text language sql volatile as $$
    select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), pk, role::smallint, kinds, label) g
$$;
create function onepass_test.set_role(cred text, mbx text, target text, role integer, kinds bytea default null)
returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_set_credential_role(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(target),
        role::smallint, kinds) s
$$;
create function onepass_test.revoke(cred text, mbx text, target text) returns text language sql volatile as $$
    select r.status from onepass_mailbox.api_revoke_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(target)) r
$$;
-- One inline put of one byte on (kind, rid(i)), unconditional on absence.
create function onepass_test.put(cred text, mbx text, kind integer, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[kind]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01'::bytea], array[null]::bytea[], array[1]) c limit 1
$$;
-- Two puts in one batch.
create function onepass_test.put2(cred text, mbx text, k1 integer, k2 integer, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[k1, k2]::smallint[], array[onepass_test.rid(i), onepass_test.rid(i + 1)], array[1, 1]::bigint[],
        array[1, 1]::smallint[], array[null, null]::bigint[], array['\x01'::bytea, '\x02'::bytea],
        array[null, null]::bytea[], array[1, 1]) c limit 1
$$;
create function onepass_test.del(cred text, mbx text, kind integer, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[kind]::smallint[], array[onepass_test.rid(i)], array[9]::bigint[], array[2]::smallint[],
        array[null]::bigint[], array[null]::bytea[], array[null]::bytea[], array[null]::integer[]) c limit 1
$$;
create function onepass_test.info(cred text, mbx text) returns text language sql volatile as $$
    select status from onepass_mailbox.api_mailbox_info(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx))
$$;
grant execute on all functions in schema onepass_test to public;

-- Fixture state, read as the superuser.
create function onepass_test.next_seq(mbx text) returns bigint language sql stable as $$
    select next_seq from onepass_mailbox.mailboxes where id = onepass_test.mbx(mbx) $$;
create function onepass_test.cred(name text) returns onepass_mailbox.credentials language sql stable as $$
    select * from onepass_mailbox.credentials where id = onepass_test.cid(name) $$;
revoke all on function onepass_test.next_seq(text), onepass_test.cred(text) from public;

-- Mailboxes: A (manager m), B (another tenant, creator b), L (one manager
-- m2), T (a tiny plan, creator t1).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(m, k) = 'ok')
     from (values ('A', 'm'), ('B', 'b'), ('L', 'm2'), ('T', 't1')) v (m, k)),
    'roles_fixture_mailboxes_created');
reset role;

-- ------------------------------------------------------- existing rows

-- A row written without a role (any row from before this migration, and
-- what a creation still writes) is a manager, not an owner, unrestricted.
insert into onepass_mailbox.credentials (id, mailbox_id, public_key)
values (onepass_test.cid('raw'), onepass_test.mbx('B'), onepass_test.pk('raw'));
select onepass_test.ok(
    (select bool_and(c.role = 3 and not c.owner and c.put_kinds is null and c.granted_by is null)
     from onepass_mailbox.credentials c where c.id in (onepass_test.cid('raw'), onepass_test.cid('m'), onepass_test.cid('b'))),
    'existing_rows_are_managers');
select onepass_test.ok(
    (select column_default = '3' and is_nullable = 'NO'
     from information_schema.columns
     where table_schema = 'onepass_mailbox' and table_name = 'credentials' and column_name = 'role'),
    'role_column_defaults_to_manager');

-- -------------------------------------------------------------- grants

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('w'), 2) = 'ok', 'manager_grants_a_writer');
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('r'), 1, null, '\x0102') = 'ok', 'manager_grants_a_reader');
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('l'), 2, onepass_test.kinds(array[14, 15, 16, 17])) = 'ok',
    'manager_grants_a_limited_writer');
reset role;
select onepass_test.ok(
    (select c.mailbox_id = onepass_test.mbx('A') and c.role = 1 and not c.owner and c.put_kinds is null
            and c.granted_by = onepass_test.cid('m') and c.enrolled_by is null and c.label = '\x0102'
            and c.public_key = onepass_test.pk('r') and c.revoked_at is null
     from onepass_mailbox.credentials c where c.id = onepass_test.cid('r')),
    'grant_writes_role_label_and_granted_by');
select onepass_test.ok(
    (select c.role = 2 and c.put_kinds = onepass_test.kinds(array[14, 15, 16, 17])
     from onepass_mailbox.credentials c where c.id = onepass_test.cid('l')),
    'grant_writes_put_kinds');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.nonces where credential_id = onepass_test.cid('w')) = 0,
    'grant_writes_no_nonce_for_the_new_credential');
set local role onepass_mailbox_api;

-- The granted key signs without a ticket.
select onepass_test.ok(onepass_test.info('w', 'A') = 'ok' and onepass_test.info('r', 'A') = 'ok',
    'granted_credentials_authenticate');

select onepass_test.ok(
    onepass_test.grant('w', 'A', onepass_test.pk('x'), 1) = 'forbidden'
    and onepass_test.grant('r', 'A', onepass_test.pk('x'), 1) = 'forbidden'
    and onepass_test.grant('l', 'A', onepass_test.pk('x'), 1) = 'forbidden'
    and onepass_test.set_role('w', 'A', 'r', 2) = 'forbidden'
    and onepass_test.set_role('r', 'A', 'r', 3) = 'forbidden',
    'only_manager_grants');
reset role;
select onepass_test.ok(onepass_test.cred('x') is null and (onepass_test.cred('r')).role = 1,
    'refused_grants_write_nothing');
set local role onepass_mailbox_api;

-- Keys: same rules as creation. A key of another mailbox, a key already
-- here, a small-order key and a short one are malformed.
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('b'), 1) = 'malformed', 'granted_key_in_other_mailbox_refused');
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('w'), 1) = 'malformed', 'granted_key_already_here_refused');
select onepass_test.ok(
    onepass_test.grant('m', 'A', decode('0100000000000000000000000000000000000000000000000000000000000000', 'hex'), 1) = 'malformed'
    and onepass_test.grant('m', 'A', '\x0102', 1) = 'malformed'
    and onepass_test.grant('m', 'A', null, 1) = 'malformed',
    'granted_weak_or_short_key_refused');
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('x'), 1, null, decode(repeat('00', 65), 'hex')) = 'malformed',
    'grant_label_over_64_is_malformed');
reset role;
select onepass_test.ok((onepass_test.cred('b')).mailbox_id = onepass_test.mbx('B') and onepass_test.cred('x') is null,
    'refused_key_grants_change_nothing');
set local role onepass_mailbox_api;

-- put_kinds only with the write role, 32 bytes; the role is 1 to 3.
select onepass_test.ok(
    onepass_test.grant('m', 'A', onepass_test.pk('x'), 1, onepass_test.kinds(array[14])) = 'malformed'
    and onepass_test.grant('m', 'A', onepass_test.pk('x'), 3, onepass_test.kinds(array[14])) = 'malformed'
    and onepass_test.grant('m', 'A', onepass_test.pk('x'), 2, '\x01') = 'malformed'
    and onepass_test.grant('m', 'A', onepass_test.pk('x'), 0) = 'malformed'
    and onepass_test.grant('m', 'A', onepass_test.pk('x'), 4) = 'malformed'
    and onepass_test.grant('m', 'A', onepass_test.pk('x'), null) = 'malformed'
    and onepass_test.set_role('m', 'A', 'w', 1, onepass_test.kinds(array[14])) = 'malformed'
    and onepass_test.set_role('m', 'A', 'w', 3, onepass_test.kinds(array[14])) = 'malformed'
    and onepass_test.set_role('m', 'A', 'w', 2, decode(repeat('00', 33), 'hex')) = 'malformed'
    and onepass_test.set_role('m', 'A', 'w', 0) = 'malformed',
    'put_kinds_only_with_write_role');

-- The plan's max_credentials counts active credentials.
reset role;
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('roles_tiny', 1048576, 100, 3, 6000, 100);
update onepass_mailbox.mailboxes set plan = 'roles_tiny' where id = onepass_test.mbx('T');
set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.grant('t1', 'T', onepass_test.pk('g1'), 1) = 'ok'
    and onepass_test.grant('t1', 'T', onepass_test.pk('g2'), 2) = 'ok'
    and onepass_test.grant('t1', 'T', onepass_test.pk('g3'), 3) = 'quota',
    'grant_respects_max_credentials');
select onepass_test.ok(
    onepass_test.revoke('t1', 'T', 'g1') = 'ok'
    and onepass_test.grant('t1', 'T', onepass_test.pk('g3'), 3) = 'ok',
    'grant_after_a_revoke_fits_again');

-- ------------------------------------------------------------- commits

select onepass_test.ok(onepass_test.put('m', 'A', 5, 1) = 'ok', 'manager_commits');
select onepass_test.ok(onepass_test.put('w', 'A', 5, 2) = 'ok' and onepass_test.del('w', 'A', 5, 2) = 'ok',
    'unrestricted_writer_puts_and_deletes_any_kind');

reset role;
create temporary table t_seq on commit drop as select onepass_test.next_seq('A') as s;
grant all on t_seq to public;
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put('r', 'A', 5, 3) = 'forbidden' and onepass_test.del('r', 'A', 5, 1) = 'forbidden',
    'read_role_cannot_commit');
-- Shapes do not matter: a reader is refused whatever it sends.
select onepass_test.answers(
    $$select * from onepass_mailbox.api_commit(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('A'),
        array[]::smallint[], array[]::bytea[], array[]::bigint[], array[]::smallint[], array[]::bigint[],
        array[]::bytea[], array[]::bytea[], array[]::integer[])$$,
    'forbidden', 'read_role_empty_batch_is_forbidden');
select onepass_test.answers(
    $$select * from onepass_mailbox.api_blob_announce(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('A'),
        array[decode(repeat('ab', 32), 'hex')], array[20000])$$,
    'forbidden', 'read_role_cannot_announce_blobs');
select onepass_test.answers(
    $$select * from onepass_mailbox.api_blob_announce(onepass_test.cid('l'), onepass_test.n(), now(), onepass_test.mbx('A'),
        array[decode(repeat('ab', 32), 'hex')], array[20000])$$,
    'ok', 'limited_writer_announces_blobs');

select onepass_test.ok(onepass_test.info('r', 'A') = 'ok', 'read_role_reads_info');
select onepass_test.answers(
    $$select * from onepass_mailbox.api_changes(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 100, false)$$,
    'ok', 'read_role_reads_changes');
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.api_changes(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('A'), 0, 100, false)
     where seq is not null),
    'read_role_sees_every_change'); -- rid 1, and rid 2 put then deleted (one row)
select onepass_test.answers(
    $$select * from onepass_mailbox.api_record(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('A'), 5::smallint, onepass_test.rid(1))$$,
    'ok', 'read_role_reads_a_record');

-- Kinds 14 to 17 only, no delete.
select onepass_test.ok(
    onepass_test.put('l', 'A', 14, 10) = 'ok'
    and onepass_test.put('l', 'A', 17, 11) = 'ok'
    and onepass_test.put2('l', 'A', 15, 16, 12) = 'ok',
    'limited_writer_puts_listed_kinds');
select onepass_test.ok(
    onepass_test.put('l', 'A', 5, 20) = 'forbidden'
    and onepass_test.put('l', 'A', 13, 21) = 'forbidden'
    and onepass_test.put('l', 'A', 18, 22) = 'forbidden'
    and onepass_test.put2('l', 'A', 14, 5, 23) = 'forbidden',
    'limited_writer_puts_listed_kinds_only');
select onepass_test.ok(onepass_test.del('l', 'A', 14, 10) = 'forbidden' and onepass_test.del('l', 'A', 5, 1) = 'forbidden',
    'limited_writer_cannot_delete');
reset role;
select onepass_test.ok(
    onepass_test.next_seq('A') = (select s from t_seq) + 4
    and not exists (select 1 from onepass_mailbox.records r
                    where r.mailbox_id = onepass_test.mbx('A') and r.id in (onepass_test.rid(3), onepass_test.rid(20),
                        onepass_test.rid(21), onepass_test.rid(22), onepass_test.rid(23), onepass_test.rid(24)))
    and (select not deleted from onepass_mailbox.records r
         where r.mailbox_id = onepass_test.mbx('A') and r.kind = 14 and r.id = onepass_test.rid(10)),
    'forbidden_batches_write_nothing');

-- A forbidden request consumed its nonce and its rate hit: replaying it is
-- a replay.
select onepass_test.ok(
    (select count from onepass_mailbox.rate
     where key = onepass_test.cid('r') || '\x00000000000000000000000000000000'::bytea
       and window_start = date_trunc('minute', now(), 'UTC')) > 0,
    'forbidden_reader_has_a_rate_row');
create temporary table t_rate on commit drop as
select count from onepass_mailbox.rate
where key = onepass_test.cid('r') || '\x00000000000000000000000000000000'::bytea
  and window_start = date_trunc('minute', now(), 'UTC');
grant all on t_rate to public;
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_mailbox.api_commit(onepass_test.cid('r'), onepass_test.nonce(424242), now(), onepass_test.mbx('A'),
        array[5]::smallint[], array[onepass_test.rid(30)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01'::bytea], array[null]::bytea[], array[1])$$,
    'forbidden', 'forbidden_commit_answers_in_band');
reset role;
select onepass_test.ok(
    (select count from onepass_mailbox.rate
     where key = onepass_test.cid('r') || '\x00000000000000000000000000000000'::bytea
       and window_start = date_trunc('minute', now(), 'UTC')) = (select count from t_rate) + 1
    and exists (select 1 from onepass_mailbox.nonces where credential_id = onepass_test.cid('r') and nonce = onepass_test.nonce(424242)),
    'forbidden_counts_rate_and_keeps_nonce');
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select * from onepass_mailbox.api_commit(onepass_test.cid('r'), onepass_test.nonce(424242), now(), onepass_test.mbx('A'),
        array[5]::smallint[], array[onepass_test.rid(30)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01'::bytea], array[null]::bytea[], array[1])$$,
    'OP401', 'replay', 'forbidden_counts_nonce_and_rate');
select onepass_test.answers(
    $$select * from onepass_mailbox.api_grant_credential(onepass_test.cid('w'), onepass_test.nonce(434343), now(), onepass_test.mbx('A'),
        onepass_test.pk('x'), 1::smallint, null, '\x')$$,
    'forbidden', 'forbidden_grant_answers_in_band');
select onepass_test.raises(
    $$select * from onepass_mailbox.api_grant_credential(onepass_test.cid('w'), onepass_test.nonce(434343), now(), onepass_test.mbx('A'),
        onepass_test.pk('x'), 1::smallint, null, '\x')$$,
    'OP401', 'replay', 'forbidden_grant_nonce_is_kept');

-- ---------------------------------------------------------- role changes

select onepass_test.ok(onepass_test.set_role('m', 'A', 'w', 1) = 'ok' and onepass_test.put('w', 'A', 5, 40) = 'forbidden',
    'manager_demotes_a_writer_to_reader');
select onepass_test.ok(
    onepass_test.set_role('m', 'A', 'w', 2, onepass_test.kinds(array[14])) = 'ok'
    and onepass_test.put('w', 'A', 14, 41) = 'ok'
    and onepass_test.put('w', 'A', 5, 42) = 'forbidden',
    'manager_limits_a_writer');
select onepass_test.ok(onepass_test.set_role('m', 'A', 'w', 3) = 'ok' and onepass_test.put('w', 'A', 5, 43) = 'ok',
    'manager_promotes_a_writer');
reset role;
select onepass_test.ok((onepass_test.cred('w')).role = 3 and (onepass_test.cred('w')).put_kinds is null,
    'promotion_clears_put_kinds');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_role('w', 'A', 'r', 2) = 'ok', 'promoted_writer_manages');
select onepass_test.ok(onepass_test.set_role('m', 'A', 'n', 2) = 'not_found', 'set_role_of_unknown_credential_is_not_found');
select onepass_test.ok(onepass_test.set_role('m', 'A', 'b', 2) = 'not_found', 'set_role_across_mailboxes_is_not_found');
reset role;
select onepass_test.ok((onepass_test.cred('b')).role = 3, 'set_role_across_mailboxes_has_no_effect');
set local role onepass_mailbox_api;

-- ------------------------------------------------------------- revokes

-- Self revoke for anyone; revoking another credential needs the manager role.
select onepass_test.ok(onepass_test.grant('m', 'A', onepass_test.pk('s'), 1) = 'ok'
    and onepass_test.grant('m', 'A', onepass_test.pk('s2'), 2) = 'ok', 'self_revoke_fixture');
select onepass_test.ok(onepass_test.revoke('s', 'A', 's2') = 'forbidden' and onepass_test.revoke('l', 'A', 's') = 'forbidden',
    'non_manager_cannot_revoke_another');
select onepass_test.ok(onepass_test.revoke('s', 'A', 's') = 'ok', 'self_revoke_allowed_for_reader');
select onepass_test.ok(onepass_test.revoke('s2', 'A', 's2') = 'ok', 'self_revoke_allowed_for_writer');
reset role;
select onepass_test.ok((onepass_test.cred('s')).revoked_at is not null and (onepass_test.cred('s2')).revoked_at is not null
    and (onepass_test.cred('s2')).push_kind is null,
    'self_revokes_are_recorded');
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select onepass_test.info('s', 'A')$$, 'OP403', 'revoked_credential', 'self_revoked_reader_is_out');
select onepass_test.ok(onepass_test.set_role('m', 'A', 's', 2) = 'not_found', 'set_role_of_revoked_credential_is_not_found');

-- An owner is revoked or demoted only by itself.
reset role;
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, role, owner)
values (onepass_test.cid('o'), onepass_test.mbx('A'), onepass_test.pk('o'), 3, true);
set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.revoke('m', 'A', 'o') = 'forbidden'
    and onepass_test.set_role('m', 'A', 'o', 2) = 'forbidden'
    and onepass_test.set_role('m', 'A', 'o', 1) = 'forbidden',
    'owner_revoked_only_by_itself');
reset role;
select onepass_test.ok((onepass_test.cred('o')).role = 3 and (onepass_test.cred('o')).revoked_at is null,
    'owner_untouched_by_another_manager');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_role('o', 'A', 'o', 2) = 'ok', 'owner_demotes_itself');
-- Another manager may give an owner the manager role back, never less.
select onepass_test.ok(
    onepass_test.set_role('m', 'A', 'o', 2, onepass_test.kinds(array[14])) = 'forbidden'
    and onepass_test.set_role('m', 'A', 'o', 3) = 'ok',
    'owner_promoted_by_another_manager');
select onepass_test.ok(onepass_test.set_role('o', 'A', 'm', 2) = 'ok' and onepass_test.set_role('o', 'A', 'm', 3) = 'ok',
    'owner_changes_a_manager');
select onepass_test.ok(onepass_test.revoke('o', 'A', 'o') = 'ok', 'owner_revokes_itself');

-- The last active manager stays: neither revoked nor demoted, even by itself.
select onepass_test.ok(onepass_test.grant('m2', 'L', onepass_test.pk('e'), 2) = 'ok', 'last_manager_fixture');
select onepass_test.ok(
    onepass_test.revoke('m2', 'L', 'm2') = 'forbidden'
    and onepass_test.set_role('m2', 'L', 'm2', 2) = 'forbidden'
    and onepass_test.set_role('m2', 'L', 'm2', 1) = 'forbidden'
    and onepass_test.set_role('m2', 'L', 'm2', 3) = 'ok',
    'last_manager_kept');
select onepass_test.ok(onepass_test.set_role('m2', 'L', 'e', 3) = 'ok' and onepass_test.set_role('m2', 'L', 'm2', 1) = 'ok',
    'a_second_manager_frees_the_first');
select onepass_test.ok(onepass_test.revoke('e', 'L', 'e') = 'forbidden', 'the_second_is_now_the_last');
select onepass_test.ok(onepass_test.revoke('e', 'L', 'm2') = 'ok' and onepass_test.revoke('e', 'L', 'm2') = 'ok',
    'revoking_a_revoked_credential_changes_nothing');
select onepass_test.ok(onepass_test.revoke('e', 'L', 'n') = 'not_found', 'revoke_unknown_credential_is_not_found');
reset role;
select onepass_test.ok(
    (select count(*) from onepass_mailbox.credentials c
     where c.mailbox_id = onepass_test.mbx('L') and c.revoked_at is null and c.role = 3) = 1,
    'one_active_manager_left');
set local role onepass_mailbox_api;

-- ------------------------------------------------------------- enroll

-- A ticket enrolls only when its approver manages the mailbox; the new
-- credential is a manager (account mailbox).
select onepass_test.answers(
    $$select * from onepass_mailbox.api_enroll(onepass_test.pk('e2'), onepass_test.n(), now(), onepass_test.mbx('A'),
        onepass_test.cid('l'), decode(repeat('71', 32), 'hex'), now() + interval '300 seconds', '\x',
        decode(md5('roles-enroll') || md5('roles-enroll/'), 'hex'))$$,
    'forbidden', 'ticket_from_non_manager_refused');
reset role;
select onepass_test.ok(onepass_test.cred('e2') is null
    and not exists (select 1 from onepass_mailbox.used_tickets where ticket_hash = decode(repeat('71', 32), 'hex')),
    'refused_ticket_writes_nothing');
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_mailbox.api_enroll(onepass_test.pk('e2'), onepass_test.n(), now(), onepass_test.mbx('A'),
        onepass_test.cid('m'), decode(repeat('72', 32), 'hex'), now() + interval '300 seconds', '\x',
        decode(md5('roles-enroll') || md5('roles-enroll/'), 'hex'))$$,
    'ok', 'ticket_from_manager_enrolls');
reset role;
select onepass_test.ok((onepass_test.cred('e2')).role = 3 and not (onepass_test.cred('e2')).owner
    and (onepass_test.cred('e2')).enrolled_by = onepass_test.cid('m'),
    'enrolled_credential_is_a_manager');

-- ------------------------------------------------------------ privileges

select onepass_test.ok(
    (select bool_and(p.prosecdef and p.proowner::regrole::text = 'onepass_mailbox_owner'
                     and has_function_privilege('onepass_mailbox_api', p.oid, 'execute')
                     and not has_function_privilege('anon', p.oid, 'execute')
                     and not has_function_privilege('service_role', p.oid, 'execute'))
     from pg_proc p
     where p.pronamespace = 'onepass_mailbox'::regnamespace
       and p.proname in ('api_grant_credential', 'api_set_credential_role')) is true,
    'grant_and_set_role_granted_to_the_api_only');
