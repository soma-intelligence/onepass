-- Per-device push targets (Task 26; sharing spec 13.7). Starts as the
-- harness superuser, inside a transaction the harness rolls back; calls
-- under test run as onepass_mailbox_api (entry points) or as the janitor
-- (push_take, push_forget_target), state is read back as the superuser.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-push-targets-test-key/' || n, 'sha256') as pk
      from unnest(array['a', 'b', 'c']) as n) k;

create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.tag(i integer) returns bytea language sql immutable as $$
    select onepass_test.nonce(3000000 + i) $$;
create function onepass_test.target(cred text, mbx text, i integer, kind integer, token bytea)
returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_set_push_target(onepass_test.cid(cred), onepass_test.n(), now(),
        onepass_test.mbx(mbx), onepass_test.tag(i), kind::smallint, token) s
$$;
create function onepass_test.put(cred text, mbx text, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[5]::smallint[], array[onepass_test.nonce(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01'::bytea], array[null]::bytea[], array[1]) c limit 1
$$;
grant execute on all functions in schema onepass_test to public;

-- Mailbox M owned by a; b granted as a writer (one credential shared by a
-- member's devices); c the owner of another mailbox N.
set local role onepass_mailbox_api;
insert into t_mbx
select 'M', r.mailbox_id from onepass_mailbox.api_create_mailbox(
    onepass_test.pk('a'), onepass_test.n(), now(), null, '\x', decode(md5('pt/a') || md5('pt/a/'), 'hex'), true) r;
insert into t_mbx
select 'N', r.mailbox_id from onepass_mailbox.api_create_mailbox(
    onepass_test.pk('c'), onepass_test.n(), now(), null, '\x', decode(md5('pt/c') || md5('pt/c/'), 'hex'), true) r;
select onepass_test.ok(
    (select g.status = 'ok' from onepass_mailbox.api_grant_credential(
        onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('M'), onepass_test.pk('b'), 2::smallint, null, '\x') g),
    'push_targets_fixture_grant');

-- Shapes.
select onepass_test.ok(onepass_test.target('b', 'M', 1, 4, '\x01') = 'malformed', 'push_target_kind_four_refused');
select onepass_test.ok(onepass_test.target('b', 'M', 1, 1, null) = 'malformed', 'push_target_without_token_refused');
select onepass_test.ok(onepass_test.target('b', 'M', 1, 0, '\x01') = 'malformed', 'push_target_none_with_token_refused');
select onepass_test.ok(
    (select s.status = 'malformed' from onepass_mailbox.api_set_push_target(onepass_test.cid('b'), onepass_test.n(), now(),
        onepass_test.mbx('M'), '\x01', 1::smallint, '\x01') s),
    'push_target_short_tag_refused');
select onepass_test.ok(
    onepass_test.target('b', 'M', 1, 1, convert_to(repeat('t', 4097), 'UTF8')) = 'malformed',
    'push_target_token_over_4096_refused');

-- push_target_cap_eight: eight tags, a ninth is quota; replacing one of the
-- eight is fine.
select onepass_test.ok(
    (select bool_and(onepass_test.target('b', 'M', i, 2, ('\xb0'::bytea || int4send(i))) = 'ok') from generate_series(1, 8) i),
    'push_target_eight_ok');
select onepass_test.ok(onepass_test.target('b', 'M', 9, 2, '\xb9') = 'quota', 'push_target_cap_eight');
select onepass_test.ok(onepass_test.target('b', 'M', 3, 1, '\xc3') = 'ok', 'push_target_replace_within_cap');
-- The cap is per credential: a has its own eight.
select onepass_test.ok(onepass_test.target('a', 'M', 9, 2, '\xa9') = 'ok', 'push_target_cap_is_per_credential');

-- push_target_kind_none_deletes
select onepass_test.ok(onepass_test.target('b', 'M', 8, 0, '\x') = 'ok', 'push_target_kind_none_ok');
reset role;
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.push_targets where credential_id = onepass_test.cid('b') and tag = onepass_test.tag(8))
    and (select count(*) = 7 from onepass_mailbox.push_targets where credential_id = onepass_test.cid('b'))
    and (select kind = 1 and token = '\xc3' from onepass_mailbox.push_targets
         where credential_id = onepass_test.cid('b') and tag = onepass_test.tag(3)),
    'push_target_kind_none_deletes');

-- RLS: under the owner role, mailbox N sees none of M's targets.
set local role onepass_mailbox_owner;
select set_config('onepass.mailbox', encode(onepass_test.mbx('N'), 'hex'), true);
select onepass_test.ok((select count(*) = 0 from onepass_mailbox.push_targets), 'push_targets_rls_other_mailbox');
select set_config('onepass.mailbox', '', true);
reset role;

-- push_take_returns_targets_of_author_too: b commits (the queue excludes
-- b's historical token), every target of b and a still comes back.
update onepass_mailbox.credentials set push_kind = 1, push_token = '\x0b' where id = onepass_test.cid('b');
update onepass_mailbox.credentials set push_kind = 1, push_token = '\x0a' where id = onepass_test.cid('a');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put('b', 'M', 1) = 'ok', 'push_targets_fixture_commit_by_b');
reset role;
set local role onepass_mailbox_janitor;
create temporary table t_take on commit drop as select * from onepass_mailbox.push_take(100);
reset role;
select onepass_test.ok(
    (select count(*) = 7 from t_take where credential_id = onepass_test.cid('b') and tag is not null)
    and (select count(*) = 1 from t_take where credential_id = onepass_test.cid('a') and tag is not null)
    and not exists (select 1 from t_take where credential_id = onepass_test.cid('b') and tag is null)
    and exists (select 1 from t_take where credential_id = onepass_test.cid('a') and tag is null and push_token = '\x0a'),
    'push_take_returns_targets_of_author_too');
select onepass_test.ok(
    (select bool_and(mailbox_id = onepass_test.mbx('M')) from t_take), 'push_take_targets_only_of_the_woken_mailbox');

-- push_forget_target_only_if_unchanged
set local role onepass_mailbox_janitor;
select onepass_mailbox.push_forget_target(onepass_test.cid('b'), onepass_test.tag(3), '\x99');
select onepass_mailbox.push_forget_target(onepass_test.cid('b'), onepass_test.tag(4), '\xb000000004');
reset role;
select onepass_test.ok(
    exists (select 1 from onepass_mailbox.push_targets where credential_id = onepass_test.cid('b') and tag = onepass_test.tag(3))
    and not exists (select 1 from onepass_mailbox.push_targets
                    where credential_id = onepass_test.cid('b') and tag = onepass_test.tag(4)),
    'push_forget_target_only_if_unchanged');
select onepass_test.throws(
    $$select onepass_mailbox.push_forget_target('\x01', '\x01', '\x01')$$, '22023', 'push_forget_target_shapes');

-- revoked_credential_targets_dropped: a (manager) revokes b.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select s.status = 'ok' from onepass_mailbox.api_revoke_credential(
        onepass_test.cid('a'), onepass_test.n(), now(), onepass_test.mbx('M'), onepass_test.cid('b')) s),
    'push_targets_fixture_revoke');
reset role;
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.push_targets where credential_id = onepass_test.cid('b')),
    'revoked_credential_targets_dropped');
select onepass_test.ok(
    exists (select 1 from onepass_mailbox.push_targets where credential_id = onepass_test.cid('a')),
    'other_credential_targets_kept');
