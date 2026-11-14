-- OnePass Business: plan `managed` and the invites an org mints for its
-- members. Starts as the harness superuser, inside a transaction the harness
-- rolls back; calls under test run as onepass_mailbox_api, state is read back
-- as the superuser. now() is fixed for the whole transaction.
--
-- Contract under test: a manager (role 3) of an org mailbox (plan org, kind
-- 1, no parent, not deleted) mints a one-use invite of plan managed
-- (api_org_invite) valid 1 to 168 hours, 200 a day per org mailbox. The
-- token is returned once; the server keeps its SHA-256 only. A member's
-- device spends it with api_create_mailbox (unchanged) and gets a mailbox on
-- plan managed. Anything else: malformed, forbidden, rate_limited in band,
-- frozen and deleted as raised by authentication.

create temporary table oi_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table oi_mbx (name text primary key, id bytea) on commit drop;
create temporary table oi_tokens (name text primary key, token bytea) on commit drop;
create temporary sequence oi_n start 940000;
grant all on oi_keys, oi_mbx, oi_tokens to public;
grant usage on sequence oi_n to public;

insert into oi_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-org-invite-test-key/' || n, 'sha256') as pk
      from unnest(array['o', 'om', 'ow', 'or', 'a', 'c', 'f', 'd', 'l', 'n', 'n2']) as n) k;

create function onepass_test.oi_pk(text) returns bytea language sql stable as $$ select pk from oi_keys where name = $1 $$;
create function onepass_test.oi_cid(text) returns bytea language sql stable as $$ select cid from oi_keys where name = $1 $$;
create function onepass_test.oi_mbx(text) returns bytea language sql stable as $$ select id from oi_mbx where name = $1 $$;
create function onepass_test.oi_n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('oi_n')) $$;
-- api_create_mailbox with key `key`, invite `invite` (null for open signup);
-- an ok mailbox is kept as `name`.
create function onepass_test.oi_open(name text, key text, invite bytea) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        onepass_test.oi_pk(key), onepass_test.oi_n(), now(), invite, '\x',
        decode(md5('org-invite/' || name) || md5('org-invite/' || name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into oi_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
-- api_org_invite by `cred` in mailbox `mbx`.
create function onepass_test.oi_invite(cred text, mbx text, uses integer, ttl integer)
returns table (status text, retry_after integer, token bytea) language sql volatile as $$
    select * from onepass_mailbox.api_org_invite(
        onepass_test.oi_cid(cred), onepass_test.oi_n(), now(), onepass_test.oi_mbx(mbx), uses::smallint, ttl::smallint)
$$;
create function onepass_test.oi_status(cred text, mbx text, uses integer, ttl integer) returns text language sql volatile as $$
    select i.status from onepass_test.oi_invite(cred, mbx, uses, ttl) i
$$;
create function onepass_test.oi_grant(cred text, mbx text, key text, role integer) returns text language sql volatile as $$
    select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.oi_cid(cred), onepass_test.oi_n(), now(), onepass_test.oi_mbx(mbx), onepass_test.oi_pk(key),
        role::smallint, null, '\x') g
$$;
create function onepass_test.oi_child(name text, cred text, parent text, owner text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_child(
        onepass_test.oi_cid(cred), onepass_test.oi_n(), now(), onepass_test.oi_mbx(parent), 2::smallint,
        onepass_test.oi_pk(owner), '\x0a');
    if r.status = 'ok' then
        insert into oi_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
grant execute on all functions in schema onepass_test to public;

-- The plan row.
select onepass_test.ok(
    (select max_bytes = 268435456 and max_records = 100000 and max_credentials = 32 and req_per_min = 120
            and max_commit_ops = 20000 and max_children_shared = 16 and max_children_contact = 256
     from onepass_mailbox.plans where plan = 'managed'),
    'managed_plan_row_matches_seed');

-- Fixtures: org mailboxes O (o; om manage, ow write, or read), F (frozen
-- later), D (deleted later), L (the daily limit), each through an invite of
-- plan org; an account mailbox A (open signup) and its shared child C, owned
-- by key c.
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest('oi-org-invite', 'sha256'), 'org', 4, now() + interval '1 day');
set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.oi_open('O', 'o', convert_to('oi-org-invite', 'UTF8')) = 'ok'
    and onepass_test.oi_open('F', 'f', convert_to('oi-org-invite', 'UTF8')) = 'ok'
    and onepass_test.oi_open('D', 'd', convert_to('oi-org-invite', 'UTF8')) = 'ok'
    and onepass_test.oi_open('L', 'l', convert_to('oi-org-invite', 'UTF8')) = 'ok'
    and onepass_test.oi_open('A', 'a', null) = 'ok',
    'org_invite_fixture_mailboxes_created');
select onepass_test.ok(
    onepass_test.oi_grant('o', 'O', 'om', 3) = 'ok' and onepass_test.oi_grant('o', 'O', 'ow', 2) = 'ok'
    and onepass_test.oi_grant('o', 'O', 'or', 1) = 'ok'
    and onepass_test.oi_child('C', 'a', 'A', 'c') = 'ok',
    'org_invite_fixture_credentials_and_child');
reset role;
select onepass_test.ok(
    (select bool_and(m.plan = 'org') from onepass_mailbox.mailboxes m
     where m.id in (onepass_test.oi_mbx('O'), onepass_test.oi_mbx('F'), onepass_test.oi_mbx('D'), onepass_test.oi_mbx('L')))
    and (select m.plan <> 'org' from onepass_mailbox.mailboxes m where m.id = onepass_test.oi_mbx('A'))
    and (select m.parent_id = onepass_test.oi_mbx('A') from onepass_mailbox.mailboxes m where m.id = onepass_test.oi_mbx('C')),
    'org_invite_fixture_plans');
-- From here on a create needs a valid invite.
delete from onepass_mailbox.settings;

-- A manager mints: ok and a 32 byte token, whose SHA-256 is an invite of
-- plan managed, one use, expiring after the ttl. The creator and a granted
-- manager both may.
set local role onepass_mailbox_api;
insert into oi_tokens select 'creator', i.token from onepass_test.oi_invite('o', 'O', 1, 24) i where i.status = 'ok';
insert into oi_tokens select 'granted', i.token from onepass_test.oi_invite('om', 'O', 1, 168) i where i.status = 'ok';
reset role;
select onepass_test.ok(
    (select count(*) = 2 and bool_and(octet_length(token) = 32) from oi_tokens)
    and (select token from oi_tokens where name = 'creator') <> (select token from oi_tokens where name = 'granted')
    and (select plan = 'managed' and uses_left = 1 and expires_at = now() + interval '24 hours'
         from onepass_mailbox.invites
         where token_hash = extensions.digest((select token from oi_tokens where name = 'creator'), 'sha256'))
    and (select plan = 'managed' and uses_left = 1 and expires_at = now() + interval '168 hours'
         from onepass_mailbox.invites
         where token_hash = extensions.digest((select token from oi_tokens where name = 'granted'), 'sha256')),
    'org_invite_ok_for_manager');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.invites i join oi_tokens t on i.token_hash = t.token),
    'org_invite_stores_hash_only');

-- The token creates a mailbox on plan managed, once.
set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.oi_open('N', 'n', (select token from oi_tokens where name = 'creator')) = 'ok'
    and onepass_test.oi_open('N2', 'n2', (select token from oi_tokens where name = 'creator')) = 'not_found',
    'org_invite_token_spent_once');
reset role;
select onepass_test.ok(
    (select plan = 'managed' and kind = 1 and parent_id is null and created_by = onepass_test.oi_cid('n')
     from onepass_mailbox.mailboxes where id = onepass_test.oi_mbx('N'))
    and onepass_test.oi_mbx('N2') is null
    and (select uses_left = 0 from onepass_mailbox.invites
         where token_hash = extensions.digest((select token from oi_tokens where name = 'creator'), 'sha256')),
    'org_invite_token_creates_managed_mailbox_once');

-- Not an org mailbox: an account mailbox, a child, a managed mailbox.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.oi_status('a', 'A', 1, 24) = 'forbidden', 'org_invite_refused_on_non_org_mailbox');
select onepass_test.ok(onepass_test.oi_status('n', 'N', 1, 24) = 'forbidden', 'org_invite_refused_on_managed_mailbox');
select onepass_test.ok(onepass_test.oi_status('c', 'C', 1, 24) = 'forbidden', 'org_invite_refused_for_child');

-- Below manager.
select onepass_test.ok(onepass_test.oi_status('ow', 'O', 1, 24) = 'forbidden', 'org_invite_refused_for_role_2');
select onepass_test.ok(onepass_test.oi_status('or', 'O', 1, 24) = 'forbidden', 'org_invite_refused_for_role_1');

-- Shapes: one use only, 1 to 168 hours.
select onepass_test.ok(
    onepass_test.oi_status('o', 'O', 0, 24) = 'malformed'
    and onepass_test.oi_status('o', 'O', 2, 24) = 'malformed'
    and onepass_test.oi_status('o', 'O', 1, 0) = 'malformed'
    and onepass_test.oi_status('o', 'O', 1, 169) = 'malformed'
    and onepass_test.oi_status('o', 'O', 1, -1) = 'malformed'
    and (select i.status = 'malformed' from onepass_mailbox.api_org_invite(
             onepass_test.oi_cid('o'), onepass_test.oi_n(), now(), onepass_test.oi_mbx('O'), null, 24::smallint) i)
    and (select i.status = 'malformed' from onepass_mailbox.api_org_invite(
             onepass_test.oi_cid('o'), onepass_test.oi_n(), now(), onepass_test.oi_mbx('O'), 1::smallint, null) i),
    'org_invite_malformed_uses_and_ttl');
-- An unknown credential is refused as on every signed route.
select onepass_test.raises(
    $$select onepass_test.oi_status('a', 'O', 1, 24)$$, 'OP403', 'unknown_credential', 'org_invite_unknown_credential');
reset role;

-- Only the two managers' invites and the managed mailbox were written.
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.invites where plan = 'managed'),
    'org_invite_refusals_write_nothing');

-- Frozen and deleted org mailboxes.
update onepass_mailbox.mailboxes set frozen = true where id = onepass_test.oi_mbx('F');
update onepass_mailbox.mailboxes set deleted_at = now() where id = onepass_test.oi_mbx('D');
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select onepass_test.oi_status('f', 'F', 1, 24)$$, 'OP403', 'frozen', 'org_invite_refused_when_frozen');
select onepass_test.raises(
    $$select onepass_test.oi_status('d', 'D', 1, 24)$$, 'OP404', 'not_found', 'org_invite_refused_when_deleted');

-- 200 a day per org mailbox, then rate_limited with the time to the next
-- UTC day. Refusals before the count (malformed) do not count.
select onepass_test.ok(onepass_test.oi_status('l', 'L', 0, 24) = 'malformed', 'org_invite_rate_fixture_malformed');
select onepass_test.ok(
    (select bool_and(onepass_test.oi_status('l', 'L', 1, 1) = 'ok') from generate_series(1, 200)),
    'org_invite_rate_200_ok');
select onepass_test.ok(
    (select i.status = 'rate_limited' and i.retry_after between 1 and 86400 and i.token is null
     from onepass_test.oi_invite('l', 'L', 1, 1) i),
    'org_invite_rate_limited');
-- The counter is the org mailbox's own: O still mints.
select onepass_test.ok(onepass_test.oi_status('o', 'O', 1, 1) = 'ok', 'org_invite_rate_per_mailbox');
reset role;
select onepass_test.ok(
    (select count(*) = 203 from onepass_mailbox.invites where plan = 'managed'),
    'org_invite_rate_limited_writes_nothing');
