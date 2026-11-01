-- Child mailboxes for shared vaults, families and contacts (Task 24, spec
-- D.3, D.7; sharing spec 13.3, 13.5, 13.6, 13.8). Starts as the harness
-- superuser, inside a transaction the harness rolls back; calls under test
-- run as onepass_mailbox_api, state is read back as the superuser.
--
-- A manager (role 3) of an account mailbox (kind 1) creates a child of kind
-- 2 (shared vault or family, plan shared) or 3 (contact, plan contact) with
-- a fresh owner key (api_create_child). The parent's plan caps its live
-- children per kind, and a parent creates 20 a day at most. The child's
-- only credential is its owner (role 3, owner). Members join a child only
-- through grants: an enroll ticket is refused. The owner deletes its child
-- at any time (api_delete_mailbox); an account mailbox is deleted only
-- under the Task 23 rules and only without a live child.
--
-- Not tested here (one session): two concurrent creations under one parent
-- both waiting on the parent row lock, which serializes the cap check.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-children-test-key/' || n, 'sha256') as pk
      from unnest(array['p', 'pm', 'pw', 'pr', 'pl', 'q', 'r', 'r2', 'd', 'e', 'en',
                        'o1', 'o2', 'o3', 'o4', 'o5', 'o6', 'o7', 'om', 'ow', 'x']) as n) k;

create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
-- A throwaway owner key from a number (never signs anything).
create function onepass_test.okey(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-children-owner/' || i) || md5('onepass-children-owner//' || i), 'hex') $$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        onepass_test.pk(key), onepass_test.n(), now(), null, '\x',
        decode(md5('children/' || name) || md5('children/' || name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
-- api_create_child by `cred` in mailbox `parent`; an ok child is kept as `name`.
create function onepass_test.child(name text, cred text, parent text, kind integer, owner_key bytea)
returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_child(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(parent), kind::smallint, owner_key, '\x0a');
    if r.status = 'ok' and name is not null then
        insert into t_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
create function onepass_test.grant(cred text, mbx text, key text, role integer, kinds bytea default null)
returns text language sql volatile as $$
    select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.pk(key),
        role::smallint, kinds, '\x') g
$$;
create function onepass_test.del(cred text, mbx text) returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_delete_mailbox(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx)) s
$$;
create function onepass_test.revoke(cred text, mbx text, target text) returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_revoke_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(target)) s
$$;
create function onepass_test.put(cred text, mbx text, i integer, data bytea default '\x01') returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[5]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array[data], array[null]::bytea[], array[octet_length(data)]) c limit 1
$$;
create function onepass_test.enroll(approver text, mbx text, key text, i integer) returns text language sql volatile as $$
    select e.status from onepass_mailbox.api_enroll(onepass_test.pk(key), onepass_test.n(), now(), onepass_test.mbx(mbx),
        onepass_test.cid(approver), decode(md5('children-ticket/' || i) || md5('children-ticket//' || i), 'hex'),
        now() + interval '300 seconds', '\x', decode(md5('children-enroll') || md5('children-enroll/'), 'hex')) e
$$;
grant execute on all functions in schema onepass_test to public;

create function onepass_test.mb(mbx text) returns onepass_mailbox.mailboxes language sql stable as $$
    select * from onepass_mailbox.mailboxes where id = onepass_test.mbx(mbx) $$;
create function onepass_test.cred(key text) returns onepass_mailbox.credentials language sql stable as $$
    select * from onepass_mailbox.credentials where id = onepass_test.cid(key) $$;
revoke all on function onepass_test.mb(text), onepass_test.cred(text) from public;

-- Account mailboxes, each named after its creator key: P (p; pm manage,
-- pw write, pr read, pl write limited to kind 14), Q (q, on a small plan),
-- R and R2 (the daily limit), D (deletion), E (enroll).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(upper(k), k) = 'ok') from unnest(array['p', 'q', 'r', 'r2', 'd', 'e']) k),
    'children_fixture_mailboxes_created');
select onepass_test.ok(
    onepass_test.grant('p', 'P', 'pm', 3) = 'ok' and onepass_test.grant('p', 'P', 'pw', 2) = 'ok'
    and onepass_test.grant('p', 'P', 'pr', 1) = 'ok'
    and onepass_test.grant('p', 'P', 'pl', 2, onepass_test.rid(0) || onepass_test.rid(0)) = 'ok',
    'children_fixture_credentials_granted');
reset role;

-- A plan with two shared children and one contact, for the per-kind caps.
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops,
                                   max_children_shared, max_children_contact)
values ('tiny_parent', 1048576, 100, 4, 600, 100, 2, 1);
update onepass_mailbox.mailboxes set plan = 'tiny_parent' where id = onepass_test.mbx('Q');

-- ------------------------------------------------------------ schema

select onepass_test.ok(
    (select bool_and(m.kind = 1 and m.parent_id is null)
     from (values ('P'), ('Q'), ('R')) v (n) join lateral (select * from onepass_test.mb(v.n)) m on true),
    'account_mailbox_is_kind_1_without_parent');
select onepass_test.throws(
    $$update onepass_mailbox.mailboxes set kind = 4 where id = onepass_test.mbx('P')$$,
    '23514', 'kind_between_1_and_3');
select onepass_test.throws(
    $$update onepass_mailbox.mailboxes set kind = 2 where id = onepass_test.mbx('P')$$,
    '23514', 'child_kind_needs_a_parent');
select onepass_test.throws(
    $$update onepass_mailbox.mailboxes set parent_id = onepass_test.mbx('Q') where id = onepass_test.mbx('P')$$,
    '23514', 'account_kind_has_no_parent');
select onepass_test.ok(
    (select max_children_shared = 16 and max_children_contact = 256 from onepass_mailbox.plans where plan = 'free')
    and (select max_children_shared = 1024 and max_children_contact = 4096 from onepass_mailbox.plans where plan = 'selfhost'),
    'parent_plans_cap_children');
select onepass_test.ok(
    (select max_bytes = 134217728 and max_records = 100000 and max_credentials = 80 and req_per_min = 600
            and max_commit_ops = 20000 and max_children_shared = 0 and max_children_contact = 0
     from onepass_mailbox.plans where plan = 'shared'),
    'plan_shared_values');
select onepass_test.ok(
    (select max_bytes = 16777216 and max_records = 2000 and max_credentials = 4 and req_per_min = 120
            and max_commit_ops = 2000 and max_children_shared = 0 and max_children_contact = 0
     from onepass_mailbox.plans where plan = 'contact'),
    'plan_contact_values');

-- ------------------------------------------------------------ creation

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.child('V', 'p', 'P', 2, onepass_test.pk('o1')) = 'ok', 'child_created_by_parent_manager');
select onepass_test.ok(onepass_test.child('C', 'pm', 'P', 3, onepass_test.pk('o2')) = 'ok', 'granted_manager_creates_contact');
reset role;
select onepass_test.ok(
    (select m.kind = 2 and m.parent_id = onepass_test.mbx('P') and m.plan = 'shared'
            and m.created_by = onepass_test.cid('o1') and m.deleted_at is null
     from onepass_test.mb('V') m)
    and (select m.kind = 3 and m.parent_id = onepass_test.mbx('P') and m.plan = 'contact'
                and m.created_by = onepass_test.cid('o2')
         from onepass_test.mb('C') m),
    'child_row_has_parent_kind_and_plan');
select onepass_test.ok(
    (select c.mailbox_id = onepass_test.mbx('V') and c.role = 3 and c.owner and c.label = '\x0a'
            and c.granted_by is null and c.enrolled_by is null and c.first_used_at is null and c.revoked_at is null
     from onepass_test.cred('o1') c)
    and (select count(*) = 1 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('V')),
    'child_owner_is_manager_and_owner');
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.nonces where credential_id = onepass_test.cid('o1')),
    'child_owner_has_signed_nothing_yet');

set local role onepass_mailbox_api;
-- The owner works in its child, nowhere else; the parent's credential is
-- not one of the child.
select onepass_test.ok(onepass_test.put('o1', 'V', 1) = 'ok', 'child_owner_commits');
select onepass_test.ok(onepass_test.grant('o1', 'V', 'om', 3) = 'ok' and onepass_test.grant('o1', 'V', 'ow', 2) = 'ok',
    'child_owner_grants');
select onepass_test.ok(onepass_test.revoke('om', 'V', 'o1') = 'forbidden', 'child_owner_not_revoked_by_another_manager');
select onepass_test.raises($$select onepass_test.put('p', 'V', 2)$$, 'OP403', 'unknown_credential',
    'parent_credential_is_not_in_child');
select onepass_test.raises($$select onepass_test.put('o1', 'P', 2)$$, 'OP403', 'unknown_credential',
    'child_owner_is_not_in_parent');

-- Refusals, each after the signature: the caller's role, the parent's kind.
select onepass_test.ok(onepass_test.child(null, 'pw', 'P', 2, onepass_test.okey(1)) = 'forbidden'
                       and onepass_test.child(null, 'pr', 'P', 2, onepass_test.okey(2)) = 'forbidden'
                       and onepass_test.child(null, 'pl', 'P', 3, onepass_test.okey(3)) = 'forbidden',
    'limited_parent_credential_cannot_create_child');
select onepass_test.ok(onepass_test.child(null, 'o1', 'V', 2, onepass_test.okey(4)) = 'forbidden'
                       and onepass_test.child(null, 'om', 'V', 3, onepass_test.okey(5)) = 'forbidden',
    'child_of_child_refused');
select onepass_test.ok(onepass_test.child(null, 'p', 'P', 1, onepass_test.okey(6)) = 'malformed'
                       and onepass_test.child(null, 'p', 'P', 4, onepass_test.okey(7)) = 'malformed'
                       and onepass_test.child(null, 'p', 'P', 2, '\x0102') = 'malformed'
                       and onepass_test.child(null, 'p', 'P', 2, null) = 'malformed',
    'child_kind_and_key_shapes');
select onepass_test.ok(
    (select s.status = 'malformed' from onepass_mailbox.api_create_child(
        onepass_test.cid('p'), onepass_test.n(), now(), onepass_test.mbx('P'), 2::smallint, onepass_test.okey(8),
        decode(repeat('00', 65), 'hex')) s),
    'child_label_at_most_64_bytes');
-- A key some mailbox holds (the parent's creator, the first child's owner).
select onepass_test.ok(onepass_test.child(null, 'p', 'P', 2, onepass_test.pk('p')) = 'malformed'
                       and onepass_test.child(null, 'p', 'P', 3, onepass_test.pk('o1')) = 'malformed',
    'child_owner_key_must_be_fresh');
reset role;
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.mailboxes where parent_id = onepass_test.mbx('P')),
    'refused_creations_leave_no_child');
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.mailboxes where parent_id = onepass_test.mbx('V')),
    'no_grandchild');

-- ------------------------------------------------------------ limits

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.child('Q1', 'q', 'Q', 2, onepass_test.pk('o3')) = 'ok'
                       and onepass_test.child('Q2', 'q', 'Q', 2, onepass_test.okey(10)) = 'ok'
                       and onepass_test.child(null, 'q', 'Q', 2, onepass_test.okey(11)) = 'quota',
    'child_limits_per_kind_shared');
select onepass_test.ok(onepass_test.child('Q3', 'q', 'Q', 3, onepass_test.okey(12)) = 'ok'
                       and onepass_test.child(null, 'q', 'Q', 3, onepass_test.okey(13)) = 'quota',
    'child_limits_per_kind_contact');
-- Deleting a child frees its slot of that kind.
select onepass_test.ok(onepass_test.del('o3', 'Q1') = 'ok', 'owner_deletes_one_shared_child');
select onepass_test.ok(onepass_test.child('Q4', 'q', 'Q', 2, onepass_test.okey(14)) = 'ok'
                       and onepass_test.child(null, 'q', 'Q', 2, onepass_test.okey(15)) = 'quota',
    'deleted_child_frees_slot');
reset role;
select onepass_test.ok(
    (select count(*) = 4 from onepass_mailbox.mailboxes where parent_id = onepass_test.mbx('Q'))
    and (select count(*) = 3 from onepass_mailbox.mailboxes where parent_id = onepass_test.mbx('Q') and deleted_at is null),
    'deleted_child_row_stays');

-- 20 creations a day per parent, counted on SHA-256('onepass/child' || parent).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.child(null, 'r', 'R', 3, onepass_test.okey(100 + i)) = 'ok') from generate_series(1, 20) i),
    'twenty_children_a_day');
select onepass_test.ok(
    (select s.status = 'rate_limited' and s.retry_after between 1 and 86400 and s.mailbox_id is null
     from onepass_mailbox.api_create_child(onepass_test.cid('r'), onepass_test.n(), now(), onepass_test.mbx('R'),
         3::smallint, onepass_test.okey(121), '\x') s),
    'child_daily_rate');
select onepass_test.ok(onepass_test.child(null, 'r2', 'R2', 3, onepass_test.okey(122)) = 'ok', 'child_rate_is_per_parent');
reset role;
select onepass_test.ok(
    (select count(*) = 20 from onepass_mailbox.mailboxes where parent_id = onepass_test.mbx('R')),
    'rate_limited_creation_leaves_no_child');
select onepass_test.ok(
    (select r.count = 21 from onepass_mailbox.rate r
     where r.key = extensions.digest('onepass/child'::bytea || onepass_test.mbx('R'), 'sha256')
       and r.window_start = date_trunc('day', now(), 'UTC')),
    'child_rate_key_and_day_window');

-- A child's quota is its own plan's; the parent's usage does not count.
update onepass_mailbox.mailboxes set bytes_used = 268435456 - 1 where id = onepass_test.mbx('P');
update onepass_mailbox.mailboxes set bytes_used = 134217728 - 4 where id = onepass_test.mbx('V');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put('o1', 'V', 2, '\x0102') = 'ok', 'child_writes_with_full_parent');
select onepass_test.ok(onepass_test.put('o1', 'V', 3, '\x010203') = 'quota', 'child_quota_is_its_own_plan');
reset role;
select onepass_test.ok(
    (select bytes_used = 134217728 - 2 from onepass_test.mb('V'))
    and (select bytes_used = 268435456 - 1 from onepass_test.mb('P')),
    'child_quota_counters_apart');
select onepass_test.ok(
    (select count(*) = 3 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('V')),
    'shared_child_holds_its_granted_credentials');
set local role onepass_mailbox_api;
-- Plan contact: 4 credentials.
select onepass_test.ok(onepass_test.grant('o2', 'C', 'o4', 2) = 'ok' and onepass_test.grant('o2', 'C', 'o5', 2) = 'ok'
                       and onepass_test.grant('o2', 'C', 'o6', 2) = 'ok' and onepass_test.grant('o2', 'C', 'o7', 2) = 'quota',
    'contact_child_holds_four_credentials');

-- ------------------------------------------------------------ enroll

-- Members join a child through grants only: a ticket from its owner is
-- refused, and nothing is recorded.
select onepass_test.ok(onepass_test.enroll('o2', 'C', 'en', 1) = 'forbidden', 'child_refuses_enroll_ticket');
reset role;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.credentials where id = onepass_test.cid('en'))
    and (select count(*) = 0 from onepass_mailbox.used_tickets where mailbox_id = onepass_test.mbx('C')),
    'refused_child_enroll_leaves_nothing');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.enroll('e', 'E', 'en', 2) = 'ok', 'account_mailbox_still_enrolls');

-- ------------------------------------------------------------ deletion

-- The owner deletes its child at any time, even old and used by others.
select onepass_test.ok(onepass_test.put('ow', 'V', 9) = 'ok', 'member_writes_in_child');
reset role;
update onepass_mailbox.mailboxes set created_at = now() - interval '30 days' where id = onepass_test.mbx('V');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.del('om', 'V') = 'forbidden' and onepass_test.del('ow', 'V') = 'forbidden',
    'only_the_child_owner_deletes_it');
select onepass_test.raises($$select onepass_test.del('p', 'V')$$, 'OP403', 'unknown_credential',
    'parent_manager_cannot_delete_child');
select onepass_test.ok(onepass_test.del('o1', 'V') = 'ok', 'child_owner_deletes_child');
select onepass_test.raises($$select onepass_test.put('o1', 'V', 10)$$, 'OP404', 'not_found', 'deleted_child_is_gone');
select onepass_test.raises($$select onepass_test.put('ow', 'V', 10)$$, 'OP404', 'not_found', 'deleted_child_gone_for_members');

-- An account mailbox with a live child is not deleted, even fresh by its
-- creator; once the child is gone it is.
select onepass_test.ok(onepass_test.child('DC', 'd', 'D', 3, onepass_test.okey(200)) = 'ok', 'fresh_parent_creates_child');
select onepass_test.ok(onepass_test.del('d', 'D') = 'forbidden', 'parent_delete_refused_with_children');
reset role;
insert into t_keys (name, pk, cid)
select 'dco', k, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || k, 'sha256') from 1 for 16)
from (select onepass_test.okey(200) as k) x;
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.del('dco', 'DC') = 'ok', 'owner_deletes_last_child');
select onepass_test.ok(onepass_test.del('d', 'D') = 'ok', 'parent_deleted_once_children_gone');
-- A deleted parent creates nothing.
select onepass_test.raises($$select onepass_test.child(null, 'd', 'D', 2, onepass_test.okey(201))$$,
    'OP404', 'not_found', 'deleted_parent_creates_no_child');
reset role;

-- The purge an hour later empties a deleted child like any mailbox.
select onepass_mailbox.maintenance(now() + interval '2 hours');
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('V'))
    and (select count(*) = 0 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('V'))
    and (select deleted_at is not null from onepass_test.mb('V')),
    'deleted_child_purged');
select onepass_test.ok(
    (select count(*) > 0 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('P')),
    'parent_untouched_by_child_purge');

-- ------------------------------------------------------------ row level security

-- The children of a mailbox are visible only through onepass.parent.
select set_config('onepass.mailbox', encode(onepass_test.mbx('P'), 'hex'), true);
set local role onepass_mailbox_owner;
select onepass_test.ok((select count(*) = 1 from onepass_mailbox.mailboxes), 'children_hidden_without_parent_setting');
select set_config('onepass.parent', encode(onepass_test.mbx('P'), 'hex'), true);
select onepass_test.ok((select count(*) = 3 from onepass_mailbox.mailboxes), 'children_visible_with_parent_setting');
select onepass_test.ok(
    onepass_test.row_count($$update onepass_mailbox.mailboxes set frozen = true where parent_id is not null$$) = 0,
    'children_not_writable_through_parent_setting');
reset role;
select set_config('onepass.parent', '', true);
select set_config('onepass.mailbox', '', true);
