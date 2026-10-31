-- Roles, grants and forced row level security of spec 4.8. Starts as the
-- harness superuser, inside a transaction the harness rolls back.

-- Every table of the schema, for the loops below.
create temporary table t_tables on commit drop as
select c.relname::text as name
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'onepass_mailbox' and c.relkind in ('r', 'p');
grant select on t_tables to public;

select onepass_test.ok(
    (select array_agg(name order by name) from t_tables) = array[
        'blobs', 'credentials', 'invites', 'mailboxes', 'nonces', 'plans', 'push_queue',
        'rate', 'rdv_chunks', 'rdv_sessions', 'records', 'used_tickets'],
    'tables_of_spec_4_5');

-- Roles.
select onepass_test.ok(
    (select not rolcanlogin and not rolbypassrls and not rolsuper from pg_roles where rolname = 'onepass_mailbox_owner'),
    'owner_is_nologin_nobypassrls');
select onepass_test.ok(
    (select rolcanlogin and not rolbypassrls and not rolsuper and not rolcreaterole and not rolcreatedb
     from pg_roles where rolname = 'onepass_mailbox_api'),
    'api_is_login_nobypassrls');
select onepass_test.ok(
    (select rolcanlogin and not rolbypassrls and not rolsuper and not rolcreaterole and not rolcreatedb
     from pg_roles where rolname = 'onepass_mailbox_janitor'),
    'janitor_is_login_nobypassrls');
select onepass_test.ok(
    (select nspowner::regrole::text = 'onepass_mailbox_owner' from pg_namespace where nspname = 'onepass_mailbox'),
    'schema_owned_by_owner');
select onepass_test.ok(
    (select bool_and(c.relowner::regrole::text = 'onepass_mailbox_owner' and c.relrowsecurity and c.relforcerowsecurity)
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'onepass_mailbox' and c.relkind in ('r', 'p')),
    'all_tables_owned_with_forced_rls');
select onepass_test.ok(
    (select bool_and(not has_schema_privilege(r, 'onepass_mailbox', 'usage')
                     and not has_schema_privilege(r, 'onepass_mailbox', 'create'))
     from unnest(array['anon', 'authenticated', 'service_role']) r),
    'api_roles_have_no_schema_privilege');
select onepass_test.ok(
    (select bool_and(not has_function_privilege(r, p.oid, 'execute'))
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace,
          unnest(array['anon', 'authenticated', 'service_role', 'onepass_mailbox_api', 'onepass_mailbox_janitor']) r
     where n.nspname = 'onepass_mailbox' and p.proname in ('current_mailbox', 'current_rdv', 'current_invite', 'in_maintenance')),
    'rls_helpers_not_executable_by_others');

-- Policies call their helpers once per statement: every helper call sits in
-- a scalar subquery (pg_policies shows it as `( SELECT onepass_mailbox....`).
select onepass_test.ok(
    (select bool_and(
        coalesce(qual, '') !~ '(?<!SELECT )onepass_mailbox\.(current_|in_maintenance)'
        and coalesce(with_check, '') !~ '(?<!SELECT )onepass_mailbox\.(current_|in_maintenance)')
     from pg_policies where schemaname = 'onepass_mailbox'),
    'policy_helpers_wrapped_in_select');
select onepass_test.ok(
    (select count(*) from pg_policies where schemaname = 'onepass_mailbox' and qual ~ 'SELECT onepass_mailbox\.') = 11,
    'policies_using_helpers_counted');

-- Two mailboxes A and B, written in maintenance by the owner.
set local role onepass_mailbox_owner;
set local onepass.maintenance = 'on';

insert into onepass_mailbox.mailboxes (id, plan) values
    (decode(repeat('aa', 16), 'hex'), 'free'),
    (decode(repeat('bb', 16), 'hex'), 'free');
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
select substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16), m, pk, '\x'
from (values (decode(repeat('aa', 16), 'hex'), decode(repeat('a1', 32), 'hex')),
             (decode(repeat('bb', 16), 'hex'), decode(repeat('b1', 32), 'hex'))) v (m, pk);
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data) values
    (decode(repeat('aa', 16), 'hex'), 1, decode(repeat('a2', 16), 'hex'), 1, 1, false, 1, '\x01'),
    (decode(repeat('bb', 16), 'hex'), 1, decode(repeat('b2', 16), 'hex'), 1, 1, false, 1, '\x02');
insert into onepass_mailbox.blobs (mailbox_id, sha256, size, state) values
    (decode(repeat('aa', 16), 'hex'), decode(repeat('a3', 32), 'hex'), 20000, 1),
    (decode(repeat('bb', 16), 'hex'), decode(repeat('b3', 32), 'hex'), 20000, 1);
insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
select id, mailbox_id, decode(repeat('0f', 16), 'hex') from onepass_mailbox.credentials;
insert into onepass_mailbox.used_tickets (ticket_hash, mailbox_id) values
    (decode(repeat('a4', 32), 'hex'), decode(repeat('aa', 16), 'hex')),
    (decode(repeat('b4', 32), 'hex'), decode(repeat('bb', 16), 'hex'));
insert into onepass_mailbox.push_queue (mailbox_id) values
    (decode(repeat('aa', 16), 'hex')),
    (decode(repeat('bb', 16), 'hex'));
insert into onepass_mailbox.rdv_sessions (session_id) values
    (decode(repeat('c1', 16), 'hex')),
    (decode(repeat('c2', 16), 'hex'));
insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data) values
    (decode(repeat('c1', 16), 'hex'), 0, 0, '\x01'),
    (decode(repeat('c2', 16), 'hex'), 0, 0, '\x02');
insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at) values
    (decode(repeat('d1', 32), 'hex'), 'free', 1, now() + interval '1 day'),
    (decode(repeat('d2', 32), 'hex'), 'free', 1, now() + interval '1 day');
insert into onepass_mailbox.rate (key, window_start, count) values
    (decode(repeat('e1', 32), 'hex'), date_trunc('minute', now()), 1);

select onepass_test.ok((select count(*) from onepass_mailbox.records) = 2, 'maintenance_by_postgres_sees_both');

-- Out of maintenance, with mailbox A authenticated.
set local onepass.maintenance = 'off';
select set_config('onepass.mailbox', repeat('aa', 16), true);

select onepass_test.ok(
    (select count(*) from onepass_mailbox.records where mailbox_id = decode(repeat('bb', 16), 'hex')) = 0,
    'owner_sees_no_record_of_b');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.records) = 1
    and (select mailbox_id from onepass_mailbox.records) = decode(repeat('aa', 16), 'hex'),
    'owner_sees_record_of_a');
select onepass_test.ok(
    (select count(*) from onepass_mailbox.mailboxes) = 1
    and (select id from onepass_mailbox.mailboxes) = decode(repeat('aa', 16), 'hex'),
    'owner_sees_only_mailbox_a');

do $$
declare
    t text;
    col text;
    n bigint;
begin
    foreach t in array array['credentials', 'records', 'blobs', 'nonces', 'used_tickets', 'push_queue'] loop
        execute format('select count(*) from onepass_mailbox.%I where mailbox_id = $1', t)
            into n using decode(repeat('bb', 16), 'hex');
        perform onepass_test.ok(n = 0, 'owner_sees_nothing_of_b_in_' || t);
        execute format('select count(*) from onepass_mailbox.%I', t) into n;
        perform onepass_test.ok(n = 1, 'owner_sees_one_row_of_a_in_' || t);
    end loop;
end
$$;

select onepass_test.ok(
    onepass_test.row_count($$update onepass_mailbox.records set version = 99 where mailbox_id = decode(repeat('bb', 16), 'hex')$$) = 0,
    'update_of_b_touches_nothing');
select onepass_test.ok(
    onepass_test.row_count($$delete from onepass_mailbox.records where mailbox_id = decode(repeat('bb', 16), 'hex')$$) = 0,
    'delete_of_b_touches_nothing');
select onepass_test.ok(
    onepass_test.row_count($$update onepass_mailbox.mailboxes set frozen = true where id = decode(repeat('bb', 16), 'hex')$$) = 0,
    'freeze_of_b_touches_nothing');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('bb', 16), 'hex'), 1, decode(repeat('b5', 16), 'hex'), 1, 2, false, 1, '\x01')$$,
    '42501', 'insert_for_b_violates_policy');
select onepass_test.throws(
    $$update onepass_mailbox.records set mailbox_id = decode(repeat('bb', 16), 'hex') where mailbox_id = decode(repeat('aa', 16), 'hex')$$,
    '42501', 'move_row_to_b_violates_policy');
select onepass_test.throws(
    $$insert into onepass_mailbox.mailboxes (id, plan) values (decode(repeat('cc', 16), 'hex'), 'free')$$,
    '42501', 'insert_of_other_mailbox_violates_policy');

-- Writing the authenticated mailbox itself works.
select onepass_test.ok(
    onepass_test.row_count($$update onepass_mailbox.records set version = 2 where mailbox_id = decode(repeat('aa', 16), 'hex')$$) = 1,
    'update_of_a_allowed');

-- Plans read only, invites hidden without the invite setting, rate open to the owner.
select onepass_test.ok((select count(*) from onepass_mailbox.plans) = 2, 'plans_readable');
select onepass_test.throws(
    $$insert into onepass_mailbox.plans values ('gold', 1, 1, 1, 1, 1)$$,
    '42501', 'plans_not_writable');
select onepass_test.ok(
    onepass_test.row_count($$update onepass_mailbox.plans set max_bytes = 1$$) = 0,
    'plans_not_updatable');
select onepass_test.ok((select count(*) from onepass_mailbox.invites) = 0, 'invites_hidden_without_setting');
select set_config('onepass.invite', repeat('d1', 32), true);
select onepass_test.ok(
    (select count(*) from onepass_mailbox.invites) = 1
    and (select token_hash from onepass_mailbox.invites) = decode(repeat('d1', 32), 'hex'),
    'invite_visible_by_its_hash_only');
select set_config('onepass.invite', '', true);
select onepass_test.ok((select count(*) from onepass_mailbox.rate) = 1, 'rate_readable_by_owner');

-- Rendezvous rows follow onepass.rdv.
select onepass_test.ok((select count(*) from onepass_mailbox.rdv_chunks) = 0, 'rdv_hidden_without_setting');
select set_config('onepass.rdv', repeat('c1', 16), true);
select onepass_test.ok(
    (select count(*) from onepass_mailbox.rdv_sessions) = 1
    and (select count(*) from onepass_mailbox.rdv_chunks) = 1
    and (select session_id from onepass_mailbox.rdv_chunks) = decode(repeat('c1', 16), 'hex'),
    'rdv_sees_its_session_only');
select onepass_test.throws(
    $$insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data) values (decode(repeat('c2', 16), 'hex'), 0, 1, '\x01')$$,
    '42501', 'rdv_write_to_other_session_violates_policy');
select set_config('onepass.rdv', '', true);

-- No setting at all: nothing visible anywhere.
select set_config('onepass.mailbox', '', true);
do $$
declare
    t text;
    n bigint;
begin
    for t in select name from t_tables where name not in ('plans', 'rate') loop
        execute format('select count(*) from onepass_mailbox.%I', t) into n;
        perform onepass_test.ok(n = 0, 'nothing_visible_without_setting_in_' || t);
    end loop;
end
$$;

-- A malformed setting is no mailbox, never an error.
select set_config('onepass.mailbox', 'zz', true);
select onepass_test.ok(onepass_mailbox.current_mailbox() is null, 'malformed_mailbox_setting_is_null');
select set_config('onepass.mailbox', repeat('aa', 15), true);
select onepass_test.ok(onepass_mailbox.current_mailbox() is null, 'short_mailbox_setting_is_null');
select set_config('onepass.mailbox', upper(repeat('aa', 16)), true);
select onepass_test.ok(onepass_mailbox.current_mailbox() = decode(repeat('aa', 16), 'hex'), 'mailbox_setting_decoded');
select set_config('onepass.invite', 'not hex', true);
select onepass_test.ok((select count(*) from onepass_mailbox.invites) = 0, 'malformed_invite_setting_matches_nothing');
select set_config('onepass.invite', '', true);
select set_config('onepass.mailbox', '', true);

reset role;

-- Maintenance only counts for postgres and the janitor as session user.
-- The harness logs in as a superuser, so `set session authorization` below is
-- a simulation: it proves the session_user gate, not that a real api or
-- janitor login could not switch (it cannot: that needs a superuser login). A
-- SECURITY DEFINER probe owned by the owner stands in for a future function.
create function onepass_mailbox.t_probe() returns bigint
language sql security definer set search_path = ''
as $$ select count(*) from onepass_mailbox.records $$;
alter function onepass_mailbox.t_probe() owner to onepass_mailbox_owner;
grant execute on function onepass_mailbox.t_probe() to onepass_mailbox_api, onepass_mailbox_janitor;

set local session authorization onepass_mailbox_api;
set local onepass.maintenance = 'on';
select onepass_test.ok(onepass_mailbox.t_probe() = 0, 'maintenance_under_api_sees_nothing');
reset session authorization;

set local session authorization onepass_mailbox_janitor;
set local onepass.maintenance = 'off';
select onepass_test.ok(onepass_mailbox.t_probe() = 0, 'janitor_without_maintenance_sees_nothing');
set local onepass.maintenance = 'on';
select onepass_test.ok(onepass_mailbox.t_probe() = 2, 'janitor_in_maintenance_sees_all');
reset session authorization;
set local onepass.maintenance = 'off';

-- No direct table access for the API roles, the edge function role or the janitor.
do $$
declare
    r text;
    t text;
    got text;
begin
    foreach r in array array['anon', 'authenticated', 'service_role', 'onepass_mailbox_api', 'onepass_mailbox_janitor'] loop
        for t in select name from t_tables loop
            execute format('set local role %I', r);
            got := null;
            begin
                execute format('select 1 from onepass_mailbox.%I limit 1', t);
            exception when insufficient_privilege then
                got := 'denied';
            end;
            reset role;
            perform onepass_test.ok(got = 'denied', 'select_denied_for_' || r || '_on_' || t);
        end loop;
        execute format('set local role %I', r);
        got := null;
        begin
            execute $q$insert into onepass_mailbox.plans values ('gold', 1, 1, 1, 1, 1)$q$;
        exception when insufficient_privilege then
            got := 'denied';
        end;
        reset role;
        perform onepass_test.ok(got = 'denied', 'insert_denied_for_' || r);
    end loop;
end
$$;

-- Default privileges: what the owner creates later is closed by default.
set local role onepass_mailbox_owner;
create table onepass_mailbox.t_later (x int);
create function onepass_mailbox.t_later_fn() returns int language sql as $$ select 1 $$;
reset role;
select onepass_test.ok(
    (select bool_and(not has_table_privilege(r, 'onepass_mailbox.t_later', 'select,insert,update,delete'))
     from unnest(array['anon', 'authenticated', 'service_role', 'onepass_mailbox_api', 'onepass_mailbox_janitor']) r),
    'default_privileges_close_new_tables');
select onepass_test.ok(
    (select bool_and(not has_function_privilege(r, 'onepass_mailbox.t_later_fn()', 'execute'))
     from unnest(array['anon', 'authenticated', 'service_role', 'onepass_mailbox_api', 'onepass_mailbox_janitor']) r),
    'default_privileges_close_new_functions');
