-- Schema-wide privilege guard. Every later migration is held to it: a
-- function or table created in onepass_mailbox by the wrong role, or left
-- open to PUBLIC, fails here. Extend the allowlists below when a migration
-- grants EXECUTE on purpose (blobs and rdv_* for the api, the collector
-- and push queue functions for the janitor). Entries are full signatures (regprocedure text), so a new
-- overload of an allowed name is not allowed by accident.

create temporary table t_allow (role text, signature text) on commit drop;
insert into t_allow (role, signature) values
    ('onepass_mailbox_api', 'onepass_mailbox.credential_key(bytea,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_create_mailbox(bytea,bytea,timestamp with time zone,bytea,bytea,bytea,boolean)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_mailbox_info(bytea,bytea,timestamp with time zone,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_changes(bytea,bytea,timestamp with time zone,bytea,bigint,integer,boolean)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_record(bytea,bytea,timestamp with time zone,bytea,smallint,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_enroll(bytea,bytea,timestamp with time zone,bytea,bytea,bytea,timestamp with time zone,bytea,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_revoke_credential(bytea,bytea,timestamp with time zone,bytea,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_set_push(bytea,bytea,timestamp with time zone,bytea,smallint,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_commit(bytea,bytea,timestamp with time zone,bytea,smallint[],bytea[],bigint[],smallint[],bigint[],bytea[],bytea[],integer[])'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_blob_announce(bytea,bytea,timestamp with time zone,bytea,bytea[],integer[])'),
    ('onepass_mailbox_api', 'onepass_mailbox.api_blob_lookup(bytea,bytea,timestamp with time zone,bytea,bytea[])'),
    ('onepass_mailbox_api', 'onepass_mailbox.rdv_put(bytea,smallint,integer,bytea,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.rdv_get(bytea,smallint,integer,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.rdv_close(bytea,bytea)'),
    ('onepass_mailbox_api', 'onepass_mailbox.ip_gate(bytea)'),
    ('onepass_mailbox_janitor', 'onepass_mailbox.gc_take(integer)'),
    ('onepass_mailbox_janitor', 'onepass_mailbox.gc_done(bytea,text)'),
    ('onepass_mailbox_janitor', 'onepass_mailbox.push_take(integer)'),
    ('onepass_mailbox_janitor', 'onepass_mailbox.push_forget(bytea,bytea)');

-- The allowlist names real functions (a typo would allow nothing and hide it).
select onepass_test.ok(
    not exists (select 1 from t_allow w
                where not exists (select 1 from pg_proc p
                                  where p.pronamespace = 'onepass_mailbox'::regnamespace
                                    and p.oid::regprocedure::text = w.signature)),
    'allowlist_entries_exist');

-- Functions: owned by the owner, an explicit ACL (NULL means PUBLIC EXECUTE)
-- with no PUBLIC entry.
select onepass_test.ok(
    (select coalesce(bool_and(p.proowner::regrole::text = 'onepass_mailbox_owner'), true)
     from pg_proc p where p.pronamespace = 'onepass_mailbox'::regnamespace),
    'functions_owned_by_owner');
select onepass_test.ok(
    (select coalesce(bool_and(p.proacl is not null
                              and not exists (select 1 from unnest(p.proacl) a where a::text like '=%')), true)
     from pg_proc p where p.pronamespace = 'onepass_mailbox'::regnamespace),
    'functions_have_no_public_execute');

-- EXECUTE for anyone but the owner only on the allowlist; the anon-side
-- roles never.
select onepass_test.ok(
    not exists (
        select 1
        from pg_proc p,
             unnest(array['public', 'anon', 'authenticated', 'service_role',
                          'onepass_mailbox_api', 'onepass_mailbox_janitor']) r
        where p.pronamespace = 'onepass_mailbox'::regnamespace
          and (case when r = 'public'
                    then p.proacl is null or exists (select 1 from unnest(p.proacl) a where a::text like '=%')
                    else has_function_privilege(r, p.oid, 'execute') end)
          and not exists (select 1 from t_allow w where w.role = r and w.signature = p.oid::regprocedure::text)),
    'execute_only_on_allowlist');

-- What api and janitor may execute runs as the owner, with an empty search_path.
select onepass_test.ok(
    not exists (
        select 1 from pg_proc p join t_allow w on w.signature = p.oid::regprocedure::text
        where p.pronamespace = 'onepass_mailbox'::regnamespace
          and not (p.prosecdef and 'search_path=""' = any (coalesce(p.proconfig, '{}')))),
    'allowed_functions_are_security_definer_with_empty_search_path');

-- Tables, sequences and views: owned by the owner, no grant to anyone.
select onepass_test.ok(
    (select coalesce(bool_and(c.relowner::regrole::text = 'onepass_mailbox_owner'), true)
     from pg_class c where c.relnamespace = 'onepass_mailbox'::regnamespace and c.relkind in ('r', 'p', 'S', 'v', 'm')),
    'relations_owned_by_owner');
select onepass_test.ok(
    (select coalesce(bool_and(c.relacl is null
                              or not exists (select 1 from unnest(c.relacl) a
                                             where a::text not like 'onepass_mailbox_owner=%')), true)
     from pg_class c where c.relnamespace = 'onepass_mailbox'::regnamespace and c.relkind in ('r', 'p', 'S', 'v', 'm')),
    'relations_granted_to_nobody');

-- No column level grant either (a column grant is invisible in relacl).
select onepass_test.ok(
    not exists (select 1 from pg_attribute a join pg_class c on c.oid = a.attrelid
                where c.relnamespace = 'onepass_mailbox'::regnamespace and a.attacl is not null),
    'columns_granted_to_nobody');

-- Every allowed entry point is granted to the api role (so the edge
-- function can call it) and to no other role.
select onepass_test.ok(
    (select bool_and(has_function_privilege('onepass_mailbox_api', w.signature::regprocedure, 'execute'))
     from t_allow w where w.role = 'onepass_mailbox_api'),
    'api_entry_points_are_granted');
select onepass_test.ok(
    (select bool_and(has_function_privilege('onepass_mailbox_janitor', w.signature::regprocedure, 'execute'))
     from t_allow w where w.role = 'onepass_mailbox_janitor'),
    'janitor_functions_are_granted');
-- maintenance() runs as postgres (pg_cron), never through a login role.
select onepass_test.ok(
    (select bool_and(not has_function_privilege(r, 'onepass_mailbox.maintenance(timestamp with time zone)'::regprocedure, 'execute'))
     from unnest(array['onepass_mailbox_api', 'onepass_mailbox_janitor', 'anon', 'authenticated', 'service_role']) r),
    'maintenance_is_not_granted');
-- Storage: the owner reads objects, nobody of ours writes them.
select onepass_test.ok(
    has_table_privilege('onepass_mailbox_owner', 'storage.objects', 'select')
    and not has_table_privilege('onepass_mailbox_owner', 'storage.objects', 'insert,update,delete')
    and not has_schema_privilege('onepass_mailbox_api', 'storage', 'usage')
    and not has_schema_privilege('onepass_mailbox_janitor', 'storage', 'usage'),
    'storage_is_read_only_for_the_owner');

-- The guard bites: a function postgres creates here without the owner role
-- is caught by the checks above.
create function onepass_mailbox.t_stray() returns int language sql as $$ select 1 $$;
select onepass_test.ok(
    (select p.proowner::regrole::text <> 'onepass_mailbox_owner'
            and (p.proacl is null or exists (select 1 from unnest(p.proacl) a where a::text like '=%'))
     from pg_proc p where p.oid = 'onepass_mailbox.t_stray()'::regprocedure),
    'stray_postgres_function_would_be_caught');

-- The wake bridge (Task 5): runs as the migration role, so it is held to
-- the same shape and reachable from the mailbox owner only. Allow lists:
-- the only grantees on the schema and its functions are their owner and
-- onepass_mailbox_owner.
select onepass_test.ok(
    (select count(*) = 1 from pg_proc p where p.pronamespace = 'onepass_mailbox_wake'::regnamespace)
    and (select bool_and(p.prosecdef and 'search_path=""' = any (coalesce(p.proconfig, '{}'))
                         and p.proowner::regrole::text <> 'onepass_mailbox_owner'
                         and has_function_privilege('onepass_mailbox_owner', p.oid, 'execute'))
         from pg_proc p where p.pronamespace = 'onepass_mailbox_wake'::regnamespace),
    'wake_bridge_is_security_definer_owned_by_the_migration_role');
select onepass_test.ok(
    not exists (
        select 1 from pg_proc p
        where p.pronamespace = 'onepass_mailbox_wake'::regnamespace
          and (p.proacl is null
               or exists (select 1 from aclexplode(p.proacl) a
                          where a.grantee not in (p.proowner, 'onepass_mailbox_owner'::regrole))))
    and not exists (
        select 1 from pg_namespace n
        where n.nspname = 'onepass_mailbox_wake'
          and (n.nspacl is null
               or exists (select 1 from aclexplode(n.nspacl) a
                          where a.grantee not in (n.nspowner, 'onepass_mailbox_owner'::regrole)))),
    'wake_bridge_granted_to_the_owner_only');
