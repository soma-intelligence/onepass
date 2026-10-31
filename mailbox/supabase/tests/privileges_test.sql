-- Schema-wide privilege guard. Every later migration is held to it: a
-- function or table created in onepass_mailbox by the wrong role, or left
-- open to PUBLIC, fails here. Extend the allowlists below when a migration
-- grants EXECUTE on purpose (Task 4: credential_key, api_*, rdv_* for the api;
-- Task 6: the janitor's functions).

create temporary table t_allow (role text, proname text) on commit drop;
-- insert into t_allow values ('onepass_mailbox_api', 'credential_key'), ...;

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
          and not exists (select 1 from t_allow w where w.role = r and w.proname = p.proname)),
    'execute_only_on_allowlist');

-- What api and janitor may execute runs as the owner, with an empty search_path.
select onepass_test.ok(
    not exists (
        select 1 from pg_proc p join t_allow w on w.proname = p.proname
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

-- The guard bites: a function postgres creates here without the owner role
-- is caught by the checks above.
create function onepass_mailbox.t_stray() returns int language sql as $$ select 1 $$;
select onepass_test.ok(
    (select p.proowner::regrole::text <> 'onepass_mailbox_owner'
            and (p.proacl is null or exists (select 1 from unnest(p.proacl) a where a::text like '=%'))
     from pg_proc p where p.oid = 'onepass_mailbox.t_stray()'::regprocedure),
    'stray_postgres_function_would_be_caught');
