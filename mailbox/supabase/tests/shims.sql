-- Stand-ins for what a Supabase project provides, so the migrations and the
-- tests run on a bare, throwaway Postgres 17 (mailbox/scripts/sql-test.sh).
-- Only the surface the mailbox uses is shimmed. Nothing here is loaded by
-- `supabase start` or `supabase db reset`.

\set ON_ERROR_STOP on

-- API roles Supabase creates. `postgres` is the harness superuser already.
do $$
declare
    r text;
begin
    foreach r in array array['anon', 'authenticated', 'service_role', 'postgres'] loop
        if not exists (select 1 from pg_roles where rolname = r) then
            execute format('create role %I nologin', r);
        end if;
    end loop;
end
$$;

-- Supabase keeps extensions in their own schema.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- Realtime Broadcast from the database: record what would have been sent.
create schema if not exists realtime;
create table realtime.sent (
    n bigint generated always as identity primary key,
    payload jsonb not null,
    event text not null,
    topic text not null,
    private boolean not null,
    sent_at timestamptz not null default now()
);
create function realtime.send(payload jsonb, event text, topic text, private boolean default true)
returns void
language sql
as $$
    insert into realtime.sent (payload, event, topic, private) values (payload, event, topic, private);
$$;

-- Storage: buckets and objects, with row level security on like the real one.
create schema if not exists storage;
create table storage.buckets (
    id text primary key,
    name text not null,
    public boolean not null default false,
    file_size_limit bigint
);
create table storage.objects (
    id uuid primary key default extensions.gen_random_uuid(),
    bucket_id text references storage.buckets (id),
    name text,
    metadata jsonb,
    created_at timestamptz not null default now()
);
alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;

-- pg_cron: scheduling is recorded, never run.
create schema if not exists cron;
create table cron.job (
    jobid bigint generated always as identity primary key,
    jobname text unique,
    schedule text not null,
    command text not null
);
create function cron.schedule(job_name text, schedule text, command text)
returns bigint
language sql
as $$
    insert into cron.job (jobname, schedule, command) values (job_name, schedule, command)
    on conflict (jobname) do update set schedule = excluded.schedule, command = excluded.command
    returning jobid;
$$;

-- pg_net is not available here: record the request instead of sending it.
create schema if not exists net;
create table net.sent (
    id bigint generated always as identity primary key,
    url text not null,
    body jsonb,
    params jsonb,
    headers jsonb,
    timeout_milliseconds integer,
    sent_at timestamptz not null default now()
);
create function net.http_post(
    url text,
    body jsonb default '{}'::jsonb,
    params jsonb default '{}'::jsonb,
    headers jsonb default '{}'::jsonb,
    timeout_milliseconds integer default 5000
)
returns bigint
language sql
as $$
    insert into net.sent (url, body, params, headers, timeout_milliseconds)
    values (url, body, params, headers, timeout_milliseconds)
    returning id;
$$;

-- Test helpers. Every assertion prints `ok <name>` (as a notice the harness
-- rewrites) or raises, which stops the run.
create schema onepass_test;
grant usage on schema onepass_test to public;

create function onepass_test.ok(cond boolean, name text)
returns void
language plpgsql
as $$
begin
    if cond is distinct from true then
        raise exception 'not ok %', name using errcode = 'P0001';
    end if;
    raise notice 'ok %', name;
end
$$;

-- Runs `stmt` and passes only if it fails with SQLSTATE `state`. The statement
-- runs in a subtransaction, so its effects are rolled back either way.
create function onepass_test.throws(stmt text, state text, name text)
returns void
language plpgsql
as $$
declare
    got text;
    msg text;
begin
    begin
        execute stmt;
    exception when others then
        get stacked diagnostics got = returned_sqlstate, msg = message_text;
    end;
    if got is null then
        raise exception 'not ok % (no error)', name using errcode = 'P0001';
    end if;
    if got <> state then
        raise exception 'not ok % (got % %)', name, got, msg using errcode = 'P0001';
    end if;
    raise notice 'ok %', name;
end
$$;

-- Runs `stmt` and returns the number of rows it touched or returned.
create function onepass_test.row_count(stmt text)
returns bigint
language plpgsql
as $$
declare
    n bigint;
begin
    execute stmt;
    get diagnostics n = row_count;
    return n;
end
$$;

grant execute on all functions in schema onepass_test to public;
