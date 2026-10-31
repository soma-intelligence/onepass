-- OnePass mailbox: schema, roles and forced row level security (spec 4.5, 4.8).
--
-- The schema is not exposed by PostgREST (config.toml lists only `public`).
-- The edge function reaches the database as onepass_mailbox_api, which can
-- only execute the api_* and rdv_* functions added by later migrations. Those
-- functions run as onepass_mailbox_owner, which owns every table and is itself
-- subject to row level security (FORCE): a function that forgets a
-- `where mailbox_id = ...` still sees only the mailbox the request
-- authenticated, set with set_config('onepass.mailbox', <hex>, true).

-- Roles are cluster wide and survive `supabase db reset`: create them once,
-- then pin their attributes on every run. Passwords for the LOGIN roles are
-- set outside migrations (mailbox/scripts/local-env.sh, or the operator).
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'onepass_mailbox_owner') then
        create role onepass_mailbox_owner;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'onepass_mailbox_api') then
        create role onepass_mailbox_api;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'onepass_mailbox_janitor') then
        create role onepass_mailbox_janitor;
    end if;
end
$$;

alter role onepass_mailbox_owner nologin nobypassrls nocreatedb nocreaterole noreplication;
alter role onepass_mailbox_api login nobypassrls nocreatedb nocreaterole noreplication noinherit;
alter role onepass_mailbox_janitor login nobypassrls nocreatedb nocreaterole noreplication noinherit;

-- The migration role (postgres) acts as the owner to create the objects.
grant onepass_mailbox_owner to postgres;

create extension if not exists pgcrypto with schema extensions;
grant usage on schema extensions to onepass_mailbox_owner;

create schema onepass_mailbox authorization onepass_mailbox_owner;
revoke all on schema onepass_mailbox from public;
grant usage on schema onepass_mailbox to onepass_mailbox_api, onepass_mailbox_janitor;

-- Nothing created in the schema later is open by default, to anyone.
alter default privileges for role onepass_mailbox_owner in schema onepass_mailbox
    revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role onepass_mailbox_owner in schema onepass_mailbox
    revoke all on sequences from public, anon, authenticated, service_role;
alter default privileges for role onepass_mailbox_owner in schema onepass_mailbox
    revoke all on functions from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema onepass_mailbox
    revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema onepass_mailbox
    revoke all on sequences from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema onepass_mailbox
    revoke all on functions from public, anon, authenticated, service_role;
-- Per schema revokes are no-ops in Postgres (they can only add to the global
-- defaults); the six above and the one below are kept as explicit intent.
-- Functions created here by postgres still get PUBLIC EXECUTE by default:
-- tests/privileges_test.sql is the real guard (owner, no PUBLIC entry,
-- EXECUTE for api and janitor only on an allowlist).
alter default privileges for role postgres in schema onepass_mailbox
    revoke execute on functions from public;
-- Per schema defaults can only add to the global ones, and the global default
-- gives EXECUTE on every new function to PUBLIC: take it back for the owner,
-- which creates objects in this schema only.
alter default privileges for role onepass_mailbox_owner
    revoke execute on functions from public;

set role onepass_mailbox_owner;

-- Request context for the policies. Each returns NULL when the setting is
-- absent, empty or malformed, so a policy never matches by accident.

create function onepass_mailbox.current_mailbox()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{32}$' then decode(s, 'hex') end
    from (select current_setting('onepass.mailbox', true) as s) c;
$$;

create function onepass_mailbox.current_rdv()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{32}$' then decode(s, 'hex') end
    from (select current_setting('onepass.rdv', true) as s) c;
$$;

create function onepass_mailbox.current_invite()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{64}$' then decode(s, 'hex') end
    from (select current_setting('onepass.invite', true) as s) c;
$$;

-- Maintenance (purges, operator gestures) sees every row, but only when the
-- connection itself belongs to postgres (pg_cron, the operator) or to the
-- janitor. The edge function role cannot turn it on: its session_user is
-- onepass_mailbox_api whatever it sets.
create function onepass_mailbox.in_maintenance()
returns boolean
language sql
stable
set search_path = ''
as $$
    select coalesce(current_setting('onepass.maintenance', true) = 'on', false)
       and session_user::text in ('postgres', 'onepass_mailbox_janitor');
$$;

revoke all on function onepass_mailbox.current_mailbox() from public;
revoke all on function onepass_mailbox.current_rdv() from public;
revoke all on function onepass_mailbox.current_invite() from public;
revoke all on function onepass_mailbox.in_maintenance() from public;

-- Tables of spec 4.5.

create table onepass_mailbox.plans (
    plan text primary key check (plan ~ '^[a-z][a-z0-9_]{0,31}$'),
    max_bytes bigint not null check (max_bytes > 0),
    max_records integer not null check (max_records > 0),
    max_credentials integer not null check (max_credentials > 0),
    req_per_min integer not null check (req_per_min > 0),
    max_commit_ops integer not null check (max_commit_ops between 1 and 20000)
);

create table onepass_mailbox.invites (
    token_hash bytea primary key check (length(token_hash) = 32),
    plan text not null references onepass_mailbox.plans (plan),
    uses_left integer not null check (uses_left >= 0),
    expires_at timestamptz not null
);

create table onepass_mailbox.mailboxes (
    id bytea primary key default extensions.gen_random_bytes(16) check (length(id) = 16),
    -- Random, non-negative so it maps onto the wire's u64 unchanged. Changes
    -- only when the operator restores a backup.
    incarnation bigint not null
        default (('x' || encode(extensions.gen_random_bytes(8), 'hex'))::bit(64)::bigint & 9223372036854775807)
        check (incarnation >= 0),
    plan text not null references onepass_mailbox.plans (plan),
    wake_topic bytea not null unique default extensions.gen_random_bytes(16) check (length(wake_topic) = 16),
    next_seq bigint not null default 1 check (next_seq >= 1),
    min_cursor bigint not null default 0 check (min_cursor >= 0),
    bytes_used bigint not null default 0 check (bytes_used >= 0),
    records_count integer not null default 0 check (records_count >= 0),
    frozen boolean not null default false,
    created_at timestamptz not null default now(),
    last_write_at timestamptz
);

create table onepass_mailbox.credentials (
    id bytea primary key check (length(id) = 16),
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id),
    public_key bytea not null check (length(public_key) = 32),
    -- Encrypted by the client, opaque here.
    label bytea not null default '\x'::bytea check (octet_length(label) <= 64),
    enrolled_by bytea references onepass_mailbox.credentials (id) check (length(enrolled_by) = 16),
    -- PushKind on the wire: 1 Fcm, 2 Apns, 3 UnifiedPush (None is NULL here).
    push_kind smallint check (push_kind between 1 and 3),
    push_token bytea check (octet_length(push_token) between 1 and 4096),
    created_at timestamptz not null default now(),
    last_used_at timestamptz not null default now(),
    revoked_at timestamptz,
    -- The id is the key's fingerprint, never a value the caller picks.
    constraint credentials_id_is_key_fingerprint check (
        id = substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || public_key, 'sha256') from 1 for 16)
    ),
    constraint credentials_push_pair check ((push_kind is null) = (push_token is null))
);
create index credentials_mailbox_idx on onepass_mailbox.credentials (mailbox_id);

create table onepass_mailbox.records (
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id),
    kind smallint not null check (kind between 1 and 255),
    id bytea not null check (length(id) = 16),
    -- The client's version, opaque here.
    version bigint not null,
    -- Server sequence of the last write.
    seq bigint not null check (seq >= 1),
    deleted boolean not null default false,
    -- When the row became a tombstone: the 90 day purge ages on it.
    deleted_at timestamptz,
    size integer not null check (size between 0 and 921600),
    data bytea check (octet_length(data) <= 16384),
    blob_sha256 bytea check (length(blob_sha256) = 32),
    primary key (mailbox_id, kind, id),
    constraint records_seq_unique unique (mailbox_id, seq),
    -- A tombstone has no body; a live row has exactly one of inline data or a blob.
    constraint records_body check (
        case when deleted then data is null and blob_sha256 is null
             else (data is null) <> (blob_sha256 is null) end
    ),
    constraint records_size check (
        case when deleted then size = 0
             when data is not null then size = length(data)
             else size between 16385 and 921600 end
    ),
    constraint records_deleted_at check (deleted = (deleted_at is not null))
);
create index records_tombstone_purge_idx on onepass_mailbox.records (deleted_at) where deleted;

create table onepass_mailbox.blobs (
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id),
    sha256 bytea not null check (length(sha256) = 32),
    -- Only bodies above the inline limit go to Storage.
    size integer not null check (size between 16385 and 921600),
    -- 1 announced, 2 present, 3 orphaned.
    state smallint not null check (state between 1 and 3),
    refs integer not null default 0 check (refs >= 0),
    orphaned_at timestamptz,
    primary key (mailbox_id, sha256)
);
create index blobs_orphaned_idx on onepass_mailbox.blobs (orphaned_at) where refs = 0;

create table onepass_mailbox.nonces (
    credential_id bytea not null references onepass_mailbox.credentials (id) check (length(credential_id) = 16),
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id),
    nonce bytea not null check (length(nonce) = 16),
    seen_at timestamptz not null default now(),
    primary key (credential_id, nonce)
);
create index nonces_seen_at_idx on onepass_mailbox.nonces (seen_at);

create table onepass_mailbox.used_tickets (
    ticket_hash bytea primary key check (length(ticket_hash) = 32),
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id),
    used_at timestamptz not null default now()
);
create index used_tickets_used_at_idx on onepass_mailbox.used_tickets (used_at);

-- Rate windows. The key is a credential id padded to 32 bytes, or the HMAC of
-- an IP address: no mailbox to scope it by.
create table onepass_mailbox.rate (
    key bytea not null check (length(key) = 32),
    window_start timestamptz not null,
    count integer not null default 0 check (count >= 0),
    primary key (key, window_start)
);
create index rate_window_start_idx on onepass_mailbox.rate (window_start);

-- One entry per mailbox: wake-ups are coalesced.
create table onepass_mailbox.push_queue (
    mailbox_id bytea primary key references onepass_mailbox.mailboxes (id),
    exclude_credential bytea check (length(exclude_credential) = 16),
    enqueued_at timestamptz not null default now()
);

create table onepass_mailbox.rdv_sessions (
    session_id bytea primary key check (length(session_id) = 16),
    created_at timestamptz not null default now(),
    bytes bigint not null default 0 check (bytes >= 0),
    closed_at timestamptz
);
create index rdv_sessions_created_at_idx on onepass_mailbox.rdv_sessions (created_at);

create table onepass_mailbox.rdv_chunks (
    session_id bytea not null references onepass_mailbox.rdv_sessions (session_id) on delete cascade,
    -- 0 newcomer to approver, 1 the other way.
    dir smallint not null check (dir in (0, 1)),
    n integer not null check (n >= 0),
    data bytea not null check (octet_length(data) <= 1048576),
    written_at timestamptz not null default now(),
    primary key (session_id, dir, n)
);
create index rdv_chunks_written_at_idx on onepass_mailbox.rdv_chunks (written_at);

-- Row level security, forced so the owner is bound too.
--
-- Every helper call in a policy is wrapped in (select ...): the helpers are
-- not inlinable (they set search_path), so a bare call would run once per
-- row; as a scalar subquery it runs once per statement (an InitPlan).

alter table onepass_mailbox.plans enable row level security;
alter table onepass_mailbox.plans force row level security;
alter table onepass_mailbox.invites enable row level security;
alter table onepass_mailbox.invites force row level security;
alter table onepass_mailbox.mailboxes enable row level security;
alter table onepass_mailbox.mailboxes force row level security;
alter table onepass_mailbox.credentials enable row level security;
alter table onepass_mailbox.credentials force row level security;
alter table onepass_mailbox.records enable row level security;
alter table onepass_mailbox.records force row level security;
alter table onepass_mailbox.blobs enable row level security;
alter table onepass_mailbox.blobs force row level security;
alter table onepass_mailbox.nonces enable row level security;
alter table onepass_mailbox.nonces force row level security;
alter table onepass_mailbox.used_tickets enable row level security;
alter table onepass_mailbox.used_tickets force row level security;
alter table onepass_mailbox.rate enable row level security;
alter table onepass_mailbox.rate force row level security;
alter table onepass_mailbox.push_queue enable row level security;
alter table onepass_mailbox.push_queue force row level security;
alter table onepass_mailbox.rdv_sessions enable row level security;
alter table onepass_mailbox.rdv_sessions force row level security;
alter table onepass_mailbox.rdv_chunks enable row level security;
alter table onepass_mailbox.rdv_chunks force row level security;

-- Plans: read only, written in maintenance (seed, operator).
create policy plans_read on onepass_mailbox.plans
    for select to onepass_mailbox_owner
    using (true);
create policy plans_maintenance on onepass_mailbox.plans
    for all to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()))
    with check ((select onepass_mailbox.in_maintenance()));

-- Invites: only the one whose hash api_create_mailbox put in onepass.invite.
create policy invites_current on onepass_mailbox.invites
    for all to onepass_mailbox_owner
    using (token_hash = (select onepass_mailbox.current_invite()) or (select onepass_mailbox.in_maintenance()))
    with check (token_hash = (select onepass_mailbox.current_invite()) or (select onepass_mailbox.in_maintenance()));

create policy mailboxes_current on onepass_mailbox.mailboxes
    for all to onepass_mailbox_owner
    using (id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy credentials_current on onepass_mailbox.credentials
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy records_current on onepass_mailbox.records
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy blobs_current on onepass_mailbox.blobs
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy nonces_current on onepass_mailbox.nonces
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy used_tickets_current on onepass_mailbox.used_tickets
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

create policy push_queue_current on onepass_mailbox.push_queue
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

-- Rate windows carry no mailbox (IP keys come before any mailbox exists):
-- open to the owner, closed to everyone else by grants.
create policy rate_owner on onepass_mailbox.rate
    for all to onepass_mailbox_owner
    using (true)
    with check (true);

create policy rdv_sessions_current on onepass_mailbox.rdv_sessions
    for all to onepass_mailbox_owner
    using (session_id = (select onepass_mailbox.current_rdv()) or (select onepass_mailbox.in_maintenance()))
    with check (session_id = (select onepass_mailbox.current_rdv()) or (select onepass_mailbox.in_maintenance()));

create policy rdv_chunks_current on onepass_mailbox.rdv_chunks
    for all to onepass_mailbox_owner
    using (session_id = (select onepass_mailbox.current_rdv()) or (select onepass_mailbox.in_maintenance()))
    with check (session_id = (select onepass_mailbox.current_rdv()) or (select onepass_mailbox.in_maintenance()));

reset role;

-- Belt and braces: whatever Supabase's own default privileges granted.
revoke all on all tables in schema onepass_mailbox from public, anon, authenticated, service_role;
revoke all on all sequences in schema onepass_mailbox from public, anon, authenticated, service_role;
revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;
