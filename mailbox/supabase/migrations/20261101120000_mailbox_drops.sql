-- OnePass mailbox: 72 hour invite drops (Task 25; sharing spec 13.9, remote
-- invitation of 5.3.2). Follows the contract in the header of
-- 20261031120100.
--
-- A drop is a tiny dead letter box keyed by a random 16 byte id that only
-- the two people of an invitation know (it travels inside the invite link).
-- No credential, like the rendezvous: the id is the only key. Four slots
-- (0 to 3), each written once, 64 KiB at most. The first write of a drop id
-- opens it for 72 hours; every slot of that drop expires with it. Past the
-- deadline a write or a read is 'not_found', and maintenance drops the
-- slots. The head row (drop_heads) outlives the drop by 7 days, so a late
-- write never reopens a drop for another 72 hours.
--
-- Limits per IP key: the minute bucket of create, enroll and the rendezvous
-- (raw IP key, 60 a minute, every call counts, failed ones included), plus
-- 50 writes a day counted on SHA-256('onepass/drop' || IP key), distinct
-- from every other bucket key.
--
--   drop_put(id, slot, data, ip_key): 'ok'; 'conflict' when that slot is
--     already written; 'not_found' once the drop expired or was deleted;
--     'malformed' (bad id or slot, no data), 'too_large' (over 65 536
--     bytes), 'rate_limited' (retry_after).
--   drop_get(id, slot, ip_key): 'ok' with the bytes; 'not_found' when the
--     slot was never written, or the drop expired or was deleted.
--   drop_delete(id, ip_key): 'ok', whatever the drop held; the drop is
--     closed for good (its head stays until its 7 days run out).
--
-- A malformed IP key raises (OP400), as on the rendezvous.

set role onepass_mailbox_owner;

-- ---------------------------------------------------------------- schema

create table onepass_mailbox.drop_heads (
    drop_id bytea primary key check (length(drop_id) = 16),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);
create index drop_heads_expires_at_idx on onepass_mailbox.drop_heads (expires_at);

create table onepass_mailbox.drops (
    drop_id bytea not null references onepass_mailbox.drop_heads (drop_id) on delete cascade
        check (length(drop_id) = 16),
    slot smallint not null check (slot between 0 and 3),
    data bytea not null check (length(data) <= 65536),
    written_at timestamptz not null default now(),
    expires_at timestamptz not null,
    primary key (drop_id, slot)
);
create index drops_expires_at_idx on onepass_mailbox.drops (expires_at);

create function onepass_mailbox.current_drop()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{32}$' then decode(s, 'hex') end
    from (select current_setting('onepass.drop', true) as s) c;
$$;

alter table onepass_mailbox.drop_heads enable row level security;
alter table onepass_mailbox.drop_heads force row level security;
alter table onepass_mailbox.drops enable row level security;
alter table onepass_mailbox.drops force row level security;

create policy drop_heads_current on onepass_mailbox.drop_heads
    for all to onepass_mailbox_owner
    using (drop_id = (select onepass_mailbox.current_drop()) or (select onepass_mailbox.in_maintenance()))
    with check (drop_id = (select onepass_mailbox.current_drop()) or (select onepass_mailbox.in_maintenance()));
create policy drops_current on onepass_mailbox.drops
    for all to onepass_mailbox_owner
    using (drop_id = (select onepass_mailbox.current_drop()) or (select onepass_mailbox.in_maintenance()))
    with check (drop_id = (select onepass_mailbox.current_drop()) or (select onepass_mailbox.in_maintenance()));

-- The context reset every entry point starts with gains onepass.drop.
create or replace function onepass_mailbox._enter(p_mailbox bytea)
returns void
language plpgsql
set search_path = ''
as $$
begin
    perform set_config('onepass.mailbox', coalesce(encode(p_mailbox, 'hex'), ''), true);
    perform set_config('onepass.rdv', '', true);
    perform set_config('onepass.invite', '', true);
    perform set_config('onepass.locator', '', true);
    perform set_config('onepass.parent', '', true);
    perform set_config('onepass.drop', '', true);
    perform set_config('onepass.maintenance', '', true);
end
$$;

-- ----------------------------------------------------------- maintenance

-- The maintenance of the earlier migrations runs first, unchanged, under its
-- new name; drops are purged after it. A later migration that replaces
-- maintenance again keeps calling _maintenance_core and the drop purge.
alter function onepass_mailbox.maintenance(timestamptz) rename to _maintenance_core;

create function onepass_mailbox.maintenance(p_now timestamptz default now())
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    perform onepass_mailbox._maintenance_core(p_now);
    perform set_config('onepass.maintenance', 'on', true);
    if not onepass_mailbox.in_maintenance() then
        raise exception 'maintenance runs as postgres or the janitor';
    end if;
    delete from onepass_mailbox.drops where expires_at <= p_now;
    delete from onepass_mailbox.drop_heads where expires_at <= p_now - interval '7 days';
    perform set_config('onepass.maintenance', '', true);
end
$$;

-- ----------------------------------------------------------- entry points

-- Shapes and the per-IP minute hit shared by the three entry points.
-- Returns retry_after when over the minute bucket.
create function onepass_mailbox._drop_enter(p_id bytea, p_ip_key bytea)
returns integer
language plpgsql
set search_path = ''
as $$
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    return onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
end
$$;

-- PUT /v1/drops/{d}/{slot}.
create function onepass_mailbox.drop_put(p_id bytea, p_slot smallint, p_data bytea, p_ip_key bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_expires timestamptz;
    v_rows bigint;
begin
    v_retry := onepass_mailbox._drop_enter(p_id, p_ip_key);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_id is null or length(p_id) <> 16 or p_slot is null or p_slot not between 0 and 3 or p_data is null then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    if octet_length(p_data) > 65536 then
        return query select 'too_large'::text, null::integer;
        return;
    end if;
    v_retry := onepass_mailbox._hit(
        extensions.digest('onepass/drop'::bytea || p_ip_key, 'sha256'), interval '1 day', 50);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;

    perform set_config('onepass.drop', encode(p_id, 'hex'), true);
    insert into onepass_mailbox.drop_heads (drop_id, expires_at) values (p_id, now() + interval '72 hours')
    on conflict (drop_id) do nothing;
    select h.expires_at into v_expires
    from onepass_mailbox.drop_heads h where h.drop_id = p_id
    for update;
    if v_expires <= now() then
        perform set_config('onepass.drop', '', true);
        return query select 'not_found'::text, null::integer;
        return;
    end if;
    insert into onepass_mailbox.drops (drop_id, slot, data, expires_at)
    values (p_id, p_slot, p_data, v_expires)
    on conflict (drop_id, slot) do nothing;
    get diagnostics v_rows = row_count;
    perform set_config('onepass.drop', '', true);
    if v_rows = 0 then
        return query select 'conflict'::text, null::integer;
        return;
    end if;
    return query select 'ok'::text, null::integer;
end
$$;

-- GET /v1/drops/{d}/{slot}.
create function onepass_mailbox.drop_get(p_id bytea, p_slot smallint, p_ip_key bytea)
returns table (status text, retry_after integer, data bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_data bytea;
begin
    v_retry := onepass_mailbox._drop_enter(p_id, p_ip_key);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;
    if p_id is null or length(p_id) <> 16 or p_slot is null or p_slot not between 0 and 3 then
        return query select 'malformed'::text, null::integer, null::bytea;
        return;
    end if;
    perform set_config('onepass.drop', encode(p_id, 'hex'), true);
    select d.data into v_data
    from onepass_mailbox.drops d
    where d.drop_id = p_id and d.slot = p_slot and d.expires_at > now();
    perform set_config('onepass.drop', '', true);
    if v_data is null then
        return query select 'not_found'::text, null::integer, null::bytea;
        return;
    end if;
    return query select 'ok'::text, null::integer, v_data;
end
$$;

-- DELETE /v1/drops/{d}. Closes the drop for good, even one never opened.
create function onepass_mailbox.drop_delete(p_id bytea, p_ip_key bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    v_retry := onepass_mailbox._drop_enter(p_id, p_ip_key);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_id is null or length(p_id) <> 16 then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    perform set_config('onepass.drop', encode(p_id, 'hex'), true);
    insert into onepass_mailbox.drop_heads as h (drop_id, expires_at) values (p_id, now())
    on conflict (drop_id) do update set expires_at = least(h.expires_at, excluded.expires_at);
    delete from onepass_mailbox.drops d where d.drop_id = p_id;
    perform set_config('onepass.drop', '', true);
    return query select 'ok'::text, null::integer;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on function onepass_mailbox.current_drop() from public;
revoke all on function onepass_mailbox._drop_enter(bytea, bytea) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox._maintenance_core(timestamptz) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.maintenance(timestamptz) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.drop_put(bytea, smallint, bytea, bytea) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.drop_get(bytea, smallint, bytea) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.drop_delete(bytea, bytea) from public, anon, authenticated, service_role;
grant execute on function
    onepass_mailbox.drop_put(bytea, smallint, bytea, bytea),
    onepass_mailbox.drop_get(bytea, smallint, bytea),
    onepass_mailbox.drop_delete(bytea, bytea)
to onepass_mailbox_api;
