-- OnePass mailbox: open signup as a database switch (Task 8, carried from
-- Tasks 4 and 6). api_create_mailbox used to trust the edge function's
-- p_open_signup alone, so anyone holding the edge's environment could turn
-- a hosted project into an open one. The switch now also lives in
-- onepass_mailbox.settings (name 'open_signup', value 'on'): signup is open
-- only when the edge says so AND the row says so. A fresh database has no
-- row, so it is closed (invite required). The row is written by the
-- operator (superuser or maintenance), never by the api role; the edge
-- variable MAILBOX_OPEN_SIGNUP stays as the way local-env.sh and self-host
-- ops declare it on the edge side. Same signature, same grants.

set role onepass_mailbox_owner;

create table onepass_mailbox.settings (
    name text primary key check (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    value text not null check (length(value) <= 256)
);
alter table onepass_mailbox.settings enable row level security;
alter table onepass_mailbox.settings force row level security;
create policy settings_read on onepass_mailbox.settings
    for select to onepass_mailbox_owner
    using (true);
create policy settings_maintenance on onepass_mailbox.settings
    for all to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()))
    with check ((select onepass_mailbox.in_maintenance()));

create or replace function onepass_mailbox.api_create_mailbox(
    p_public_key bytea, p_nonce bytea, p_created timestamptz, p_invite bytea,
    p_label bytea, p_ip_key bytea, p_open_signup boolean)
returns table (status text, retry_after integer, mailbox_id bytea, incarnation bigint, wake_topic bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_open boolean;
    v_err text;
    v_plan text;
    v_hash bytea;
    v_uses integer;
    v_expires timestamptz;
    v_id bytea;
    v_cid bytea;
    v_incarnation bigint;
    v_wake bytea;
begin
    perform onepass_mailbox._enter(null);
    -- Open signup needs both the edge's word (p_open_signup) and the database's.
    v_open := p_open_signup and exists (
        select 1 from onepass_mailbox.settings s where s.name = 'open_signup' and s.value = 'on');
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    if p_public_key is null or length(p_public_key) <> 32
       or p_nonce is null or length(p_nonce) <> 16
       or p_open_signup is null
       or (p_label is not null and octet_length(p_label) > 64)
       or (not v_open and (p_invite is null or octet_length(p_invite) not between 1 and 256))
       or onepass_mailbox._ed25519_key_refused(p_public_key) then
        v_err := 'malformed';
    else
        v_err := onepass_mailbox._skew_error(p_created);
    end if;
    if v_err is not null then
        return query select v_err, null::integer, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    if v_open then
        v_plan := 'selfhost';
    else
        v_hash := extensions.digest(p_invite, 'sha256');
        perform set_config('onepass.invite', encode(v_hash, 'hex'), true);
        select i.plan, i.uses_left, i.expires_at into v_plan, v_uses, v_expires
        from onepass_mailbox.invites i where i.token_hash = v_hash
        for update;
        if not found or v_uses <= 0 or v_expires < now() then
            return query select 'not_found'::text, null::integer, null::bytea, null::bigint, null::bytea;
            return;
        end if;
    end if;

    -- Day bucket on a hash of the IP key: the raw key is the minute bucket,
    -- and a day window would share its row with the minute at midnight.
    v_retry := onepass_mailbox._hit(extensions.digest(p_ip_key, 'sha256'), interval '1 day', 5);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    v_id := extensions.gen_random_bytes(16);
    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_public_key, 'sha256') from 1 for 16);
    begin
        if not v_open then
            update onepass_mailbox.invites set uses_left = uses_left - 1 where token_hash = v_hash;
        end if;
        perform onepass_mailbox._enter(v_id);
        insert into onepass_mailbox.mailboxes (id, plan) values (v_id, v_plan)
        returning mailboxes.incarnation, mailboxes.wake_topic into v_incarnation, v_wake;
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
        values (v_cid, v_id, p_public_key, coalesce(p_label, '\x'::bytea));
        insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce) values (v_cid, v_id, p_nonce);
    exception when unique_violation then
        -- The key is enrolled in some mailbox. Only the key's owner (who
        -- signed this request) learns it, and only that much. The block is
        -- rolled back: no mailbox, the invite use is kept.
        v_err := 'malformed';
    end;
    perform onepass_mailbox._enter(null);
    if v_err is not null then
        return query select v_err, null::integer, null::bytea, null::bigint, null::bytea;
        return;
    end if;
    return query select 'ok'::text, null::integer, v_id, v_incarnation, v_wake;
end
$$;

reset role;

revoke all on onepass_mailbox.settings from public, anon, authenticated, service_role;
