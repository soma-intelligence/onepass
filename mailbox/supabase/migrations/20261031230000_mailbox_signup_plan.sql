-- OnePass mailbox: configurable open signup plan and a global daily creation
-- cap (Task 21, spec D.6 and 4.9). Two optional rows of
-- onepass_mailbox.settings, written by the operator in maintenance mode:
--   open_signup_plan  name of an existing plan for open signup (absent:
--                     selfhost, the behaviour so far). An unknown name is a
--                     bug and raises a plain error (503 retry at the edge).
--   daily_create_cap  integer, mailboxes created per UTC day over the whole
--                     instance (absent: no cap). Counted in a rate row keyed
--                     SHA-256('onepass/global-create'), only for a creation
--                     that succeeds; over the cap the answer is the in-band
--                     status retry (503 retry, no retry_after).
-- An invite's own plan always wins over open_signup_plan. Open signup itself
-- stays off unless open_signup = 'on' (migration 20261031120700). Same
-- signature, same grants.

set role onepass_mailbox_owner;

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
    v_cap integer;
    v_day timestamptz;
    v_cap_key bytea;
    v_made integer;
    v_use_invite boolean := false;
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

    -- A valid invite always wins, even when signup is open: its plan applies
    -- and a use is spent. An invalid one on an open instance falls through to
    -- the open signup plan; on a closed one it is not_found.
    if p_invite is not null and octet_length(p_invite) between 1 and 256 then
        v_hash := extensions.digest(p_invite, 'sha256');
        perform set_config('onepass.invite', encode(v_hash, 'hex'), true);
        select i.plan, i.uses_left, i.expires_at into v_plan, v_uses, v_expires
        from onepass_mailbox.invites i where i.token_hash = v_hash
        for update;
        if found and v_uses > 0 and v_expires >= now() then
            v_use_invite := true;
        else
            v_plan := null;
        end if;
    end if;
    if not v_use_invite then
        if not v_open then
            return query select 'not_found'::text, null::integer, null::bytea, null::bigint, null::bytea;
            return;
        end if;
        -- Plan of an open signup: the setting names an existing plan, else
        -- selfhost. A name that is no plan is an operator bug: it raises a
        -- plain error (no OP code), which the edge answers as 503 retry.
        select s.value into v_plan from onepass_mailbox.settings s where s.name = 'open_signup_plan';
        v_plan := coalesce(v_plan, 'selfhost');
        if not exists (select 1 from onepass_mailbox.plans p where p.plan = v_plan) then
            raise exception 'open_signup_plan % is not a plan', v_plan using errcode = 'P0001';
        end if;
    end if;

    -- Day bucket on a hash of the IP key: the raw key is the minute bucket,
    -- and a day window would share its row with the minute at midnight.
    v_retry := onepass_mailbox._hit(extensions.digest(p_ip_key, 'sha256'), interval '1 day', 5);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    -- Global daily creation cap (setting daily_create_cap, absent = none):
    -- one rate row, locked until the end of the transaction so concurrent
    -- creations cannot overshoot. Only a creation that succeeds is counted
    -- (below); at the cap the answer is an in-band retry without retry_after.
    select s.value::integer into v_cap from onepass_mailbox.settings s where s.name = 'daily_create_cap';
    if v_cap is not null then
        v_day := date_trunc('day', now(), 'UTC');
        v_cap_key := extensions.digest('onepass/global-create'::bytea, 'sha256');
        insert into onepass_mailbox.rate (key, window_start, count) values (v_cap_key, v_day, 0)
        on conflict (key, window_start) do nothing;
        select r.count into v_made from onepass_mailbox.rate r
        where r.key = v_cap_key and r.window_start = v_day for update;
        if v_made >= v_cap then
            return query select 'retry'::text, null::integer, null::bytea, null::bigint, null::bytea;
            return;
        end if;
    end if;

    v_id := extensions.gen_random_bytes(16);
    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_public_key, 'sha256') from 1 for 16);
    begin
        if v_use_invite then
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
    if v_cap is not null then
        update onepass_mailbox.rate r set count = r.count + 1
        where r.key = v_cap_key and r.window_start = v_day;
    end if;
    return query select 'ok'::text, null::integer, v_id, v_incarnation, v_wake;
end
$$;

reset role;
