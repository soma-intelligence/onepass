-- OnePass mailbox: locator lookup and abandoning a fresh mailbox (Task 23,
-- spec D.4, D.5, D.7). Follows the contract in the header of 20261031120100.
--
-- Locator (D.4). 16 bytes the client derives from the Secret Key
-- (HKDF-SHA256, info "onepass/mailbox-locator/v1"), so a new device holding
-- only the Emergency Kit finds its mailbox. A locator is not unique: two
-- devices that raced a migration (D.5), or a holder of the Secret Key, may
-- register it on several mailboxes, and the client tells its own by trying
-- each with its recovery credential and the core's account verification.
--   api_set_locator     a manager (role 3, read again under the mailbox lock)
--                       adds a locator to the mailbox. Never refused for a
--                       locator another mailbox holds. A mailbox keeps at
--                       most 2 (old and new coexist until phase 3 of a
--                       rotation, D.4): a third drops that mailbox's oldest.
--                       Setting a pair the table already holds changes
--                       nothing (its age included).
--   locate              no signature, no credential: 'ok' rows with up to 8
--                       live mailbox ids, oldest registration first, or one
--                       'not_found' row (unknown locator, or only deleted
--                       mailboxes). Every call counts on the per-IP minute
--                       bucket shared with create, enroll and rendezvous
--                       (60, raw IP key) and on 30 an hour keyed
--                       SHA-256('onepass/locate' || IP key), distinct from
--                       every other window key. A locator is 128 bits
--                       derived from a secret: not enumerable at that rate,
--                       and the answer says nothing about a mailbox beyond
--                       its id to whoever already holds its locator.
--
-- Abandon (D.5, the losing side of a migration race).
--   api_abandon_mailbox  the creator credential only (mailboxes.created_by,
--                       written by api_create_mailbox from now on; a mailbox
--                       created before this migration has none and cannot be
--                       abandoned), still a manager (role 3 under the lock),
--                       within 24 hours of created_at, and only while the
--                       mailbox is fresh: no credential but the creator has
--                       ever authenticated (credentials.first_used_at, set
--                       by _authenticate from now on, so a nonce, a commit or
--                       a grant by it all count), none was enrolled, and at
--                       most one other exists (the unused recovery
--                       credential the creator granted). Task 24 adds: no
--                       children. Otherwise forbidden, in band after
--                       authentication. Sets deleted_at, drops the locators
--                       and the push queue entry.
-- From deleted_at on, every api_* entry point on the mailbox raises
-- not_found (_authenticate, _locked_caller under the lock, api_enroll in
-- band), and locate does not find it. credential_key is unchanged: before
-- the signature is checked nothing tells a deleted mailbox from a live one.
-- maintenance purges a mailbox deleted more than an hour ago: nonces, used
-- tickets, push queue, locator, records, credentials, and its blob rows,
-- whose object names go to blob_graves for mailbox-gc (the path of 4.11).
-- The mailbox row itself stays, empty, with deleted_at: blob_graves
-- references it, and its id is never handed out again.
--
-- Replaced (same signatures and grants): _enter (also clears
-- onepass.locator), _hit (adds the hour window), _authenticate,
-- _locked_caller, api_create_mailbox (created_by), api_enroll (a deleted
-- mailbox is not_found), maintenance (the purge).

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- schema

alter table onepass_mailbox.mailboxes
    add column created_by bytea check (length(created_by) = 16),
    add column deleted_at timestamptz;
alter table onepass_mailbox.credentials
    add column first_used_at timestamptz;
comment on column onepass_mailbox.credentials.first_used_at is
    'first authenticated request (nonce recorded); NULL = never used, which keeps a mailbox abandonable';
comment on column onepass_mailbox.mailboxes.created_by is
    'credential id of the creator: the only one that may abandon the mailbox (24 h)';
create index mailboxes_deleted_idx on onepass_mailbox.mailboxes (deleted_at) where deleted_at is not null;

create table onepass_mailbox.locators (
    locator bytea not null check (length(locator) = 16),
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id) check (length(mailbox_id) = 16),
    -- Registration order: oldest first in locate, oldest dropped past 2.
    seq bigint generated always as identity,
    primary key (locator, mailbox_id)
);
create index locators_locator_seq_idx on onepass_mailbox.locators (locator, seq);
create index locators_mailbox_seq_idx on onepass_mailbox.locators (mailbox_id, seq);

-- The locator a locate call looks up (NULL when absent or malformed).
create function onepass_mailbox.current_locator()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{32}$' then decode(s, 'hex') end
    from (select current_setting('onepass.locator', true) as s) c;
$$;
revoke all on function onepass_mailbox.current_locator() from public;

alter table onepass_mailbox.locators enable row level security;
alter table onepass_mailbox.locators force row level security;
create policy locators_current on onepass_mailbox.locators
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox())
           or locator = (select onepass_mailbox.current_locator())
           or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox())
                or (select onepass_mailbox.in_maintenance()));

-- ------------------------------------------------------------ helpers

-- _enter of 20261031120100: also clears onepass.locator.
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
    perform set_config('onepass.maintenance', '', true);
end
$$;

-- _hit of 20261031120100, with the hour window (locate), and retry_after
-- measured to the window end in UTC.
create or replace function onepass_mailbox._hit(p_key bytea, p_window interval, p_limit integer)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_start timestamptz;
    v_count integer;
begin
    v_start := case p_window
        when interval '1 minute' then date_trunc('minute', now(), 'UTC')
        when interval '1 hour' then date_trunc('hour', now(), 'UTC')
        when interval '1 day' then date_trunc('day', now(), 'UTC')
    end;
    if v_start is null then
        raise exception 'unsupported rate window %', p_window;
    end if;
    insert into onepass_mailbox.rate as r (key, window_start, count)
    values (p_key, v_start, 1)
    on conflict (key, window_start) do update set count = r.count + 1
    returning r.count into v_count;
    if v_count > p_limit then
        -- The window end in UTC: timestamptz + interval follows the session
        -- time zone, where a day can last 23 or 25 hours (DST).
        return greatest(1, ceil(extract(epoch from
            (((v_start at time zone 'UTC') + p_window) at time zone 'UTC') - now())))::integer;
    end if;
    return null;
end
$$;

-- _authenticate of 20261031120100: a deleted mailbox raises not_found,
-- before anything is recorded; once the nonce is recorded, first_used_at.
create or replace function onepass_mailbox._authenticate(p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_revoked timestamptz;
    v_last timestamptz;
    v_first timestamptz;
    v_frozen boolean;
    v_deleted timestamptz;
    v_rate integer;
    v_retry integer;
    v_err text;
begin
    perform onepass_mailbox._enter(null);
    if p_credential is null or length(p_credential) <> 16
       or p_nonce is null or length(p_nonce) <> 16
       or p_mailbox is null or length(p_mailbox) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_err := onepass_mailbox._skew_error(p_created);
    if v_err is not null then
        perform onepass_mailbox._fail(v_err);
    end if;
    perform onepass_mailbox._enter(p_mailbox);

    select c.revoked_at, c.last_used_at, c.first_used_at into v_revoked, v_last, v_first
    from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_revoked is not null then
        perform onepass_mailbox._fail('revoked_credential');
    end if;

    select m.frozen, m.deleted_at, p.req_per_min into v_frozen, v_deleted, v_rate
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_deleted is not null then
        -- Abandoned (api_abandon_mailbox): gone for every caller.
        perform onepass_mailbox._fail('not_found');
    end if;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;

    begin
        insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
        values (p_credential, p_mailbox, p_nonce);
    exception when unique_violation then
        perform onepass_mailbox._fail('replay');
    end;

    -- Credential rate key: the 16 byte id zero-padded to 32 (an IP key is a
    -- 32 byte HMAC; a collision is negligible).
    v_retry := onepass_mailbox._hit(p_credential || '\x00000000000000000000000000000000'::bytea, interval '1 minute', v_rate);

    -- first_used_at: this credential is no longer unused, so its mailbox
    -- is no longer fresh for api_abandon_mailbox.
    if v_last < now() - interval '1 minute' or v_first is null then
        update onepass_mailbox.credentials
        set last_used_at = now(), first_used_at = coalesce(first_used_at, now())
        where id = p_credential and mailbox_id = p_mailbox;
    end if;
    return v_retry;
end
$$;

-- _locked_caller of 20261031233000: a mailbox abandoned while the request
-- waited for its lock raises not_found too.
create or replace function onepass_mailbox._locked_caller(
    p_credential bytea, p_mailbox bytea, out o_role smallint, out o_put_kinds bytea)
language plpgsql
set search_path = ''
as $$
declare
    v_revoked timestamptz;
begin
    select c.role, c.put_kinds, c.revoked_at into o_role, o_put_kinds, v_revoked
    from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_revoked is not null then
        perform onepass_mailbox._fail('revoked_credential');
    end if;
    -- Abandoned while the request waited for the lock.
    if exists (select 1 from onepass_mailbox.mailboxes m where m.id = p_mailbox and m.deleted_at is not null) then
        perform onepass_mailbox._fail('not_found');
    end if;
end
$$;

-- ------------------------------------------------------ replaced entry points

-- api_create_mailbox of 20261031230000: the creator credential goes into
-- mailboxes.created_by.
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
    -- Creations through a valid invite are exempt: they neither check nor count.
    if not v_use_invite then
        select s.value::integer into v_cap from onepass_mailbox.settings s where s.name = 'daily_create_cap';
    end if;
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
        insert into onepass_mailbox.mailboxes (id, plan, created_by) values (v_id, v_plan, v_cid)
        returning mailboxes.incarnation, mailboxes.wake_topic into v_incarnation, v_wake;
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
        values (v_cid, v_id, p_public_key, coalesce(p_label, '\x'::bytea));
        insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce) values (v_cid, v_id, p_nonce);
    exception when unique_violation then
        -- The key is enrolled in some mailbox. Only the key's owner (who
        -- signed this request) learns it, and only that much. The block is
        -- rolled back with the whole block: no mailbox, and the invite use
        -- (decremented inside the block) is given back too.
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

-- api_enroll of 20261031233000: a deleted mailbox is not_found (in band,
-- after the per-IP hit).
create or replace function onepass_mailbox.api_enroll(
    p_new_public_key bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_approver bytea, p_ticket_hash bytea, p_ticket_expires timestamptz, p_label bytea, p_ip_key bytea)
returns table (status text, retry_after integer, credential_id bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_frozen boolean;
    v_deleted timestamptz;
    v_max integer;
    v_revoked timestamptz;
    v_active integer;
    v_cid bytea;
    v_constraint text;
    v_role smallint;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    -- The minute bucket of the credential-less routes (spec 4.9: 60 a
    -- minute per IP key, shared with create and the rendezvous routes).
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;

    if p_new_public_key is null or length(p_new_public_key) <> 32
       or p_nonce is null or length(p_nonce) <> 16
       or p_mailbox is null or length(p_mailbox) <> 16
       or p_approver is null or length(p_approver) <> 16
       or p_ticket_hash is null or length(p_ticket_hash) <> 32
       or p_ticket_expires is null
       or (p_label is not null and octet_length(p_label) > 64)
       or onepass_mailbox._ed25519_key_refused(p_new_public_key)
       or p_ticket_expires > now() + interval '900 seconds' then
        v_err := 'malformed';
    else
        v_err := onepass_mailbox._skew_error(p_created);
    end if;

    if v_err is null then
        perform onepass_mailbox._enter(p_mailbox);
        -- Locked: concurrent enrollments count active credentials one at a time.
        select m.frozen, m.deleted_at, p.max_credentials into v_frozen, v_deleted, v_max
        from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
        where m.id = p_mailbox
        for update of m;
        if not found or v_deleted is not null then
            v_err := 'not_found';
        elsif v_frozen then
            v_err := 'frozen';
        end if;
    end if;

    if v_err is null then
        select c.revoked_at, c.role into v_revoked, v_role
        from onepass_mailbox.credentials c
        where c.id = p_approver and c.mailbox_id = p_mailbox;
        if not found then
            v_err := 'unknown_credential';
        elsif v_revoked is not null then
            v_err := 'revoked_credential';
        elsif v_role <> 3 then
            -- Only a manager lets a device in.
            v_err := 'forbidden';
        elsif p_ticket_expires < now() then
            v_err := 'stale_request';
        end if;
    end if;

    if v_err is null then
        v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_new_public_key, 'sha256') from 1 for 16);
        if exists (select 1 from onepass_mailbox.credentials c where c.id = v_cid and c.mailbox_id = p_mailbox) then
            -- The same key again (another signature over the same ticket, or
            -- a second ticket): at worst a no-op, answered as a replay.
            v_err := 'replay';
        else
            select count(*)::integer into v_active
            from onepass_mailbox.credentials c
            where c.mailbox_id = p_mailbox and c.revoked_at is null;
            if v_active >= v_max then
                v_err := 'quota';
            end if;
        end if;
    end if;

    if v_err is null then
        begin
            insert into onepass_mailbox.used_tickets (ticket_hash, mailbox_id) values (p_ticket_hash, p_mailbox);
            insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label, enrolled_by)
            values (v_cid, p_mailbox, p_new_public_key, coalesce(p_label, '\x'::bytea), p_approver);
            insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce) values (v_cid, p_mailbox, p_nonce);
        exception when unique_violation then
            get stacked diagnostics v_constraint = constraint_name;
            -- A used ticket (here or in another mailbox) is a replay; the key
            -- enrolled in another mailbox is malformed (see create).
            v_err := case when v_constraint = 'used_tickets_pkey' then 'replay' else 'malformed' end;
        end;
    end if;

    if v_err is not null then
        return query select v_err, null::integer, null::bytea;
        return;
    end if;
    return query select 'ok'::text, null::integer, v_cid;
end
$$;

-- maintenance of 20261031120400, with the purge of abandoned mailboxes.
create or replace function onepass_mailbox.maintenance(p_now timestamptz default now())
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_cutoff timestamptz;
    v_locked bytea[];
    v_day date;
    v_dead bytea[];
begin
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    if not onepass_mailbox.in_maintenance() then
        raise exception 'maintenance runs as postgres or the janitor';
    end if;

    delete from onepass_mailbox.nonces where seen_at < p_now - interval '600 seconds';
    delete from onepass_mailbox.used_tickets where used_at < p_now - interval '1 hour';
    delete from onepass_mailbox.rdv_chunks where written_at < p_now - interval '120 seconds';
    delete from onepass_mailbox.rdv_chunks c
    using onepass_mailbox.rdv_sessions s
    where c.session_id = s.session_id and s.created_at < p_now - interval '600 seconds';
    -- The row outlives the session by a day, so its id cannot start another.
    delete from onepass_mailbox.rdv_sessions where created_at < p_now - interval '1 day';
    delete from onepass_mailbox.rate r
    where r.window_start < p_now - interval '2 days'
       or (r.window_start < p_now - interval '2 minutes' and r.window_start <> date_trunc('hour', r.window_start, 'UTC'))
       or (r.window_start < p_now - interval '2 hours' and r.window_start <> date_trunc('day', r.window_start, 'UTC'));

    -- Tombstones of 90 days: lock their mailboxes first, as a commit does.
    v_cutoff := p_now - interval '90 days';
    select array_agg(m.id order by m.id) into v_locked
    from (
        select m.id from onepass_mailbox.mailboxes m
        where m.id in (select t.mailbox_id from (
                           select r.mailbox_id from onepass_mailbox.records r
                           where r.deleted and r.deleted_at < v_cutoff
                           order by r.deleted_at limit 50000) t)
        order by m.id
        for no key update
    ) m;
    if v_locked is not null then
        with victims as (
            select r.mailbox_id, r.kind, r.id from onepass_mailbox.records r
            where r.deleted and r.deleted_at < v_cutoff and r.mailbox_id = any (v_locked)
            order by r.deleted_at
            limit 50000
        ), purged as (
            delete from onepass_mailbox.records r
            using victims v
            where r.mailbox_id = v.mailbox_id and r.kind = v.kind and r.id = v.id and r.deleted
            returning r.mailbox_id, r.seq
        ), per as (
            select p.mailbox_id, count(*)::integer as n, max(p.seq) as top from purged p group by p.mailbox_id
        )
        update onepass_mailbox.mailboxes m set
            records_count = m.records_count - per.n,
            bytes_used = m.bytes_used - 128 * per.n,
            min_cursor = greatest(m.min_cursor, per.top)
        from per
        where m.id = per.mailbox_id;
    end if;

    -- Mailboxes abandoned more than an hour ago (api_abandon_mailbox), at
    -- most 1 000 a run, locked in id order and skipped while a request holds
    -- them. A mailbox still has credentials until it is purged: the purge
    -- deletes them last, so a purged mailbox is never picked again. Its blob
    -- rows go to blob_graves at once (the 24 hour orphan delay protects a
    -- commit racing the collector; nothing commits here any more).
    select array_agg(d.id order by d.id) into v_dead
    from (
        select m.id from onepass_mailbox.mailboxes m
        where m.deleted_at < p_now - interval '1 hour'
          and exists (select 1 from onepass_mailbox.credentials c where c.mailbox_id = m.id)
        order by m.id
        limit 1000
        for no key update skip locked
    ) d;
    if v_dead is not null then
        delete from onepass_mailbox.nonces where mailbox_id = any (v_dead);
        delete from onepass_mailbox.used_tickets where mailbox_id = any (v_dead);
        delete from onepass_mailbox.push_queue where mailbox_id = any (v_dead);
        delete from onepass_mailbox.locators where mailbox_id = any (v_dead);
        delete from onepass_mailbox.records where mailbox_id = any (v_dead);
        with gone as (
            delete from onepass_mailbox.blobs b
            where b.mailbox_id = any (v_dead)
            returning b.mailbox_id, onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen) as object_name
        )
        insert into onepass_mailbox.blob_graves (mailbox_id, object_name, queued_at)
        select g.mailbox_id, g.object_name, p_now from gone g
        on conflict (mailbox_id, object_name) do nothing;
        delete from onepass_mailbox.credentials where mailbox_id = any (v_dead);
        update onepass_mailbox.mailboxes set bytes_used = 0, records_count = 0
        where id = any (v_dead);
    end if;

    -- Skips rows a commit or announce holds (they lock in hash order): no
    -- deadlock, and a skipped row is marked a minute later.
    update onepass_mailbox.blobs b set orphaned_at = p_now
    from (select x.mailbox_id, x.sha256 from onepass_mailbox.blobs x
          where x.refs = 0 and x.orphaned_at is null
          order by x.mailbox_id, x.sha256
          for update skip locked) t
    where b.mailbox_id = t.mailbox_id and b.sha256 = t.sha256;

    -- Collect: row out, object name into the graves, under the row lock.
    with t as (
        select x.mailbox_id, x.sha256 from onepass_mailbox.blobs x
        where x.refs = 0 and x.orphaned_at <= p_now - interval '24 hours'
        order by x.mailbox_id, x.sha256
        limit 10000
        for update skip locked
    ), gone as (
        delete from onepass_mailbox.blobs b
        using t
        where b.mailbox_id = t.mailbox_id and b.sha256 = t.sha256 and b.refs = 0
        returning b.mailbox_id, onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen) as object_name
    )
    insert into onepass_mailbox.blob_graves (mailbox_id, object_name, queued_at)
    select g.mailbox_id, g.object_name, p_now from gone g
    on conflict (mailbox_id, object_name) do nothing;
    -- A take mailbox-gc never confirmed goes back to the queue.
    update onepass_mailbox.blob_graves set taken_at = null
    where taken_at < p_now - interval '10 minutes';

    for v_day in select * from onepass_mailbox.wake_partitions_missing(p_now) loop
        raise warning 'onepass_mailbox maintenance: realtime.messages has no partition for % (UTC), wake-ups that day are lost; the Realtime service creates them', v_day;
    end loop;

    perform set_config('onepass.maintenance', '', true);
end
$$;

-- ------------------------------------------------------- new entry points

-- PUT /v1/mailboxes/{m}/locator.
create function onepass_mailbox.api_set_locator(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_locator bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_role smallint;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_locator is null or length(p_locator) <> 16 then
        return query select 'malformed'::text, null::integer;
        return;
    end if;

    perform 1 from onepass_mailbox.mailboxes m where m.id = p_mailbox for no key update;
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
    if v_role is distinct from 3 then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    -- Another mailbox holding the same locator is no conflict (D.4).
    insert into onepass_mailbox.locators (locator, mailbox_id) values (p_locator, p_mailbox)
    on conflict (locator, mailbox_id) do nothing;
    -- Keep the mailbox's 2 latest.
    delete from onepass_mailbox.locators l
    where l.mailbox_id = p_mailbox
      and l.seq not in (select k.seq from onepass_mailbox.locators k
                        where k.mailbox_id = p_mailbox order by k.seq desc limit 2);
    return query select 'ok'::text, null::integer;
end
$$;

-- POST /v1/locate, unsigned. Up to 8 'ok' rows, oldest registration
-- first, or a single row for any other status.
create function onepass_mailbox.locate(p_locator bytea, p_ip_key bytea)
returns table (status text, retry_after integer, mailbox_id bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_candidates bytea[];
    v_mailbox bytea;
    v_live bytea[] := '{}';
    v_ok boolean;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    -- Minute bucket shared with create, enroll and rendezvous.
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is null then
        v_retry := onepass_mailbox._hit(
            extensions.digest('onepass/locate'::bytea || p_ip_key, 'sha256'), interval '1 hour', 30);
    end if;
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;
    if p_locator is null or length(p_locator) <> 16 then
        return query select 'malformed'::text, null::integer, null::bytea;
        return;
    end if;

    -- Read the candidates first: _enter, which the liveness check needs,
    -- clears onepass.locator. Abandon drops a mailbox's rows, so a deleted
    -- one here is rare; 16 leaves room for it.
    perform set_config('onepass.locator', encode(p_locator, 'hex'), true);
    select array_agg(x.mailbox_id order by x.seq) into v_candidates
    from (select l.mailbox_id, l.seq from onepass_mailbox.locators l
          where l.locator = p_locator order by l.seq limit 16) x;
    foreach v_mailbox in array coalesce(v_candidates, '{}') loop
        exit when cardinality(v_live) >= 8;
        perform onepass_mailbox._enter(v_mailbox);
        select m.deleted_at is null into v_ok from onepass_mailbox.mailboxes m where m.id = v_mailbox;
        if v_ok then
            v_live := v_live || v_mailbox;
        end if;
    end loop;
    perform onepass_mailbox._enter(null);
    if cardinality(v_live) = 0 then
        return query select 'not_found'::text, null::integer, null::bytea;
        return;
    end if;
    return query select 'ok'::text, null::integer, u.id
    from unnest(v_live) with ordinality u(id, n) order by u.n;
end
$$;

-- DELETE /v1/mailboxes/{m}.
create function onepass_mailbox.api_abandon_mailbox(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_created_by bytea;
    v_created_at timestamptz;
    v_role smallint;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;

    select m.created_by, m.created_at into v_created_by, v_created_at
    from onepass_mailbox.mailboxes m where m.id = p_mailbox
    for no key update;
    -- Revoked or abandoned while waiting for the lock: raised.
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
    -- Task 24 adds: and the mailbox has no child.
    if v_created_by is distinct from p_credential
       or v_role is distinct from 3
       or v_created_at <= now() - interval '24 hours'
       -- Fresh: no other credential ever used or enrolled, at most one
       -- other at all (the unused recovery credential).
       or exists (select 1 from onepass_mailbox.credentials c
                  where c.mailbox_id = p_mailbox and c.id <> p_credential
                    and (c.first_used_at is not null or c.enrolled_by is not null))
       or (select count(*) from onepass_mailbox.credentials c
           where c.mailbox_id = p_mailbox and c.id <> p_credential) > 1 then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    update onepass_mailbox.mailboxes set deleted_at = now() where id = p_mailbox;
    delete from onepass_mailbox.locators l where l.mailbox_id = p_mailbox;
    delete from onepass_mailbox.push_queue q where q.mailbox_id = p_mailbox;
    return query select 'ok'::text, null::integer;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.api_set_locator(bytea, bytea, timestamptz, bytea, bytea),
    onepass_mailbox.locate(bytea, bytea),
    onepass_mailbox.api_abandon_mailbox(bytea, bytea, timestamptz, bytea)
to onepass_mailbox_api;
