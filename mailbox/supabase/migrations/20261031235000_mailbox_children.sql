-- OnePass mailbox: child mailboxes for shared vaults, families and contacts
-- (Task 24, spec D.3, D.7; sharing spec 13.3, 13.5, 13.6, 13.8). Follows the
-- contract in the header of 20261031120100.
--
-- mailboxes.kind: 1 account (or the anchor of an account that stayed on
-- iCloud, D.3), 2 shared vault or family, 3 contact. A kind 2 or 3 mailbox
-- is a child: parent_id names the account mailbox it was created under
-- (never a child itself). plans gains max_children_shared and
-- max_children_contact, the live children of each kind a parent on that
-- plan may hold (0 by default). Plans shared and contact (seed.sql) are the
-- children's own: a child counts against its plan, never its parent's.
--
--   api_create_child    POST /v1/mailboxes/{m}/children, signed in the
--                       parent. After _authenticate, in this order: a kind
--                       other than 2 or 3, an owner key that is no 32 byte
--                       key or a weak encoding, a label over 64 bytes:
--                       malformed. Then the parent row lock (concurrent
--                       creations under one parent count one at a time),
--                       the caller read again under it (_locked_caller):
--                       not role 3, or a parent that is a child: forbidden.
--                       Live children of that kind at the parent plan's cap:
--                       quota. Then 20 a day per parent, counted on
--                       SHA-256('onepass/child' || parent), day window in
--                       UTC: rate_limited with retry_after. An owner key
--                       some mailbox holds: malformed (the creation is
--                       rolled back, the day hit stays). The child takes
--                       plan shared or contact, created_by = its owner
--                       credential, which is its only credential: role 3,
--                       owner, nothing signed yet. Members come in through
--                       grants by the owner (sharing 13.4).
--   api_delete_mailbox  DELETE /v1/mailboxes/{m}, replaces
--                       api_abandon_mailbox (same signature). A child: its
--                       owner credential (role 3 under the lock), at any
--                       time, whoever else used it. An account mailbox: the
--                       Task 23 rules (creator, manager, within 24 hours,
--                       fresh) and no live child. Otherwise forbidden.
--                       Deleted as before: deleted_at, locators and push
--                       queue entry dropped, purged by maintenance an hour
--                       later. A deleted child no longer counts against its
--                       parent's cap.
--   api_enroll          a child refuses every ticket (forbidden, in band,
--                       after the approver checks): its members join only
--                       through grants. Same signature.
--
-- Counting a parent's children needs their rows, which the mailboxes policy
-- hides (each is another mailbox). The setting onepass.parent (helper
-- current_parent, cleared by _enter) shows, read only, the rows whose
-- parent_id it names; only api_create_child and api_delete_mailbox set it,
-- to the authenticated mailbox, for one statement.
--
-- Replaced (same signatures and grants): _enter (also clears
-- onepass.parent), api_enroll. Dropped: api_abandon_mailbox.

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- schema

alter table onepass_mailbox.plans
    add column max_children_shared integer not null default 0 check (max_children_shared >= 0),
    add column max_children_contact integer not null default 0 check (max_children_contact >= 0);
comment on column onepass_mailbox.plans.max_children_shared is
    'live kind 2 children (shared vaults, families) a mailbox on this plan may hold';
comment on column onepass_mailbox.plans.max_children_contact is
    'live kind 3 children (contacts) a mailbox on this plan may hold';

alter table onepass_mailbox.mailboxes
    add column parent_id bytea references onepass_mailbox.mailboxes (id) check (length(parent_id) = 16),
    add column kind smallint not null default 1 check (kind between 1 and 3),
    add constraint mailboxes_child_has_parent check ((kind = 1) = (parent_id is null));
comment on column onepass_mailbox.mailboxes.kind is
    '1 account or anchor, 2 shared vault or family, 3 contact (2 and 3 are children of parent_id)';
create index mailboxes_live_children_idx on onepass_mailbox.mailboxes (parent_id, kind)
    where parent_id is not null and deleted_at is null;

-- The parent whose children a statement may read (NULL when absent or
-- malformed).
create function onepass_mailbox.current_parent()
returns bytea
language sql
stable
set search_path = ''
as $$
    select case when s ~ '^[0-9a-fA-F]{32}$' then decode(s, 'hex') end
    from (select current_setting('onepass.parent', true) as s) c;
$$;
revoke all on function onepass_mailbox.current_parent() from public;

create policy mailboxes_children on onepass_mailbox.mailboxes
    for select to onepass_mailbox_owner
    using (parent_id = (select onepass_mailbox.current_parent()));

-- ------------------------------------------------------------ helpers

-- _enter of 20261031234000: also clears onepass.parent.
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
    perform set_config('onepass.maintenance', '', true);
end
$$;

-- Live children of p_parent, of kind p_kind (any child kind when NULL).
-- The caller has entered p_parent; the setting is cleared again after.
create function onepass_mailbox._live_children(p_parent bytea, p_kind smallint)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_n integer;
begin
    perform set_config('onepass.parent', encode(p_parent, 'hex'), true);
    select count(*)::integer into v_n from onepass_mailbox.mailboxes m
    where m.parent_id = p_parent and m.deleted_at is null and (p_kind is null or m.kind = p_kind);
    perform set_config('onepass.parent', '', true);
    return v_n;
end
$$;

-- ------------------------------------------------------- new entry points

-- POST /v1/mailboxes/{m}/children. The edge function has imported the
-- owner key (a curve point).
create function onepass_mailbox.api_create_child(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_parent bytea,
    p_kind smallint, p_owner_key bytea, p_label bytea)
returns table (status text, retry_after integer, mailbox_id bytea, incarnation bigint, wake_topic bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_frozen boolean;
    v_parent_kind smallint;
    v_cap integer;
    v_role smallint;
    v_plan text;
    v_id bytea;
    v_cid bytea;
    v_incarnation bigint;
    v_wake bytea;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_parent);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;
    if p_kind is null or p_kind not in (2, 3)
       or p_owner_key is null or length(p_owner_key) <> 32
       or onepass_mailbox._ed25519_key_refused(p_owner_key)
       or (p_label is not null and octet_length(p_label) > 64) then
        return query select 'malformed'::text, null::integer, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    -- The parent row lock: creations under one parent count its children
    -- one at a time, and a deletion of the parent waits.
    select m.frozen, m.kind,
           case when p_kind = 2 then p.max_children_shared else p.max_children_contact end
    into v_frozen, v_parent_kind, v_cap
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_parent
    for no key update of m;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;
    -- Revoked, demoted or deleted while waiting for the lock: applies.
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_parent) l;
    if v_role is distinct from 3 or v_parent_kind <> 1 then
        v_err := 'forbidden';
    elsif onepass_mailbox._live_children(p_parent, p_kind) >= v_cap then
        v_err := 'quota';
    end if;
    if v_err is not null then
        return query select v_err, null::integer, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    -- A key of its own, distinct from every other window key.
    v_retry := onepass_mailbox._hit(
        extensions.digest('onepass/child'::bytea || p_parent, 'sha256'), interval '1 day', 20);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    v_plan := case when p_kind = 2 then 'shared' else 'contact' end;
    if not exists (select 1 from onepass_mailbox.plans p where p.plan = v_plan) then
        -- seed.sql was not run: an operator bug, 503 retry at the edge.
        raise exception 'plan % is missing', v_plan using errcode = 'P0001';
    end if;

    v_id := extensions.gen_random_bytes(16);
    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_owner_key, 'sha256') from 1 for 16);
    begin
        perform onepass_mailbox._enter(v_id);
        insert into onepass_mailbox.mailboxes (id, plan, created_by, parent_id, kind)
        values (v_id, v_plan, v_cid, p_parent, p_kind)
        returning mailboxes.incarnation, mailboxes.wake_topic into v_incarnation, v_wake;
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label, role, owner)
        values (v_cid, v_id, p_owner_key, coalesce(p_label, '\x'::bytea), 3, true);
    exception when unique_violation then
        -- The key is in some mailbox: malformed, as on create and grant.
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

-- DELETE /v1/mailboxes/{m}: api_abandon_mailbox of 20261031234000, which
-- it replaces, plus children.
drop function onepass_mailbox.api_abandon_mailbox(bytea, bytea, timestamptz, bytea);

create function onepass_mailbox.api_delete_mailbox(
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
    v_kind smallint;
    v_role smallint;
    v_owner boolean;
    v_allowed boolean;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;

    select m.created_by, m.created_at, m.kind into v_created_by, v_created_at, v_kind
    from onepass_mailbox.mailboxes m where m.id = p_mailbox
    for no key update;
    -- Revoked or deleted while waiting for the lock: raised.
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
    select c.owner into v_owner from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;

    if v_kind <> 1 then
        -- A child: its owner, at any time (stop sharing, transfer, 13.8).
        v_allowed := v_owner and v_role = 3;
    else
        -- An account mailbox: the creator abandons it within 24 hours while
        -- it is fresh (no other credential ever used or enrolled, at most
        -- one other at all: the unused recovery credential), and only
        -- without a live child.
        v_allowed := v_created_by is not distinct from p_credential
            and v_role is not distinct from 3
            and v_created_at > now() - interval '24 hours'
            and not exists (select 1 from onepass_mailbox.credentials c
                            where c.mailbox_id = p_mailbox and c.id <> p_credential
                              and (c.first_used_at is not null or c.enrolled_by is not null))
            and (select count(*) from onepass_mailbox.credentials c
                 where c.mailbox_id = p_mailbox and c.id <> p_credential) <= 1
            and onepass_mailbox._live_children(p_mailbox, null) = 0;
    end if;
    if not coalesce(v_allowed, false) then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    update onepass_mailbox.mailboxes set deleted_at = now() where id = p_mailbox;
    delete from onepass_mailbox.locators l where l.mailbox_id = p_mailbox;
    delete from onepass_mailbox.push_queue q where q.mailbox_id = p_mailbox;
    return query select 'ok'::text, null::integer;
end
$$;

-- ------------------------------------------------------ replaced entry points

-- api_enroll of 20261031234000: a child refuses every ticket.
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
    v_kind smallint;
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
        select m.frozen, m.deleted_at, m.kind, p.max_credentials into v_frozen, v_deleted, v_kind, v_max
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
        elsif v_kind <> 1 then
            -- A child takes members through grants only (sharing 13.4).
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

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.api_create_child(bytea, bytea, timestamptz, bytea, smallint, bytea, bytea),
    onepass_mailbox.api_delete_mailbox(bytea, bytea, timestamptz, bytea)
to onepass_mailbox_api;
