-- OnePass mailbox: plan `managed` and the invites an organisation mints for
-- its members (OnePass Business E0).
--
-- A managed member's own account mailbox lives on the organisation's server
-- and is created by the member's device, with a one-use invite a manager of
-- the org mailbox minted. Member credentials on the org mailbox itself are
-- granted, changed and revoked with the existing api_grant_credential,
-- api_set_credential_role and api_revoke_credential: nothing new here.
--
--   plan managed        the free row with max_credentials 32: the member's
--                       own devices plus the company devices the org enrols
--                       for them, with room for re-enrolment churn (the
--                       revoked-row bound of 20261108130000, 4 times
--                       max_credentials, stays at 128). Created only through
--                       an invite; never set open_signup_plan to managed.
--   api_org_invite      POST /v1/mailboxes/{m}/org-invites, signed in the
--                       org mailbox. After _authenticate (frozen and deleted
--                       raise there), in this order: uses other than 1 or a
--                       ttl outside 1..168 hours: malformed. Then the mailbox
--                       row lock and the caller read again under it
--                       (_locked_caller): frozen meanwhile raises frozen; not
--                       role 3, or a mailbox that is not an org account
--                       mailbox (plan org, kind 1, no parent, not deleted):
--                       forbidden. Then 200 a UTC day per org mailbox,
--                       counted on SHA-256('onepass/org-invite' || mailbox):
--                       rate_limited with retry_after. Then a fresh 32 byte
--                       token; its SHA-256 goes into invites (plan managed,
--                       uses_left 1, expiring after the ttl) and the token
--                       itself is returned once, never stored. The plan row
--                       managed missing raises (operator bug, 503 retry at
--                       the edge). api_create_mailbox is unchanged: it takes
--                       the plan from the invite.
--
-- The invite row is written in the owner's ordinary context: the invites
-- policy shows the row whose hash onepass.invite names, set for that one
-- insert, as api_create_mailbox does to spend one. No maintenance switch.
--
-- New: api_org_invite (granted to onepass_mailbox_api).

-- ----------------------------------------------------------------- order

do $$
begin
    if to_regprocedure('onepass_mailbox._immutable_kind(smallint)') is null then
        raise exception 'apply 20261113120000_mailbox_org.sql before 20261113130000_mailbox_org_invites.sql';
    end if;
end
$$;

-- ------------------------------------------------------------------ plan

-- As in seed.sql, written here so the hosted database needs no seed run. A
-- plan row already there (an operator's) is left alone. One statement, so
-- the transaction local maintenance switch covers it whether or not the
-- migration runs in a transaction of its own.
do $$
begin
    perform set_config('onepass.maintenance', 'on', true);
    insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops,
                                       max_children_shared, max_children_contact)
    values ('managed', 268435456, 100000, 32, 120, 20000, 16, 256)
    on conflict (plan) do nothing;
    perform set_config('onepass.maintenance', '', true);
end
$$;

set role onepass_mailbox_owner;

-- ---------------------------------------------------------- api_org_invite

create function onepass_mailbox.api_org_invite(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_uses smallint, p_ttl_hours smallint)
returns table (status text, retry_after integer, token bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_frozen boolean;
    v_deleted timestamptz;
    v_kind smallint;
    v_parent bytea;
    v_plan text;
    v_role smallint;
    v_token bytea;
    v_hash bytea;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;
    if p_uses is distinct from 1 or p_ttl_hours is null or p_ttl_hours not between 1 and 168 then
        return query select 'malformed'::text, null::integer, null::bytea;
        return;
    end if;

    -- The mailbox row lock: a freeze, a deletion or a role change that
    -- commits first applies.
    select m.frozen, m.deleted_at, m.kind, m.parent_id, m.plan
    into v_frozen, v_deleted, v_kind, v_parent, v_plan
    from onepass_mailbox.mailboxes m
    where m.id = p_mailbox
    for no key update;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
    if v_role is distinct from 3 or v_deleted is not null or v_kind is distinct from 1
       or v_parent is not null or v_plan is distinct from 'org' then
        return query select 'forbidden'::text, null::integer, null::bytea;
        return;
    end if;

    -- A key of its own, distinct from every other window key.
    v_retry := onepass_mailbox._hit(
        extensions.digest('onepass/org-invite'::bytea || p_mailbox, 'sha256'), interval '1 day', 200);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;

    if not exists (select 1 from onepass_mailbox.plans p where p.plan = 'managed') then
        -- The plan row was removed by hand: an operator bug, 503 retry at
        -- the edge.
        raise exception 'plan managed is missing' using errcode = 'P0001';
    end if;

    v_token := extensions.gen_random_bytes(32);
    v_hash := extensions.digest(v_token, 'sha256');
    perform set_config('onepass.invite', encode(v_hash, 'hex'), true);
    insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
    values (v_hash, 'managed', p_uses, now() + make_interval(hours => p_ttl_hours));
    perform set_config('onepass.invite', '', true);
    return query select 'ok'::text, null::integer, v_token;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on function onepass_mailbox.api_org_invite(bytea, bytea, timestamptz, bytea, smallint, smallint)
from public, anon, authenticated, service_role;

grant execute on function onepass_mailbox.api_org_invite(bytea, bytea, timestamptz, bytea, smallint, smallint)
to onepass_mailbox_api;
