-- OnePass mailbox: per-device push targets (Task 26; sharing spec 13.7: a
-- member's credential is shared by all of that member's devices, so one
-- push token per credential wakes only one of them). Follows the contract
-- in the header of 20261031120100.
--
-- A credential holds up to 8 targets, each under a 16 byte tag its device
-- picks (random, kept on the device). The historical credentials.push_token
-- stays as it was (api_set_push): an account device keeps using it.
--
--   api_set_push_target  PUT /v1/mailboxes/{m}/push-targets/{tag}, signed,
--                        any role. Kind 0 (None) with an empty token
--                        deletes the target; kinds 1 to 3 with a token of 1
--                        to 4 096 bytes add or replace it. A ninth target of
--                        the credential: quota. Bad tag, kind or token:
--                        malformed.
--   push_take            now also returns, for every mailbox it takes, the
--                        targets of all its active credentials, author
--                        included: the queue's exclusion only applies to the
--                        historical token (the author of a shared credential
--                        cannot be told apart from its other devices). A
--                        target row has its tag; a historical token row has
--                        tag NULL.
--   push_forget_target   forgets a target the provider calls stale, only if
--                        it still holds that token (janitor).
--
-- A revoked credential loses its targets at once (trigger on revoked_at);
-- a purged one too (foreign key, on delete cascade).

set role onepass_mailbox_owner;

create table onepass_mailbox.push_targets (
    credential_id bytea not null references onepass_mailbox.credentials (id) on delete cascade
        check (length(credential_id) = 16),
    mailbox_id bytea not null references onepass_mailbox.mailboxes (id) check (length(mailbox_id) = 16),
    tag bytea not null check (length(tag) = 16),
    kind smallint not null check (kind between 1 and 3),
    token bytea not null check (octet_length(token) between 1 and 4096),
    updated_at timestamptz not null default now(),
    primary key (credential_id, tag)
);
create index push_targets_mailbox_idx on onepass_mailbox.push_targets (mailbox_id);

alter table onepass_mailbox.push_targets enable row level security;
alter table onepass_mailbox.push_targets force row level security;
create policy push_targets_current on onepass_mailbox.push_targets
    for all to onepass_mailbox_owner
    using (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()))
    with check (mailbox_id = (select onepass_mailbox.current_mailbox()) or (select onepass_mailbox.in_maintenance()));

-- Revocation drops the credential's targets, in the revoking transaction
-- (which has entered the credential's mailbox).
create function onepass_mailbox._drop_revoked_targets()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    delete from onepass_mailbox.push_targets t where t.credential_id = new.id;
    return new;
end
$$;

create trigger credentials_revoked_drop_targets
    after update of revoked_at on onepass_mailbox.credentials
    for each row
    when (old.revoked_at is null and new.revoked_at is not null)
    execute function onepass_mailbox._drop_revoked_targets();

-- PUT /v1/mailboxes/{m}/push-targets/{tag}.
create function onepass_mailbox.api_set_push_target(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_tag bytea, p_kind smallint, p_token bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_count integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_tag is null or length(p_tag) <> 16
       or p_kind is null or p_kind not between 0 and 3
       or (p_kind = 0 and coalesce(octet_length(p_token), 0) <> 0)
       or (p_kind <> 0 and (p_token is null or octet_length(p_token) not between 1 and 4096)) then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    if p_kind = 0 then
        delete from onepass_mailbox.push_targets t
        where t.credential_id = p_credential and t.tag = p_tag;
        return query select 'ok'::text, null::integer;
        return;
    end if;
    -- Serializes the cap check of one credential's concurrent calls.
    perform 1 from onepass_mailbox.credentials c where c.id = p_credential for no key update;
    update onepass_mailbox.push_targets t
    set kind = p_kind, token = p_token, updated_at = now()
    where t.credential_id = p_credential and t.tag = p_tag;
    if found then
        return query select 'ok'::text, null::integer;
        return;
    end if;
    select count(*) into v_count from onepass_mailbox.push_targets t where t.credential_id = p_credential;
    if v_count >= 8 then
        return query select 'quota'::text, null::integer;
        return;
    end if;
    insert into onepass_mailbox.push_targets (credential_id, mailbox_id, tag, kind, token)
    values (p_credential, p_mailbox, p_tag, p_kind, p_token);
    return query select 'ok'::text, null::integer;
end
$$;

-- push_take gains the tag column: a new return type, so drop and create.
drop function onepass_mailbox.push_take(integer);

create function onepass_mailbox.push_take(p_limit integer)
returns table (mailbox_id bytea, credential_id bytea, tag bytea, push_kind smallint, push_token bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    if p_limit is null or p_limit not between 1 and 1000 then
        raise exception using errcode = '22023', message = 'push_take limit must be 1 to 1000';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    return query
    with q as (
        select q.mailbox_id from onepass_mailbox.push_queue q
        order by q.enqueued_at, q.mailbox_id
        limit p_limit
        for update skip locked
    ), d as (
        delete from onepass_mailbox.push_queue p
        using q
        where p.mailbox_id = q.mailbox_id
        returning p.mailbox_id, p.exclude_credential
    ), live as (
        select d.mailbox_id, d.exclude_credential
        from d join onepass_mailbox.mailboxes m on m.id = d.mailbox_id and not m.frozen
    )
    select x.mailbox_id, x.credential_id, x.tag, x.push_kind, x.push_token
    from (
        select l.mailbox_id, c.id as credential_id, null::bytea as tag, c.push_kind, c.push_token
        from live l
        join onepass_mailbox.credentials c on c.mailbox_id = l.mailbox_id
        where c.revoked_at is null and c.push_token is not null
          and c.id is distinct from l.exclude_credential
        union all
        select l.mailbox_id, t.credential_id, t.tag, t.kind, t.token
        from live l
        join onepass_mailbox.push_targets t on t.mailbox_id = l.mailbox_id
        join onepass_mailbox.credentials c on c.id = t.credential_id and c.revoked_at is null
    ) x
    order by x.mailbox_id, x.credential_id, x.tag nulls first;
    perform set_config('onepass.maintenance', '', true);
end
$$;

create function onepass_mailbox.push_forget_target(p_credential bytea, p_tag bytea, p_token bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_credential is null or length(p_credential) <> 16 or p_tag is null or length(p_tag) <> 16
       or p_token is null then
        raise exception using errcode = '22023',
            message = 'push_forget_target takes a 16 byte credential, a 16 byte tag and its token';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    delete from onepass_mailbox.push_targets t
    where t.credential_id = p_credential and t.tag = p_tag and t.token = p_token;
    perform set_config('onepass.maintenance', '', true);
end
$$;

reset role;

revoke all on function onepass_mailbox._drop_revoked_targets() from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.api_set_push_target(bytea, bytea, timestamptz, bytea, bytea, smallint, bytea)
    from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.push_take(integer) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox.push_forget_target(bytea, bytea, bytea) from public, anon, authenticated, service_role;
grant execute on function onepass_mailbox.api_set_push_target(bytea, bytea, timestamptz, bytea, bytea, smallint, bytea)
    to onepass_mailbox_api;
grant execute on function
    onepass_mailbox.push_take(integer),
    onepass_mailbox.push_forget_target(bytea, bytea, bytea)
to onepass_mailbox_janitor;
