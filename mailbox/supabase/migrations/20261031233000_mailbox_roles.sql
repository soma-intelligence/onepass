-- OnePass mailbox: credential roles and grants by a manager (Task 22, spec
-- D.4, D.5, D.7; sharing spec 13.4 and 13.8).
--
-- Every credential gets a role: 1 read, 2 write, 3 manage. Rows from before
-- this migration, and every credential a creation or an enroll writes, are
-- managers: an account mailbox behaves as it did. A write credential may be
-- limited by put_kinds, a 256 bit set (bit k = byte k / 8, bit k % 8 from the
-- least significant, as get_bit numbers them): it then puts only those kinds
-- and deletes nothing. `owner` marks a credential that only itself may
-- revoke or demote (set by the child mailbox creation of Task 24, nothing
-- here sets it). `granted_by` is the manager that granted it.
--
-- Rules, checked after _authenticate, so the nonce and the rate hit of a
-- refused request stay (in-band status forbidden, 403):
--   api_commit          role 1 refused; role 2 with put_kinds refuses any
--                       Delete and any Put of a kind outside the set
--   api_blob_announce   role 2 or 3
--   api_grant_credential, api_set_credential_role   role 3
--   api_revoke_credential   role 3, or the caller itself
--   an owner is revoked, or given less than the manager role, only by itself
--   the last active manager is neither revoked nor demoted
--   put_kinds only with role 2 (malformed otherwise)
--   api_enroll          the ticket's approver has role 3
-- A grant follows the key rules of a creation: a curve point (the edge
-- imports it first), a key no mailbox holds (malformed), and the plan's
-- max_credentials over active credentials (quota).
--
-- Credential changes of one mailbox (grant, role change, revoke) take the
-- mailbox row lock, so two managers demoting each other cannot both pass the
-- last manager check. Replaced functions keep their signatures and grants.

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- schema

alter table onepass_mailbox.credentials
    add column role smallint not null default 3 check (role between 1 and 3),
    add column owner boolean not null default false,
    add column put_kinds bytea check (put_kinds is null or length(put_kinds) = 32),
    add column granted_by bytea check (length(granted_by) = 16),
    add constraint credentials_put_kinds_write_only check (put_kinds is null or role = 2),
    add constraint credentials_granted_by_in_mailbox_fk
        foreign key (mailbox_id, granted_by) references onepass_mailbox.credentials (mailbox_id, id);

comment on column onepass_mailbox.credentials.role is '1 read, 2 write, 3 manage';
comment on column onepass_mailbox.credentials.put_kinds is
    'role 2 only: kinds the credential may put (bit k = kind k); no delete when set';

-- ------------------------------------------------------------ helpers

-- _fail of 20261031120100, with forbidden.
create or replace function onepass_mailbox._fail(p_code text)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_state text;
begin
    v_state := case p_code
        when 'malformed' then 'OP400'
        when 'bad_signature' then 'OP401'
        when 'stale_request' then 'OP401'
        when 'replay' then 'OP401'
        when 'unknown_credential' then 'OP403'
        when 'revoked_credential' then 'OP403'
        when 'frozen' then 'OP403'
        when 'forbidden' then 'OP403'
        when 'not_found' then 'OP404'
        when 'cursor_expired' then 'OP410'
        when 'too_large' then 'OP413'
        when 'quota' then 'OP422'
        when 'rate_limited' then 'OP429'
        when 'retry' then 'OP503'
    end;
    if v_state is null then
        raise exception 'unknown mailbox error code %', p_code;
    end if;
    raise exception using errcode = v_state, message = p_code;
end
$$;

-- Active managers of p_mailbox, other than p_except.
create function onepass_mailbox._other_managers(p_mailbox bytea, p_except bytea)
returns integer
language sql
stable
set search_path = ''
as $$
    select count(*)::integer from onepass_mailbox.credentials c
    where c.mailbox_id = p_mailbox and c.revoked_at is null and c.role = 3 and c.id <> p_except;
$$;

-- ------------------------------------------------------- new entry points

-- POST /v1/mailboxes/{m}/grants. The edge function has imported the key
-- (a curve point). A manager adds a credential without a ticket: the
-- follower of a migration (D.5), the recovery credential (D.4), a member of a
-- shared zone (sharing 13.4).
create function onepass_mailbox.api_grant_credential(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_public_key bytea, p_role smallint, p_put_kinds bytea, p_label bytea)
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
    v_max integer;
    v_role smallint;
    v_active integer;
    v_cid bytea;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea;
        return;
    end if;
    if p_public_key is null or length(p_public_key) <> 32
       or onepass_mailbox._ed25519_key_refused(p_public_key)
       or p_role is null or p_role not between 1 and 3
       or (p_put_kinds is not null and (p_role <> 2 or length(p_put_kinds) <> 32))
       or (p_label is not null and octet_length(p_label) > 64) then
        return query select 'malformed'::text, null::integer, null::bytea;
        return;
    end if;

    select m.frozen, p.max_credentials into v_frozen, v_max
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox
    for update of m;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;
    select c.role into v_role from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if v_role is distinct from 3 then
        v_err := 'forbidden';
    else
        select count(*)::integer into v_active
        from onepass_mailbox.credentials c
        where c.mailbox_id = p_mailbox and c.revoked_at is null;
        if v_active >= v_max then
            v_err := 'quota';
        end if;
    end if;

    if v_err is null then
        v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_public_key, 'sha256') from 1 for 16);
        begin
            insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label, role, put_kinds, granted_by)
            values (v_cid, p_mailbox, p_public_key, coalesce(p_label, '\x'::bytea), p_role, p_put_kinds, p_credential);
        exception when unique_violation then
            -- The key is in some mailbox, this one included (a credential id
            -- is never reused, even once revoked): malformed, as on create.
            v_err := 'malformed';
        end;
    end if;

    if v_err is not null then
        return query select v_err, null::integer, null::bytea;
        return;
    end if;
    return query select 'ok'::text, null::integer, v_cid;
end
$$;

-- PUT /v1/mailboxes/{m}/credentials/{c}/role. A manager changes the role
-- (and put_kinds) of an active credential of the mailbox, itself included.
create function onepass_mailbox.api_set_credential_role(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_target bytea, p_role smallint, p_put_kinds bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_role smallint;
    v_t_role smallint;
    v_t_owner boolean;
    v_t_revoked timestamptz;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_target is null or length(p_target) <> 16
       or p_role is null or p_role not between 1 and 3
       or (p_put_kinds is not null and (p_role <> 2 or length(p_put_kinds) <> 32)) then
        return query select 'malformed'::text, null::integer;
        return;
    end if;

    perform 1 from onepass_mailbox.mailboxes m where m.id = p_mailbox for no key update;
    select c.role into v_role from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if v_role is distinct from 3 then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    select c.role, c.owner, c.revoked_at into v_t_role, v_t_owner, v_t_revoked
    from onepass_mailbox.credentials c
    where c.id = p_target and c.mailbox_id = p_mailbox;
    if not found or v_t_revoked is not null then
        return query select 'not_found'::text, null::integer;
        return;
    end if;
    -- An owner gets less than the manager role only from itself; the last
    -- active manager keeps its role.
    if (v_t_owner and p_target <> p_credential and p_role <> 3)
       or (v_t_role = 3 and p_role <> 3 and onepass_mailbox._other_managers(p_mailbox, p_target) = 0) then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    update onepass_mailbox.credentials set role = p_role, put_kinds = p_put_kinds
    where id = p_target and mailbox_id = p_mailbox;
    return query select 'ok'::text, null::integer;
end
$$;

-- ------------------------------------------------------ replaced entry points

-- api_revoke_credential of 20261031120100 with the role rules. The target
-- must be in the same mailbox; revoking a revoked credential changes
-- nothing. The push token is dropped with it.
create or replace function onepass_mailbox.api_revoke_credential(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_target bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_role smallint;
    v_t_role smallint;
    v_t_owner boolean;
    v_t_revoked timestamptz;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_target is null or length(p_target) <> 16 then
        return query select 'malformed'::text, null::integer;
        return;
    end if;

    perform 1 from onepass_mailbox.mailboxes m where m.id = p_mailbox for no key update;
    select c.role into v_role from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if v_role is distinct from 3 and p_target <> p_credential then
        return query select 'forbidden'::text, null::integer;
        return;
    end if;
    select c.role, c.owner, c.revoked_at into v_t_role, v_t_owner, v_t_revoked
    from onepass_mailbox.credentials c
    where c.id = p_target and c.mailbox_id = p_mailbox;
    if not found then
        return query select 'not_found'::text, null::integer;
        return;
    end if;
    if v_t_revoked is null then
        if (v_t_owner and p_target <> p_credential)
           or (v_t_role = 3 and onepass_mailbox._other_managers(p_mailbox, p_target) = 0) then
            return query select 'forbidden'::text, null::integer;
            return;
        end if;
        update onepass_mailbox.credentials
        set revoked_at = now(), push_kind = null, push_token = null
        where id = p_target and mailbox_id = p_mailbox;
    end if;
    return query select 'ok'::text, null::integer;
end
$$;

-- api_enroll of 20261031120100: the approver must be a manager. The new
-- credential takes the column default, a manager (account mailbox).
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
        select m.frozen, p.max_credentials into v_frozen, v_max
        from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
        where m.id = p_mailbox
        for update of m;
        if not found then
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

-- api_blob_announce of 20261031120300: a reader is refused.
create or replace function onepass_mailbox.api_blob_announce(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_shas bytea[], p_sizes integer[])
returns table (status text, retry_after integer, sha256 bytea, needs_upload boolean, object_name text)
language plpgsql
security definer
set search_path = ''
-- Joins the arrays to the mailbox's blobs and objects: plan each call with
-- them in hand (see api_commit).
set plan_cache_mode = force_custom_plan
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_n integer;
    v_bad boolean;
    v_distinct integer;
    v_frozen boolean;
    v_max_bytes bigint;
    v_bytes_used bigint;
    v_clash boolean;
    v_growth bigint;
    v_pending bigint;
    v_prefix text;
    v_out_sha bytea[];
    v_out_gen bigint[];
    v_out_size integer[];
    v_role smallint;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;

    -- An upload is a write: a reader announces nothing.
    if v_err is null then
        select c.role into v_role from onepass_mailbox.credentials c
        where c.id = p_credential and c.mailbox_id = p_mailbox;
        if v_role = 1 then
            v_err := 'forbidden';
        end if;
    end if;

    if v_err is null then
        v_n := cardinality(p_shas);
        if v_n is null or v_n = 0 or v_n > 1000
           or array_ndims(p_shas) <> 1 or array_lower(p_shas, 1) <> 1
           or array_ndims(p_sizes) is distinct from 1 or array_lower(p_sizes, 1) <> 1 or cardinality(p_sizes) <> v_n then
            v_err := 'malformed';
        end if;
    end if;
    if v_err is null then
        select coalesce(bool_or(o.s is null or length(o.s) <> 32 or o.z is null or o.z not between 16385 and 921600), true),
               count(distinct o.s)
        into v_bad, v_distinct
        from unnest(p_shas, p_sizes) as o (s, z);
        if v_bad or v_distinct <> v_n then
            v_err := 'malformed';
        end if;
    end if;

    if v_err is null then
        -- One writer at a time per mailbox, like a commit: the quota below
        -- reads counters a concurrent commit or announce would move.
        select m.frozen, p.max_bytes, m.bytes_used into v_frozen, v_max_bytes, v_bytes_used
        from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
        where m.id = p_mailbox
        for no key update of m;
        if v_frozen then
            perform onepass_mailbox._fail('frozen');
        end if;

    end if;

    if v_err is null then
        -- A referenced blob has a known size: another one is a lie. An
        -- unreferenced one takes the new size.
        select coalesce(bool_or(b.refs > 0 and b.size <> o.z), false),
               coalesce(sum(o.z - coalesce(b.size, 0)) filter (where b.sha256 is null or b.refs = 0), 0)
        into v_clash, v_growth
        from unnest(p_shas, p_sizes) as o (s, z)
        left join onepass_mailbox.blobs b on b.mailbox_id = p_mailbox and b.sha256 = o.s;
        if v_clash then
            v_err := 'malformed';
        elsif v_growth > 0 then
            select coalesce(sum(b.size), 0) into v_pending
            from onepass_mailbox.blobs b
            where b.mailbox_id = p_mailbox and b.refs = 0;
            if v_bytes_used + v_pending + v_growth > v_max_bytes then
                v_err := 'quota';
            end if;
        end if;
    end if;

    if v_err is not null then
        return query select v_err, v_retry, null::bytea, null::boolean, null::text;
        return;
    end if;

    -- Rows in hash order (the order every writer of blobs locks them in).
    -- A row being collected (maintenance holds it) is waited for; once it
    -- is gone the blob comes back as a new row, under a new generation.
    with up as (
        insert into onepass_mailbox.blobs as b (mailbox_id, sha256, size, state)
        select p_mailbox, o.s, o.z, 1 from unnest(p_shas, p_sizes) as o (s, z)
        order by o.s
        on conflict (mailbox_id, sha256) do update set
            size = case when b.refs = 0 then excluded.size else b.size end,
            -- An unreferenced blob is kept alive another 24 hours.
            orphaned_at = case when b.refs = 0 then null else b.orphaned_at end
        returning b.sha256, b.gen, b.size
    )
    select array_agg(up.sha256 order by up.sha256), array_agg(up.gen order by up.sha256),
           array_agg(up.size order by up.sha256)
    into v_out_sha, v_out_gen, v_out_size
    from up;

    -- An upload is needed unless the current generation's object is there
    -- with the blob's size.
    return query
    select 'ok'::text, null::integer, o.s,
           not exists (select 1 from storage.objects so
                       where so.bucket_id = 'onepass-mailbox'
                         and so.name collate "C" = onepass_mailbox._blob_object(p_mailbox, o.s, o.g)
                         and so.metadata ->> 'size' = o.z::text),
           onepass_mailbox._blob_object(p_mailbox, o.s, o.g)
    from unnest(v_out_sha, v_out_gen, v_out_size) as o (s, g, z)
    order by o.s;
end
$$;

-- api_commit of 20261031120300: a reader is refused, a limited writer puts
-- only its kinds and deletes nothing.
create or replace function onepass_mailbox.api_commit(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_kinds smallint[], p_ids bytea[], p_versions bigint[], p_ops smallint[],
    p_expected bigint[], p_data bytea[], p_blob_sha bytea[], p_sizes integer[])
returns table (
    status text, retry_after integer,
    kind smallint, id bytea, seq bigint, version bigint,
    deleted boolean, data bytea, blob_sha256 bytea, size integer)
language plpgsql
security definer
set search_path = ''
set plan_cache_mode = force_custom_plan
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_n integer;
    v_bad boolean;
    v_keys integer;
    v_carried bigint;
    v_next bigint;
    v_wake bytea;
    v_max_bytes bigint;
    v_max_records integer;
    v_max_ops integer;
    v_seqs bigint[];
    v_writes integer;
    v_dbytes bigint;
    v_drecords integer;
    v_conflict boolean;
    v_bytes bigint;
    v_records integer;
    v_frozen boolean;
    v_deletes_only boolean;
    v_prefix text;
    v_inc_sha bytea[];
    v_inc_n integer[];
    v_inc_size integer[];
    v_inc_gen bigint[];
    v_dec_sha bytea[];
    v_dec_n integer[];
    v_rows integer;
    v_role smallint;
    v_put_kinds bytea;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;

    -- A reader commits nothing, whatever it sends.
    if v_err is null then
        select c.role, c.put_kinds into v_role, v_put_kinds from onepass_mailbox.credentials c
        where c.id = p_credential and c.mailbox_id = p_mailbox;
        if v_role = 1 then
            v_err := 'forbidden';
        end if;
    end if;

    -- Shapes first: they need neither the plan nor the lock.
    if v_err is null then
        v_n := cardinality(p_kinds);
        if v_n is null or v_n = 0
           or array_ndims(p_kinds) <> 1 or array_lower(p_kinds, 1) <> 1
           or array_ndims(p_ids) is distinct from 1 or array_lower(p_ids, 1) <> 1 or cardinality(p_ids) <> v_n
           or array_ndims(p_versions) is distinct from 1 or array_lower(p_versions, 1) <> 1 or cardinality(p_versions) <> v_n
           or array_ndims(p_ops) is distinct from 1 or array_lower(p_ops, 1) <> 1 or cardinality(p_ops) <> v_n
           or array_ndims(p_expected) is distinct from 1 or array_lower(p_expected, 1) <> 1 or cardinality(p_expected) <> v_n
           or array_ndims(p_data) is distinct from 1 or array_lower(p_data, 1) <> 1 or cardinality(p_data) <> v_n
           or array_ndims(p_blob_sha) is distinct from 1 or array_lower(p_blob_sha, 1) <> 1 or cardinality(p_blob_sha) <> v_n
           or array_ndims(p_sizes) is distinct from 1 or array_lower(p_sizes, 1) <> 1 or cardinality(p_sizes) <> v_n then
            v_err := 'malformed';
        elsif v_n > 20000 then
            v_err := 'too_large';
        end if;
    end if;

    if v_err is null then
        select
            coalesce(bool_or(
                o.k is null or o.k not between 1 and 255
                or o.i is null or length(o.i) <> 16
                or o.v is null
                or o.op is null or o.op not in (1, 2)
                or (o.op = 2 and (o.e is not null or o.d is not null or o.b is not null or o.s is not null))
                or (o.op = 1 and (
                    (o.e is not null and o.e < 1)
                    or (o.d is null) = (o.b is null)
                    or (o.d is not null and (octet_length(o.d) > 16384 or o.s is distinct from octet_length(o.d)))
                    -- A blob body: above INLINE_MAX, at most RECORD_MAX.
                    or (o.b is not null and (length(o.b) <> 32 or o.s is null or o.s not between 16385 and 921600))))), true),
            count(distinct (o.k, o.i)),
            coalesce(sum(coalesce(octet_length(o.i), 0) + coalesce(octet_length(o.d), 0) + coalesce(octet_length(o.b), 0)), 0),
            bool_and(o.op = 2)
        into v_bad, v_keys, v_carried, v_deletes_only
        from unnest(p_kinds, p_ids, p_versions, p_ops, p_expected, p_data, p_blob_sha, p_sizes)
            as o (k, i, v, op, e, d, b, s);
        if v_bad or v_keys <> v_n then
            v_err := 'malformed';
        elsif v_carried > 4194304 then
            v_err := 'too_large';
        end if;
    end if;

    -- A writer limited to put_kinds puts only those kinds and deletes nothing.
    if v_err is null and v_put_kinds is not null then
        if exists (select 1 from unnest(p_kinds, p_ops) as o (k, op)
                   where o.op = 2 or get_bit(v_put_kinds, o.k) = 0) then
            v_err := 'forbidden';
        end if;
    end if;

    if v_err is null then
        -- One batch at a time per mailbox, held until the transaction ends.
        select m.next_seq, m.wake_topic, m.frozen, p.max_bytes, p.max_records, p.max_commit_ops
        into v_next, v_wake, v_frozen, v_max_bytes, v_max_records, v_max_ops
        from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
        where m.id = p_mailbox
        for no key update of m;
        if v_frozen then
            -- Frozen while this batch waited: refused like at authentication.
            perform onepass_mailbox._fail('frozen');
        end if;
        if v_n > v_max_ops then
            v_err := 'too_large';
        end if;
    end if;

    if v_err is null then
        -- Lock every blob row this batch touches, in hash order, before
        -- checking them: the blobs it puts and those the rows it replaces
        -- hold. Held to the end, so the collector (which skips locked rows)
        -- cannot take one away between the check and the write.
        perform 1 from onepass_mailbox.blobs b
        where b.mailbox_id = p_mailbox
          and b.sha256 in (
              select o.b from unnest(p_ops, p_blob_sha) as o (op, b) where o.op = 1 and o.b is not null
              union
              select r.blob_sha256 from unnest(p_kinds, p_ids) as o (k, i)
              join onepass_mailbox.records r on r.mailbox_id = p_mailbox and r.kind = o.k and r.id = o.i
              where r.blob_sha256 is not null)
        order by b.sha256
        for update;

        -- Every blob the batch puts: announced (its row gives the
        -- generation its object is named after), that object present with
        -- this size, and the size it is known by when rows reference it.
        select coalesce(bool_or(bl.sha256 is null or so.id is null or (bl.refs > 0 and bl.size <> x.s)), false)
        into v_bad
        from (select distinct o.b, o.s from unnest(p_ops, p_blob_sha, p_sizes) as o (op, b, s)
              where o.op = 1 and o.b is not null) x
        left join onepass_mailbox.blobs bl on bl.mailbox_id = p_mailbox and bl.sha256 = x.b
        left join storage.objects so
            on so.bucket_id = 'onepass-mailbox'
           and so.name collate "C" = onepass_mailbox._blob_object(p_mailbox, x.b, bl.gen)
           and so.metadata ->> 'size' = x.s::text;
        if v_bad then
            v_err := 'malformed';
        end if;
    end if;

    if v_err is not null then
        return query select v_err, v_retry, null::smallint, null::bytea, null::bigint, null::bigint,
            null::boolean, null::bytea, null::bytea, null::integer;
        return;
    end if;

    -- The plan, from the current rows: which operations conflict, which
    -- write (every put, a delete of a live row) and the seq each takes, and
    -- what the counters gain.
    select
        bool_or(w.conflict),
        array_agg(w.new_seq order by w.ord),
        count(w.new_seq)::integer,
        -- What each writing op changes in the counters: its new cost (a put
        -- its size, a tombstone 128 bytes, TOMBSTONE_COST) minus the cost of
        -- the row it replaces (none when absent); one record unless the key
        -- was absent.
        coalesce(sum(case when w.new_seq is not null
                          then (case when w.op = 1 then w.s else 128 end)
                               - (case when w.cur_deleted is null then 0
                                       when w.cur_deleted then 128
                                       else w.cur_size end)
                     end), 0)::bigint,
        coalesce(sum(case when w.new_seq is not null and w.cur_deleted is null then 1 else 0 end), 0)::integer
    into v_conflict, v_seqs, v_writes, v_dbytes, v_drecords
    from (
        select x.*,
               case when x.writes
                    then v_next + count(*) filter (where x.writes) over (order by x.ord) - 1
               end as new_seq
        from (
            select o.ord, o.op, o.s, r.size as cur_size, r.deleted as cur_deleted,
                   coalesce(not r.deleted, false) as live,
                   o.op = 1 and case when o.e is null then coalesce(not r.deleted, false)
                                     else r.seq is null or r.deleted or r.seq <> o.e end as conflict,
                   o.op = 1 or coalesce(not r.deleted, false) as writes
            from unnest(p_kinds, p_ids, p_ops, p_expected, p_sizes) with ordinality as o (k, i, op, e, s, ord)
            left join onepass_mailbox.records r
                on r.mailbox_id = p_mailbox and r.kind = o.k and r.id = o.i
        ) x
    ) w;

    if v_conflict then
        -- A prefix of the conflicts: 1000 rows (PAGE_MAX_RECORDS) and 4 MiB
        -- of data (PAGE_MAX_BYTES) at most, the first row always.
        return query
        select 'conflict'::text, null::integer, c.k, c.i, c.seq, c.version, c.deleted, c.data, c.blob_sha256, c.size
        from (
            select o.ord, o.k, o.i, r.seq, r.version, r.deleted, r.data, r.blob_sha256, r.size,
                   row_number() over (order by o.ord) as n,
                   sum(coalesce(octet_length(r.data), 0)) over (order by o.ord) as acc
            from unnest(p_kinds, p_ids, p_ops, p_expected) with ordinality as o (k, i, op, e, ord)
            left join onepass_mailbox.records r
                on r.mailbox_id = p_mailbox and r.kind = o.k and r.id = o.i
            where o.op = 1
              and case when o.e is null then coalesce(not r.deleted, false)
                       else r.seq is null or r.deleted or r.seq <> o.e end
        ) c
        where c.n = 1 or (c.n <= 1000 and c.acc <= 4194304)
        order by c.ord;
        return;
    end if;

    if v_writes > 0 then
        -- Net reference change per blob, read before the rows change: +1 for
        -- each written put of the blob, -1 for each written op whose row held
        -- it. Blobs whose net is 0 are left alone.
        select array_agg(d.b order by d.b) filter (where d.n > 0), array_agg(d.n order by d.b) filter (where d.n > 0),
               array_agg(d.s order by d.b) filter (where d.n > 0), array_agg(bl.gen order by d.b) filter (where d.n > 0),
               array_agg(d.b order by d.b) filter (where d.n < 0), array_agg(-d.n order by d.b) filter (where d.n < 0)
        into v_inc_sha, v_inc_n, v_inc_size, v_inc_gen, v_dec_sha, v_dec_n
        from (
            select x.b, sum(x.n)::integer as n, max(x.s) as s
            from (
                select o.b, 1 as n, o.s
                from unnest(p_ops, p_blob_sha, p_sizes, v_seqs) as o (op, b, s, q)
                where o.q is not null and o.op = 1 and o.b is not null
                union all
                select r.blob_sha256, -1, null
                from unnest(p_kinds, p_ids, v_seqs) as o (k, i, q)
                join onepass_mailbox.records r on r.mailbox_id = p_mailbox and r.kind = o.k and r.id = o.i
                where o.q is not null and r.blob_sha256 is not null
            ) x
            group by x.b
        ) d
        left join onepass_mailbox.blobs bl on bl.mailbox_id = p_mailbox and bl.sha256 = d.b
        where d.n <> 0;

        -- All or nothing: a quota refusal, or a blob row that is not the one
        -- checked, rolls the writes back (contract 3).
        begin
            insert into onepass_mailbox.records as r
                (mailbox_id, kind, id, version, seq, deleted, deleted_at, size, data, blob_sha256)
            select p_mailbox, o.k, o.i, o.v, o.q, o.op = 2,
                   case when o.op = 2 then now() end,
                   case when o.op = 2 then 0 else o.s end,
                   case when o.op = 1 then o.d end,
                   case when o.op = 1 then o.b end
            from unnest(p_kinds, p_ids, p_versions, p_ops, p_data, p_blob_sha, p_sizes, v_seqs)
                as o (k, i, v, op, d, b, s, q)
            where o.q is not null
            on conflict (mailbox_id, kind, id) do update set
                version = excluded.version,
                seq = excluded.seq,
                deleted = excluded.deleted,
                deleted_at = excluded.deleted_at,
                size = excluded.size,
                data = excluded.data,
                blob_sha256 = excluded.blob_sha256;

            -- Update only, bound to the generation checked under the lock.
            if v_inc_sha is not null then
                update onepass_mailbox.blobs b set
                    refs = b.refs + i.n,
                    state = 2,
                    orphaned_at = null
                from unnest(v_inc_sha, v_inc_n, v_inc_gen) as i (b, n, g)
                where b.mailbox_id = p_mailbox and b.sha256 = i.b and b.gen = i.g;
                get diagnostics v_rows = row_count;
                if v_rows <> cardinality(v_inc_sha) then
                    raise exception using errcode = 'OP400', message = 'malformed';
                end if;
            end if;
            if v_dec_sha is not null then
                update onepass_mailbox.blobs b set refs = b.refs - d.n
                from unnest(v_dec_sha, v_dec_n) as d (b, n)
                where b.mailbox_id = p_mailbox and b.sha256 = d.b;
            end if;

            update onepass_mailbox.mailboxes m set
                next_seq = m.next_seq + v_writes,
                bytes_used = m.bytes_used + v_dbytes,
                records_count = m.records_count + v_drecords,
                last_write_at = now()
            where m.id = p_mailbox
            returning m.bytes_used, m.records_count into v_bytes, v_records;

            if not v_deletes_only
               and ((v_dbytes > 0 and v_bytes > v_max_bytes) or (v_drecords > 0 and v_records > v_max_records)) then
                raise exception using errcode = 'OP422', message = 'quota';
            end if;
        exception
            when sqlstate 'OP422' then
                v_err := 'quota';
            when sqlstate 'OP400' then
                v_err := 'malformed';
        end;

        if v_err is not null then
            return query select v_err, null::integer, null::smallint, null::bytea, null::bigint, null::bigint,
                null::boolean, null::bytea, null::bytea, null::integer;
            return;
        end if;

        perform onepass_mailbox_wake.send(v_wake);
        insert into onepass_mailbox.push_queue as q (mailbox_id, exclude_credential, enqueued_at)
        values (p_mailbox, p_credential, now())
        on conflict (mailbox_id) do update set
            exclude_credential = case when q.exclude_credential = excluded.exclude_credential
                                      then excluded.exclude_credential end,
            enqueued_at = excluded.enqueued_at;
    end if;

    return query
    select 'ok'::text, null::integer, o.k, o.i, o.q, o.v, o.op = 2, null::bytea, null::bytea,
           case when o.q is null then null when o.op = 2 then 0 else o.s end
    from unnest(p_kinds, p_ids, p_versions, p_ops, p_sizes, v_seqs) with ordinality as o (k, i, v, op, s, q, ord)
    order by o.ord;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.api_grant_credential(bytea, bytea, timestamptz, bytea, bytea, smallint, bytea, bytea),
    onepass_mailbox.api_set_credential_role(bytea, bytea, timestamptz, bytea, bytea, smallint, bytea)
to onepass_mailbox_api;
