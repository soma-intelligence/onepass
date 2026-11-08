-- OnePass mailbox: fixes from the security and robustness review of
-- 2026-11-08. Follows the contract in the header of 20261031120100.
--
-- Blob quota counts stored bytes (review finding 1). A signed upload URL
-- takes any object up to the bucket limit (RECORD_MAX), whatever size was
-- announced, so declared sizes alone let a mailbox keep far more in Storage
-- than its plan.
--   api_blob_announce   an unreferenced blob costs the larger of its
--                       declared size and the size of the object stored
--                       under its current name, both in the growth of the
--                       batch and in the pending bytes of the mailbox. An
--                       unreferenced blob of the batch whose object is
--                       stored with another size than the one announced now
--                       is collected on the spot (row out, name into
--                       blob_graves) and comes back as a new row under a new
--                       generation: announcing it again no longer keeps an
--                       oversize object alive. A refused announce changes
--                       nothing. (api_commit already refuses a blob whose
--                       stored size is not the declared one: unchanged.)
--   maintenance         collects at once any announced blob (state 1, no
--                       reference) whose object is stored with another size
--                       than its row's, through the graves like any other.
--
-- Credential rows are bounded (finding 2). Revoked rows stayed forever, so
-- grant and revoke (or enroll and revoke) in a loop grew the table without
-- bound.
--   api_grant_credential, api_enroll   also refuse 'quota' once the mailbox
--                       holds 4 times max_credentials credentials that are
--                       active or were revoked within the last 7 days (a
--                       grant and revoke loop fills it within a week; normal
--                       use, such as device upgrades, never does).
--   maintenance         deletes credentials revoked more than 7 days ago in
--                       live mailboxes, unless a nonce names them; the
--                       enrolled_by and granted_by of the credentials that
--                       named them are cleared first (only an audit trail;
--                       the one semantic reader, api_abandon_mailbox, looks
--                       at mailboxes under 24 hours old). A revoked
--                       device that comes back after that is refused as
--                       unknown_credential instead of revoked_credential: the
--                       clients treat both alike. A mailbox being deleted is
--                       left to the purge, which needs its credentials to
--                       find it.
--
-- Upload URLs and the purge (finding 4). An upload URL lives 2 hours
-- (Storage's SIGNED_UPLOAD_URL_EXPIRATION_TIME); the purge of a deleted
-- mailbox ran 1 hour after deleted_at, so an object could land after its row
-- and its grave were gone.
--   _maintenance_core   purges a deleted mailbox 3 hours after deleted_at.
--   maintenance         at most once an hour (settings row orphan_sweep_at,
--                       the time of the last sweep) queues into blob_graves
--                       every object of the bucket older than 3 hours that
--                       has no blob row and no grave (_sweep_orphan_objects),
--                       10 000 a run: an object uploaded again through a URL
--                       still valid after its blob was collected is not kept.
--   storage.objects     the owner reads the whole bucket in maintenance (a
--                       second select policy), still nothing outside it, and
--                       per request still only the prefix of the mailbox of
--                       the request.
--
-- Not changed here (finding 3, the wake topic never rotates): rotating
-- wake_topic on revoke would only hide the channel name, which every member
-- learns again from GET /v1/mailboxes/{m}; a public Broadcast channel is
-- still open to anyone holding the publishable key. The fix is a private
-- channel with Realtime authorization, a client and spec change.
--
-- Replaced (same signatures and grants): api_blob_announce, api_grant_credential,
-- api_enroll, _maintenance_core, maintenance. New, owner only:
-- _object_size, _sweep_orphan_objects.

-- ----------------------------------------------------------------- order

-- This migration replaces the maintenance of 20261101120000 (which renamed
-- the earlier one to _maintenance_core and purges drops) and assumes the
-- push targets of 20261101120100. Applied by hand before them, it would
-- leave a maintenance that fails on every run and make 20261101120000 fail
-- in turn: refuse.
do $$
begin
    if to_regclass('onepass_mailbox.drops') is null
       or to_regclass('onepass_mailbox.drop_heads') is null
       or to_regprocedure('onepass_mailbox._maintenance_core(timestamptz)') is null then
        raise exception 'apply 20261101120000_mailbox_drops.sql before 20261108130000_mailbox_scan_fixes.sql';
    end if;
    if to_regclass('onepass_mailbox.push_targets') is null then
        raise exception 'apply 20261101120100_mailbox_push_targets.sql before 20261108130000_mailbox_scan_fixes.sql';
    end if;
end
$$;

-- --------------------------------------------------------------- Storage

-- Maintenance (session postgres or the janitor, onepass.maintenance on)
-- reads every object of the bucket: the stored size of announced blobs and
-- the orphan sweep. Policies add up: the request policy of 20261031120300
-- is unchanged.
create policy onepass_mailbox_owner_maintenance_read on storage.objects
    for select to onepass_mailbox_owner
    using (bucket_id = 'onepass-mailbox' and (select onepass_mailbox.in_maintenance()));

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- helpers

-- The size Storage recorded for an object (metadata.size), or NULL when it
-- is missing or not a plain number.
create function onepass_mailbox._object_size(p_metadata jsonb)
returns bigint
language sql
immutable
set search_path = ''
as $$
    select case when p_metadata ->> 'size' ~ '^[0-9]{1,15}$' then (p_metadata ->> 'size')::bigint end
$$;

-- Objects of the bucket older than 3 hours (past the 2 hour life of any
-- upload URL) that no blob row names (mailbox, hash and generation) and no
-- grave holds: into blob_graves for mailbox-gc, at most 10 000 a call.
-- Returns how many were queued. An object name is never handed out twice
-- (generations come from one sequence), so an object with no row is never
-- wanted again. Only inside maintenance.
create function onepass_mailbox._sweep_orphan_objects(p_now timestamptz)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_n integer;
begin
    if not onepass_mailbox.in_maintenance() then
        raise exception 'the orphan sweep runs inside maintenance';
    end if;
    with o as (
        select decode(left(so.name, 32), 'hex') as mailbox_id,
               decode(substr(so.name, 34, 64), 'hex') as sha256,
               substr(so.name, 99) as gen,
               so.name::text as object_name
        from storage.objects so
        where so.bucket_id = 'onepass-mailbox'
          and so.created_at < p_now - interval '3 hours'
          and so.name collate "C" ~ '^[0-9a-f]{32}/[0-9a-f]{64}\.[1-9][0-9]{0,18}$'
    ), orphan as (
        select o.mailbox_id, o.object_name from o
        where exists (select 1 from onepass_mailbox.mailboxes m where m.id = o.mailbox_id)
          and not exists (select 1 from onepass_mailbox.blobs b
                          where b.mailbox_id = o.mailbox_id and b.sha256 = o.sha256 and b.gen::text = o.gen)
          and not exists (select 1 from onepass_mailbox.blob_graves g
                          where g.mailbox_id = o.mailbox_id and g.object_name = o.object_name)
        limit 10000
    )
    insert into onepass_mailbox.blob_graves (mailbox_id, object_name, queued_at)
    select x.mailbox_id, x.object_name, p_now from orphan x
    on conflict (mailbox_id, object_name) do nothing;
    get diagnostics v_n = row_count;
    return v_n;
end
$$;

-- ------------------------------------------------------ replaced entry points

-- api_blob_announce of 20261031233000: the quota counts stored sizes, and an
-- unreferenced blob stored with another size is collected and announced anew.
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
-- As set by 20261108120000: never worth compiling.
set jit = off
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
    v_put_kinds bytea;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;

    -- An upload is a write of a body of any kind: a reader, or a writer
    -- limited to some kinds, announces nothing.
    if v_err is null then
        select c.role, c.put_kinds into v_role, v_put_kinds from onepass_mailbox.credentials c
        where c.id = p_credential and c.mailbox_id = p_mailbox;
        if v_role = 1 or v_put_kinds is not null then
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
        -- The caller again, under the lock.
        select l.o_role, l.o_put_kinds into v_role, v_put_kinds
        from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
        if v_role = 1 or v_put_kinds is not null then
            v_err := 'forbidden';
        end if;
    end if;

    if v_err is null then
        -- A referenced blob has a known size: another one is a lie. An
        -- unreferenced one takes the new size. An unreferenced blob costs
        -- the larger of its declared size and the size of the object stored
        -- under its current name (a client may upload more than it
        -- declared, up to the bucket's limit): growth is the new declared
        -- sizes over what those blobs cost so far.
        select coalesce(bool_or(b.refs > 0 and b.size <> o.z), false),
               coalesce(sum(o.z - greatest(coalesce(b.size, 0), coalesce(st.z, 0)))
                        filter (where b.sha256 is null or b.refs = 0), 0)
        into v_clash, v_growth
        from unnest(p_shas, p_sizes) as o (s, z)
        left join onepass_mailbox.blobs b on b.mailbox_id = p_mailbox and b.sha256 = o.s
        left join lateral (
            select onepass_mailbox._object_size(so.metadata) as z
            from storage.objects so
            where so.bucket_id = 'onepass-mailbox'
              and so.name collate "C" = onepass_mailbox._blob_object(p_mailbox, b.sha256, b.gen)
        ) st on b.sha256 is not null;
        if v_clash then
            v_err := 'malformed';
        elsif v_growth > 0 then
            select coalesce(sum(greatest(b.size, coalesce(st.z, 0))), 0) into v_pending
            from onepass_mailbox.blobs b
            left join lateral (
                select onepass_mailbox._object_size(so.metadata) as z
                from storage.objects so
                where so.bucket_id = 'onepass-mailbox'
                  and so.name collate "C" = onepass_mailbox._blob_object(p_mailbox, b.sha256, b.gen)
            ) st on true
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

    -- An unreferenced blob of the batch whose object is stored with another
    -- size than the one announced now can never be committed (a commit
    -- checks the stored size). It is collected here, row out and object name
    -- into the graves, and comes back below as a new row under a new
    -- generation: announcing it again never keeps that object alive, and
    -- never hands out a URL for its name again. (Under the mailbox lock:
    -- no commit or announce runs beside this one; maintenance skips the
    -- rows locked here.)
    with bad as (
        select b.sha256 from onepass_mailbox.blobs b
        join unnest(p_shas, p_sizes) as o (s, z) on b.sha256 = o.s
        join storage.objects so
            on so.bucket_id = 'onepass-mailbox'
           and so.name collate "C" = onepass_mailbox._blob_object(p_mailbox, b.sha256, b.gen)
        where b.mailbox_id = p_mailbox and b.refs = 0
          and (so.metadata ->> 'size') is distinct from o.z::text
        order by b.sha256
        for update of b
    ), gone as (
        delete from onepass_mailbox.blobs b
        using bad
        where b.mailbox_id = p_mailbox and b.sha256 = bad.sha256 and b.refs = 0
        returning onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen) as object_name
    )
    insert into onepass_mailbox.blob_graves (mailbox_id, object_name, queued_at)
    select p_mailbox, g.object_name, now() from gone g
    on conflict (mailbox_id, object_name) do nothing;

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

-- api_grant_credential of 20261031233000: every credential row counts, up to
-- 4 times max_credentials.
create or replace function onepass_mailbox.api_grant_credential(
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
    v_rows integer;
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
    select l.o_role into v_role from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
    if v_role is distinct from 3 then
        v_err := 'forbidden';
    else
        -- Active credentials against the plan; active ones plus those
        -- revoked within the last 7 days against 4 times it. Maintenance
        -- purges every row revoked earlier, so the cap always frees up.
        select count(*) filter (where c.revoked_at is null)::integer,
               count(*) filter (where c.revoked_at is null or c.revoked_at > now() - interval '7 days')::integer
        into v_active, v_rows
        from onepass_mailbox.credentials c
        where c.mailbox_id = p_mailbox;
        if v_active >= v_max or v_rows >= 4 * v_max then
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

-- api_enroll of 20261031235000: every credential row counts, up to 4 times
-- max_credentials.
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
    v_rows integer;
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
            -- As in api_grant_credential: active ones against the plan,
            -- active ones plus those revoked within 7 days against 4 times it.
            select count(*) filter (where c.revoked_at is null)::integer,
                   count(*) filter (where c.revoked_at is null or c.revoked_at > now() - interval '7 days')::integer
            into v_active, v_rows
            from onepass_mailbox.credentials c
            where c.mailbox_id = p_mailbox;
            if v_active >= v_max or v_rows >= 4 * v_max then
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

-- --------------------------------------------------------------- maintenance

-- _maintenance_core (the maintenance of 20261031234000): the purge of a
-- deleted mailbox waits 3 hours instead of 1.
create or replace function onepass_mailbox._maintenance_core(p_now timestamptz default now())
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

    -- Mailboxes abandoned more than 3 hours ago (api_abandon_mailbox, or
    -- api_delete_mailbox for a child), past the 2 hour life of an upload URL
    -- signed before the deletion, so no upload lands after the purge; at
    -- most 1 000 a run, locked in id order and skipped while a request holds
    -- them. A mailbox still has credentials until it is purged: the purge
    -- deletes them last, so a purged mailbox is never picked again. Its blob
    -- rows go to blob_graves at once (the 24 hour orphan delay protects a
    -- commit racing the collector; nothing commits here any more).
    select array_agg(d.id order by d.id) into v_dead
    from (
        select m.id from onepass_mailbox.mailboxes m
        where m.deleted_at < p_now - interval '3 hours'
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

-- maintenance of 20261101120000: the core, the drop purge, then the purge of
-- old revoked credentials, the collection of announced blobs stored with the
-- wrong size, and the hourly orphan sweep.
create or replace function onepass_mailbox.maintenance(p_now timestamptz default now())
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_purge_mbx bytea[];
    v_purge_ids bytea[];
begin
    perform onepass_mailbox._maintenance_core(p_now);
    perform set_config('onepass.maintenance', 'on', true);
    if not onepass_mailbox.in_maintenance() then
        raise exception 'maintenance runs as postgres or the janitor';
    end if;
    delete from onepass_mailbox.drops where expires_at <= p_now;
    delete from onepass_mailbox.drop_heads where expires_at <= p_now - interval '7 days';

    -- Credentials revoked more than 7 days ago, in mailboxes not being
    -- deleted, that no nonce names; 10 000 a run, skipping rows a request
    -- holds. The references other credentials hold to them (enrolled_by,
    -- granted_by) are cleared first, so a device lineage never pins rows. In
    -- a subtransaction: a lock conflict with a request skips this step for
    -- this run instead of failing the whole maintenance.
    begin
        select array_agg(x.mailbox_id), array_agg(x.id) into v_purge_mbx, v_purge_ids
        from (
            select x.mailbox_id, x.id from onepass_mailbox.credentials x
            join onepass_mailbox.mailboxes m on m.id = x.mailbox_id
            where x.revoked_at < p_now - interval '7 days'
              and m.deleted_at is null
              and not exists (select 1 from onepass_mailbox.nonces n where n.credential_id = x.id)
            order by x.revoked_at
            limit 10000
            for update of x skip locked
        ) x;
        if v_purge_ids is not null then
            update onepass_mailbox.credentials y set enrolled_by = null
            from unnest(v_purge_mbx, v_purge_ids) as d (m, i)
            where y.mailbox_id = d.m and y.enrolled_by = d.i;
            update onepass_mailbox.credentials y set granted_by = null
            from unnest(v_purge_mbx, v_purge_ids) as d (m, i)
            where y.mailbox_id = d.m and y.granted_by = d.i;
            delete from onepass_mailbox.credentials c
            using unnest(v_purge_mbx, v_purge_ids) as d (m, i)
            where c.mailbox_id = d.m and c.id = d.i;
        end if;
    exception
        when deadlock_detected or lock_not_available then
            raise warning 'onepass_mailbox maintenance: revoked credential purge skipped this run (lock conflict)';
    end;

    -- Announced blobs (never committed, no reference) whose object is stored
    -- with another size than the row's: no commit can take them, so they go
    -- now instead of 24 hours later. Skips rows a commit or announce holds.
    with t as (
        select x.mailbox_id, x.sha256 from onepass_mailbox.blobs x
        join storage.objects so
            on so.bucket_id = 'onepass-mailbox'
           and so.name collate "C" = onepass_mailbox._blob_object(x.mailbox_id, x.sha256, x.gen)
        where x.refs = 0 and x.state = 1
          and (so.metadata ->> 'size') is distinct from x.size::text
        order by x.mailbox_id, x.sha256
        limit 10000
        for update of x skip locked
    ), gone as (
        delete from onepass_mailbox.blobs b
        using t
        where b.mailbox_id = t.mailbox_id and b.sha256 = t.sha256 and b.refs = 0
        returning b.mailbox_id, onepass_mailbox._blob_object(b.mailbox_id, b.sha256, b.gen) as object_name
    )
    insert into onepass_mailbox.blob_graves (mailbox_id, object_name, queued_at)
    select g.mailbox_id, g.object_name, p_now from gone g
    on conflict (mailbox_id, object_name) do nothing;

    -- The orphan sweep reads the whole bucket: at most once an hour. The
    -- time of the last one is kept in settings, in ISO 8601 UTC.
    if not exists (select 1 from onepass_mailbox.settings s
                   where s.name = 'orphan_sweep_at'
                     and s.value ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$'
                     and s.value::timestamptz > p_now - interval '1 hour') then
        perform onepass_mailbox._sweep_orphan_objects(p_now);
        insert into onepass_mailbox.settings (name, value)
        values ('orphan_sweep_at', to_char(p_now at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
        on conflict (name) do update set value = excluded.value;
    end if;

    perform set_config('onepass.maintenance', '', true);
end
$$;

reset role;

-- ------------------------------------------------------------- grants

-- Replaced functions keep their grants. The new helpers run only inside the
-- owner's functions.
revoke all on function onepass_mailbox._object_size(jsonb) from public, anon, authenticated, service_role;
revoke all on function onepass_mailbox._sweep_orphan_objects(timestamptz) from public, anon, authenticated, service_role;
