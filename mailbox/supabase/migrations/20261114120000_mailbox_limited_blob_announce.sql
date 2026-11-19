-- OnePass mailbox: a writer limited by put_kinds may announce blobs
-- (OnePass Business plan C, ruling R1). Follows the contract in the header of
-- 20261031120100.
--
-- An organisation invitee holds a Write credential limited to kind 32
-- (put_kinds) on the org mailbox and posts its join request there. The
-- request carries the member's account genesis, an SLH-DSA signature of
-- about 30 KB, so it is larger than the inline limit and travels as a blob.
--   api_blob_announce   role 2 or 3 (was: role 2 without put_kinds, or 3).
--                       A reader (role 1) is still refused, in-band status
--                       forbidden, after _authenticate and again under the
--                       mailbox lock (_locked_caller).
-- Nothing else changes: api_commit still refuses any Put of a kind outside
-- put_kinds and any Delete, which is what binds a blob to an allowed kind.
-- A blob that is announced and never bound is collected like any other
-- unreferenced blob, and counts against the quota of the mailbox as today.
--
-- Replaced (same signature and grants, jit off kept): api_blob_announce.

-- ----------------------------------------------------------------- order

-- Replaces the version of 20261108130000 (stored-size quota): applied before
-- it, the older body would come back over this one on the next apply.
do $$
begin
    if to_regprocedure('onepass_mailbox._object_size(jsonb)') is null then
        raise exception 'apply 20261108130000_mailbox_scan_fixes.sql before 20261114120000_mailbox_limited_blob_announce.sql';
    end if;
end
$$;

-- ------------------------------------------------------ replaced entry point

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
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;

    -- A reader announces nothing. A writer limited to some kinds may: the
    -- commit refuses any Put of a kind outside its set, so its blob can only
    -- be bound under an allowed kind.
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
        -- The caller again, under the lock.
        select l.o_role into v_role
        from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
        if v_role = 1 then
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
