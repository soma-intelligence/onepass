-- OnePass mailbox: blobs in Storage and the pairing rendezvous (spec 4.5,
-- 4.6, 4.9, 4.11, 5.3). Follows the contract in the header of
-- 20261031120100: refusals before authentication raise, every other outcome
-- is returned in band with `status text, retry_after integer` first, and a
-- refused write leaves only the consumed counters.
--
-- Blobs. A body above 16 KiB (INLINE_MAX) lives in the private Storage
-- bucket 'onepass-mailbox' under hex(mailbox) || '/' || hex(sha256), the
-- object name of the proto's `hex` helper. The edge function (Task 7) signs
-- the upload and download URLs with the service key, for Storage only; this
-- schema only reads storage.objects, through a policy scoped to the mailbox
-- of the request. The server never sees a body, so it cannot check that the
-- object hashes to its name: the name and the size bind the commit, and the
-- client checks the SHA-256 of everything it downloads. A client that
-- uploads a body under the wrong hash hurts only its own mailbox.
--
--   api_blob_announce: 1 to 1 000 (PAGE_MAX_RECORDS) distinct blobs of
--     16 385 to 921 600 bytes. Records each one as announced (state 1) when
--     absent and answers, sorted by hash, whether it needs an upload: yes
--     unless its object is in Storage with that size, and always when the
--     collector has taken it (state 3), since its object may go at any
--     moment. Quota: bytes_used counts committed bodies through their
--     records (inline and blob alike); blobs no record references yet are
--     counted at announce, so the bytes a mailbox holds in Storage stay
--     under its plan. Only growth is refused, like a commit.
--   api_blob_lookup: the hashes asked for that a live row of the mailbox
--     references, with their size, sorted (one 'ok' row with NULL columns
--     when none is).
--   api_commit, Blob branch (replaces the Task 5 function, same signature):
--     a put with blob_sha (32 bytes) and size (16 385 to 921 600) and no
--     data passes only if the object exists under the mailbox's prefix with
--     metadata size equal to size, and the collector has not taken it;
--     otherwise the batch is malformed. A written put takes one reference
--     on its blob, the body it replaces (put or delete) gives one back. A
--     blob whose count falls to 0 is marked orphaned by maintenance and
--     collected 24 hours later (20261031120400).
--
-- Blob states: 1 announced (no commit has seen its object yet), 2 present (a
-- commit checked its object), 3 orphaned and handed to the collector
-- (gc_take). A taken blob is never referenced again: a commit refuses it,
-- an announce takes it back (state 1) and asks for a new upload. If the
-- collector deletes the object anyway (it took the blob before), the next
-- commit finds no object, the client announces again, uploads, and the
-- loop converges.
--
-- Rendezvous (spec 5.3, T-RDV). No credential: the session id from the QR
-- code is the only key, and every call counts on the per-IP minute bucket of
-- create and enroll (60 a minute, raw IP key), failed calls included. A
-- frame is written once (another put on its n is 'conflict'), readable for
-- 120 s after it was written, 1 MiB at most; a session takes 66 MiB per
-- direction (69 206 016 bytes, 'too_large' past that) and 4 096 frames per
-- direction (n from 0 to 4095, so tiny frames cannot pile up rows), and is
-- closed 600 s after its first frame ('not_found' then). Per IP key, 200 MiB
-- of frames an hour on a second bucket keyed by SHA-256(SHA-256(IP key)):
-- distinct from the raw key (minute bucket) and from SHA-256(IP key) (the
-- creation day bucket), so no two windows ever share a row.
--
--   rdv_put(session, dir, n, data, ip_key): starts the session on its first
--     frame.
--   rdv_get(session, dir, n, ip_key): 'ok' with the frame, or with NULL while
--     it is absent (or older than 120 s, or the session not started yet);
--     'not_found' once the session is closed or older than 600 s. The edge
--     function long-polls (wait=25) by calling it again: it passes the IP
--     key on the first call of an HTTP request and NULL on the polls that
--     follow, so one request counts once.
--   rdv_close(session, ip_key): closes the session (even one never started,
--     which then cannot start) and drops its frames.

-- ---------------------------------------------------------------- schema

set role onepass_mailbox_owner;

-- When the collector took the blob (gc_take); NULL otherwise.
alter table onepass_mailbox.blobs add column gc_taken_at timestamptz;
alter table onepass_mailbox.blobs
    add constraint blobs_taken check ((state = 3) = (gc_taken_at is not null));

-- Live rows by the blob they reference: lookups and reference counts.
create index records_blob_idx on onepass_mailbox.records (mailbox_id, blob_sha256) where blob_sha256 is not null;

-- Bytes per direction: 0 newcomer to approver, 1 the other way.
alter table onepass_mailbox.rdv_sessions rename column bytes to bytes_0;
alter table onepass_mailbox.rdv_sessions
    add column bytes_1 bigint not null default 0 check (bytes_1 >= 0);

reset role;

-- --------------------------------------------------------------- Storage

-- The bucket is private: objects are reachable only through signed URLs.
-- 921 600 bytes is RECORD_MAX.
insert into storage.buckets (id, name, public, file_size_limit)
values ('onepass-mailbox', 'onepass-mailbox', false, 921600)
on conflict (id) do update set public = false, file_size_limit = 921600;

-- Read only, and only under the prefix of the mailbox the request
-- authenticated. The bucket is not versioned: one object per name.
grant usage on schema storage to onepass_mailbox_owner;
grant select on storage.objects to onepass_mailbox_owner;
create policy onepass_mailbox_owner_read on storage.objects
    for select to onepass_mailbox_owner
    using (bucket_id = 'onepass-mailbox'
           and left(name, 33) = encode((select onepass_mailbox.current_mailbox()), 'hex') || '/');

set role onepass_mailbox_owner;

-- ------------------------------------------------------------ helpers

-- Adds p_amount to a fixed UTC window if the total stays within p_limit,
-- and returns NULL; otherwise adds nothing and returns the seconds left in
-- the window (retry_after).
create function onepass_mailbox._add(p_key bytea, p_window interval, p_amount integer, p_limit integer)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_start timestamptz;
    v_count integer;
begin
    v_start := case p_window
        when interval '1 hour' then date_trunc('hour', now(), 'UTC')
    end;
    if v_start is null then
        raise exception 'unsupported rate window %', p_window;
    end if;
    if p_amount <= p_limit then
        insert into onepass_mailbox.rate as r (key, window_start, count)
        values (p_key, v_start, p_amount)
        on conflict (key, window_start) do update set count = r.count + excluded.count
            where r.count + excluded.count <= p_limit
        returning r.count into v_count;
    end if;
    if v_count is null then
        return greatest(1, ceil(extract(epoch from (v_start + p_window - now()))))::integer;
    end if;
    return null;
end
$$;

-- ---------------------------------------------------------------- blobs

-- POST /v1/mailboxes/{m}/blobs/uploads.
create function onepass_mailbox.api_blob_announce(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_shas bytea[], p_sizes integer[])
returns table (status text, retry_after integer, sha256 bytea, needs_upload boolean)
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
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
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
        return query select v_err, v_retry, null::bytea, null::boolean;
        return;
    end if;

    v_prefix := encode(p_mailbox, 'hex') || '/';
    return query
    with o as (
        select o.s, o.z from unnest(p_shas, p_sizes) as o (s, z)
    ), cur as (
        select o.s, b.state,
               exists (select 1 from storage.objects so
                       where so.bucket_id = 'onepass-mailbox'
                         and so.name collate "C" = v_prefix || encode(o.s, 'hex')
                         and so.metadata ->> 'size' = o.z::text) as present
        from o left join onepass_mailbox.blobs b on b.mailbox_id = p_mailbox and b.sha256 = o.s
    ), up as (
        insert into onepass_mailbox.blobs as b (mailbox_id, sha256, size, state)
        select p_mailbox, o.s, o.z, 1 from o
        on conflict (mailbox_id, sha256) do update set
            size = case when b.refs = 0 then excluded.size else b.size end,
            -- Taken back from the collector, or kept alive another 24 hours.
            state = case when b.state = 3 then 1 else b.state end,
            gc_taken_at = null,
            orphaned_at = case when b.refs = 0 then null else b.orphaned_at end
        returning 1
    )
    select 'ok'::text, null::integer, cur.s, not cur.present or cur.state is not distinct from 3::smallint
    from cur
    order by cur.s;
end
$$;

-- POST /v1/mailboxes/{m}/blobs/downloads.
create function onepass_mailbox.api_blob_lookup(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_shas bytea[])
returns table (status text, retry_after integer, sha256 bytea, size integer)
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
    v_distinct integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;
    if v_err is null then
        v_n := cardinality(p_shas);
        if v_n is null or v_n = 0 or v_n > 1000 or array_ndims(p_shas) <> 1 or array_lower(p_shas, 1) <> 1 then
            v_err := 'malformed';
        else
            select coalesce(bool_or(s is null or length(s) <> 32), true), count(distinct s) into v_bad, v_distinct
            from unnest(p_shas) s;
            if v_bad or v_distinct <> v_n then
                v_err := 'malformed';
            end if;
        end if;
    end if;
    if v_err is not null then
        return query select v_err, v_retry, null::bytea, null::integer;
        return;
    end if;

    -- Tombstones carry no blob: a row with blob_sha256 is live.
    return query
    select 'ok'::text, null::integer, b.sha256, b.size
    from unnest(p_shas) as o (s)
    join onepass_mailbox.blobs b on b.mailbox_id = p_mailbox and b.sha256 = o.s
    where exists (select 1 from onepass_mailbox.records r where r.mailbox_id = p_mailbox and r.blob_sha256 = o.s)
    order by b.sha256;
    if not found then
        return query select 'ok'::text, null::integer, null::bytea, null::integer;
    end if;
end
$$;

-- --------------------------------------------------------------- commit

-- api_commit of 20261031120200 with the Blob branch: the shapes, the Storage
-- check after the lock, the blob hash stored on the row, and the reference
-- counts moved in the same subtransaction as the records.
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
    v_dec_sha bytea[];
    v_dec_n integer[];
    v_rows integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
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
        -- Every blob the batch puts: its object under this mailbox's prefix,
        -- with this size, and not taken by the collector.
        v_prefix := encode(p_mailbox, 'hex') || '/';
        select coalesce(bool_or(so.id is null or bl.state is not distinct from 3::smallint), false)
        into v_bad
        from (select distinct o.b, o.s from unnest(p_ops, p_blob_sha, p_sizes) as o (op, b, s)
              where o.op = 1 and o.b is not null) x
        left join storage.objects so
            on so.bucket_id = 'onepass-mailbox'
           and so.name collate "C" = v_prefix || encode(x.b, 'hex')
           and so.metadata ->> 'size' = x.s::text
        left join onepass_mailbox.blobs bl on bl.mailbox_id = p_mailbox and bl.sha256 = x.b;
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
        select array_agg(d.b) filter (where d.n > 0), array_agg(d.n) filter (where d.n > 0),
               array_agg(d.s) filter (where d.n > 0),
               array_agg(d.b) filter (where d.n < 0), array_agg(-d.n) filter (where d.n < 0)
        into v_inc_sha, v_inc_n, v_inc_size, v_dec_sha, v_dec_n
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
        where d.n <> 0;

        -- All or nothing: a quota refusal, or a blob the collector took while
        -- this batch ran, rolls the writes back (contract 3).
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

            if v_inc_sha is not null then
                insert into onepass_mailbox.blobs as b (mailbox_id, sha256, size, state, refs)
                select p_mailbox, i.b, i.s, 2, i.n
                from unnest(v_inc_sha, v_inc_n, v_inc_size) as i (b, n, s)
                on conflict (mailbox_id, sha256) do update set
                    refs = b.refs + excluded.refs,
                    state = 2,
                    size = excluded.size,
                    orphaned_at = null,
                    gc_taken_at = null
                where b.state <> 3;
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

-- ------------------------------------------------------------ rendezvous

-- PUT /v1/rendezvous/{s}/{dir}/{n}.
create function onepass_mailbox.rdv_put(p_session bytea, p_dir smallint, p_n integer, p_data bytea, p_ip_key bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_len integer;
    v_created timestamptz;
    v_closed timestamptz;
    v_bytes bigint;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    -- The minute bucket shared with create and enroll (spec 4.9).
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_session is null or length(p_session) <> 16 or p_dir is null or p_dir not in (0, 1)
       or p_n is null or p_n not between 0 and 4095 or p_data is null then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    v_len := octet_length(p_data);
    if v_len > 1048576 then
        return query select 'too_large'::text, null::integer;
        return;
    end if;

    perform set_config('onepass.rdv', encode(p_session, 'hex'), true);
    v_retry := null;
    -- Everything below is undone on a refusal: the session a first frame
    -- would have started, the hour bucket, the frame.
    begin
        insert into onepass_mailbox.rdv_sessions (session_id) values (p_session)
        on conflict (session_id) do nothing;
        select s.created_at, s.closed_at, case when p_dir = 0 then s.bytes_0 else s.bytes_1 end
        into v_created, v_closed, v_bytes
        from onepass_mailbox.rdv_sessions s where s.session_id = p_session
        for update;
        if v_closed is not null or v_created < now() - interval '600 seconds' then
            v_err := 'not_found';
        elsif v_bytes + v_len > 69206016 then
            v_err := 'too_large';
        else
            v_retry := onepass_mailbox._add(
                extensions.digest(extensions.digest(p_ip_key, 'sha256'), 'sha256'), interval '1 hour', v_len, 209715200);
            if v_retry is not null then
                v_err := 'rate_limited';
            else
                insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data)
                values (p_session, p_dir, p_n, p_data)
                on conflict (session_id, dir, n) do nothing;
                if not found then
                    v_err := 'conflict';
                else
                    update onepass_mailbox.rdv_sessions set
                        bytes_0 = bytes_0 + case when p_dir = 0 then v_len else 0 end,
                        bytes_1 = bytes_1 + case when p_dir = 1 then v_len else 0 end
                    where session_id = p_session;
                end if;
            end if;
        end if;
        if v_err is not null then
            raise exception using errcode = 'OP000', message = v_err;
        end if;
    exception when sqlstate 'OP000' then
        null;
    end;
    perform set_config('onepass.rdv', '', true);

    if v_err is not null then
        return query select v_err, v_retry;
        return;
    end if;
    return query select 'ok'::text, null::integer;
end
$$;

-- GET /v1/rendezvous/{s}/{dir}/{n}. p_ip_key NULL: a poll inside an HTTP
-- request whose first call already counted.
create function onepass_mailbox.rdv_get(p_session bytea, p_dir smallint, p_n integer, p_ip_key bytea)
returns table (status text, retry_after integer, data bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_created timestamptz;
    v_closed timestamptz;
    v_data bytea;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is not null and length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    if p_ip_key is not null then
        v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
        if v_retry is not null then
            return query select 'rate_limited'::text, v_retry, null::bytea;
            return;
        end if;
    end if;
    if p_session is null or length(p_session) <> 16 or p_dir is null or p_dir not in (0, 1)
       or p_n is null or p_n not between 0 and 4095 then
        return query select 'malformed'::text, null::integer, null::bytea;
        return;
    end if;

    perform set_config('onepass.rdv', encode(p_session, 'hex'), true);
    select s.created_at, s.closed_at into v_created, v_closed
    from onepass_mailbox.rdv_sessions s where s.session_id = p_session;
    if found and (v_closed is not null or v_created < now() - interval '600 seconds') then
        perform set_config('onepass.rdv', '', true);
        return query select 'not_found'::text, null::integer, null::bytea;
        return;
    end if;
    select c.data into v_data
    from onepass_mailbox.rdv_chunks c
    where c.session_id = p_session and c.dir = p_dir and c.n = p_n
      and c.written_at >= now() - interval '120 seconds';
    perform set_config('onepass.rdv', '', true);
    return query select 'ok'::text, null::integer, v_data;
end
$$;

-- DELETE /v1/rendezvous/{s}.
create function onepass_mailbox.rdv_close(p_session bytea, p_ip_key bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_session is null or length(p_session) <> 16 then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    perform set_config('onepass.rdv', encode(p_session, 'hex'), true);
    insert into onepass_mailbox.rdv_sessions as s (session_id, closed_at) values (p_session, now())
    on conflict (session_id) do update set closed_at = coalesce(s.closed_at, excluded.closed_at);
    delete from onepass_mailbox.rdv_chunks c where c.session_id = p_session;
    perform set_config('onepass.rdv', '', true);
    return query select 'ok'::text, null::integer;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.api_blob_announce(bytea, bytea, timestamptz, bytea, bytea[], integer[]),
    onepass_mailbox.api_blob_lookup(bytea, bytea, timestamptz, bytea, bytea[]),
    onepass_mailbox.rdv_put(bytea, smallint, integer, bytea, bytea),
    onepass_mailbox.rdv_get(bytea, smallint, integer, bytea),
    onepass_mailbox.rdv_close(bytea, bytea)
to onepass_mailbox_api;
