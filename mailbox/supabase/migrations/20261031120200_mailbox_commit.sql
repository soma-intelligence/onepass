-- OnePass mailbox: atomic conditional commit with wake-up (spec 4.5, 4.6,
-- 4.9, 4.10). Follows the contract in the header of 20261031120100.
--
-- api_commit(credential, nonce, created, mailbox, kinds[], ids[],
-- versions[], ops[], expected[], data[], blob_sha[], sizes[]): one batch,
-- the i-th element of each array is the i-th operation.
--
--   op 1, put: expected NULL passes only on an absent key or a tombstone;
--     expected s passes only on a live row whose seq is s. Inline body:
--     data (16 KiB at most) and size = its length, blob_sha NULL. A blob
--     body (data NULL, blob_sha and size) is malformed until Task 6.
--   op 2, delete: unconditional and idempotent; expected, data, blob_sha
--     and size are NULL. A live row becomes a tombstone with a new seq
--     (deleted_at = now(), no body, size 0); an absent key or a tombstone
--     is left alone and takes no seq.
--
-- Authentication refusals raise (contract 1). Then, in band:
--   'rate_limited' (retry_after), 'malformed' (arrays of different
--   lengths, not one dimensional from 1, empty, a bad operation, a key
--   twice), 'too_large' (more operations than the plan's max_commit_ops or
--   than 20 000, or more than 4 MiB of ids, inline bodies and blob hashes:
--   a floor of the body the edge function measures), each as one row with
--   NULL data columns;
--   'conflict': one row per key whose expectation fails, in the order sent,
--   with the current server row (seq NULL and no data when absent); nothing
--   is written;
--   'quota': the batch would take the mailbox over the plan's bytes (inline
--   and blobs) or live records; nothing is written. A mailbox already over
--   (its plan shrank) may still commit a batch that does not grow the
--   counter it is over on;
--   'ok': one row per operation in the order sent, with the seq it took
--   (NULL for a delete that changed nothing), its version, deleted, the
--   stored size; data and blob_sha256 are NULL (the client has them).
--
-- Seqs: the mailbox row is locked (FOR NO KEY UPDATE: one batch at a time
-- per mailbox, without waiting on the KEY SHARE locks that the nonce and
-- rate inserts of other requests take on it), so the writing operations of
-- a batch take next_seq, next_seq + 1, ... in the order sent and readers
-- never see a seq below one they already saw appear later. A batch that
-- writes nothing (conflict, refusal, only no-op deletes) takes no seq,
-- leaves last_write_at, and wakes nobody.
--
-- Wake-up (spec 4.10), only when a batch wrote: an empty broadcast 'wake'
-- on the public topic 'mbx:' || hex(wake_topic), and the push_queue entry
-- of the mailbox, coalesced: it excludes the author when every batch it
-- stands for came from the same credential, nobody otherwise (each author
-- must hear of the other's write).

-- ------------------------------------------------------------- wake bridge

-- realtime.send is not SECURITY DEFINER and inserts into realtime.messages,
-- whose row level security has no policy for us: run as the owner, a
-- broadcast would fail, and realtime.send swallows the error. This bridge
-- runs as the migration role (on Supabase: postgres, BYPASSRLS, INSERT on
-- realtime.messages), takes only a 16 byte topic, and is executable by the
-- mailbox owner alone. It lives outside onepass_mailbox, whose functions all
-- belong to the owner (tests/privileges_test.sql).
create schema onepass_mailbox_wake;
revoke all on schema onepass_mailbox_wake from public;
grant usage on schema onepass_mailbox_wake to onepass_mailbox_owner;

create function onepass_mailbox_wake.send(p_topic bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_topic is null or length(p_topic) <> 16 then
        raise exception 'wake topic must be 16 bytes';
    end if;
    perform realtime.send('{}'::jsonb, 'wake', 'mbx:' || encode(p_topic, 'hex'), false);
end
$$;
revoke all on function onepass_mailbox_wake.send(bytea) from public, anon, authenticated, service_role;
grant execute on function onepass_mailbox_wake.send(bytea) to onepass_mailbox_owner;

-- ---------------------------------------------------------------- commit

set role onepass_mailbox_owner;

create function onepass_mailbox.api_commit(
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
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    end if;

    if v_err is null then
        -- One batch at a time per mailbox, held until the transaction ends.
        select m.next_seq, m.wake_topic, p.max_bytes, p.max_records, p.max_commit_ops
        into v_next, v_wake, v_max_bytes, v_max_records, v_max_ops
        from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
        where m.id = p_mailbox
        for no key update of m;

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
        elsif v_n > least(v_max_ops, 20000) then
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
                    -- Blob bodies are checked against Storage by Task 6.
                    or o.b is not null))), true),
            count(distinct (o.k, o.i)),
            coalesce(sum(coalesce(octet_length(o.i), 0) + coalesce(octet_length(o.d), 0) + coalesce(octet_length(o.b), 0)), 0)
        into v_bad, v_keys, v_carried
        from unnest(p_kinds, p_ids, p_versions, p_ops, p_expected, p_data, p_blob_sha, p_sizes)
            as o (k, i, v, op, e, d, b, s);
        if v_bad or v_keys <> v_n then
            v_err := 'malformed';
        elsif v_carried > 4194304 then
            v_err := 'too_large';
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
        coalesce(sum(case when w.new_seq is not null
                          then (case when w.op = 1 then w.s else 0 end) - (case when w.live then w.cur_size else 0 end)
                     end), 0)::bigint,
        coalesce(sum(case when w.new_seq is not null
                          then (case when w.op = 1 then 1 else 0 end) - (case when w.live then 1 else 0 end)
                     end), 0)::integer
    into v_conflict, v_seqs, v_writes, v_dbytes, v_drecords
    from (
        select x.*,
               case when x.writes
                    then v_next + count(*) filter (where x.writes) over (order by x.ord) - 1
               end as new_seq
        from (
            select o.ord, o.op, o.s, r.size as cur_size,
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
        return query
        select 'conflict'::text, null::integer, o.k, o.i, r.seq, r.version, r.deleted, r.data, r.blob_sha256, r.size
        from unnest(p_kinds, p_ids, p_ops, p_expected) with ordinality as o (k, i, op, e, ord)
        left join onepass_mailbox.records r
            on r.mailbox_id = p_mailbox and r.kind = o.k and r.id = o.i
        where o.op = 1
          and case when o.e is null then coalesce(not r.deleted, false)
                   else r.seq is null or r.deleted or r.seq <> o.e end
        order by o.ord;
        return;
    end if;

    if v_writes > 0 then
        -- All or nothing: a quota refusal rolls the writes back (contract 3).
        begin
            insert into onepass_mailbox.records as r
                (mailbox_id, kind, id, version, seq, deleted, deleted_at, size, data, blob_sha256)
            select p_mailbox, o.k, o.i, o.v, o.q, o.op = 2,
                   case when o.op = 2 then now() end,
                   case when o.op = 2 then 0 else o.s end,
                   case when o.op = 1 then o.d end,
                   null
            from unnest(p_kinds, p_ids, p_versions, p_ops, p_data, p_sizes, v_seqs) as o (k, i, v, op, d, s, q)
            where o.q is not null
            on conflict (mailbox_id, kind, id) do update set
                version = excluded.version,
                seq = excluded.seq,
                deleted = excluded.deleted,
                deleted_at = excluded.deleted_at,
                size = excluded.size,
                data = excluded.data,
                blob_sha256 = excluded.blob_sha256;

            update onepass_mailbox.mailboxes m set
                next_seq = m.next_seq + v_writes,
                bytes_used = m.bytes_used + v_dbytes,
                records_count = m.records_count + v_drecords,
                last_write_at = now()
            where m.id = p_mailbox
            returning m.bytes_used, m.records_count into v_bytes, v_records;

            if (v_dbytes > 0 and v_bytes > v_max_bytes) or (v_drecords > 0 and v_records > v_max_records) then
                raise exception using errcode = 'OP422', message = 'quota';
            end if;
        exception when sqlstate 'OP422' then
            v_err := 'quota';
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

revoke all on function onepass_mailbox.api_commit(bytea, bytea, timestamptz, bytea, smallint[], bytea[], bigint[],
    smallint[], bigint[], bytea[], bytea[], integer[]) from public, anon, authenticated, service_role;
grant execute on function onepass_mailbox.api_commit(bytea, bytea, timestamptz, bytea, smallint[], bytea[], bigint[],
    smallint[], bigint[], bytea[], bytea[], integer[]) to onepass_mailbox_api;
