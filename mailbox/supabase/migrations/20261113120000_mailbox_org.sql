-- OnePass mailbox: plan `org` and write-once org records (OnePass Business).
--
-- An organisation's mailbox holds its lineage (kind 29) and roster (kind 30)
-- records. They are write-once: a record of those kinds, once written, is
-- never replaced, changed or deleted by a client, so a hostile or buggy
-- writer cannot rewrite the organisation's history. Kinds 31 and 32 stay
-- ordinary mutable records.
--
--   plan org            max_bytes 17179869184, max_records 200000,
--                       max_credentials 4096, req_per_min 600,
--                       max_commit_ops 20000, no children. The mailbox is
--                       created only through an invite of plan org
--                       (api_create_mailbox is unchanged); never set
--                       open_signup_plan to org.
--   api_commit          a put on an existing key (live or tombstone, any
--                       expected seq) of kind 29 or 30 is a conflict that
--                       carries the current row; a delete of kind 29 or 30,
--                       present or not, is the in-band `forbidden`, checked
--                       before the mailbox lock like the put_kinds rule.
--                       Everything else is the api_commit of 20261031233000.
--   records trigger     records_org_immutable raises OP403 on UPDATE or
--                       DELETE of a kind 29 or 30 row outside maintenance,
--                       so only the purge of a deleted mailbox removes them.
--
-- Replaced (same signature and grants): api_commit. New, owner only:
-- _immutable_kind, _records_org_immutable.

-- ----------------------------------------------------------------- order

do $$
begin
    if to_regclass('onepass_mailbox.drops') is null
       or not exists (select 1 from information_schema.columns
                      where table_schema = 'onepass_mailbox' and table_name = 'plans'
                        and column_name = 'max_children_shared') then
        raise exception 'apply 20261101120000_mailbox_drops.sql and 20261031235000_mailbox_children.sql before 20261113120000_mailbox_org.sql';
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
    values ('org', 17179869184, 200000, 4096, 600, 20000, 0, 0)
    on conflict (plan) do nothing;
    perform set_config('onepass.maintenance', '', true);
end
$$;

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- helpers

-- The kinds that are written once.
create function onepass_mailbox._immutable_kind(p_kind smallint)
returns boolean
language sql
immutable
set search_path = ''
as $$
    select p_kind in (29, 30);
$$;

-- ------------------------------------------------------------- api_commit

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

    -- Org lineage and roster records (kinds 29 and 30) are never deleted,
    -- whoever asks and whether or not the key exists. No recheck under the
    -- lock: the kinds of a batch cannot change while it waits.
    if v_err is null and exists (select 1 from unnest(p_kinds, p_ops) as o (k, op)
                                 where o.op = 2 and onepass_mailbox._immutable_kind(o.k)) then
        v_err := 'forbidden';
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
        -- The caller again, under the lock: a demotion committed while this
        -- batch waited applies.
        select l.o_role, l.o_put_kinds into v_role, v_put_kinds
        from onepass_mailbox._locked_caller(p_credential, p_mailbox) l;
        if v_role = 1 then
            v_err := 'forbidden';
        elsif v_put_kinds is not null and exists (
                select 1 from unnest(p_kinds, p_ops) as o (k, op)
                where o.op = 2 or get_bit(v_put_kinds, o.k) = 0) then
            v_err := 'forbidden';
        elsif v_n > v_max_ops then
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
                   o.op = 1 and case when onepass_mailbox._immutable_kind(o.k) then r.seq is not null
                                     when o.e is null then coalesce(not r.deleted, false)
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
              and case when onepass_mailbox._immutable_kind(o.k) then r.seq is not null
                       when o.e is null then coalesce(not r.deleted, false)
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

-- --------------------------------------------------------------- trigger

create function onepass_mailbox._records_org_immutable()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    if not onepass_mailbox.in_maintenance() then
        raise exception using errcode = 'OP403', message = 'forbidden';
    end if;
    return case when tg_op = 'DELETE' then old else new end;
end
$$;

create trigger records_org_immutable
    before update or delete on onepass_mailbox.records
    for each row when (old.kind in (29, 30))
    execute function onepass_mailbox._records_org_immutable();

reset role;

-- ------------------------------------------------------------- grants

revoke all on function
    onepass_mailbox._immutable_kind(smallint),
    onepass_mailbox._records_org_immutable()
from public, anon, authenticated, service_role;

revoke all on function
    onepass_mailbox.api_commit(bytea, bytea, timestamptz, bytea, smallint[], bytea[], bigint[], smallint[], bigint[], bytea[], bytea[], integer[])
from public, anon, authenticated, service_role;
grant execute on function
    onepass_mailbox.api_commit(bytea, bytea, timestamptz, bytea, smallint[], bytea[], bigint[], smallint[], bigint[], bytea[], bytea[], integer[])
to onepass_mailbox_api;
