-- OnePass mailbox: change pages bounded by their head, and time limits for
-- the api role (Task 7 review). Follows the contract in the header of
-- 20261031120100.
--
-- api_changes reads head (next_seq - 1) in one statement and the rows in
-- another. Under READ COMMITTED the second one takes a new snapshot, so a
-- batch that commits in between showed rows above the head the page
-- carried, and the proto refuses such a page (the edge answered 503 after
-- the nonce was spent). Rows are now bounded by the head read for the page:
-- what a concurrent batch wrote comes on the next page, and `more` (last
-- seq below head) stays honest. Same signature, same grants.
--
-- The api role gets a statement and a lock timeout: a request waiting on a
-- lock (a commit behind another commit or the collector) or a runaway
-- statement gives up (SQLSTATE 57014 or 55P03, answered 503 retry) instead
-- of holding an isolate and a pooler connection. 30 s covers a 20 000
-- operation batch on a large mailbox; locks are held for one batch at most.

set role onepass_mailbox_owner;

create or replace function onepass_mailbox.api_changes(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_after bigint, p_limit integer, p_full boolean)
returns table (
    status text, retry_after integer,
    incarnation bigint, min_cursor bigint, head bigint,
    seq bigint, kind smallint, id bytea, version bigint,
    deleted boolean, data bytea, blob_sha256 bytea, size integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_incarnation bigint;
    v_min bigint;
    v_head bigint;
    v_limit integer;
    v_err text;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        v_err := 'rate_limited';
    elsif p_after is null or p_after < 0 or p_limit is null or p_limit < 1 or p_full is null then
        v_err := 'malformed';
    end if;
    if v_err is null then
        select m.incarnation, m.min_cursor, m.next_seq - 1 into v_incarnation, v_min, v_head
        from onepass_mailbox.mailboxes m where m.id = p_mailbox;
        if not p_full and p_after < v_min then
            v_err := 'cursor_expired';
        end if;
    end if;
    if v_err is not null then
        return query select v_err, v_retry, null::bigint, null::bigint, null::bigint,
            null::bigint, null::smallint, null::bytea, null::bigint,
            null::boolean, null::bytea, null::bytea, null::integer;
        return;
    end if;
    v_limit := least(p_limit, 1000);

    return query
    select 'ok'::text, null::integer, v_incarnation, v_min, v_head,
           w.seq, w.kind, w.id, w.version, w.deleted, w.data, w.blob_sha256, w.size
    from (
        select r.*, sum(coalesce(octet_length(r.data), 0)) over (order by r.seq) as acc
        from (
            select r.seq, r.kind, r.id, r.version, r.deleted, r.data, r.blob_sha256, r.size
            from onepass_mailbox.records r
            where r.mailbox_id = p_mailbox and r.seq > p_after and r.seq <= v_head
              and not (p_full and r.deleted)
            order by r.seq
            limit v_limit
        ) r
    ) w
    where w.acc <= 4194304
    order by w.seq;
    if not found then
        return query select 'ok'::text, null::integer, v_incarnation, v_min, v_head,
            null::bigint, null::smallint, null::bytea, null::bigint,
            null::boolean, null::bytea, null::bytea, null::integer;
    end if;
end
$$;

reset role;

alter role onepass_mailbox_api set statement_timeout = '30s';
alter role onepass_mailbox_api set lock_timeout = '10s';
