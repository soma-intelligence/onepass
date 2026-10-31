-- OnePass mailbox: authenticated SQL entry points and reads (spec 4.5, 4.6,
-- 4.9, 4.12).
--
-- The edge function (Task 7) parses and verifies the signed request, then
-- calls exactly one of these functions in one transaction, as
-- onepass_mailbox_api. Each runs as onepass_mailbox_owner (SECURITY DEFINER,
-- empty search_path) and is bound by the forced row level security of the
-- schema migration.
--
-- Contract with the edge function (Task 7):
--
-- 1. Raised errors are refusals before anything is recorded: the request is
--    not authenticated (malformed shape, stale_request, unknown_credential,
--    revoked_credential, frozen, replay on a signed route; a malformed IP key
--    on create or enroll). SQLSTATE 'OP' || <HTTP status>, message = the
--    ErrorCode name in snake case. The transaction is rolled back. Any other
--    SQLSTATE is a bug: the edge answers 503 retry.
-- 2. Every other outcome is returned in band and the edge COMMITS the
--    transaction, so what the request consumed sticks: the nonce, the
--    per-credential rate hit and last_used_at on a signed route; the per-IP
--    hit on create and enroll. Every entry point returns rows whose first
--    two columns are `status text, retry_after integer`: status 'ok' with the
--    data columns, or one row with an ErrorCode name (`not_found`,
--    `rate_limited`, `cursor_expired`, `quota`, `malformed`, ...) and NULL
--    data columns; retry_after is set only for rate_limited (seconds). The
--    HTTP status of an in-band code is the one of spec 4.6.
-- 3. A refused write leaves no trace but the consumed counters: work that
--    can still fail after its first write runs in a subtransaction that is
--    rolled back before the in-band error is returned.
--
-- Request context. The onepass.* settings are USERSET: the api role could
-- SET them before calling in. Every entry point therefore starts by
-- overwriting all of them (transaction local), and sets onepass.mailbox to
-- the mailbox of the request path before its first table access: a preset
-- value never widens what a call can see. Rate windows are cut in UTC, never
-- in the session TimeZone (also USERSET).

set role onepass_mailbox_owner;

-- ------------------------------------------------------------- schema

-- A credential is unique within its mailbox (implied by the global key, kept
-- explicit), and the composite key lets the tables that pair a credential
-- with a mailbox refuse a cross-mailbox pair.
alter table onepass_mailbox.credentials
    add constraint credentials_mailbox_id_unique unique (mailbox_id, id);
alter table onepass_mailbox.nonces
    add constraint nonces_credential_in_mailbox_fk
    foreign key (mailbox_id, credential_id) references onepass_mailbox.credentials (mailbox_id, id);
alter table onepass_mailbox.credentials
    add constraint credentials_enrolled_by_in_mailbox_fk
    foreign key (mailbox_id, enrolled_by) references onepass_mailbox.credentials (mailbox_id, id);
-- The unique index above starts with mailbox_id: the plain index is redundant.
drop index onepass_mailbox.credentials_mailbox_idx;

-- Ed25519 public keys that must never be enrolled: the eight encodings of
-- the small-order points (order 1, 2, 4 and 8), the two "negative zero"
-- encodings (x = 0 with the sign bit set, refused by RFC 8032 decoding), and
-- every non-canonical encoding (y >= p = 2^255 - 19, 38 values, some of them
-- small-order aliases). With a small-order key and cofactorless
-- verification, anyone forges a signature for that credential with
-- probability 1/8. Points off the curve cannot be found without curve
-- arithmetic: the edge function refuses them when it imports the key
-- (Task 7, WebCrypto Ed25519), before any of these functions runs.
create function onepass_mailbox._ed25519_key_refused(k bytea)
returns boolean
language sql
immutable
parallel safe
set search_path = ''
as $$
    select length(k) = 32 and (
        k = any (array[
            '\x0100000000000000000000000000000000000000000000000000000000000000',
            '\xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
            '\x0000000000000000000000000000000000000000000000000000000000000000',
            '\x0000000000000000000000000000000000000000000000000000000000000080',
            '\x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
            '\x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
            '\xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            '\xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
            '\x0100000000000000000000000000000000000000000000000000000000000080',
            '\xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        ]::bytea[])
        -- y >= p: low byte >= 0xed, bytes 1..30 all 0xff, top byte 0x7f or 0xff.
        or (get_byte(k, 0) >= 237
            and substring(k from 2 for 30) = '\xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'::bytea
            and (get_byte(k, 31) & 127) = 127)
    );
$$;

alter table onepass_mailbox.credentials
    add constraint credentials_key_not_refused check (not onepass_mailbox._ed25519_key_refused(public_key));


-- ------------------------------------------------------------ helpers
-- Private: run as the owner from inside the entry points, never granted.

-- Raises a refusal (contract 1).
create function onepass_mailbox._fail(p_code text)
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

-- Overwrites every request setting for the rest of the transaction, then
-- scopes the policies to p_mailbox (NULL leaves no mailbox in scope).
create function onepass_mailbox._enter(p_mailbox bytea)
returns void
language plpgsql
set search_path = ''
as $$
begin
    perform set_config('onepass.mailbox', coalesce(encode(p_mailbox, 'hex'), ''), true);
    perform set_config('onepass.rdv', '', true);
    perform set_config('onepass.invite', '', true);
    perform set_config('onepass.maintenance', '', true);
end
$$;

-- Clock skew of spec 4.7: 300 s either way. NULL is malformed.
create function onepass_mailbox._skew_error(p_created timestamptz)
returns text
language sql
stable
set search_path = ''
as $$
    select case
        when p_created is null then 'malformed'
        when abs(extract(epoch from (now() - p_created))) > 300 then 'stale_request'
    end;
$$;

-- One more hit on a fixed UTC window. Returns NULL within p_limit, else the
-- seconds left in the window (retry_after). The hit is recorded either way:
-- the caller returns rate_limited in band and the transaction commits.
create function onepass_mailbox._hit(p_key bytea, p_window interval, p_limit integer)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_start timestamptz;
    v_count integer;
begin
    v_start := case p_window
        when interval '1 minute' then date_trunc('minute', now(), 'UTC')
        when interval '1 day' then date_trunc('day', now(), 'UTC')
    end;
    if v_start is null then
        raise exception 'unsupported rate window %', p_window;
    end if;
    insert into onepass_mailbox.rate as r (key, window_start, count)
    values (p_key, v_start, 1)
    on conflict (key, window_start) do update set count = r.count + 1
    returning r.count into v_count;
    if v_count > p_limit then
        return greatest(1, ceil(extract(epoch from (v_start + p_window - now()))))::integer;
    end if;
    return null;
end
$$;

-- The authentication every signed route shares, after the edge function
-- has checked the signature. Refusals raise (contract 1): shapes, skew,
-- credential enrolled in the path mailbox and not revoked, mailbox not
-- frozen, nonce never seen. Then the request is recorded: nonce, rate hit,
-- last_used_at (at most once a minute, to spare a row version per request).
-- Returns NULL, or retry_after when the credential is over its rate: the
-- caller then returns rate_limited in band. The context is reset first and
-- scoped to p_mailbox before the first table access.
create function onepass_mailbox._authenticate(p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_revoked timestamptz;
    v_last timestamptz;
    v_frozen boolean;
    v_rate integer;
    v_retry integer;
    v_err text;
begin
    perform onepass_mailbox._enter(null);
    if p_credential is null or length(p_credential) <> 16
       or p_nonce is null or length(p_nonce) <> 16
       or p_mailbox is null or length(p_mailbox) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_err := onepass_mailbox._skew_error(p_created);
    if v_err is not null then
        perform onepass_mailbox._fail(v_err);
    end if;
    perform onepass_mailbox._enter(p_mailbox);

    select c.revoked_at, c.last_used_at into v_revoked, v_last
    from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_revoked is not null then
        perform onepass_mailbox._fail('revoked_credential');
    end if;

    select m.frozen, p.req_per_min into v_frozen, v_rate
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;

    begin
        insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
        values (p_credential, p_mailbox, p_nonce);
    exception when unique_violation then
        perform onepass_mailbox._fail('replay');
    end;

    -- Credential rate key: the 16 byte id zero-padded to 32 (an IP key is a
    -- 32 byte HMAC; a collision is negligible).
    v_retry := onepass_mailbox._hit(p_credential || '\x00000000000000000000000000000000'::bytea, interval '1 minute', v_rate);

    if v_last < now() - interval '1 minute' then
        update onepass_mailbox.credentials set last_used_at = now()
        where id = p_credential and mailbox_id = p_mailbox;
    end if;
    return v_retry;
end
$$;

-- --------------------------------------------------------- entry points

-- Public key of a credential, looked up only inside the mailbox of the
-- request path (no global key oracle). Read only, called before the
-- signature is checked: status 'ok' with the key, or 'unknown_credential'.
create function onepass_mailbox.credential_key(p_mailbox bytea, p_credential bytea)
returns table (status text, retry_after integer, mailbox_id bytea, public_key bytea, revoked boolean)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    perform onepass_mailbox._enter(null);
    if p_mailbox is null or length(p_mailbox) <> 16 or p_credential is null or length(p_credential) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    perform onepass_mailbox._enter(p_mailbox);
    return query
    select 'ok'::text, null::integer, c.mailbox_id, c.public_key, c.revoked_at is not null
    from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
    if not found then
        return query select 'unknown_credential'::text, null::integer, null::bytea, null::bytea, null::boolean;
    end if;
end
$$;

-- POST /v1/mailboxes. Hosted: an invite is required (p_invite is the raw
-- token; its SHA-256 is the invite key). Open signup (self-host): no
-- invite, plan selfhost. Every attempt counts on the per-IP minute bucket
-- (60, shared with enroll and the rendezvous routes); five creations a day
-- per IP key count on a second bucket, hit once the invite checks out.
create function onepass_mailbox.api_create_mailbox(
    p_public_key bytea, p_nonce bytea, p_created timestamptz, p_invite bytea,
    p_label bytea, p_ip_key bytea, p_open_signup boolean)
returns table (status text, retry_after integer, mailbox_id bytea, incarnation bigint, wake_topic bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
    v_err text;
    v_plan text;
    v_hash bytea;
    v_uses integer;
    v_expires timestamptz;
    v_id bytea;
    v_cid bytea;
    v_incarnation bigint;
    v_wake bytea;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_retry := onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    if p_public_key is null or length(p_public_key) <> 32
       or p_nonce is null or length(p_nonce) <> 16
       or p_open_signup is null
       or (p_label is not null and octet_length(p_label) > 64)
       or (not p_open_signup and (p_invite is null or octet_length(p_invite) not between 1 and 256))
       or onepass_mailbox._ed25519_key_refused(p_public_key) then
        v_err := 'malformed';
    else
        v_err := onepass_mailbox._skew_error(p_created);
    end if;
    if v_err is not null then
        return query select v_err, null::integer, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    if p_open_signup then
        v_plan := 'selfhost';
    else
        v_hash := extensions.digest(p_invite, 'sha256');
        perform set_config('onepass.invite', encode(v_hash, 'hex'), true);
        select i.plan, i.uses_left, i.expires_at into v_plan, v_uses, v_expires
        from onepass_mailbox.invites i where i.token_hash = v_hash
        for update;
        if not found or v_uses <= 0 or v_expires < now() then
            return query select 'not_found'::text, null::integer, null::bytea, null::bigint, null::bytea;
            return;
        end if;
    end if;

    -- Day bucket on a hash of the IP key: the raw key is the minute bucket,
    -- and a day window would share its row with the minute at midnight.
    v_retry := onepass_mailbox._hit(extensions.digest(p_ip_key, 'sha256'), interval '1 day', 5);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bytea, null::bigint, null::bytea;
        return;
    end if;

    v_id := extensions.gen_random_bytes(16);
    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_public_key, 'sha256') from 1 for 16);
    begin
        if not p_open_signup then
            update onepass_mailbox.invites set uses_left = uses_left - 1 where token_hash = v_hash;
        end if;
        perform onepass_mailbox._enter(v_id);
        insert into onepass_mailbox.mailboxes (id, plan) values (v_id, v_plan)
        returning mailboxes.incarnation, mailboxes.wake_topic into v_incarnation, v_wake;
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
        values (v_cid, v_id, p_public_key, coalesce(p_label, '\x'::bytea));
        insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce) values (v_cid, v_id, p_nonce);
    exception when unique_violation then
        -- The key is enrolled in some mailbox. Only the key's owner (who
        -- signed this request) learns it, and only that much. The block is
        -- rolled back: no mailbox, the invite use is kept.
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

-- GET /v1/mailboxes/{m}.
create function onepass_mailbox.api_mailbox_info(p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns table (
    status text, retry_after integer,
    incarnation bigint, wake_topic bytea, min_cursor bigint,
    max_bytes bigint, max_records integer, max_credentials integer, req_per_min integer, max_commit_ops integer,
    bytes_used bigint, records_count integer, credentials_count integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry, null::bigint, null::bytea, null::bigint,
            null::bigint, null::integer, null::integer, null::integer, null::integer,
            null::bigint, null::integer, null::integer;
        return;
    end if;
    return query
    select 'ok'::text, null::integer, m.incarnation, m.wake_topic, m.min_cursor,
           p.max_bytes, p.max_records, p.max_credentials, p.req_per_min, p.max_commit_ops,
           m.bytes_used, m.records_count,
           (select count(*)::integer from onepass_mailbox.credentials c
            where c.mailbox_id = m.id and c.revoked_at is null)
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox;
end
$$;

-- GET /v1/mailboxes/{m}/changes?after=&limit=&full=. Always at least one
-- row: with status 'ok', a row with seq NULL carries only incarnation,
-- min_cursor and head (empty page). Every row carries head, the mailbox's
-- last written seq (next_seq - 1).
--
-- Full fetch (p_full): live rows with seq > p_after, tombstones skipped,
-- min_cursor ignored, so a tombstone purge between two pages never breaks
-- it. The client keeps p_full on every page, keeps the head of its FIRST
-- page, and after finish_full_fetch goes on incrementally from that head:
-- changes made during the fetch (rows moved past the client, tombstones)
-- all have a seq above it, and min_cursor never passes it (the purge only
-- takes 90 day old tombstones).
--
-- Incremental (not p_full): every row with seq > p_after, tombstones
-- included; p_after < min_cursor means tombstones the client missed are
-- purged: cursor_expired, the client starts a full fetch.
--
-- A page holds 1 000 rows and 4 MiB of inline data at most (a blob row
-- counts 0: its body is fetched from Storage).
create function onepass_mailbox.api_changes(
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
            where r.mailbox_id = p_mailbox and r.seq > p_after and not (p_full and r.deleted)
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

-- GET /v1/mailboxes/{m}/records/{kind}/{id}. A tombstone is returned as such.
create function onepass_mailbox.api_record(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_kind smallint, p_id bytea)
returns table (
    status text, retry_after integer,
    seq bigint, version bigint, deleted boolean, data bytea, blob_sha256 bytea, size integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry,
            null::bigint, null::bigint, null::boolean, null::bytea, null::bytea, null::integer;
        return;
    end if;
    if p_kind is null or p_kind not between 1 and 255 or p_id is null or length(p_id) <> 16 then
        return query select 'malformed'::text, null::integer,
            null::bigint, null::bigint, null::boolean, null::bytea, null::bytea, null::integer;
        return;
    end if;
    return query
    select 'ok'::text, null::integer, r.seq, r.version, r.deleted, r.data, r.blob_sha256, r.size
    from onepass_mailbox.records r
    where r.mailbox_id = p_mailbox and r.kind = p_kind and r.id = p_id;
    if not found then
        return query select 'not_found'::text, null::integer,
            null::bigint, null::bigint, null::boolean, null::bytea, null::bytea, null::integer;
    end if;
end
$$;

-- POST /v1/mailboxes/{m}/credentials (spec 4.12). The edge function has
-- verified the request signature against p_new_public_key and the ticket
-- signature against the approver's key (read with credential_key), and
-- checked that the ticket names this mailbox and this key. Every attempt
-- counts on the per-IP minute bucket. Then, in band: shapes, skew, weak key,
-- ticket not living more than 600 s plus the 300 s skew, mailbox
-- (not_found, frozen), approver active in it, ticket not expired, same key
-- already in (replay), active credentials under the plan's limit (quota),
-- ticket never used (replay). The writes (used ticket, credential, nonce
-- under the new credential) are all or nothing.
create function onepass_mailbox.api_enroll(
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
        select c.revoked_at into v_revoked
        from onepass_mailbox.credentials c
        where c.id = p_approver and c.mailbox_id = p_mailbox;
        if not found then
            v_err := 'unknown_credential';
        elsif v_revoked is not null then
            v_err := 'revoked_credential';
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

-- DELETE /v1/mailboxes/{m}/credentials/{c}. The target must be in the same
-- mailbox; revoking a revoked credential changes nothing. The push token is
-- dropped with it.
create function onepass_mailbox.api_revoke_credential(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_target bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
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
    update onepass_mailbox.credentials
    set revoked_at = coalesce(revoked_at, now()), push_kind = null, push_token = null
    where id = p_target and mailbox_id = p_mailbox;
    if not found then
        return query select 'not_found'::text, null::integer;
        return;
    end if;
    return query select 'ok'::text, null::integer;
end
$$;

-- PUT /v1/mailboxes/{m}/push. p_kind is the wire PushKind index: 0 None
-- (clears; the token must be empty), 1 Fcm, 2 Apns, 3 UnifiedPush (a
-- token of 1 to 4096 bytes is required).
create function onepass_mailbox.api_set_push(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_kind smallint, p_token bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    v_retry := onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    if p_kind is null or p_kind not between 0 and 3
       or (p_kind = 0 and coalesce(octet_length(p_token), 0) <> 0)
       or (p_kind <> 0 and (p_token is null or octet_length(p_token) not between 1 and 4096)) then
        return query select 'malformed'::text, null::integer;
        return;
    end if;
    update onepass_mailbox.credentials
    set push_kind = nullif(p_kind, 0), push_token = case when p_kind = 0 then null else p_token end
    where id = p_credential and mailbox_id = p_mailbox;
    return query select 'ok'::text, null::integer;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.credential_key(bytea, bytea),
    onepass_mailbox.api_create_mailbox(bytea, bytea, timestamptz, bytea, bytea, bytea, boolean),
    onepass_mailbox.api_mailbox_info(bytea, bytea, timestamptz, bytea),
    onepass_mailbox.api_changes(bytea, bytea, timestamptz, bytea, bigint, integer, boolean),
    onepass_mailbox.api_record(bytea, bytea, timestamptz, bytea, smallint, bytea),
    onepass_mailbox.api_enroll(bytea, bytea, timestamptz, bytea, bytea, bytea, timestamptz, bytea, bytea),
    onepass_mailbox.api_revoke_credential(bytea, bytea, timestamptz, bytea, bytea),
    onepass_mailbox.api_set_push(bytea, bytea, timestamptz, bytea, smallint, bytea)
to onepass_mailbox_api;
