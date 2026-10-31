-- OnePass mailbox: authenticated SQL entry points and reads (spec 4.5, 4.6,
-- 4.9, 4.12).
--
-- The edge function (Task 7) parses and verifies the signed request, then
-- calls exactly one of these functions in one transaction, as
-- onepass_mailbox_api. Each runs as onepass_mailbox_owner (SECURITY DEFINER,
-- empty search_path) and is bound by the forced row level security of the
-- schema migration.
--
-- Errors: SQLSTATE 'OP' || <HTTP status> and the message set to the
-- ErrorCode name in snake case (`replay`, `quota`, ...), so the edge
-- function maps them without reading free text. rate_limited carries its
-- retry_after, in seconds, as the DETAIL. Any other SQLSTATE is a bug: the
-- edge function answers 503 retry.
--
-- Request context. The onepass.* settings are USERSET: the api role could
-- SET them before calling in. Every entry point therefore starts by
-- overwriting all of them (transaction local), and sets onepass.mailbox to
-- the mailbox of the request path before its first table access: a preset
-- value never widens what a call can see.

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

create function onepass_mailbox._fail(p_code text, p_retry_after integer default null)
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
    if p_retry_after is null then
        raise exception using errcode = v_state, message = p_code;
    end if;
    raise exception using errcode = v_state, message = p_code, detail = p_retry_after::text;
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

-- Clock skew of spec 4.7: 300 s either way.
create function onepass_mailbox._check_created(p_created timestamptz)
returns void
language plpgsql
set search_path = ''
as $$
begin
    if p_created is null then
        perform onepass_mailbox._fail('malformed');
    end if;
    if abs(extract(epoch from (now() - p_created))) > 300 then
        perform onepass_mailbox._fail('stale_request');
    end if;
end
$$;

-- One more hit on a fixed window; over p_limit raises rate_limited with the
-- seconds left in the window. The raise rolls the hit back, so a refused
-- request does not push the window further.
create function onepass_mailbox._hit(p_key bytea, p_window interval, p_limit integer)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_start timestamptz;
    v_count integer;
begin
    v_start := case p_window
        when interval '1 minute' then date_trunc('minute', now())
        when interval '1 day' then date_trunc('day', now())
    end;
    if v_start is null then
        raise exception 'unsupported rate window %', p_window;
    end if;
    insert into onepass_mailbox.rate as r (key, window_start, count)
    values (p_key, v_start, 1)
    on conflict (key, window_start) do update set count = r.count + 1
    returning r.count into v_count;
    if v_count > p_limit then
        perform onepass_mailbox._fail('rate_limited',
            greatest(1, ceil(extract(epoch from (v_start + p_window - now()))))::integer);
    end if;
end
$$;

-- Stores a nonce under its credential; a nonce already seen is a replay.
create function onepass_mailbox._spend_nonce(p_credential bytea, p_mailbox bytea, p_nonce bytea)
returns void
language plpgsql
set search_path = ''
as $$
begin
    insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
    values (p_credential, p_mailbox, p_nonce);
exception when unique_violation then
    perform onepass_mailbox._fail('replay');
end
$$;

-- The authentication every signed route shares, after the edge function
-- has checked the signature: skew, credential enrolled in the path mailbox
-- and not revoked, mailbox not frozen, nonce, rate, last use. The context
-- is reset first and scoped to p_mailbox before the first table access.
create function onepass_mailbox._authenticate(p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_revoked timestamptz;
    v_frozen boolean;
    v_rate integer;
begin
    perform onepass_mailbox._enter(null);
    if p_credential is null or length(p_credential) <> 16
       or p_nonce is null or length(p_nonce) <> 16
       or p_mailbox is null or length(p_mailbox) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    perform onepass_mailbox._check_created(p_created);
    perform onepass_mailbox._enter(p_mailbox);

    select c.revoked_at into v_revoked
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

    perform onepass_mailbox._spend_nonce(p_credential, p_mailbox, p_nonce);
    -- Credential rate key: the 16 byte id zero-padded to 32 (an IP key is a
    -- 32 byte HMAC; a collision is negligible).
    perform onepass_mailbox._hit(p_credential || '\x00000000000000000000000000000000'::bytea, interval '1 minute', v_rate);

    update onepass_mailbox.credentials set last_used_at = now()
    where id = p_credential and mailbox_id = p_mailbox;
end
$$;

-- --------------------------------------------------------- entry points

-- Public key of a credential, looked up only inside the mailbox of the
-- request path (no global key oracle). Zero rows: unknown credential.
create function onepass_mailbox.credential_key(p_mailbox bytea, p_credential bytea)
returns table (mailbox_id bytea, public_key bytea, revoked boolean)
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
    select c.mailbox_id, c.public_key, c.revoked_at is not null
    from onepass_mailbox.credentials c
    where c.id = p_credential and c.mailbox_id = p_mailbox;
end
$$;

-- POST /v1/mailboxes. Hosted: an invite is required (p_invite is the raw
-- token; its SHA-256 is the invite key), five creations a day per IP key.
-- Open signup (self-host): no invite, plan selfhost.
create function onepass_mailbox.api_create_mailbox(
    p_public_key bytea, p_nonce bytea, p_created timestamptz, p_invite bytea,
    p_label bytea, p_ip_key bytea, p_open_signup boolean)
returns table (mailbox_id bytea, incarnation bigint, wake_topic bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
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
    if p_public_key is null or length(p_public_key) <> 32
       or p_nonce is null or length(p_nonce) <> 16
       or p_ip_key is null or length(p_ip_key) <> 32
       or p_open_signup is null
       or (p_label is not null and octet_length(p_label) > 64)
       or (not p_open_signup and (p_invite is null or octet_length(p_invite) not between 1 and 256)) then
        perform onepass_mailbox._fail('malformed');
    end if;
    perform onepass_mailbox._check_created(p_created);
    if onepass_mailbox._ed25519_key_refused(p_public_key) then
        perform onepass_mailbox._fail('malformed');
    end if;

    -- Day bucket on a hash of the IP key: the raw key is the per-minute
    -- bucket of the credential-less routes, and a day window would share
    -- its row with the minute starting at midnight.
    perform onepass_mailbox._hit(extensions.digest(p_ip_key, 'sha256'), interval '1 day', 5);

    if p_open_signup then
        v_plan := 'selfhost';
    else
        v_hash := extensions.digest(p_invite, 'sha256');
        perform set_config('onepass.invite', encode(v_hash, 'hex'), true);
        select i.plan, i.uses_left, i.expires_at into v_plan, v_uses, v_expires
        from onepass_mailbox.invites i where i.token_hash = v_hash
        for update;
        if not found or v_uses <= 0 or v_expires < now() then
            perform onepass_mailbox._fail('not_found');
        end if;
        update onepass_mailbox.invites set uses_left = uses_left - 1 where token_hash = v_hash;
        perform set_config('onepass.invite', '', true);
    end if;

    v_id := extensions.gen_random_bytes(16);
    perform onepass_mailbox._enter(v_id);
    insert into onepass_mailbox.mailboxes (id, plan) values (v_id, v_plan)
    returning mailboxes.incarnation, mailboxes.wake_topic into v_incarnation, v_wake;

    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_public_key, 'sha256') from 1 for 16);
    begin
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
        values (v_cid, v_id, p_public_key, coalesce(p_label, '\x'::bytea));
    exception when unique_violation then
        -- Enrolled in some other mailbox. Only the key's owner (who signed
        -- this request) learns it, and only that much.
        perform onepass_mailbox._fail('malformed');
    end;
    perform onepass_mailbox._spend_nonce(v_cid, v_id, p_nonce);

    return query select v_id, v_incarnation, v_wake;
end
$$;

-- GET /v1/mailboxes/{m}.
create function onepass_mailbox.api_mailbox_info(p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea)
returns table (
    incarnation bigint, wake_topic bytea, min_cursor bigint,
    max_bytes bigint, max_records integer, max_credentials integer, req_per_min integer, max_commit_ops integer,
    bytes_used bigint, records_count integer, credentials_count integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    perform onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    return query
    select m.incarnation, m.wake_topic, m.min_cursor,
           p.max_bytes, p.max_records, p.max_credentials, p.req_per_min, p.max_commit_ops,
           m.bytes_used, m.records_count,
           (select count(*)::integer from onepass_mailbox.credentials c
            where c.mailbox_id = m.id and c.revoked_at is null)
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox;
end
$$;

-- GET /v1/mailboxes/{m}/changes?after=&limit=. Always at least one row: a
-- row with seq NULL carries only incarnation and min_cursor (empty page).
-- after = 0 is a full fetch: live rows only. 0 < after < min_cursor: the
-- tombstones the client missed are purged, cursor_expired. A page holds
-- 1 000 rows and 4 MiB of inline data at most (a blob row counts 0: the
-- body is fetched from Storage).
create function onepass_mailbox.api_changes(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_after bigint, p_limit integer)
returns table (
    incarnation bigint, min_cursor bigint, seq bigint, kind smallint, id bytea, version bigint,
    deleted boolean, data bytea, blob_sha256 bytea, size integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_incarnation bigint;
    v_min bigint;
    v_limit integer;
begin
    perform onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if p_after is null or p_after < 0 or p_limit is null or p_limit < 1 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_limit := least(p_limit, 1000);

    select m.incarnation, m.min_cursor into v_incarnation, v_min
    from onepass_mailbox.mailboxes m where m.id = p_mailbox;
    if p_after > 0 and p_after < v_min then
        perform onepass_mailbox._fail('cursor_expired');
    end if;

    return query
    select v_incarnation, v_min, w.seq, w.kind, w.id, w.version, w.deleted, w.data, w.blob_sha256, w.size
    from (
        select r.*, sum(coalesce(octet_length(r.data), 0)) over (order by r.seq) as acc
        from (
            select r.seq, r.kind, r.id, r.version, r.deleted, r.data, r.blob_sha256, r.size
            from onepass_mailbox.records r
            where r.mailbox_id = p_mailbox and r.seq > p_after and (p_after > 0 or not r.deleted)
            order by r.seq
            limit v_limit
        ) r
    ) w
    where w.acc <= 4194304
    order by w.seq;
    if not found then
        return query select v_incarnation, v_min, null::bigint, null::smallint, null::bytea, null::bigint,
                            null::boolean, null::bytea, null::bytea, null::integer;
    end if;
end
$$;

-- GET /v1/mailboxes/{m}/records/{kind}/{id}. A tombstone is returned as such.
create function onepass_mailbox.api_record(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_kind smallint, p_id bytea)
returns table (seq bigint, version bigint, deleted boolean, data bytea, blob_sha256 bytea, size integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    perform onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if p_kind is null or p_kind not between 1 and 255 or p_id is null or length(p_id) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    return query
    select r.seq, r.version, r.deleted, r.data, r.blob_sha256, r.size
    from onepass_mailbox.records r
    where r.mailbox_id = p_mailbox and r.kind = p_kind and r.id = p_id;
    if not found then
        perform onepass_mailbox._fail('not_found');
    end if;
end
$$;

-- POST /v1/mailboxes/{m}/credentials (spec 4.12). The edge function has
-- verified the request signature against p_new_public_key and the ticket
-- signature against the approver's key (read with credential_key), and
-- checked that the ticket names this mailbox and this key. Here: approver
-- active in p_mailbox, ticket not expired and not living more than 600 s
-- plus the 300 s skew, ticket never used, active credentials under the plan's
-- limit, nonce stored under the new credential.
create function onepass_mailbox.api_enroll(
    p_new_public_key bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea,
    p_approver bytea, p_ticket_hash bytea, p_ticket_expires timestamptz, p_label bytea, p_ip_key bytea)
returns table (credential_id bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_frozen boolean;
    v_max integer;
    v_revoked timestamptz;
    v_active integer;
    v_cid bytea;
begin
    perform onepass_mailbox._enter(null);
    if p_new_public_key is null or length(p_new_public_key) <> 32
       or p_nonce is null or length(p_nonce) <> 16
       or p_mailbox is null or length(p_mailbox) <> 16
       or p_approver is null or length(p_approver) <> 16
       or p_ticket_hash is null or length(p_ticket_hash) <> 32
       or p_ticket_expires is null
       or p_ip_key is null or length(p_ip_key) <> 32
       or (p_label is not null and octet_length(p_label) > 64) then
        perform onepass_mailbox._fail('malformed');
    end if;
    perform onepass_mailbox._check_created(p_created);
    if onepass_mailbox._ed25519_key_refused(p_new_public_key) then
        perform onepass_mailbox._fail('malformed');
    end if;
    if p_ticket_expires > now() + interval '900 seconds' then
        perform onepass_mailbox._fail('malformed');
    end if;
    -- The per-minute bucket of the credential-less routes (spec 4.9: 60 a
    -- minute per IP key, shared with the rendezvous routes).
    perform onepass_mailbox._hit(p_ip_key, interval '1 minute', 60);

    perform onepass_mailbox._enter(p_mailbox);
    -- Locked: concurrent enrollments count active credentials one at a time.
    select m.frozen, p.max_credentials into v_frozen, v_max
    from onepass_mailbox.mailboxes m join onepass_mailbox.plans p on p.plan = m.plan
    where m.id = p_mailbox
    for update of m;
    if not found then
        perform onepass_mailbox._fail('not_found');
    end if;
    if v_frozen then
        perform onepass_mailbox._fail('frozen');
    end if;

    select c.revoked_at into v_revoked
    from onepass_mailbox.credentials c
    where c.id = p_approver and c.mailbox_id = p_mailbox;
    if not found then
        perform onepass_mailbox._fail('unknown_credential');
    end if;
    if v_revoked is not null then
        perform onepass_mailbox._fail('revoked_credential');
    end if;

    if p_ticket_expires < now() then
        perform onepass_mailbox._fail('stale_request');
    end if;
    begin
        insert into onepass_mailbox.used_tickets (ticket_hash, mailbox_id) values (p_ticket_hash, p_mailbox);
    exception when unique_violation then
        perform onepass_mailbox._fail('replay');
    end;

    v_cid := substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || p_new_public_key, 'sha256') from 1 for 16);
    if exists (select 1 from onepass_mailbox.credentials c where c.id = v_cid and c.mailbox_id = p_mailbox) then
        -- The same key again (another signature over the same ticket, or a
        -- second ticket): at worst a no-op, refused as a replay.
        perform onepass_mailbox._fail('replay');
    end if;

    select count(*)::integer into v_active
    from onepass_mailbox.credentials c
    where c.mailbox_id = p_mailbox and c.revoked_at is null;
    if v_active >= v_max then
        perform onepass_mailbox._fail('quota');
    end if;

    begin
        insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label, enrolled_by)
        values (v_cid, p_mailbox, p_new_public_key, coalesce(p_label, '\x'::bytea), p_approver);
    exception when unique_violation then
        -- Enrolled in another mailbox; see api_create_mailbox.
        perform onepass_mailbox._fail('malformed');
    end;
    perform onepass_mailbox._spend_nonce(v_cid, p_mailbox, p_nonce);

    return query select v_cid;
end
$$;

-- DELETE /v1/mailboxes/{m}/credentials/{c}. The target must be in the same
-- mailbox; revoking a revoked credential changes nothing. The push token is
-- dropped with it.
create function onepass_mailbox.api_revoke_credential(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_target bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    perform onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if p_target is null or length(p_target) <> 16 then
        perform onepass_mailbox._fail('malformed');
    end if;
    perform 1 from onepass_mailbox.credentials c
    where c.id = p_target and c.mailbox_id = p_mailbox
    for update;
    if not found then
        perform onepass_mailbox._fail('not_found');
    end if;
    update onepass_mailbox.credentials
    set revoked_at = coalesce(revoked_at, now()), push_kind = null, push_token = null
    where id = p_target and mailbox_id = p_mailbox;
end
$$;

-- PUT /v1/mailboxes/{m}/push. p_kind is the wire PushKind index: 0 None
-- (clears; the token must be empty), 1 Fcm, 2 Apns, 3 UnifiedPush (a
-- token of 1 to 4096 bytes is required).
create function onepass_mailbox.api_set_push(
    p_credential bytea, p_nonce bytea, p_created timestamptz, p_mailbox bytea, p_kind smallint, p_token bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    perform onepass_mailbox._authenticate(p_credential, p_nonce, p_created, p_mailbox);
    if p_kind is null or p_kind not between 0 and 3 then
        perform onepass_mailbox._fail('malformed');
    end if;
    if p_kind = 0 then
        if coalesce(octet_length(p_token), 0) <> 0 then
            perform onepass_mailbox._fail('malformed');
        end if;
        update onepass_mailbox.credentials set push_kind = null, push_token = null
        where id = p_credential and mailbox_id = p_mailbox;
    else
        if p_token is null or octet_length(p_token) not between 1 and 4096 then
            perform onepass_mailbox._fail('malformed');
        end if;
        update onepass_mailbox.credentials set push_kind = p_kind, push_token = p_token
        where id = p_credential and mailbox_id = p_mailbox;
    end if;
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.credential_key(bytea, bytea),
    onepass_mailbox.api_create_mailbox(bytea, bytea, timestamptz, bytea, bytea, bytea, boolean),
    onepass_mailbox.api_mailbox_info(bytea, bytea, timestamptz, bytea),
    onepass_mailbox.api_changes(bytea, bytea, timestamptz, bytea, bigint, integer),
    onepass_mailbox.api_record(bytea, bytea, timestamptz, bytea, smallint, bytea),
    onepass_mailbox.api_enroll(bytea, bytea, timestamptz, bytea, bytea, bytea, timestamptz, bytea, bytea),
    onepass_mailbox.api_revoke_credential(bytea, bytea, timestamptz, bytea, bytea),
    onepass_mailbox.api_set_push(bytea, bytea, timestamptz, bytea, smallint, bytea)
to onepass_mailbox_api;
