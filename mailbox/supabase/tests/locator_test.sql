-- Locator lookup and abandoning a fresh mailbox (Task 23, spec D.4, D.5,
-- D.7). Starts as the harness superuser, inside a transaction the harness
-- rolls back; calls under test run as onepass_mailbox_api, state is read
-- back as the superuser. now() is fixed for the whole transaction: ageing is
-- simulated by moving created_at back or by passing a later p_now to
-- maintenance.
--
-- A locator is 16 bytes derived from the Secret Key; a manager adds it to
-- its mailbox (api_set_locator, 2 kept per mailbox), anyone looks it up
-- without a signature (locate: up to 8 live mailboxes, oldest first),
-- counted per IP key on the minute bucket and on 30 an hour. The creator
-- credential, still a manager, abandons its mailbox within 24 hours while it
-- is fresh (api_abandon_mailbox); every api_* on it is then not_found, and
-- maintenance purges it an hour later, its blob objects queued in
-- blob_graves.
--
-- Not tested here (one transaction, one session): a commit waiting on the
-- mailbox lock behind an abandon (it then raises not_found from
-- _locked_caller), and the purge skipping a mailbox locked by a request
-- (for no key update skip locked). Both need two concurrent sessions.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-locator-test-key/' || n, 'sha256') as pk
      from unnest(array['a', 'r', 'g', 'b', 'c', 'd', 'e', 'f', 'rf', 'j', 'jr', 'k', 'kr',
                                 'l', 'l1', 'l2', 'm', 'mx', 'new', 'x',
                                 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9']) as n) k;

create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
-- A 16 byte locator, a 32 byte IP key and a 32 byte blob hash from a number.
create function onepass_test.loc(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-locator-test/' || i), 'hex') $$;
create function onepass_test.ip(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-locator-ip/' || i) || md5('onepass-locator-ip//' || i), 'hex') $$;
create function onepass_test.sha(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-locator-sha/' || i) || md5('onepass-locator-sha//' || i), 'hex') $$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        onepass_test.pk(key), onepass_test.n(), now(), null, '\x',
        decode(md5('locator/' || name) || md5('locator/' || name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
create function onepass_test.grant(cred text, mbx text, key text, role integer) returns text language sql volatile as $$
    select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.pk(key),
        role::smallint, null, '\x') g
$$;
create function onepass_test.set_locator(cred text, mbx text, loc bytea) returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_set_locator(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), loc) s
$$;
create function onepass_test.locate(loc bytea, ip integer default 1)
returns table (status text, retry_after integer, mailbox_id bytea) language sql volatile as $$
    select * from onepass_mailbox.locate(loc, onepass_test.ip(ip))
$$;
-- The mailbox ids an 'ok' locate answers, in order (NULL for any other status).
create function onepass_test.located(loc bytea, ip integer default 1) returns bytea[] language sql volatile as $$
    select array_agg(l.mailbox_id order by l.n) filter (where l.status = 'ok')
    from onepass_mailbox.locate(loc, onepass_test.ip(ip)) with ordinality l(status, retry_after, mailbox_id, n)
$$;
create function onepass_test.mbxs(variadic names text[]) returns bytea[] language sql stable as $$
    select array_agg(onepass_test.mbx(n) order by i) from unnest(names) with ordinality u(n, i)
$$;
create function onepass_test.abandon(cred text, mbx text) returns text language sql volatile as $$
    select s.status from onepass_mailbox.api_abandon_mailbox(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx)) s
$$;
create function onepass_test.info(cred text, mbx text) returns text language sql volatile as $$
    select status from onepass_mailbox.api_mailbox_info(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx))
$$;
create function onepass_test.put(cred text, mbx text, i integer) returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[5]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array['\x01'::bytea], array[null]::bytea[], array[1]) c limit 1
$$;
create function onepass_test.put_blob(cred text, mbx text, i integer, sha bytea, size integer)
returns text language sql volatile as $$
    select c.status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[5]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array[null]::bytea[], array[sha], array[size]) c limit 1
$$;
create function onepass_test.announce(cred text, mbx text, sha bytea, size integer) returns text language sql volatile as $$
    select a.status from onepass_mailbox.api_blob_announce(onepass_test.cid(cred), onepass_test.n(), now(),
        onepass_test.mbx(mbx), array[sha], array[size]) a limit 1
$$;
grant execute on all functions in schema onepass_test to public;

-- Superuser side: Storage objects as the Storage API stores them, and state.
create function onepass_test.oname(mbx text, sha bytea) returns text language sql stable security definer as $$
    select encode(onepass_test.mbx(mbx), 'hex') || '/' || encode(sha, 'hex') || '.'
           || (select gen from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx(mbx) and sha256 = sha)
$$;
create function onepass_test.object(mbx text, sha bytea, size integer) returns void language sql volatile as $$
    insert into storage.objects (bucket_id, name, metadata)
    values ('onepass-mailbox', onepass_test.oname(mbx, sha),
            jsonb_build_object('size', size, 'mimetype', 'application/octet-stream'))
$$;
create function onepass_test.mb(mbx text) returns onepass_mailbox.mailboxes language sql stable as $$
    select * from onepass_mailbox.mailboxes where id = onepass_test.mbx(mbx) $$;
create function onepass_test.locs(mbx text) returns bytea[] language sql stable as $$
    select array_agg(l.locator order by l.seq) from onepass_mailbox.locators l where l.mailbox_id = onepass_test.mbx(mbx) $$;
revoke all on function onepass_test.object(text, bytea, integer), onepass_test.mb(text), onepass_test.locs(text) from public;

-- Mailboxes, each named after its creator key: A (a; r read and g manage
-- granted), B, C, D, E, F (f; rf granted manage, never used: the recovery
-- credential), J (jr granted), K (kr granted), L (l1 and l2 granted), M,
-- S1 to S9.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(upper(k), k) = 'ok')
     from unnest(array['a', 'b', 'c', 'd', 'e', 'f', 'j', 'k', 'l', 'm',
                       's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9']) k),
    'locator_fixture_mailboxes_created');
select onepass_test.ok(onepass_test.grant('a', 'A', 'r', 1) = 'ok' and onepass_test.grant('a', 'A', 'g', 3) = 'ok'
                       and onepass_test.grant('f', 'F', 'rf', 3) = 'ok'
                       and onepass_test.grant('j', 'J', 'jr', 3) = 'ok'
                       and onepass_test.grant('k', 'K', 'kr', 1) = 'ok'
                       and onepass_test.grant('l', 'L', 'l1', 3) = 'ok' and onepass_test.grant('l', 'L', 'l2', 1) = 'ok',
    'locator_fixture_credentials_granted');
reset role;

-- ------------------------------------------------------------ schema

select onepass_test.ok(
    (select bool_and(m.created_by = onepass_test.cid(k) and m.deleted_at is null)
     from (values ('A', 'a'), ('B', 'b')) v (m, k)
     join lateral (select * from onepass_test.mb(v.m)) m on true),
    'creation_records_the_creator');
select onepass_test.ok(
    (select c.relrowsecurity and c.relforcerowsecurity from pg_class c where c.oid = 'onepass_mailbox.locators'::regclass),
    'locators_force_row_level_security');
select onepass_test.throws(
    $$insert into onepass_mailbox.locators (locator, mailbox_id) values ('\x01', onepass_test.mbx('A'))$$,
    '23514', 'locator_is_16_bytes');
select onepass_test.ok(
    (select first_used_at is not null from onepass_mailbox.credentials where id = onepass_test.cid('a'))
    and (select first_used_at is null from onepass_mailbox.credentials where id = onepass_test.cid('rf')),
    'first_used_at_marks_an_authenticated_credential');

-- ------------------------------------------------------------ locator

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_locator('a', 'A', onepass_test.loc(1)) = 'ok', 'manager_sets_locator');
select onepass_test.ok(
    (select status = 'ok' and retry_after is null and mailbox_id = onepass_test.mbx('A')
     from onepass_test.locate(onepass_test.loc(1))),
    'locator_round_trip');
select onepass_test.ok(onepass_test.set_locator('g', 'A', onepass_test.loc(2)) = 'ok', 'granted_manager_sets_locator');
select onepass_test.ok(
    onepass_test.located(onepass_test.loc(1)) = onepass_test.mbxs('A')
    and onepass_test.located(onepass_test.loc(2)) = onepass_test.mbxs('A'),
    'old_and_new_locator_coexist');
select onepass_test.ok(onepass_test.set_locator('a', 'A', onepass_test.loc(1)) = 'ok', 'set_existing_locator_again');
reset role;
select onepass_test.ok(onepass_test.locs('A') = array[onepass_test.loc(1), onepass_test.loc(2)], 'set_existing_pair_is_idempotent');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_locator('g', 'A', onepass_test.loc(3)) = 'ok', 'set_third_locator');
select onepass_test.ok(
    onepass_test.located(onepass_test.loc(1)) is null
    and (select status = 'not_found' and mailbox_id is null from onepass_test.locate(onepass_test.loc(1))),
    'third_locator_drops_the_oldest_lookup');
reset role;
select onepass_test.ok(onepass_test.locs('A') = array[onepass_test.loc(2), onepass_test.loc(3)], 'mailbox_keeps_two_locators');
-- Setting the older one again does not make it younger.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_locator('a', 'A', onepass_test.loc(2)) = 'ok'
                       and onepass_test.set_locator('a', 'A', onepass_test.loc(4)) = 'ok', 'set_old_again_then_new');
reset role;
select onepass_test.ok(onepass_test.locs('A') = array[onepass_test.loc(3), onepass_test.loc(4)], 'existing_pair_keeps_its_age');

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'not_found' and retry_after is null and mailbox_id is null from onepass_test.locate(onepass_test.loc(99))),
    'locator_unknown_is_not_found');
select onepass_test.ok(
    (select status = 'malformed' from onepass_mailbox.locate('\x0102', onepass_test.ip(1))),
    'locate_short_locator_is_malformed');
select onepass_test.raises(
    $$select * from onepass_mailbox.locate(onepass_test.loc(1), '\x01')$$,
    'OP400', 'malformed', 'locate_malformed_ip_key_raises');
select onepass_test.ok(onepass_test.set_locator('r', 'A', onepass_test.loc(5)) = 'forbidden', 'locator_needs_manager');
select onepass_test.ok(onepass_test.set_locator('a', 'A', '\x0102') = 'malformed', 'set_locator_short_is_malformed');
reset role;
select onepass_test.ok(
    (select count(*) = 1 from onepass_mailbox.nonces n
     where n.credential_id = onepass_test.cid('r') and n.mailbox_id = onepass_test.mbx('A'))
    and onepass_test.locs('A') = array[onepass_test.loc(3), onepass_test.loc(4)],
    'forbidden_set_locator_keeps_its_nonce_and_nothing_else');

-- A locator is not unique: B shares A's, both are found, A (registered
-- first) first.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.set_locator('b', 'B', onepass_test.loc(3)) = 'ok', 'locator_shared_with_another_mailbox');
select onepass_test.ok(onepass_test.located(onepass_test.loc(3)) = onepass_test.mbxs('A', 'B'),
    'two_mailboxes_share_a_locator_oldest_first');
select onepass_test.ok(onepass_test.located(onepass_test.loc(4)) = onepass_test.mbxs('A'), 'unshared_locator_finds_one');
-- Nine mailboxes on one locator: the eight oldest are answered.
select onepass_test.ok(
    (select bool_and(onepass_test.set_locator(s, upper(s), onepass_test.loc(50)) = 'ok')
     from unnest(array['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9']) s),
    'nine_mailboxes_share_a_locator');
select onepass_test.ok(
    onepass_test.located(onepass_test.loc(50)) = onepass_test.mbxs('S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8'),
    'locate_answers_eight_oldest_first');
-- A deleted mailbox is left out, and the next one comes in.
select onepass_test.ok(onepass_test.abandon('s1', 'S1') = 'ok', 'abandon_a_sharing_mailbox');
select onepass_test.ok(
    onepass_test.located(onepass_test.loc(50)) = onepass_test.mbxs('S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9'),
    'deleted_mailbox_excluded');
reset role;
select onepass_test.ok(onepass_test.locs('S1') is null, 'abandon_drops_the_locators');
-- Even a locator row left behind (none should be) does not find it.
insert into onepass_mailbox.locators (locator, mailbox_id) values (onepass_test.loc(51), onepass_test.mbx('S1'));
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'not_found' and mailbox_id is null from onepass_test.locate(onepass_test.loc(51))),
    'deleted_mailbox_not_located_by_a_stray_row');
reset role;

-- Row level security: a locate sees the rows of its locator only, and
-- writes nothing through it.
set local role onepass_mailbox_owner;
select set_config('onepass.locator', encode(onepass_test.loc(3), 'hex'), true);
select onepass_test.ok(
    (select array_agg(l.mailbox_id order by l.seq) from onepass_mailbox.locators l) = onepass_test.mbxs('A', 'B'),
    'locator_setting_sees_its_rows_only');
select onepass_test.throws(
    $$insert into onepass_mailbox.locators (locator, mailbox_id) values (onepass_test.loc(8), onepass_test.mbx('C'))$$,
    '42501', 'locator_setting_writes_nothing');
select set_config('onepass.locator', '', true);
select onepass_test.ok(not exists (select 1 from onepass_mailbox.locators), 'locators_hidden_without_setting');
reset role;

-- Lookups count on the minute bucket of the raw IP key, shared with
-- create, enroll and rendezvous, and on 30 an hour under
-- SHA-256('onepass/locate' || IP key).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 3 from generate_series(1, 3) i, lateral onepass_test.locate(onepass_test.loc(200 + i), 5)),
    'locate_fixture_three_calls');
reset role;
select onepass_test.ok(
    (select count = 3 from onepass_mailbox.rate
     where key = onepass_test.ip(5) and window_start = date_trunc('minute', now(), 'UTC')),
    'locate_counts_on_the_minute_bucket');
select onepass_test.ok(
    (select count = 3 from onepass_mailbox.rate
     where key = extensions.digest('onepass/locate'::bytea || onepass_test.ip(5), 'sha256')
       and window_start = date_trunc('hour', now(), 'UTC')),
    'locate_counts_on_the_hour_bucket');

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(s = 'not_found') from (select (onepass_test.locate(onepass_test.loc(100 + i), 2)).status as s
                                            from generate_series(1, 30) i) t),
    'locate_thirty_an_hour');
select onepass_test.ok(
    (select status = 'rate_limited' and retry_after between 1 and 3600 and mailbox_id is null
     from onepass_test.locate(onepass_test.loc(3), 2)),
    'locate_rate_limited_per_hour');
select onepass_test.ok(onepass_test.located(onepass_test.loc(3), 3) = onepass_test.mbxs('A', 'B'),
    'locate_limit_is_per_ip_key');
reset role;

-- ------------------------------------------------------------ abandon

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.abandon('g', 'A') = 'forbidden', 'abandon_refused_for_other_credential');
select onepass_test.ok(onepass_test.abandon('r', 'A') = 'forbidden', 'abandon_refused_for_a_reader');
-- g and r authenticated on A: not fresh, even for its creator.
select onepass_test.ok(onepass_test.abandon('a', 'A') = 'forbidden', 'abandon_refused_once_another_credential_was_used');
reset role;
select onepass_test.ok((select deleted_at is null from onepass_test.mb('A')), 'refused_abandon_changes_nothing');
select onepass_test.ok(
    -- g's two set_locator calls and its refused abandon.
    (select count(*) = 3 from onepass_mailbox.nonces n where n.credential_id = onepass_test.cid('g')
       and n.mailbox_id = onepass_test.mbx('A')),
    'forbidden_abandon_keeps_its_nonce');

update onepass_mailbox.mailboxes set created_at = now() - interval '24 hours 1 second' where id = onepass_test.mbx('C');
-- The creator demoted to read (here by hand: through the API it takes
-- another manager, which already ends freshness).
update onepass_mailbox.credentials set role = 1 where id = onepass_test.cid('d');
-- Another device enrolled on M (by hand: the enroll path is tested in
-- api_test.sql; only enrolled_by matters here).
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, enrolled_by)
values (onepass_test.cid('mx'), onepass_test.mbx('M'), onepass_test.pk('mx'), onepass_test.cid('m'));
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.abandon('c', 'C') = 'forbidden', 'abandon_refused_after_day');
select onepass_test.ok(onepass_test.info('c', 'C') = 'ok', 'mailbox_kept_after_refused_abandon');
select onepass_test.ok(onepass_test.abandon('d', 'D') = 'forbidden', 'abandon_refused_for_a_demoted_creator');
select onepass_test.ok(onepass_test.abandon('m', 'M') = 'forbidden', 'abandon_refused_after_an_enrollment');
select onepass_test.ok(onepass_test.put('jr', 'J', 1) = 'ok' and onepass_test.abandon('j', 'J') = 'forbidden',
    'abandon_refused_after_another_credential_committed');
select onepass_test.ok(onepass_test.info('kr', 'K') = 'ok' and onepass_test.abandon('k', 'K') = 'forbidden',
    'abandon_refused_after_another_credential_authenticated');
select onepass_test.ok(onepass_test.abandon('l', 'L') = 'forbidden', 'abandon_refused_with_two_other_credentials');
reset role;
select onepass_test.ok(
    (select bool_and(deleted_at is null) from onepass_mailbox.mailboxes
     where id in (onepass_test.mbx('C'), onepass_test.mbx('D'), onepass_test.mbx('M'), onepass_test.mbx('J'),
                  onepass_test.mbx('K'), onepass_test.mbx('L'))),
    'refused_abandons_delete_nothing');

-- F: the creator wrote, set a locator and granted the recovery credential,
-- which never ran: still fresh.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put('f', 'F', 1) = 'ok'
                       and onepass_test.set_locator('f', 'F', onepass_test.loc(9)) = 'ok', 'abandon_fixture_record');
select onepass_test.ok(onepass_test.abandon('f', 'F') = 'ok', 'abandon_fresh_mailbox_by_creator');
select onepass_test.ok(onepass_test.located(onepass_test.loc(9)) is null, 'abandoned_mailbox_not_located');
reset role;
select onepass_test.ok((select deleted_at = now() from onepass_test.mb('F')), 'abandon_sets_deleted_at');

-- Every entry point on a deleted mailbox answers not_found, raised before
-- anything is recorded.
create temporary table t_calls (name text, stmt text) on commit drop;
grant all on t_calls to public;
insert into t_calls values
    ('info', $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'))$$),
    ('changes', $$select * from onepass_mailbox.api_changes(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), 0, 10, false)$$),
    ('record', $$select * from onepass_mailbox.api_record(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), 5::smallint, onepass_test.rid(1))$$),
    ('commit', $$select onepass_test.put('f', 'F', 2)$$),
    ('announce', $$select onepass_test.announce('f', 'F', onepass_test.sha(1), 20000)$$),
    ('lookup', $$select * from onepass_mailbox.api_blob_lookup(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), array[onepass_test.sha(1)])$$),
    ('set_push', $$select * from onepass_mailbox.api_set_push(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), 1::smallint, '\x01')$$),
    ('revoke', $$select * from onepass_mailbox.api_revoke_credential(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), onepass_test.cid('rf'))$$),
    ('grant', $$select onepass_test.grant('f', 'F', 'x', 1)$$),
    ('set_role', $$select * from onepass_mailbox.api_set_credential_role(onepass_test.cid('f'), onepass_test.n(), now(), onepass_test.mbx('F'), onepass_test.cid('rf'), 2::smallint, null)$$),
    ('set_locator', $$select onepass_test.set_locator('f', 'F', onepass_test.loc(4))$$),
    ('abandon', $$select onepass_test.abandon('f', 'F')$$),
    ('info_by_grantee', $$select onepass_test.info('rf', 'F')$$);
create function onepass_test.all_not_found() returns boolean language plpgsql volatile as $$
declare
    c record;
    got text;
    msg text;
begin
    for c in select * from t_calls loop
        got := null;
        begin
            execute c.stmt;
        exception when others then
            get stacked diagnostics got = returned_sqlstate, msg = message_text;
        end;
        if got is distinct from 'OP404' or msg is distinct from 'not_found' then
            raise notice 'deleted mailbox, %: got % %', c.name, coalesce(got, 'no error'), msg;
            return false;
        end if;
    end loop;
    return true;
end
$$;
grant execute on function onepass_test.all_not_found() to public;
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.all_not_found(), 'deleted_mailbox_refuses_everything');
-- Enroll answers in band (it counts on the IP key first).
select onepass_test.ok(
    (select e.status = 'not_found' from onepass_mailbox.api_enroll(
        onepass_test.pk('new'), onepass_test.n(), now(), onepass_test.mbx('F'), onepass_test.cid('f'),
        onepass_test.sha(99), now() + interval '60 seconds', '\x', onepass_test.ip(9)) e),
    'deleted_mailbox_refuses_enroll');
reset role;
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.credentials c where c.id = onepass_test.cid('new')),
    'deleted_mailbox_enrolls_nobody');

reset role;
select onepass_test.ok(
    (select first_used_at is null from onepass_mailbox.credentials where id = onepass_test.cid('rf')),
    'refused_calls_on_a_deleted_mailbox_record_no_use');

-- ------------------------------------------------------------- purge

-- E holds a committed blob, a blob only announced and an inline record,
-- then is abandoned.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.announce('e', 'E', onepass_test.sha(1), 20000) = 'ok'
                       and onepass_test.announce('e', 'E', onepass_test.sha(2), 30000) = 'ok',
    'purge_fixture_announced');
reset role;
select onepass_test.object('E', onepass_test.sha(1), 20000);
select onepass_test.object('E', onepass_test.sha(2), 30000);
create temporary table t_names on commit drop as
    select onepass_test.oname('E', onepass_test.sha(1)) as n
    union all select onepass_test.oname('E', onepass_test.sha(2));
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put_blob('e', 'E', 1, onepass_test.sha(1), 20000) = 'ok'
                       and onepass_test.put('e', 'E', 2) = 'ok'
                       and onepass_test.set_locator('e', 'E', onepass_test.loc(6)) = 'ok'
                       and onepass_test.abandon('e', 'E') = 'ok',
    'purge_fixture_written_and_abandoned');
reset role;
insert into onepass_mailbox.locators (locator, mailbox_id) values (onepass_test.loc(7), onepass_test.mbx('E'));

-- Not before an hour.
select onepass_mailbox.maintenance(now() + interval '59 minutes');
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('E'))
    and (select count(*) = 1 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('E'))
    and (select count(*) = 2 from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.blob_graves where mailbox_id = onepass_test.mbx('E')),
    'purge_waits_an_hour');

select onepass_mailbox.maintenance(now() + interval '2 hours');
select onepass_test.ok(
    (select array_agg(g.object_name order by g.object_name) from onepass_mailbox.blob_graves g
     where g.mailbox_id = onepass_test.mbx('E') and g.taken_at is null)
    = (select array_agg(n order by n) from t_names),
    'purge_queues_blob_objects');
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.nonces where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.locators where mailbox_id = onepass_test.mbx('E'))
    and not exists (select 1 from onepass_mailbox.push_queue where mailbox_id = onepass_test.mbx('E')),
    'purge_removes_the_mailbox_contents');
select onepass_test.ok(
    (select deleted_at is not null and bytes_used = 0 and records_count = 0 from onepass_test.mb('E')),
    'purged_mailbox_row_stays_empty');
-- Every abandoned mailbox went; the live ones are untouched.
select onepass_test.ok(
    not exists (select 1 from onepass_mailbox.credentials where mailbox_id in (onepass_test.mbx('F'), onepass_test.mbx('S1')))
    and (select count(*) = 3 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('A'))
    and (select count(*) = 1 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('B'))
    and (select count(*) = 1 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('C')),
    'purge_touches_only_abandoned_mailboxes');
-- The collector takes the graves of a purged mailbox like any other.
set local role onepass_mailbox_janitor;
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.gc_take(1000) t where t.mailbox_id = onepass_test.mbx('E')),
    'purged_graves_reach_the_collector');
reset role;
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select onepass_test.info('e', 'E')$$, 'OP403', 'unknown_credential', 'purged_mailbox_knows_no_credential');
reset role;
