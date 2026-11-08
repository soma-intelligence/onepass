-- The fixes of 20261108130000 (security review of 2026-11-08): the blob
-- quota counts stored sizes, an oversize object is not kept alive by a new
-- announce, maintenance collects announced blobs stored with the wrong size,
-- credential rows are capped and old revoked ones purged, deleted mailboxes
-- are purged after 3 hours, and the hourly orphan sweep queues objects that
-- no row names. Starts as the harness superuser, inside a transaction the
-- harness rolls back; entry points run as onepass_mailbox_api. Storage
-- objects are rows the test writes, as the Storage API would after an upload.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

-- SHA-256 for the api side, which has no access to the extensions schema.
create function onepass_test.h(t text) returns bytea language sql immutable security definer as $$
    select extensions.digest(t, 'sha256') $$;
create function onepass_test.key(n text) returns bytea language sql immutable as $$
    select onepass_test.h('onepass-scan-fixes-test-key/' || n) $$;
create function onepass_test.add_key(n text) returns void language sql volatile security definer as $$
    insert into t_keys (name, pk, cid)
    values (n, onepass_test.key(n),
            substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || onepass_test.key(n), 'sha256') from 1 for 16))
    on conflict (name) do nothing $$;
create function onepass_test.pk(text) returns bytea language sql stable as $$ select pk from t_keys where name = $1 $$;
create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.sha(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-scan-fixes/' || i) || md5('onepass-scan-fixes//' || i), 'hex') $$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    perform onepass_test.add_key(key);
    select * into r from onepass_mailbox.api_create_mailbox(
        onepass_test.pk(key), onepass_test.n(), now(), null, '\x',
        decode(md5(name) || md5(name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id);
    end if;
    return r.status;
end
$$;
create function onepass_test.announce(cred text, mbx text, shas bytea[], sizes integer[])
returns table (status text, retry_after integer, sha256 bytea, needs_upload boolean, object_name text)
language sql volatile as $$
    select * from onepass_mailbox.api_blob_announce(onepass_test.cid(cred), onepass_test.n(), now(),
        onepass_test.mbx(mbx), shas, sizes)
$$;
create function onepass_test.put_blob(cred text, mbx text, i integer, sha bytea, size integer) returns text
language sql volatile as $$
    select status from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        array[1]::smallint[], array[onepass_test.nonce(i)], array[1]::bigint[], array[1]::smallint[],
        array[null]::bigint[], array[null]::bytea[], array[sha], array[size]) limit 1
$$;
create function onepass_test.grant(cred text, mbx text, key text) returns text language plpgsql volatile as $$
begin
    perform onepass_test.add_key(key);
    return (select g.status from onepass_mailbox.api_grant_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        onepass_test.pk(key), 3::smallint, null, '\x') g);
end
$$;
create function onepass_test.revoke(cred text, mbx text, target text) returns text language sql volatile as $$
    select r.status from onepass_mailbox.api_revoke_credential(
        onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(target)) r
$$;
create function onepass_test.enroll(approver text, mbx text, key text) returns text language plpgsql volatile as $$
begin
    perform onepass_test.add_key(key);
    return (select e.status from onepass_mailbox.api_enroll(
        onepass_test.pk(key), onepass_test.n(), now(), onepass_test.mbx(mbx), onepass_test.cid(approver),
        onepass_test.h('ticket/' || key), now() + interval '60 seconds', '\x',
        decode(md5('ip/' || key) || md5('ip//' || key), 'hex')) e);
end
$$;
grant execute on all functions in schema onepass_test to public;

-- Superuser side.
-- Object name of the blob's current generation (0 when no row has one).
create function onepass_test.oname(mbx text, sha bytea) returns text language sql stable security definer as $$
    select encode(onepass_test.mbx(mbx), 'hex') || '/' || encode(sha, 'hex') || '.'
           || coalesce((select gen from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx(mbx) and sha256 = sha), 0)
$$;
create function onepass_test.object(mbx text, sha bytea, size integer) returns void language sql volatile as $$
    insert into storage.objects (bucket_id, name, metadata)
    values ('onepass-mailbox', onepass_test.oname(mbx, sha),
            jsonb_build_object('size', size, 'mimetype', 'application/octet-stream'))
$$;
create function onepass_test.blob(mbx text, sha bytea) returns onepass_mailbox.blobs language sql stable as $$
    select * from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx(mbx) and sha256 = sha $$;
create function onepass_test.graves(mbx text) returns text[] language sql stable as $$
    select coalesce(array_agg(object_name order by object_name), '{}') from onepass_mailbox.blob_graves
    where mailbox_id = onepass_test.mbx(mbx) $$;
revoke all on function onepass_test.object(text, bytea, integer), onepass_test.blob(text, bytea),
    onepass_test.graves(text) from public;

set local onepass.maintenance = 'on';
-- 100 000 bytes, 2 credentials (so 8 rows at most).
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('t_scan_tiny', 100000, 1000, 2, 100000, 20000);
reset onepass.maintenance;

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(m, k) = 'ok')
     from (values ('Q', 'q'), ('C', 'c'), ('E', 'e'), ('X', 'x')) v (m, k)),
    'scan_fixture_mailboxes_created');
reset role;
update onepass_mailbox.mailboxes set plan = 't_scan_tiny' where id in (onepass_test.mbx('Q'), onepass_test.mbx('C'));

-- ------------------------------------------------- quota on stored bytes

-- Two blobs announced at the smallest blob size, uploaded far larger.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 2 and bool_and(status = 'ok' and needs_upload)
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(1), onepass_test.sha(2)], array[16385, 16385])),
    'small_declared_blobs_announced');
reset role;
select onepass_test.object('Q', onepass_test.sha(1), 45000);
select onepass_test.object('Q', onepass_test.sha(2), 45000);
create temporary table t_old on commit drop as
    select onepass_test.oname('Q', onepass_test.sha(1)) as n1, onepass_test.oname('Q', onepass_test.sha(2)) as n2;
grant select on t_old to public;

-- 90 000 bytes stored: a third blob of 16 385 goes over 100 000 (the
-- declared sizes alone, 49 155, would have let it in).
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'quota')
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(3)], array[16385])),
    'announce_counts_stored_size_of_pending_blobs');
reset role;
select onepass_test.ok(
    (onepass_test.blob('Q', onepass_test.sha(3))).gen is null
    and onepass_test.graves('Q') = '{}'
    and (select count(*) = 2 from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx('Q')),
    'refused_announce_changes_nothing');

-- The oversize blob announced again: collected on the spot, back as a new
-- row and generation that needs an upload; the old name is a grave. The
-- growth is negative, so this passes the quota.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and needs_upload and object_name <> (select n1 from t_old))
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(1)], array[16385])),
    'reannounce_of_an_oversize_blob_names_a_new_generation');
reset role;
select onepass_test.ok(
    onepass_test.graves('Q') = array[(select n1 from t_old)]
    and (select b.orphaned_at is null and b.refs = 0 and b.size = 16385 from onepass_test.blob('Q', onepass_test.sha(1)) b)
    and onepass_test.oname('Q', onepass_test.sha(1)) <> (select n1 from t_old),
    'reannounce_sends_the_oversize_object_to_the_graves');
-- Marked orphaned, then announced again: an oversize object never gets its
-- orphan clock reset.
update onepass_mailbox.blobs set orphaned_at = now() - interval '23 hours'
where mailbox_id = onepass_test.mbx('Q') and sha256 = onepass_test.sha(2);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok' and needs_upload)
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(2)], array[16385])),
    'reannounce_of_the_second_oversize_blob_ok');
reset role;
select onepass_test.ok(
    onepass_test.graves('Q') = (select array_agg(n order by n) from (select n1 as n from t_old union all select n2 from t_old) x),
    'no_oversize_object_kept_alive');

-- A blob stored with its declared size, announced again: kept as it is.
select onepass_test.object('Q', onepass_test.sha(1), 16385);
create temporary table t_keep on commit drop as select onepass_test.oname('Q', onepass_test.sha(1)) as n;
grant select on t_keep to public;
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok' and not needs_upload and object_name = (select n from t_keep))
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(1)], array[16385])),
    'reannounce_of_a_matching_object_keeps_it');
-- And it commits; a commit of a blob stored with another size does not.
select onepass_test.ok(onepass_test.put_blob('q', 'Q', 1, onepass_test.sha(1), 16385) = 'ok',
    'matching_blob_commits');
reset role;
select onepass_test.object('Q', onepass_test.sha(2), 16386);
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.put_blob('q', 'Q', 2, onepass_test.sha(2), 16385) = 'malformed',
    'commit_refuses_a_stored_size_other_than_declared');
reset role;

-- --------------------------- maintenance collects wrong-size announced blobs

-- sha 2 (announced, stored 16 386 for 16 385) goes at once; sha 1
-- (committed) and sha 4 (announced, stored right) stay.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok') from onepass_test.announce('q', 'Q', array[onepass_test.sha(4)], array[20000])),
    'third_blob_announced');
reset role;
select onepass_test.object('Q', onepass_test.sha(4), 20000);
create temporary table t_wrong on commit drop as select onepass_test.oname('Q', onepass_test.sha(2)) as n;
grant select on t_wrong to public;
update onepass_mailbox.blobs set orphaned_at = null where mailbox_id = onepass_test.mbx('Q');
select onepass_mailbox.maintenance();
select onepass_test.ok(
    (onepass_test.blob('Q', onepass_test.sha(2))).gen is null
    and (select n from t_wrong) = any (onepass_test.graves('Q'))
    and (onepass_test.blob('Q', onepass_test.sha(1))).gen is not null
    and (onepass_test.blob('Q', onepass_test.sha(4))).gen is not null
    and not (onepass_test.oname('Q', onepass_test.sha(4)) = any (onepass_test.graves('Q'))),
    'maintenance_collects_an_announced_blob_stored_with_another_size');

-- ------------------------------------------------- credential rows capped

-- Plan of 2 credentials: 8 rows at most. The owner and one grant are
-- active; each further grant is revoked again.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.grant('c', 'C', 'c1') = 'ok', 'cap_fixture_granted');
select onepass_test.ok(onepass_test.grant('c', 'C', 'c2') = 'quota', 'max_credentials_still_counts_active_ones');
select onepass_test.ok(onepass_test.revoke('c', 'C', 'c1') = 'ok', 'cap_fixture_revoked');
select onepass_test.ok(
    (select bool_and(onepass_test.grant('c', 'C', 'churn' || i) = 'ok' and onepass_test.revoke('c', 'C', 'churn' || i) = 'ok')
     from generate_series(1, 6) i),
    'grant_and_revoke_up_to_the_row_cap');
reset role;
select onepass_test.ok(
    (select count(*) = 8 and count(*) filter (where revoked_at is null) = 1
     from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('C')),
    'eight_rows_one_active');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.grant('c', 'C', 'churn7') = 'quota', 'grant_refused_past_4_times_max_credentials');
select onepass_test.ok(onepass_test.enroll('c', 'C', 'enrolled1') = 'quota', 'enroll_refused_past_4_times_max_credentials');
reset role;

-- Revoked 6 days ago: kept. 8 days ago: purged, even one another
-- credential names (its granted_by is cleared), except the rows of a
-- mailbox being deleted.
update onepass_mailbox.credentials set revoked_at = now() - interval '6 days'
where mailbox_id = onepass_test.mbx('C') and revoked_at is not null;
select onepass_mailbox.maintenance();
select onepass_test.ok(
    (select count(*) = 8 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('C')),
    'revoked_less_than_a_week_ago_kept');
-- churn1 granted churn1b before being revoked.
set local onepass.maintenance = 'on';
insert into t_keys (name, pk, cid)
select 'churn1b', onepass_test.key('churn1b'),
       substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || onepass_test.key('churn1b'), 'sha256') from 1 for 16);
insert into onepass_mailbox.credentials (id, mailbox_id, public_key, role, granted_by, revoked_at)
values (onepass_test.cid('churn1b'), onepass_test.mbx('C'), onepass_test.pk('churn1b'), 1, onepass_test.cid('churn1'),
        now() - interval '1 day');
reset onepass.maintenance;
update onepass_mailbox.credentials set revoked_at = now() - interval '8 days'
where mailbox_id = onepass_test.mbx('C') and revoked_at is not null and id <> onepass_test.cid('churn1b');
-- X: deleted, with a credential revoked long ago; the purge handles it.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.grant('x', 'X', 'x1') = 'ok' and onepass_test.revoke('x', 'X', 'x1') = 'ok',
    'deleted_fixture_revoked');
reset role;
update onepass_mailbox.credentials set revoked_at = now() - interval '30 days' where mailbox_id = onepass_test.mbx('X');
update onepass_mailbox.mailboxes set deleted_at = now() - interval '1 hour' where id = onepass_test.mbx('X');
select onepass_mailbox.maintenance();
select onepass_test.ok(
    (select array_agg(id order by id) from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('C'))
    = (select array_agg(x order by x) from unnest(array[onepass_test.cid('c'), onepass_test.cid('churn1b')]) x)
    and (select granted_by is null from onepass_mailbox.credentials where id = onepass_test.cid('churn1b')),
    'revoked_more_than_a_week_ago_purged_and_references_cleared');
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('X')),
    'credentials_of_a_mailbox_being_deleted_left_to_the_purge');
-- A purged credential is unknown; room for grants again.
set local role onepass_mailbox_api;
select onepass_test.raises(
    $$select * from onepass_mailbox.api_mailbox_info(onepass_test.cid('c1'), onepass_test.n(), now(), onepass_test.mbx('C'))$$,
    'OP403', 'unknown_credential', 'purged_credential_is_unknown');
select onepass_test.ok(onepass_test.grant('c', 'C', 'churn7') = 'ok', 'grant_allowed_again_after_the_purge');
reset role;

-- Device upgrades: each new device is enrolled by the previous one, which
-- it then revokes, a month apart. With no maintenance at all the cap never
-- bites (old revocations do not count); maintenance then purges the whole
-- lineage, references included.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.open('U', 'u') = 'ok', 'upgrade_fixture_created');
reset role;
-- 3 credentials (the owner, the current device and the one enrolling), so
-- 12 rows at most: 20 upgrades would pass it if old revocations counted.
set local onepass.maintenance = 'on';
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('t_scan_upgrade', 100000, 1000, 3, 100000, 20000);
reset onepass.maintenance;
update onepass_mailbox.mailboxes set plan = 't_scan_upgrade' where id = onepass_test.mbx('U');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.grant('u', 'U', 'dev0') = 'ok', 'upgrade_first_device_granted');
reset role;
create function pg_temp.upgrade(i integer) returns text language plpgsql as $$
declare
    v text;
begin
    set local role onepass_mailbox_api;
    v := onepass_test.enroll('dev' || (i - 1), 'U', 'dev' || i);
    if v = 'ok' then
        v := onepass_test.revoke('dev' || i, 'U', 'dev' || (i - 1));
    end if;
    reset role;
    -- A month passes.
    update onepass_mailbox.credentials set revoked_at = revoked_at - interval '30 days'
    where mailbox_id = onepass_test.mbx('U') and revoked_at is not null;
    update onepass_mailbox.nonces set seen_at = seen_at - interval '30 days'
    where mailbox_id = onepass_test.mbx('U');
    return v;
end
$$;
select onepass_test.ok(
    (select bool_and(pg_temp.upgrade(i) = 'ok') from generate_series(1, 20) i),
    'twenty_device_upgrades_never_hit_the_cap');
select onepass_test.ok(
    (select count(*) = 22 and count(*) filter (where revoked_at is null) = 2
     from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('U')),
    'upgrade_lineage_rows_kept_until_maintenance');
select onepass_mailbox.maintenance();
select onepass_test.ok(
    (select array_agg(id order by id) from onepass_mailbox.credentials where mailbox_id = onepass_test.mbx('U'))
    = (select array_agg(x order by x) from unnest(array[onepass_test.cid('u'), onepass_test.cid('dev20')]) x)
    and (select enrolled_by is null from onepass_mailbox.credentials where id = onepass_test.cid('dev20')),
    'maintenance_purges_the_upgrade_lineage');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.enroll('dev20', 'U', 'dev21') = 'ok', 'upgrade_after_the_purge_works');
reset role;

-- ------------------------------------------- purge of deleted mailboxes

-- E: a blob announced and uploaded, then the mailbox deleted. Not purged
-- before 3 hours (an upload URL signed before the deletion still works for
-- 2), purged after.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok') from onepass_test.announce('e', 'E', array[onepass_test.sha(9)], array[20000])),
    'purge_fixture_announced');
reset role;
select onepass_test.object('E', onepass_test.sha(9), 20000);
create temporary table t_e on commit drop as select onepass_test.oname('E', onepass_test.sha(9)) as n;
grant select on t_e to public;
update onepass_mailbox.mailboxes set deleted_at = now() where id = onepass_test.mbx('E');
select onepass_mailbox.maintenance(now() + interval '2 hours 59 minutes');
select onepass_test.ok(
    (onepass_test.blob('E', onepass_test.sha(9))).gen is not null and onepass_test.graves('E') = '{}',
    'deleted_mailbox_not_purged_within_3_hours');
select onepass_mailbox.maintenance(now() + interval '3 hours 1 minute');
select onepass_test.ok(
    (onepass_test.blob('E', onepass_test.sha(9))).gen is null and onepass_test.graves('E') = array[(select n from t_e)],
    'deleted_mailbox_purged_after_3_hours');

-- ------------------------------------------------------- orphan sweep

delete from onepass_mailbox.blob_graves;
delete from onepass_mailbox.settings where name = 'orphan_sweep_at';
delete from storage.objects where name = (select n from t_e);
-- E's object uploaded again after the purge and the collector (no row, no
-- grave), Q's live sha 4 object (a row), a young orphan, an object of an
-- unknown mailbox and a name of another shape.
insert into storage.objects (bucket_id, name, metadata, created_at) values
    ('onepass-mailbox', (select n from t_e), '{"size": 20000}', now() - interval '4 hours'),
    ('onepass-mailbox', encode(onepass_test.mbx('E'), 'hex') || '/' || encode(onepass_test.sha(10), 'hex') || '.5',
     '{"size": 20000}', now() - interval '2 hours'),
    ('onepass-mailbox', repeat('ab', 16) || '/' || encode(onepass_test.sha(11), 'hex') || '.6',
     '{"size": 20000}', now() - interval '4 hours'),
    ('onepass-mailbox', encode(onepass_test.mbx('E'), 'hex') || '/not-a-blob', '{"size": 1}', now() - interval '4 hours');
update storage.objects set created_at = now() - interval '4 hours'
where name = onepass_test.oname('Q', onepass_test.sha(4));
select onepass_mailbox.maintenance();
select onepass_test.ok(
    onepass_test.graves('E') = array[(select n from t_e)]
    and onepass_test.graves('Q') = '{}'
    and not exists (select 1 from onepass_mailbox.blob_graves where object_name like repeat('ab', 16) || '/%'),
    'sweep_queues_old_objects_no_row_names');
select onepass_test.ok(
    exists (select 1 from onepass_mailbox.settings where name = 'orphan_sweep_at'),
    'sweep_time_recorded');
-- Within the hour: no second sweep. An hour later: the young orphan, now
-- old enough, goes too.
delete from onepass_mailbox.blob_graves;
select onepass_mailbox.maintenance(now() + interval '59 minutes');
select onepass_test.ok(not exists (select 1 from onepass_mailbox.blob_graves), 'sweep_at_most_once_an_hour');
select onepass_mailbox.maintenance(now() + interval '61 minutes');
select onepass_test.ok(
    onepass_test.graves('E') = (select array_agg(n order by n) from (
        select (select n from t_e) as n
        union all select encode(onepass_test.mbx('E'), 'hex') || '/' || encode(onepass_test.sha(10), 'hex') || '.5') x),
    'sweep_an_hour_later_takes_the_now_old_orphan');
select onepass_test.throws($$select onepass_mailbox._sweep_orphan_objects(now())$$, 'P0001',
    'sweep_refused_outside_maintenance');
select onepass_test.ok(
    not has_function_privilege('onepass_mailbox_api', 'onepass_mailbox._sweep_orphan_objects(timestamptz)', 'execute')
    and not has_function_privilege('onepass_mailbox_janitor', 'onepass_mailbox._sweep_orphan_objects(timestamptz)', 'execute')
    and not has_function_privilege('onepass_mailbox_api', 'onepass_mailbox._object_size(jsonb)', 'execute'),
    'new_helpers_not_callable_by_the_api_or_the_janitor');

-- Requests still read only the objects of their mailbox.
set local role onepass_mailbox_owner;
select set_config('onepass.mailbox', '', true);
select onepass_test.ok((select count(*) = 0 from storage.objects), 'owner_outside_maintenance_reads_no_object');
reset role;

-- The replaced announce keeps the settings of 20261108120000 and 20261031233000.
select onepass_test.ok(
    (select 'jit=off' = any (p.proconfig) and 'plan_cache_mode=force_custom_plan' = any (p.proconfig)
            and 'search_path=""' = any (p.proconfig) and p.prosecdef
     from pg_proc p where p.oid = 'onepass_mailbox.api_blob_announce(bytea, bytea, timestamptz, bytea, bytea[], integer[])'::regprocedure),
    'announce_keeps_jit_off_and_custom_plans');
