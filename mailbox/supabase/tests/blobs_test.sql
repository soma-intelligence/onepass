-- Blobs in Storage (spec 4.6, 4.9, 4.11): announce, lookup, the Blob branch
-- of api_commit, reference counts and the collection of orphans.
-- Starts as the harness superuser, inside a transaction the harness rolls
-- back; entry points run as onepass_mailbox_api, the collector as
-- onepass_mailbox_janitor, state is read back as the superuser. now() is
-- fixed for the whole transaction. Storage objects are rows the test writes
-- into storage.objects, as the Storage API would after an upload.

create temporary table t_keys (name text primary key, pk bytea not null, cid bytea not null) on commit drop;
create temporary table t_mbx (name text primary key, id bytea, wake_topic bytea) on commit drop;
create temporary sequence t_n;
grant all on t_keys, t_mbx to public;
grant usage on sequence t_n to public;

insert into t_keys (name, pk, cid)
select n, pk, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16)
from (select n, extensions.digest('onepass-blob-test-key/' || n, 'sha256') as pk
      from unnest(array['a', 'b', 'q', 'p']) as n) k;

create function onepass_test.cid(text) returns bytea language sql stable as $$ select cid from t_keys where name = $1 $$;
create function onepass_test.mbx(text) returns bytea language sql stable as $$ select id from t_mbx where name = $1 $$;
create function onepass_test.n() returns bytea language sql volatile as $$ select onepass_test.nonce(nextval('t_n')) $$;
create function onepass_test.rid(i integer) returns bytea language sql immutable as $$ select onepass_test.nonce(i) $$;
-- A blob hash from a number (any 32 bytes do: the server cannot hash what
-- it never sees).
create function onepass_test.sha(i integer) returns bytea language sql immutable as $$
    select decode(md5('onepass-blob-test/' || i) || md5('onepass-blob-test//' || i), 'hex') $$;
create function onepass_test.open(name text, key text) returns text language plpgsql volatile as $$
declare
    r record;
begin
    select * into r from onepass_mailbox.api_create_mailbox(
        (select pk from t_keys where t_keys.name = key), onepass_test.n(), now(), null, '\x',
        decode(md5(name) || md5(name || '/'), 'hex'), true);
    if r.status = 'ok' then
        insert into t_mbx values (name, r.mailbox_id, r.wake_topic);
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
create function onepass_test.lookup(cred text, mbx text, shas bytea[])
returns table (status text, retry_after integer, sha256 bytea, size integer, object_name text)
language sql volatile as $$
    select * from onepass_mailbox.api_blob_lookup(onepass_test.cid(cred), onepass_test.n(), now(),
        onepass_test.mbx(mbx), shas)
$$;
create function onepass_test.commit(
    cred text, mbx text, kinds smallint[], ids bytea[], versions bigint[], ops smallint[],
    expected bigint[], data bytea[], blob_sha bytea[], sizes integer[])
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_mailbox.api_commit(onepass_test.cid(cred), onepass_test.n(), now(), onepass_test.mbx(mbx),
        kinds, ids, versions, ops, expected, data, blob_sha, sizes)
$$;
-- One put of a blob body on (kind 1, rid(i)).
create function onepass_test.put_blob(cred text, mbx text, i integer, expected bigint, sha bytea, size integer)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.commit(cred, mbx, array[1]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[],
        array[1]::smallint[], array[expected], array[null]::bytea[], array[sha], array[size])
$$;
create function onepass_test.put(cred text, mbx text, i integer, expected bigint, body bytea)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.commit(cred, mbx, array[1]::smallint[], array[onepass_test.rid(i)], array[1]::bigint[],
        array[1]::smallint[], array[expected], array[body], array[null]::bytea[], array[octet_length(body)])
$$;
create function onepass_test.del(cred text, mbx text, i integer)
returns table (status text, retry_after integer, kind smallint, id bytea, seq bigint, version bigint,
               deleted boolean, data bytea, blob_sha256 bytea, size integer)
language sql volatile as $$
    select * from onepass_test.commit(cred, mbx, array[1]::smallint[], array[onepass_test.rid(i)], array[2]::bigint[],
        array[2]::smallint[], array[null]::bigint[], array[null]::bytea[], array[null]::bytea[], array[null]::integer[])
$$;
grant execute on all functions in schema onepass_test to public;

-- Superuser side: Storage objects, as the Storage API stores them, and state.
-- Object name of the blob's current generation (0 when no row has one).
-- Security definer: the api side of a test compares names with it.
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
revoke all on function onepass_test.object(text, bytea, integer), onepass_test.blob(text, bytea) from public;
-- The take the collector got, kept for gc_done.
create temporary table t_take (name text primary key, gen bigint, take bigint, object_name text) on commit drop;
grant all on t_take to public;

set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(onepass_test.open(m, k) = 'ok') from (values ('A', 'a'), ('B', 'b'), ('Q', 'q'), ('P', 'p')) v (m, k)),
    'blob_fixture_mailboxes_created');
reset role;

set local onepass.maintenance = 'on';
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values ('t_blob_tiny', 50000, 1000, 4, 1000, 20000);
reset onepass.maintenance;
update onepass_mailbox.mailboxes set plan = 't_blob_tiny' where id = onepass_test.mbx('Q');

-- --------------------------------------------------------------- bucket

select onepass_test.ok(
    (select not public from storage.buckets where id = 'onepass-mailbox'),
    'blob_bucket_is_private');
select onepass_test.ok(
    exists (select 1 from pg_policy p where p.polrelid = 'storage.objects'::regclass and p.polname like 'onepass_mailbox%')
    and not exists (select 1 from pg_policy p
                where p.polrelid = 'storage.objects'::regclass
                  and (p.polcmd <> 'r' or p.polroles <> array['onepass_mailbox_owner'::regrole::oid])
                  and p.polname like 'onepass_mailbox%'),
    'storage_policy_is_read_only_for_the_owner');

-- -------------------------------------------------------------- announce

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_test.announce('a', 'B', array[onepass_test.sha(1)], array[20000])$$,
    'OP403', 'unknown_credential', 'announce_with_credential_of_another_mailbox_raises');

select onepass_test.answers(format('select * from onepass_test.announce(''a'', ''A'', %s, %s)', s, z), 'malformed',
    'announce_malformed_' || name)
from (values
    ('lengths_differ', 'array[onepass_test.sha(1)]', 'array[20000, 20000]'),
    ('empty', '''{}''::bytea[]', '''{}''::integer[]'),
    ('null', 'null::bytea[]', 'null::integer[]'),
    ('sha_short', 'array[''\x0102''::bytea]', 'array[20000]'),
    ('sha_null', 'array[null::bytea]', 'array[20000]'),
    ('size_16384', 'array[onepass_test.sha(1)]', 'array[16384]'),
    ('size_921601', 'array[onepass_test.sha(1)]', 'array[921601]'),
    ('size_null', 'array[onepass_test.sha(1)]', 'array[null::integer]'),
    ('duplicate', 'array[onepass_test.sha(1), onepass_test.sha(1)]', 'array[20000, 20000]'),
    ('over_1000', 'array(select onepass_test.sha(i) from generate_series(1, 1001) i)', 'array_fill(20000, array[1001])'))
    as t (name, s, z);

select onepass_test.ok(
    (select count(*) = 2 and bool_and(status = 'ok' and needs_upload and retry_after is null)
            and array_agg(sha256) = (select array_agg(x order by x) from unnest(array[onepass_test.sha(1), onepass_test.sha(2)]) x)
     from onepass_test.announce('a', 'A', array[onepass_test.sha(2), onepass_test.sha(1)], array[20000, 30000])),
    'announce_returns_every_blob_sorted_with_needs_upload');
reset role;
select onepass_test.ok(
    (select b.state = 1 and b.refs = 0 and b.size = 30000 and b.orphaned_at is null from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select b.state = 1 and b.size = 20000 from onepass_test.blob('A', onepass_test.sha(2)) b),
    'announced_blobs_are_recorded_as_announced');
select onepass_test.object('A', onepass_test.sha(1), 30000);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select count(*) = 2
            and bool_and(needs_upload = (sha256 = onepass_test.sha(2)))
     from onepass_test.announce('a', 'A', array[onepass_test.sha(1), onepass_test.sha(2)], array[30000, 20000])),
    'announce_of_an_uploaded_blob_needs_no_upload');

-- --------------------------------------------------------------- commit

select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 1, null, onepass_test.sha(2), 20000)$$,
    'malformed', 'commit_blob_without_storage_object_refused');
reset role;
select onepass_test.object('A', onepass_test.sha(2), 20001);
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 1, null, onepass_test.sha(2), 20000)$$,
    'malformed', 'commit_blob_size_mismatch_refused');
reset role;
-- B's object with A's hash name: A's commit only sees objects under A's prefix.
select onepass_test.object('B', onepass_test.sha(3), 20000);
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 1, null, onepass_test.sha(3), 20000)$$,
    'malformed', 'commit_blob_of_another_mailbox_object_refused');

-- Blob shapes, refused before Storage is looked at.
select onepass_test.answers(format(
    'select * from onepass_test.commit(''a'', ''A'', array[1]::smallint[], array[onepass_test.rid(1)], array[1]::bigint[],
        array[1]::smallint[], array[null]::bigint[], array[null]::bytea[], array[%s], array[%s])', b, s),
    'malformed', 'commit_blob_malformed_' || name)
from (values
    ('size_16384', 'onepass_test.sha(1)', '16384'),
    ('size_921601', 'onepass_test.sha(1)', '921601'),
    ('size_null', 'onepass_test.sha(1)', 'null::integer'),
    ('sha_31_bytes', 'substring(onepass_test.sha(1) from 1 for 31)', '30000')) as t (name, b, s);

reset role;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.records where mailbox_id = onepass_test.mbx('A'))
    and (select next_seq = 1 and bytes_used = 0 from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'refused_blob_commits_wrote_nothing');
set local role onepass_mailbox_api;

select onepass_test.ok(
    (select status = 'ok' and seq = 1 and size = 30000 and not deleted
     from onepass_test.put_blob('a', 'A', 1, null, onepass_test.sha(1), 30000)),
    'commit_blob_with_its_storage_object_is_applied');
reset role;
select onepass_test.ok(
    (select r.blob_sha256 = onepass_test.sha(1) and r.data is null and r.size = 30000
     from onepass_mailbox.records r where r.mailbox_id = onepass_test.mbx('A') and r.id = onepass_test.rid(1))
    and (select b.refs = 1 and b.state = 2 and b.orphaned_at is null from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select bytes_used = 30000 and records_count = 1 from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'blob_commit_counts_one_reference_and_its_size');

-- A blob is committed only after its announce gave it an object name.
select onepass_test.object('A', onepass_test.sha(4), 40000);
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 4, null, onepass_test.sha(4), 40000)$$,
    'malformed', 'commit_blob_without_announce_refused');
select onepass_test.ok(
    (select status = 'ok' and needs_upload from onepass_test.announce('a', 'A', array[onepass_test.sha(4)], array[40000])),
    'announce_names_a_new_generation');
reset role;
delete from storage.objects where name like '%' || encode(onepass_test.sha(4), 'hex') || '.0';
select onepass_test.object('A', onepass_test.sha(4), 40000);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put_blob('a', 'A', 4, null, onepass_test.sha(4), 40000)),
    'commit_blob_after_announce_and_upload_is_applied');
reset role;
select onepass_test.ok(
    (select b.refs = 1 and b.state = 2 and b.size = 40000 from onepass_test.blob('A', onepass_test.sha(4)) b),
    'announced_blob_is_recorded_present');
set local role onepass_mailbox_api;

-- Two rows on one blob, then the body of each replaced or deleted.
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put_blob('a', 'A', 2, null, onepass_test.sha(1), 30000)),
    'second_row_on_the_same_blob_is_applied');
reset role;
select onepass_test.ok(
    (select b.refs = 2 from onepass_test.blob('A', onepass_test.sha(1)) b),
    'two_rows_count_two_references');
-- A referenced blob keeps its size: an object re-uploaded under the same
-- name with another size does not rewrite it.
update storage.objects set metadata = '{"size": 31000}'
where name = onepass_test.oname('A', onepass_test.sha(1));
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 6, null, onepass_test.sha(1), 31000)$$,
    'malformed', 'commit_of_a_referenced_blob_with_another_size_refused');
reset role;
select onepass_test.ok(
    (select b.refs = 2 and b.size = 30000 from onepass_test.blob('A', onepass_test.sha(1)) b),
    'referenced_blob_size_unchanged');
update storage.objects set metadata = '{"size": 30000}'
where name = onepass_test.oname('A', onepass_test.sha(1));
set local role onepass_mailbox_api;
-- Same blob again on the same row: no change in the count.
select onepass_test.ok(
    (select status = 'ok' and seq = 4 from onepass_test.put_blob('a', 'A', 2, 3, onepass_test.sha(1), 30000)),
    'same_blob_put_again_is_applied');
reset role;
select onepass_test.ok(
    (select b.refs = 2 from onepass_test.blob('A', onepass_test.sha(1)) b),
    'same_blob_put_again_keeps_the_count');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put('a', 'A', 1, 1, '\x0102')),
    'blob_row_replaced_by_an_inline_body');
select onepass_test.ok(
    (select status = 'ok' and deleted from onepass_test.del('a', 'A', 2)),
    'blob_row_deleted');
reset role;
select onepass_test.ok(
    (select b.refs = 0 and b.orphaned_at is null from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select bytes_used = 2 + 40000 + 128 and records_count = 3 from onepass_mailbox.mailboxes where id = onepass_test.mbx('A')),
    'replaced_and_deleted_bodies_drop_their_references');

-- A conflicting batch moves no count.
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 4, null, onepass_test.sha(1), 30000)$$,
    'conflict', 'conflicting_blob_put_is_a_conflict');
reset role;
select onepass_test.ok(
    (select b.refs = 0 from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select b.refs = 1 from onepass_test.blob('A', onepass_test.sha(4)) b),
    'conflicting_blob_put_moves_no_count');

-- Maintenance marks the unreferenced blob as orphaned, not the referenced one.
select onepass_mailbox.maintenance();
select onepass_test.ok(
    (select b.orphaned_at = now() and b.refs = 0 from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select b.orphaned_at is null from onepass_test.blob('A', onepass_test.sha(4)) b)
    and (select b.orphaned_at = now() from onepass_test.blob('A', onepass_test.sha(2)) b),
    'maintenance_marks_unreferenced_blobs_orphaned');

-- ---------------------------------------------------------------- lookup

set local role onepass_mailbox_api;
select onepass_test.answers(format('select * from onepass_test.lookup(''a'', ''A'', %s)', s), 'malformed',
    'lookup_malformed_' || name)
from (values
    ('empty', '''{}''::bytea[]'),
    ('null', 'null::bytea[]'),
    ('sha_short', 'array[''\x01''::bytea]'),
    ('duplicate', 'array[onepass_test.sha(4), onepass_test.sha(4)]'),
    ('over_1000', 'array(select onepass_test.sha(i) from generate_series(1, 1001) i)')) as t (name, s);
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and sha256 = onepass_test.sha(4) and size = 40000)
     from onepass_test.lookup('a', 'A', array[onepass_test.sha(1), onepass_test.sha(4), onepass_test.sha(9)])),
    'lookup_returns_only_blobs_of_live_rows');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'ok' and sha256 is null and size is null)
     from onepass_test.lookup('b', 'B', array[onepass_test.sha(4), onepass_test.sha(3)])),
    'lookup_of_a_blob_of_another_mailbox_returns_nothing');

-- -------------------------------------------------------------- RLS on Storage

reset role;
set local role onepass_mailbox_owner;
select set_config('onepass.mailbox', encode(onepass_test.mbx('A'), 'hex'), true);
select onepass_test.ok(
    (select count(*) = 3 from storage.objects)
    and not exists (select 1 from storage.objects where name like encode(onepass_test.mbx('B'), 'hex') || '/%'),
    'owner_reads_only_the_objects_of_the_current_mailbox');
select onepass_test.throws(
    $$delete from storage.objects$$, '42501', 'owner_cannot_delete_storage_objects');
select set_config('onepass.mailbox', '', true);
select onepass_test.ok((select count(*) = 0 from storage.objects), 'owner_without_mailbox_reads_no_object');
reset role;
select onepass_test.throws(
    $$set local role onepass_mailbox_api; select count(*) from storage.objects$$, '42501',
    'api_role_cannot_read_storage_objects');

-- ------------------------------------------------------------- collection

-- Orphaned for just under 24 h: not yet.
update onepass_mailbox.blobs set orphaned_at = now() - interval '23 hours 59 minutes'
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(1);
update onepass_mailbox.blobs set orphaned_at = null
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(2);
set local role onepass_mailbox_janitor;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.gc_take(100)),
    'gc_take_leaves_a_blob_orphaned_for_less_than_24_hours');
reset role;
update onepass_mailbox.blobs set orphaned_at = now() - interval '24 hours 1 second'
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(1);
set local role onepass_mailbox_janitor;
insert into t_take select 'sha1', gen, take, object_name from onepass_mailbox.gc_take(100);
reset role;
select onepass_test.ok(
    (select count(*) = 1 and bool_and(t.object_name = onepass_test.oname('A', onepass_test.sha(1))
                                      and t.gen = b.gen and t.take = b.gc_take)
     from t_take t, onepass_test.blob('A', onepass_test.sha(1)) b),
    'gc_take_returns_a_blob_orphaned_for_24_hours_with_its_object_name');
set local role onepass_mailbox_janitor;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.gc_take(100)),
    'gc_take_does_not_return_a_taken_blob_again_at_once');
reset role;
select onepass_test.ok(
    (select b.state = 3 from onepass_test.blob('A', onepass_test.sha(1)) b),
    'taken_blob_is_marked_orphaned');

-- While a take is pending the collector may delete the object at any
-- moment: the blob is neither committable nor revived by an announce
-- (retry, with retry_after). The collector deletes the object, then calls
-- gc_done, which drops the row; the client announces again, sees no object,
-- uploads and commits. End to end, in that order.
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 5, null, onepass_test.sha(1), 30000)$$,
    'malformed', 'commit_of_a_blob_taken_by_gc_refused');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(status = 'retry' and retry_after between 1 and 3600 and sha256 is null)
     from onepass_test.announce('a', 'A', array[onepass_test.sha(2), onepass_test.sha(1)], array[20000, 30000])),
    'announce_of_a_blob_with_a_pending_take_is_retry');
reset role;
select onepass_test.ok(
    (select b.state = 3 and b.gc_taken_at is not null from onepass_test.blob('A', onepass_test.sha(1)) b)
    and (select b.state = 1 and b.orphaned_at is null from onepass_test.blob('A', onepass_test.sha(2)) b),
    'announce_refused_for_a_pending_take_changes_nothing');
set local role onepass_mailbox_api;
select onepass_test.answers(
    $$select * from onepass_test.put_blob('a', 'A', 5, null, onepass_test.sha(1), 30000)$$,
    'malformed', 'commit_after_a_refused_announce_still_refused');
reset role;
-- The collector deletes exactly the name it got, then confirms its take.
delete from storage.objects where name = (select object_name from t_take where name = 'sha1');
set local role onepass_mailbox_janitor;
select onepass_mailbox.gc_done(onepass_test.mbx('A'), onepass_test.sha(1),
    (select gen from t_take where name = 'sha1'), (select take from t_take where name = 'sha1'));
reset role;
select onepass_test.ok(
    (select count(*) = 0 from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(1)),
    'gc_done_deletes_the_collected_blob');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' and needs_upload from onepass_test.announce('a', 'A', array[onepass_test.sha(1)], array[30000])),
    'announce_after_collection_needs_an_upload');
reset role;
select onepass_test.object('A', onepass_test.sha(1), 30000);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put_blob('a', 'A', 5, null, onepass_test.sha(1), 30000)),
    'commit_after_reupload_is_applied');
reset role;
select onepass_test.ok(
    (select b.refs = 1 and b.state = 2 and b.gc_taken_at is null from onepass_test.blob('A', onepass_test.sha(1)) b),
    'collected_then_reuploaded_blob_is_referenced_with_its_object');
-- Back to an orphan for what follows.
set local role onepass_mailbox_api;
select onepass_test.ok((select status = 'ok' from onepass_test.del('a', 'A', 5)), 'reuploaded_blob_row_deleted');
reset role;

-- A take the collector never confirmed is handed out again an hour later,
-- as a new take of the same generation.
update onepass_mailbox.blobs set orphaned_at = now() - interval '2 days'
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(2);
set local role onepass_mailbox_janitor;
insert into t_take select 'sha2_first', gen, take, object_name from onepass_mailbox.gc_take(100);
reset role;
select onepass_test.ok((select count(*) = 1 from t_take where name = 'sha2_first'), 'gc_take_takes_a_second_blob');
update onepass_mailbox.blobs set gc_taken_at = now() - interval '61 minutes'
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(2);
set local role onepass_mailbox_janitor;
insert into t_take select 'sha2_second', gen, take, object_name from onepass_mailbox.gc_take(100);
reset role;
select onepass_test.ok(
    (select f.gen = s.gen and f.object_name = s.object_name and f.take < s.take
     from t_take f, t_take s where f.name = 'sha2_first' and s.name = 'sha2_second'),
    'unconfirmed_take_is_retaken_with_a_new_take');
-- Two collectors: the older one's confirmation is a no-op.
set local role onepass_mailbox_janitor;
select onepass_mailbox.gc_done(onepass_test.mbx('A'), onepass_test.sha(2),
    (select gen from t_take where name = 'sha2_first'), (select take from t_take where name = 'sha2_first'));
reset role;
select onepass_test.ok(
    (select b.state = 3 and b.gc_take = (select take from t_take where name = 'sha2_second')
     from onepass_test.blob('A', onepass_test.sha(2)) b),
    'gc_done_of_an_older_take_is_a_no_op');

-- The second take expires too: an announce takes the blob back under a new
-- generation, so a new object name. Upload and commit; then the late
-- collector deletes the name it was given and confirms: nothing it does
-- reaches the new object or the row.
update onepass_mailbox.blobs set gc_taken_at = now() - interval '61 minutes'
where mailbox_id = onepass_test.mbx('A') and sha256 = onepass_test.sha(2);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' and needs_upload
            and object_name <> (select object_name from t_take where name = 'sha2_second')
     from onepass_test.announce('a', 'A', array[onepass_test.sha(2)], array[20000])),
    'announce_after_an_expired_take_revives_the_blob');
reset role;
select onepass_test.ok(
    (select b.state = 1 and b.gc_taken_at is null and b.gc_take is null and b.orphaned_at is null
            and b.gen > (select gen from t_take where name = 'sha2_second')
     from onepass_test.blob('A', onepass_test.sha(2)) b),
    'revive_bumps_the_generation');
select onepass_test.object('A', onepass_test.sha(2), 20000);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' from onepass_test.put_blob('a', 'A', 7, null, onepass_test.sha(2), 20000)),
    'commit_of_the_revived_blob_is_applied');
reset role;
delete from storage.objects where name = (select object_name from t_take where name = 'sha2_second');
set local role onepass_mailbox_janitor;
select onepass_mailbox.gc_done(onepass_test.mbx('A'), onepass_test.sha(2),
    (select gen from t_take where name = 'sha2_second'), (select take from t_take where name = 'sha2_second'));
reset role;
select onepass_test.ok(
    exists (select 1 from storage.objects where name = onepass_test.oname('A', onepass_test.sha(2)))
    and (select b.refs = 1 and b.state = 2 from onepass_test.blob('A', onepass_test.sha(2)) b),
    'late_collector_leaves_the_new_generation_intact');
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select status = 'ok' and object_name = onepass_test.oname('A', onepass_test.sha(2)) and size = 20000
     from onepass_test.lookup('a', 'A', array[onepass_test.sha(2)])),
    'lookup_names_the_current_generation');
reset role;
set local role onepass_mailbox_janitor;
select onepass_test.throws($$select * from onepass_mailbox.gc_take(0)$$, '22023', 'gc_take_limit_zero_refused');
select onepass_test.throws(
    $$select * from onepass_test.announce('a', 'A', array[onepass_test.sha(1)], array[30000])$$, '42501',
    'janitor_cannot_announce');
reset role;

-- ----------------------------------------------------------------- quota

-- Q holds 50 000 bytes: announced blobs nobody references yet count too.
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok')
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(11), onepass_test.sha(12)], array[20000, 20000])),
    'announce_within_the_quota');
select onepass_test.answers(
    $$select * from onepass_test.announce('q', 'Q', array[onepass_test.sha(13)], array[20000])$$,
    'quota', 'announce_over_the_quota_refused');
select onepass_test.ok(
    (select bool_and(status = 'ok')
     from onepass_test.announce('q', 'Q', array[onepass_test.sha(12)], array[20000])),
    'announce_again_of_a_counted_blob_passes');
reset role;
select onepass_test.ok(
    (select count(*) = 2 from onepass_mailbox.blobs where mailbox_id = onepass_test.mbx('Q')),
    'refused_announce_recorded_nothing');
-- Committed, a blob counts through its record: still 40 000 for the two.
select onepass_test.object('Q', onepass_test.sha(11), 20000);
select onepass_test.object('Q', onepass_test.sha(12), 20000);
set local role onepass_mailbox_api;
select onepass_test.ok(
    (select bool_and(status = 'ok') from onepass_test.commit('q', 'Q', array[1, 1]::smallint[],
        array[onepass_test.rid(1), onepass_test.rid(2)], array[1, 1]::bigint[], array[1, 1]::smallint[],
        array[null, null]::bigint[], array[null, null]::bytea[], array[onepass_test.sha(11), onepass_test.sha(12)],
        array[20000, 20000])),
    'commit_of_two_announced_blobs');
select onepass_test.answers(
    $$select * from onepass_test.announce('q', 'Q', array[onepass_test.sha(13)], array[20000])$$,
    'quota', 'referenced_blobs_count_through_bytes_used');
select onepass_test.answers(
    $$select * from onepass_test.put_blob('q', 'Q', 3, null, onepass_test.sha(12), 20000)$$,
    'quota', 'blob_commit_over_the_quota_refused');
reset role;
select onepass_test.ok(
    (select bytes_used = 40000 and records_count = 2 from onepass_mailbox.mailboxes where id = onepass_test.mbx('Q'))
    and (select b.refs = 1 from onepass_test.blob('Q', onepass_test.sha(12)) b),
    'blob_commit_over_the_quota_moved_no_count');

-- ------------------------------------------------------------------ plans

-- The largest announce and lookup (1 000 blobs) on a mailbox that already
-- holds 20 000 blobs and their objects: planned with the arrays in hand.
insert into onepass_mailbox.blobs (mailbox_id, sha256, size, state, refs)
select onepass_test.mbx('P'), onepass_test.sha(100000 + i), 20000, 2, 1 from generate_series(1, 20000) i;
insert into storage.objects (bucket_id, name, metadata)
select 'onepass-mailbox', encode(b.mailbox_id, 'hex') || '/' || encode(b.sha256, 'hex') || '.' || b.gen,
       '{"size": 20000}'::jsonb
from onepass_mailbox.blobs b where b.mailbox_id = onepass_test.mbx('P');
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, size, blob_sha256)
select onepass_test.mbx('P'), 2, onepass_test.rid(i), 1, i, 20000, onepass_test.sha(100000 + i) from generate_series(1, 20000) i;
update onepass_mailbox.mailboxes set next_seq = 20001, records_count = 20000, bytes_used = 400000000, plan = 'selfhost'
where id = onepass_test.mbx('P');
analyze onepass_mailbox.blobs;
analyze onepass_mailbox.records;
analyze storage.objects;

create temporary table t_clock (name text primary key, ms double precision) on commit drop;
grant all on t_clock to public;
create function onepass_test.timed(name text, stmt text) returns bigint language plpgsql volatile as $$
declare
    t0 timestamptz := clock_timestamp();
    n bigint;
begin
    n := onepass_test.row_count(stmt);
    insert into t_clock values (name, extract(epoch from clock_timestamp() - t0) * 1000);
    return n;
end
$$;
grant execute on function onepass_test.timed(text, text) to public;

set local role onepass_mailbox_api;
select onepass_test.ok(
    onepass_test.timed('announce', $$select * from onepass_test.announce('p', 'P',
        array(select onepass_test.sha(100000 + i) from generate_series(19501, 20500) i), array_fill(20000, array[1000]))
        where status = 'ok'$$) = 1000,
    'largest_announce_batch_answers_every_blob');
select onepass_test.ok(
    onepass_test.timed('lookup', $$select * from onepass_test.lookup('p', 'P',
        array(select onepass_test.sha(100000 + i) from generate_series(19001, 20000) i)) where status = 'ok'$$) = 1000,
    'largest_lookup_batch_answers_every_blob');
reset role;
select onepass_test.ok(
    (select bool_and(ms < 2000) from t_clock) and (select count(*) = 2 from t_clock),
    'largest_blob_batches_take_under_two_seconds');
