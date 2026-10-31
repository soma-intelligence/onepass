-- Change pages bounded by their head (Task 7 review I2) and the api role's
-- time limits. A batch that commits between the head read and the rows read
-- of api_changes is simulated by a row whose seq is above next_seq - 1, as
-- the second statement's snapshot would show it.

create temporary table t_head (mailbox bytea, cred bytea) on commit drop;
grant all on t_head to public;

with k as (select extensions.digest('onepass-head-key', 'sha256') as pk)
insert into t_head
select c.mailbox_id, substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || k.pk, 'sha256') from 1 for 16)
from k, onepass_mailbox.api_create_mailbox(k.pk, onepass_test.nonce(900001), now(), null, '\x',
    decode(md5('head') || md5('head/'), 'hex'), true) c;

select onepass_test.ok(
    (select count(*) from t_head h,
         onepass_mailbox.api_commit(h.cred, onepass_test.nonce(900002), now(), h.mailbox,
             array[5, 5]::smallint[], array['\x000000000000000000000000000000a1', '\x000000000000000000000000000000a2']::bytea[],
             array[1, 1]::bigint[], array[1, 1]::smallint[], array[null, null]::bigint[],
             array['\x01', '\x02']::bytea[], array[null, null]::bytea[], array[1, 1]) c
     where c.status = 'ok') = 2,
    'changes_head_two_rows_committed');

-- The concurrent batch: seq 3 is visible, next_seq still says head 2.
set onepass.maintenance = 'on';
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, size, data)
select mailbox, 5, '\x000000000000000000000000000000a3', 1, 3, 1, '\x03' from t_head;
reset onepass.maintenance;

set local role onepass_mailbox_api;

select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[1, 2]::bigint[] and bool_and(c.head = 2)
     from t_head h,
          onepass_mailbox.api_changes(h.cred, onepass_test.nonce(900003), now(), h.mailbox, 0, 1000, false) c),
    'changes_incremental_page_never_above_its_head');
select onepass_test.ok(
    (select array_agg(c.seq order by c.seq) = array[1, 2]::bigint[]
     from t_head h,
          onepass_mailbox.api_changes(h.cred, onepass_test.nonce(900004), now(), h.mailbox, 0, 1000, true) c),
    'changes_full_page_never_above_its_head');
select onepass_test.ok(
    (select count(*) = 1 and bool_and(c.seq is null and c.head = 2)
     from t_head h,
          onepass_mailbox.api_changes(h.cred, onepass_test.nonce(900005), now(), h.mailbox, 2, 1000, false) c),
    'changes_page_at_head_is_empty');

reset role;

select onepass_test.ok(
    (select rolconfig @> array['statement_timeout=30s', 'lock_timeout=10s']
     from pg_roles where rolname = 'onepass_mailbox_api'),
    'api_role_has_statement_and_lock_timeouts');
