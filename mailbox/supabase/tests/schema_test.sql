-- Table shapes and constraints of spec 4.5. Runs as the harness superuser
-- (row level security does not apply), inside a transaction the harness
-- rolls back.

-- Fixtures: one mailbox, one credential.
insert into onepass_mailbox.mailboxes (id, plan)
values (decode(repeat('a1', 16), 'hex'), 'free');

insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
select substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16),
       decode(repeat('a1', 16), 'hex'), pk, '\x'::bytea
from (select decode(repeat('42', 32), 'hex') as pk) k;

-- Identifier sizes.
select onepass_test.throws(
    $$insert into onepass_mailbox.mailboxes (id, plan) values (decode(repeat('b1', 15), 'hex'), 'free')$$,
    '23514', 'mailbox_id_of_15_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.mailboxes (id, plan, wake_topic) values (decode(repeat('b1', 16), 'hex'), 'free', decode(repeat('b2', 17), 'hex'))$$,
    '23514', 'wake_topic_of_17_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c1', 15), 'hex'), 1, 1, false, 1, '\x01')$$,
    '23514', 'record_id_of_15_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
      values (decode(repeat('d1', 16), 'hex'), decode(repeat('a1', 16), 'hex'), decode(repeat('43', 32), 'hex'), '\x')$$,
    '23514', 'credential_id_not_derived_from_key_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
      select substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16),
             decode(repeat('a1', 16), 'hex'), pk, '\x'
      from (select decode(repeat('44', 31), 'hex') as pk) k$$,
    '23514', 'public_key_of_31_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.credentials (id, mailbox_id, public_key, label)
      select substring(extensions.digest('onepass/mailbox-credential-id/v1'::bytea || pk, 'sha256') from 1 for 16),
             decode(repeat('a1', 16), 'hex'), pk, decode(repeat('00', 65), 'hex')
      from (select decode(repeat('45', 32), 'hex') as pk) k$$,
    '23514', 'label_of_65_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.nonces (credential_id, mailbox_id, nonce)
      select id, mailbox_id, decode(repeat('e1', 15), 'hex') from onepass_mailbox.credentials limit 1$$,
    '23514', 'nonce_of_15_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.used_tickets (ticket_hash, mailbox_id) values (decode(repeat('f1', 31), 'hex'), decode(repeat('a1', 16), 'hex'))$$,
    '23514', 'ticket_hash_of_31_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.rate (key, window_start) values (decode(repeat('f2', 16), 'hex'), now())$$,
    '23514', 'rate_key_of_16_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at) values (decode(repeat('f3', 33), 'hex'), 'free', 1, now())$$,
    '23514', 'invite_hash_of_33_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.rdv_sessions (session_id) values (decode(repeat('f4', 15), 'hex'))$$,
    '23514', 'rdv_session_of_15_bytes_refused');

-- Record kinds.
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 0, decode(repeat('c2', 16), 'hex'), 1, 1, false, 1, '\x01')$$,
    '23514', 'kind_0_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 256, decode(repeat('c2', 16), 'hex'), 1, 1, false, 1, '\x01')$$,
    '23514', 'kind_256_refused');

-- Tombstones and live rows.
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, true, 0, '\x01')$$,
    '23514', 'tombstone_with_data_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, blob_sha256)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, true, 0, decode(repeat('ab', 32), 'hex'))$$,
    '23514', 'tombstone_with_blob_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, false, 0)$$,
    '23514', 'live_row_without_body_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data, blob_sha256)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, false, 1, '\x01', decode(repeat('ab', 32), 'hex'))$$,
    '23514', 'live_row_with_data_and_blob_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, false, 16385, extensions.gen_random_bytes(1024) || decode(repeat('00', 15361), 'hex'))$$,
    '23514', 'inline_data_of_16385_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, blob_sha256)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, false, 921601, decode(repeat('ab', 32), 'hex'))$$,
    '23514', 'record_of_921601_bytes_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, blob_sha256)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c3', 16), 'hex'), 1, 1, false, 20000, decode(repeat('ab', 31), 'hex'))$$,
    '23514', 'blob_sha_of_31_bytes_refused');

-- The accepted shapes, at their limits.
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c4', 16), 'hex'), 1, 1, false, 16384, decode(repeat('00', 16384), 'hex'));
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, blob_sha256)
values (decode(repeat('a1', 16), 'hex'), 255, decode(repeat('c5', 16), 'hex'), 1, 2, false, 921600, decode(repeat('ab', 32), 'hex'));
insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size)
values (decode(repeat('a1', 16), 'hex'), 2, decode(repeat('c6', 16), 'hex'), 1, 3, true, 0);
select onepass_test.ok(
    (select count(*) from onepass_mailbox.records where mailbox_id = decode(repeat('a1', 16), 'hex')) = 3,
    'inline_16384_blob_921600_and_tombstone_accepted');

-- One seq per mailbox: the change feed has no duplicate.
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c7', 16), 'hex'), 1, 2, false, 1, '\x01')$$,
    '23505', 'seq_unique_per_mailbox');
select onepass_test.throws(
    $$insert into onepass_mailbox.records (mailbox_id, kind, id, version, seq, deleted, size, data)
      values (decode(repeat('a1', 16), 'hex'), 1, decode(repeat('c4', 16), 'hex'), 2, 9, false, 1, '\x01')$$,
    '23505', 'record_key_unique_per_mailbox');

-- Mailbox defaults: random id, topic and incarnation, cursors at their start.
insert into onepass_mailbox.mailboxes (plan) values ('free');
select onepass_test.ok(
    (select bool_and(length(id) = 16 and length(wake_topic) = 16 and next_seq = 1 and min_cursor = 0
                     and bytes_used = 0 and records_count = 0 and not frozen and incarnation >= 0)
     from onepass_mailbox.mailboxes),
    'mailbox_defaults');
select onepass_test.throws(
    $$insert into onepass_mailbox.mailboxes (plan) values ('gold')$$,
    '23503', 'mailbox_plan_must_exist');

-- Blob and rendezvous shapes.
select onepass_test.throws(
    $$insert into onepass_mailbox.blobs (mailbox_id, sha256, size, state) values (decode(repeat('a1', 16), 'hex'), decode(repeat('ab', 32), 'hex'), 20000, 9)$$,
    '23514', 'blob_state_out_of_range_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.blobs (mailbox_id, sha256, size, state) values (decode(repeat('a1', 16), 'hex'), decode(repeat('ab', 32), 'hex'), 921601, 1)$$,
    '23514', 'blob_over_900_kib_refused');
insert into onepass_mailbox.rdv_sessions (session_id) values (decode(repeat('f5', 16), 'hex'));
select onepass_test.throws(
    $$insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data) values (decode(repeat('f5', 16), 'hex'), 2, 0, '\x01')$$,
    '23514', 'rdv_dir_2_refused');
select onepass_test.throws(
    $$insert into onepass_mailbox.rdv_chunks (session_id, dir, n, data) values (decode(repeat('f5', 16), 'hex'), 0, 0, decode(repeat('00', 1048577), 'hex'))$$,
    '23514', 'rdv_chunk_over_1_mib_refused');

-- Plans of spec 4.5.
select onepass_test.ok(
    (select max_bytes = 268435456 and max_records = 100000 and max_credentials = 16
            and req_per_min = 120 and max_commit_ops = 20000
     from onepass_mailbox.plans where plan = 'free'),
    'plan_free_values');
select onepass_test.ok(
    (select max_bytes >= 268435456 and max_records >= 100000 and max_credentials >= 16
            and req_per_min >= 120 and max_commit_ops = 20000
     from onepass_mailbox.plans where plan = 'selfhost'),
    'plan_selfhost_present_with_high_limits');
