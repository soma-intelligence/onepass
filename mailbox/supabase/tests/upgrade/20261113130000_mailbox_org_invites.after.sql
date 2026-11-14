-- Loaded by sql-test.sh just after migration 20261113130000: the migration
-- writes the managed plan itself, so a database it upgrades needs no seed
-- run. Then the rows of the before file are removed, so seed.sql loads on
-- the same state as a fresh database.
select onepass_test.ok(
    (select max_bytes = 268435456 and max_records = 100000 and max_credentials = 32 and req_per_min = 120
            and max_commit_ops = 20000 and max_children_shared = 16 and max_children_contact = 256
     from onepass_mailbox.plans where plan = 'managed'),
    'migration_inserts_managed_plan');
select onepass_test.ok(
    (select max_credentials = 16 from onepass_mailbox.plans where plan = 'free')
    and (select max_credentials = 4096 from onepass_mailbox.plans where plan = 'org')
    and (select count(*) = 6 from onepass_mailbox.plans),
    'migration_leaves_other_plans');
select onepass_test.ok(current_setting('onepass.maintenance', true) is distinct from 'on',
    'migration_leaves_maintenance_off');
select set_config('onepass.maintenance', 'on', false);
delete from onepass_mailbox.plans;
select set_config('onepass.maintenance', '', false);
