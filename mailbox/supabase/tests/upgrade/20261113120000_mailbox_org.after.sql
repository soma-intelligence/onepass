-- Loaded by sql-test.sh just after migration 20261113120000: the migration
-- writes the org plan itself, so a database it upgrades needs no seed run.
-- Then the rows of the before file are removed, so seed.sql loads on the
-- same state as a fresh database.
select onepass_test.ok(
    (select max_bytes = 17179869184 and max_records = 200000 and max_credentials = 4096 and req_per_min = 600
            and max_commit_ops = 20000 and max_children_shared = 0 and max_children_contact = 0
     from onepass_mailbox.plans where plan = 'org'),
    'migration_inserts_org_plan');
select onepass_test.ok(
    (select max_bytes = 268435456 and max_children_shared = 16 from onepass_mailbox.plans where plan = 'free')
    and (select max_records = 2000 and max_commit_ops = 2000 from onepass_mailbox.plans where plan = 'contact'),
    'migration_leaves_other_plans');
select onepass_test.ok(current_setting('onepass.maintenance', true) is distinct from 'on',
    'migration_leaves_maintenance_off');
select set_config('onepass.maintenance', 'on', false);
delete from onepass_mailbox.plans;
select set_config('onepass.maintenance', '', false);
