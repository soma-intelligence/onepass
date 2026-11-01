-- Loaded by sql-test.sh just after migration 20261031235000: the migration
-- writes the child plans itself, so a database it upgrades needs no seed
-- run. A plan row already there is left alone; free and selfhost get their
-- child caps (the update runs only while both are still 0, so caps set by
-- hand in between survive a rerun of the block). Then the rows of the before file
-- are removed, so seed.sql loads on the same state as a fresh database.
select onepass_test.ok(
    (select max_children_shared = 16 and max_children_contact = 256 from onepass_mailbox.plans where plan = 'free')
    and (select max_children_shared = 1024 and max_children_contact = 4096 from onepass_mailbox.plans where plan = 'selfhost'),
    'migration_sets_parent_child_caps');
select onepass_test.ok(
    (select max_bytes = 16777216 and max_records = 2000 and max_credentials = 4 and req_per_min = 120
            and max_commit_ops = 2000 and max_children_shared = 0 and max_children_contact = 0
     from onepass_mailbox.plans where plan = 'contact'),
    'migration_inserts_contact_plan');
select onepass_test.ok(
    (select max_bytes = 1 and max_records = 1 from onepass_mailbox.plans where plan = 'shared'),
    'migration_keeps_an_existing_plan_row');
select onepass_test.ok(current_setting('onepass.maintenance', true) is distinct from 'on',
    'migration_leaves_maintenance_off');
select set_config('onepass.maintenance', 'on', false);
delete from onepass_mailbox.plans;
select set_config('onepass.maintenance', '', false);
