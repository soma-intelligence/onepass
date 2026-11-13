-- Loaded by sql-test.sh just before migration 20261113120000, as the hosted
-- database stood when it was applied: the four plans of the seed before the
-- org plan existed.
select set_config('onepass.maintenance', 'on', false);
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops,
                                   max_children_shared, max_children_contact)
values
    ('free', 268435456, 100000, 16, 120, 20000, 16, 256),
    ('selfhost', 1099511627776, 10000000, 256, 6000, 20000, 1024, 4096),
    ('shared', 134217728, 100000, 80, 600, 20000, 0, 0),
    ('contact', 16777216, 2000, 4, 120, 2000, 0, 0);
select set_config('onepass.maintenance', '', false);
