-- Loaded by sql-test.sh just before migration 20261031235000, as the
-- hosted database stood when it was applied: the free and selfhost plans of
-- the old seed, no shared or contact plan, and the shared plan of a
-- previous run with values of its own (the migration must not overwrite it).
select set_config('onepass.maintenance', 'on', false);
insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values
    ('free', 268435456, 100000, 16, 120, 20000),
    ('selfhost', 1099511627776, 10000000, 256, 6000, 20000),
    ('shared', 1, 1, 1, 1, 1);
select set_config('onepass.maintenance', '', false);
