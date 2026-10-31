-- Plans of spec 4.5. Written in maintenance: the plans table is read only
-- for the owner otherwise. `free` is the hosted default; `selfhost` is the
-- plan of open signup (MAILBOX_OPEN_SIGNUP=true), with high limits. The batch
-- size stays at the protocol's 20 000 operations on every plan.
set onepass.maintenance = 'on';

insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops)
values
    ('free', 268435456, 100000, 16, 120, 20000),
    ('selfhost', 1099511627776, 10000000, 256, 6000, 20000)
on conflict (plan) do update set
    max_bytes = excluded.max_bytes,
    max_records = excluded.max_records,
    max_credentials = excluded.max_credentials,
    req_per_min = excluded.req_per_min,
    max_commit_ops = excluded.max_commit_ops;

reset onepass.maintenance;
