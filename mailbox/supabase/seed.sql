-- Plans of spec 4.5 and of the sharing spec 13.6. Written in maintenance:
-- the plans table is read only for the owner otherwise. `free` is the hosted
-- default; `selfhost` is the plan of open signup (MAILBOX_OPEN_SIGNUP=true),
-- with high limits. `shared` (vaults and families) and `contact` are the
-- plans of child mailboxes (api_create_child); max_children_* cap the live
-- children of each kind a mailbox on the plan holds (children hold none).
-- Migration 20261031235000 writes the same child rows and caps on a
-- database it upgrades; this file is for a fresh one.
-- The batch size stays at the protocol's 20 000 operations on every plan
-- but contact.
set onepass.maintenance = 'on';

insert into onepass_mailbox.plans (plan, max_bytes, max_records, max_credentials, req_per_min, max_commit_ops,
                                   max_children_shared, max_children_contact)
values
    ('free', 268435456, 100000, 16, 120, 20000, 16, 256),
    ('selfhost', 1099511627776, 10000000, 256, 6000, 20000, 1024, 4096),
    ('shared', 134217728, 100000, 80, 600, 20000, 0, 0),
    ('contact', 16777216, 2000, 4, 120, 2000, 0, 0)
on conflict (plan) do update set
    max_bytes = excluded.max_bytes,
    max_records = excluded.max_records,
    max_credentials = excluded.max_credentials,
    req_per_min = excluded.req_per_min,
    max_commit_ops = excluded.max_commit_ops,
    max_children_shared = excluded.max_children_shared,
    max_children_contact = excluded.max_children_contact;

reset onepass.maintenance;
