-- plans and settings had two permissive SELECT policies for the owner: the
-- read policy (true) and the FOR ALL maintenance policy. Postgres evaluates
-- both for every read; the Supabase performance advisor flags it
-- (multiple_permissive_policies). Reads stay open to the owner through the
-- read policy alone; the maintenance policy is split into INSERT, UPDATE
-- and DELETE, with the same check. Nothing a role can do changes.

drop policy plans_maintenance on onepass_mailbox.plans;
create policy plans_maintenance_insert on onepass_mailbox.plans
    for insert to onepass_mailbox_owner
    with check ((select onepass_mailbox.in_maintenance()));
create policy plans_maintenance_update on onepass_mailbox.plans
    for update to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()))
    with check ((select onepass_mailbox.in_maintenance()));
create policy plans_maintenance_delete on onepass_mailbox.plans
    for delete to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()));

drop policy settings_maintenance on onepass_mailbox.settings;
create policy settings_maintenance_insert on onepass_mailbox.settings
    for insert to onepass_mailbox_owner
    with check ((select onepass_mailbox.in_maintenance()));
create policy settings_maintenance_update on onepass_mailbox.settings
    for update to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()))
    with check ((select onepass_mailbox.in_maintenance()));
create policy settings_maintenance_delete on onepass_mailbox.settings
    for delete to onepass_mailbox_owner
    using ((select onepass_mailbox.in_maintenance()));
