-- OnePass mailbox: maintenance, the collector and push queue functions of
-- the janitor, and the pg_cron schedule (spec 4.5, 4.7, 4.8, 4.9, 4.10,
-- 4.11).
--
-- maintenance(p_now), every minute by pg_cron as postgres. It runs as the
-- owner in maintenance mode (onepass.maintenance = 'on', which the policies
-- honour only when the session belongs to postgres or the janitor) and
-- leaves the setting empty when it returns. It purges:
--   nonces seen more than 600 s ago (twice the 300 s clock skew);
--   used tickets older than an hour (a ticket lives 900 s at most, so a
--     purged one is expired anyway);
--   rendezvous frames written more than 120 s ago, sessions started more
--     than 600 s ago (their frames go with them);
--   rate windows by their length, which the row does not carry: a window
--     start on neither an hour nor a day boundary is a minute window, purged
--     after 2 minutes; one on an hour boundary but not a day boundary is an
--     hour window (or a minute window that started on the hour), purged
--     after 2 hours; anything after 2 days. A minute window can therefore
--     linger up to 2 hours (on the hour) or 2 days (at midnight), harmless;
--   tombstones deleted more than 90 days ago, 50 000 at most a run, oldest
--     first. Each frees its quota cost (1 record and 128 bytes,
--     TOMBSTONE_COST of 20261031120200) and min_cursor rises to the highest
--     seq purged in the mailbox, never lower: an incremental fetch with
--     after >= min_cursor missed no purged tombstone, one below it did and
--     gets cursor_expired. min_cursor never passes a live row or a tombstone
--     younger than 90 days, so the head a full fetch keeps from its first
--     page stays valid. The mailboxes are locked like a commit locks them
--     (FOR NO KEY UPDATE, in id order), so a batch that read a tombstone
--     never counts it after the purge took it.
-- and marks every blob nobody references (refs = 0) as orphaned now; the
-- collector takes it 24 hours later.
--
-- Wake-up partitions. On Supabase, realtime.messages is partitioned by day
-- and the Realtime service creates the partitions ahead (today and the next
-- days, named messages_YYYY_MM_DD); without the partition of the day a
-- broadcast fails and realtime.send turns the error into a warning, so the
-- wake-up is lost in silence (clients still poll). maintenance checks today
-- and tomorrow (UTC) and raises a WARNING naming each missing day, visible
-- in the Postgres logs; it does not create partitions, which belong to the
-- Realtime service and its own retention.
--
-- Janitor (onepass_mailbox_janitor, the role of the mailbox-gc and
-- mailbox-push edge functions, Task 8). Internal functions, not request
-- entry points: they raise 22023 on a bad argument and return plain rows.
--   gc_take(limit): up to limit blobs orphaned for 24 hours, marked taken
--     (state 3), oldest first. A take never confirmed is handed out again an
--     hour later. The caller deletes each object through the Storage API,
--     then calls gc_done.
--   gc_done(mailbox, sha): deletes the blob row if it is still taken and
--     unreferenced (an announce may have taken it back meanwhile).
--   push_take(limit): removes up to limit mailboxes from the push queue,
--     oldest first, and returns the push tokens to wake: the active
--     credentials of each mailbox that is not frozen, without the one the
--     entry excludes (the author, when one credential wrote everything the
--     entry stands for). The queue row is read and deleted in one statement
--     under its row lock, so a commit that enqueues meanwhile either waits
--     and inserts a fresh entry or is taken whole: no wake-up is dropped
--     between reading and deleting (the "delete only if enqueued_at is
--     unchanged" rule of Task 8 holds by construction). A wake-up the edge
--     function fails to send is lost; clients still poll.
--   push_forget(credential, token): forgets a token the provider calls
--     stale, only if it is still the credential's token (it may have been
--     replaced since the push was sent).
--
-- Schedule (pg_cron, as postgres): maintenance every minute; mailbox-push
-- every 10 seconds and mailbox-gc every hour, by pg_net. The URL of the
-- functions (for example https://<project>.supabase.co/functions/v1) and the
-- key the functions check (Authorization: Bearer <key>) are read from Vault
-- at each run (vault.decrypted_secrets, names mailbox_functions_url and
-- mailbox_cron_key): until both are set, the jobs send nothing.

set role onepass_mailbox_owner;

-- Days (UTC) among p_now's and the next whose realtime.messages partition
-- is missing.
create function onepass_mailbox.wake_partitions_missing(p_now timestamptz)
returns setof date
language sql
stable
set search_path = ''
as $$
    select v.d
    from (values ((p_now at time zone 'UTC')::date), ((p_now at time zone 'UTC')::date + 1)) as v (d)
    where not exists (
        select 1 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'realtime' and c.relname = 'messages_' || to_char(v.d, 'YYYY_MM_DD'))
    order by v.d;
$$;

create function onepass_mailbox.maintenance(p_now timestamptz default now())
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_cutoff timestamptz;
    v_locked bytea[];
    v_day date;
begin
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    if not onepass_mailbox.in_maintenance() then
        raise exception 'maintenance runs as postgres or the janitor';
    end if;

    delete from onepass_mailbox.nonces where seen_at < p_now - interval '600 seconds';
    delete from onepass_mailbox.used_tickets where used_at < p_now - interval '1 hour';
    delete from onepass_mailbox.rdv_chunks where written_at < p_now - interval '120 seconds';
    delete from onepass_mailbox.rdv_sessions where created_at < p_now - interval '600 seconds';
    delete from onepass_mailbox.rate r
    where r.window_start < p_now - interval '2 days'
       or (r.window_start < p_now - interval '2 minutes' and r.window_start <> date_trunc('hour', r.window_start, 'UTC'))
       or (r.window_start < p_now - interval '2 hours' and r.window_start <> date_trunc('day', r.window_start, 'UTC'));

    -- Tombstones of 90 days: lock their mailboxes first, as a commit does.
    v_cutoff := p_now - interval '90 days';
    select array_agg(m.id order by m.id) into v_locked
    from (
        select m.id from onepass_mailbox.mailboxes m
        where m.id in (select t.mailbox_id from (
                           select r.mailbox_id from onepass_mailbox.records r
                           where r.deleted and r.deleted_at < v_cutoff
                           order by r.deleted_at limit 50000) t)
        order by m.id
        for no key update
    ) m;
    if v_locked is not null then
        with victims as (
            select r.mailbox_id, r.kind, r.id from onepass_mailbox.records r
            where r.deleted and r.deleted_at < v_cutoff and r.mailbox_id = any (v_locked)
            order by r.deleted_at
            limit 50000
        ), purged as (
            delete from onepass_mailbox.records r
            using victims v
            where r.mailbox_id = v.mailbox_id and r.kind = v.kind and r.id = v.id and r.deleted
            returning r.mailbox_id, r.seq
        ), per as (
            select p.mailbox_id, count(*)::integer as n, max(p.seq) as top from purged p group by p.mailbox_id
        )
        update onepass_mailbox.mailboxes m set
            records_count = m.records_count - per.n,
            bytes_used = m.bytes_used - 128 * per.n,
            min_cursor = greatest(m.min_cursor, per.top)
        from per
        where m.id = per.mailbox_id;
    end if;

    update onepass_mailbox.blobs set orphaned_at = p_now where refs = 0 and orphaned_at is null;

    for v_day in select * from onepass_mailbox.wake_partitions_missing(p_now) loop
        raise warning 'onepass_mailbox maintenance: realtime.messages has no partition for % (UTC), wake-ups that day are lost; the Realtime service creates them', v_day;
    end loop;

    perform set_config('onepass.maintenance', '', true);
end
$$;

-- --------------------------------------------------------------- janitor

create function onepass_mailbox.gc_take(p_limit integer)
returns table (mailbox_id bytea, sha256 bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    if p_limit is null or p_limit not between 1 and 1000 then
        raise exception using errcode = '22023', message = 'gc_take limit must be 1 to 1000';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    return query
    with t as (
        select b.mailbox_id, b.sha256 from onepass_mailbox.blobs b
        where b.refs = 0 and b.orphaned_at <= now() - interval '24 hours'
          and (b.state <> 3 or b.gc_taken_at < now() - interval '1 hour')
        order by b.orphaned_at
        limit p_limit
        for update skip locked
    )
    update onepass_mailbox.blobs b set state = 3, gc_taken_at = now()
    from t
    where b.mailbox_id = t.mailbox_id and b.sha256 = t.sha256
    returning b.mailbox_id, b.sha256;
    perform set_config('onepass.maintenance', '', true);
end
$$;

create function onepass_mailbox.gc_done(p_mailbox bytea, p_sha bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_mailbox is null or length(p_mailbox) <> 16 or p_sha is null or length(p_sha) <> 32 then
        raise exception using errcode = '22023', message = 'gc_done takes a 16 byte mailbox and a 32 byte hash';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    delete from onepass_mailbox.blobs b
    where b.mailbox_id = p_mailbox and b.sha256 = p_sha and b.state = 3 and b.refs = 0;
    perform set_config('onepass.maintenance', '', true);
end
$$;

create function onepass_mailbox.push_take(p_limit integer)
returns table (mailbox_id bytea, credential_id bytea, push_kind smallint, push_token bytea)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
    if p_limit is null or p_limit not between 1 and 1000 then
        raise exception using errcode = '22023', message = 'push_take limit must be 1 to 1000';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    return query
    with q as (
        select q.mailbox_id from onepass_mailbox.push_queue q
        order by q.enqueued_at, q.mailbox_id
        limit p_limit
        for update skip locked
    ), d as (
        delete from onepass_mailbox.push_queue p
        using q
        where p.mailbox_id = q.mailbox_id
        returning p.mailbox_id, p.exclude_credential
    )
    select d.mailbox_id, c.id, c.push_kind, c.push_token
    from d
    join onepass_mailbox.mailboxes m on m.id = d.mailbox_id and not m.frozen
    join onepass_mailbox.credentials c on c.mailbox_id = d.mailbox_id
    where c.revoked_at is null and c.push_token is not null
      and c.id is distinct from d.exclude_credential
    order by d.mailbox_id, c.id;
    perform set_config('onepass.maintenance', '', true);
end
$$;

create function onepass_mailbox.push_forget(p_credential bytea, p_token bytea)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_credential is null or length(p_credential) <> 16 or p_token is null then
        raise exception using errcode = '22023', message = 'push_forget takes a 16 byte credential and its token';
    end if;
    perform onepass_mailbox._enter(null);
    perform set_config('onepass.maintenance', 'on', true);
    update onepass_mailbox.credentials set push_kind = null, push_token = null
    where id = p_credential and push_token = p_token;
    perform set_config('onepass.maintenance', '', true);
end
$$;

reset role;

-- ------------------------------------------------------------- grants

revoke all on all functions in schema onepass_mailbox from public, anon, authenticated, service_role;

grant execute on function
    onepass_mailbox.gc_take(integer),
    onepass_mailbox.gc_done(bytea, bytea),
    onepass_mailbox.push_take(integer),
    onepass_mailbox.push_forget(bytea, bytea)
to onepass_mailbox_janitor;

-- -------------------------------------------------------------- schedule

-- pg_cron and pg_net come with Supabase (hosted, local and self-hosted
-- images). Elsewhere (the SQL test harness shims both) nothing is created.
do $$
begin
    if to_regnamespace('cron') is null
       and exists (select 1 from pg_available_extensions where name = 'pg_cron') then
        create extension if not exists pg_cron with schema pg_catalog;
    end if;
    if to_regnamespace('net') is null
       and exists (select 1 from pg_available_extensions where name = 'pg_net') then
        create extension if not exists pg_net with schema extensions;
    end if;
end
$$;

do $$
declare
    -- The edge function URL and key, read from Vault when the job runs.
    v_post text := $cmd$
select net.http_post(
    url := s.url || '/%s',
    headers := jsonb_build_object('Authorization', 'Bearer ' || s.key, 'Content-Type', 'application/json'),
    body := '{}'::jsonb,
    timeout_milliseconds := %s)
from (select (select decrypted_secret from vault.decrypted_secrets where name = 'mailbox_functions_url') as url,
             (select decrypted_secret from vault.decrypted_secrets where name = 'mailbox_cron_key') as key) s
where s.url is not null and s.key is not null
$cmd$;
begin
    if to_regprocedure('cron.schedule(text,text,text)') is null then
        raise warning 'pg_cron is not installed: schedule onepass_mailbox.maintenance() every minute, mailbox-push every 10 s and mailbox-gc every hour by other means';
        return;
    end if;
    perform cron.schedule('onepass-mailbox-maintenance', '* * * * *', 'select onepass_mailbox.maintenance()');
    perform cron.schedule('onepass-mailbox-push', '10 seconds', format(v_post, 'mailbox-push', 5000));
    perform cron.schedule('onepass-mailbox-gc', '17 * * * *', format(v_post, 'mailbox-gc', 30000));
end
$$;
