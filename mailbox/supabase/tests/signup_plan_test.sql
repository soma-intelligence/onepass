-- Task 21: configurable open signup plan and a global daily creation cap.

create temporary sequence sp_n start 920000;
grant usage on sequence sp_n to public;

create function onepass_test.sp_create(k text, invite text default null, label bytea default '\x') returns text language sql volatile as $$
    select status from onepass_mailbox.api_create_mailbox(
        decode(md5('sp-key/' || k) || md5('sp-key//' || k), 'hex'), onepass_test.nonce(nextval('sp_n')), now(),
        case when invite is null then null else convert_to(invite, 'UTF8') end, label,
        decode(md5('sp/' || k) || md5('sp//' || k), 'hex'), true)
$$;
grant execute on function onepass_test.sp_create(text, text, bytea) to public;

create function onepass_test.sp_plan(k text) returns text language sql stable as $$
    select m.plan from onepass_mailbox.mailboxes m
    join onepass_mailbox.credentials c on c.mailbox_id = m.id
    where c.public_key = decode(md5('sp-key/' || k) || md5('sp-key//' || k), 'hex')
$$;
grant execute on function onepass_test.sp_plan(text) to public;

create function onepass_test.sp_count() returns bigint language sql stable as $$
    select count(*) from onepass_mailbox.credentials where public_key in (
        select decode(md5('sp-key/' || k) || md5('sp-key//' || k), 'hex')
        from unnest(array['p1','p2','p3','c1','c2','c3','c4','f1','f2','i1']) k)
$$;
grant execute on function onepass_test.sp_count() to public;

insert into onepass_mailbox.invites (token_hash, plan, uses_left, expires_at)
values (extensions.digest('sp-inv', 'sha256'), 'selfhost', 5, now() + interval '1 day');
delete from onepass_mailbox.settings;
insert into onepass_mailbox.settings (name, value) values ('open_signup', 'on');

-- No plan row: selfhost.
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.sp_create('p1') = 'ok', 'open_signup_defaults_to_selfhost_creates');
reset role;
select onepass_test.ok(onepass_test.sp_plan('p1') = 'selfhost', 'open_signup_defaults_to_selfhost');

-- Configured plan.
insert into onepass_mailbox.settings (name, value) values ('open_signup_plan', 'free');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.sp_create('p2') = 'ok', 'open_signup_configured_plan_creates');
select onepass_test.ok(onepass_test.sp_create('i1', 'sp-inv') = 'ok', 'invite_plan_creates');
reset role;
select onepass_test.ok(onepass_test.sp_plan('p2') = 'free', 'open_signup_uses_configured_plan');
select onepass_test.ok(onepass_test.sp_plan('i1') = 'selfhost', 'invite_plan_wins');

-- Unknown plan: a plain error, no OP code.
update onepass_mailbox.settings set value = 'nonesuch' where name = 'open_signup_plan';
set local role onepass_mailbox_api;
select onepass_test.raises($$select onepass_test.sp_create('p3')$$, 'P0001', 'open_signup_plan nonesuch is not a plan',
    'unknown_plan_setting_is_a_bug');
reset role;
select onepass_test.ok(onepass_test.sp_plan('p3') is null, 'unknown_plan_setting_creates_nothing');
delete from onepass_mailbox.settings where name = 'open_signup_plan';

-- Daily cap of 2.
insert into onepass_mailbox.settings (name, value) values ('daily_create_cap', '2');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.sp_create('c1') = 'ok', 'daily_cap_first_creates');
-- A refused creation (bad label size) is not counted.
select onepass_test.ok(onepass_test.sp_create('f1', null, decode(repeat('00', 65), 'hex')) = 'malformed', 'failed_creation_malformed');
select onepass_test.ok(onepass_test.sp_create('c2') = 'ok', 'failed_creation_not_counted');
select onepass_test.ok(onepass_test.sp_create('c3') = 'retry', 'daily_cap_returns_retry');
select onepass_test.ok((select retry_after from onepass_mailbox.api_create_mailbox(
    decode(md5('sp-key/c4') || md5('sp-key//c4'), 'hex'), onepass_test.nonce(nextval('sp_n')), now(), null, '\x',
    decode(md5('sp/c4') || md5('sp//c4'), 'hex'), true)) is null, 'daily_cap_retry_has_no_retry_after');
reset role;
select onepass_test.ok(onepass_test.sp_plan('c3') is null and onepass_test.sp_plan('c4') is null, 'daily_cap_writes_nothing');
select onepass_test.ok(onepass_test.sp_count() = 5, 'daily_cap_total_created');
select onepass_test.ok((select count from onepass_mailbox.rate
    where key = extensions.digest('onepass/global-create'::bytea, 'sha256')) = 2, 'daily_cap_counter_is_two');

-- Raising the cap lets creation resume.
update onepass_mailbox.settings set value = '3' where name = 'daily_create_cap';
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.sp_create('c3') = 'ok', 'daily_cap_raised_creates');
reset role;
