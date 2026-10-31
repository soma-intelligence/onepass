-- Open signup is a database switch (Task 8): the edge's word alone does not
-- open signup. Calls run as onepass_mailbox_api.

create temporary sequence os_n start 910000;
grant usage on sequence os_n to public;

create function onepass_test.try_open(k text, edge_open boolean) returns text language sql volatile as $$
    select status from onepass_mailbox.api_create_mailbox(
        decode(md5('os-key/' || k) || md5('os-key//' || k), 'hex'), onepass_test.nonce(nextval('os_n')), now(), null, '\x',
        decode(md5(k) || md5(k || '/'), 'hex'), edge_open)
$$;
grant execute on function onepass_test.try_open(text, boolean) to public;

set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.try_open('on1', true) = 'ok', 'open_signup_row_on_edge_on_creates');
select onepass_test.ok(onepass_test.try_open('on2', false) = 'malformed', 'open_signup_row_on_edge_off_needs_invite');
reset role;

delete from onepass_mailbox.settings where name = 'open_signup';
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.try_open('off1', true) = 'malformed', 'open_signup_edge_on_without_row_needs_invite');
select onepass_test.ok(onepass_test.try_open('off2', false) = 'malformed', 'open_signup_both_off_needs_invite');
reset role;

insert into onepass_mailbox.settings (name, value) values ('open_signup', 'off');
set local role onepass_mailbox_api;
select onepass_test.ok(onepass_test.try_open('off3', true) = 'malformed', 'open_signup_row_off_needs_invite');

-- The api role can neither read nor write settings, and setting the
-- session variables does not help.
select onepass_test.throws($$select * from onepass_mailbox.settings$$, '42501', 'settings_not_readable_by_api');
select onepass_test.throws($$update onepass_mailbox.settings set value = 'on'$$, '42501', 'settings_not_writable_by_api');
select onepass_test.throws($$insert into onepass_mailbox.settings values ('x', 'y')$$, '42501', 'settings_not_insertable_by_api');
set local onepass.maintenance = 'on';
select onepass_test.ok(onepass_test.try_open('off4', true) = 'malformed', 'open_signup_session_variable_does_not_open');
reset role;
