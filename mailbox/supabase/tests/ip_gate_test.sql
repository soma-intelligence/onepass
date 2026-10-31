-- Per-IP gate in front of the signed routes (spec 4.9): 1 200 requests a
-- minute per IP key, on its own bucket (SHA-256 three times over the raw
-- key), so signed traffic never eats the 60 a minute of create, enroll and
-- the rendezvous. Calls run as onepass_mailbox_api; the harness rolls back.

create function onepass_test.gip(name text) returns bytea language sql immutable as $$
    select decode(md5(name) || md5(name || '/'), 'hex') $$;
grant execute on all functions in schema onepass_test to public;

set local role onepass_mailbox_api;

select onepass_test.raises(
    $$select * from onepass_mailbox.ip_gate('\x0102')$$,
    'OP400', 'malformed', 'ip_gate_with_malformed_key_raises');
select onepass_test.raises(
    $$select * from onepass_mailbox.ip_gate(null)$$,
    'OP400', 'malformed', 'ip_gate_without_key_raises');

select onepass_test.answers(
    $$select * from onepass_mailbox.ip_gate(onepass_test.gip('a'))$$, 'ok', 'ip_gate_first_call_ok');

do $$
declare
    r record;
begin
    for i in 2..1200 loop
        select * into r from onepass_mailbox.ip_gate(onepass_test.gip('a'));
        if r.status <> 'ok' then
            raise exception 'not ok ip_gate_1200_a_minute (call % got %)', i, r.status;
        end if;
    end loop;
    raise notice 'ok ip_gate_1200_a_minute';
    select * into r from onepass_mailbox.ip_gate(onepass_test.gip('a'));
    perform onepass_test.ok(r.status = 'rate_limited' and r.retry_after between 1 and 60,
        'ip_gate_1201st_is_rate_limited_with_retry_after');
end
$$;

select onepass_test.answers(
    $$select * from onepass_mailbox.ip_gate(onepass_test.gip('b'))$$, 'ok', 'ip_gate_per_ip_key');

-- The credential-less minute bucket of the same IP is untouched.
select onepass_test.answers(
    $$select * from onepass_mailbox.rdv_close(onepass_test.nonce(77), onepass_test.gip('a'))$$,
    'ok', 'ip_gate_does_not_share_the_rendezvous_bucket');

reset role;
select onepass_test.ok(
    (select count(*) from onepass_mailbox.rate r where r.key = onepass_test.gip('a')) = 1
    and (select r.count from onepass_mailbox.rate r where r.key = onepass_test.gip('a')) = 1,
    'ip_gate_leaves_the_raw_key_bucket_alone');
select onepass_test.ok(
    (select r.count from onepass_mailbox.rate r
     where r.key = extensions.digest(extensions.digest(extensions.digest(onepass_test.gip('a'), 'sha256'), 'sha256'), 'sha256')) = 1201,
    'ip_gate_counts_on_the_triple_hash_key');
