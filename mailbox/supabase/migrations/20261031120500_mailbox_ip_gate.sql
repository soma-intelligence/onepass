-- OnePass mailbox: per-IP gate in front of the signed routes (spec 4.9).
-- Follows the contract in the header of 20261031120100.
--
-- A signed route makes the edge function look up the credential's key
-- (credential_key) before it can check the signature, so an unsigned flood
-- would cost a table read each. The edge function therefore calls ip_gate
-- first, in the same transaction as credential_key, and commits it: every
-- request that reaches the lookup counts, whatever comes after. Requests
-- refused before (missing or malformed signature headers, skew, digest)
-- touch no table at all.
--
-- 1 200 a minute per IP key (ten free-plan credentials at full rate behind
-- one address). The key is SHA-256 applied three times to the raw IP key:
-- distinct from the raw key (the 60 a minute of create, enroll and the
-- rendezvous), SHA-256 once (the creation day bucket) and twice (the
-- rendezvous hour bucket), so no two windows share a row.
--
--   ip_gate(ip_key): a malformed IP key raises (OP400); otherwise 'ok', or
--   'rate_limited' with retry_after.

set role onepass_mailbox_owner;

create function onepass_mailbox.ip_gate(p_ip_key bytea)
returns table (status text, retry_after integer)
language plpgsql
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
    v_retry integer;
begin
    perform onepass_mailbox._enter(null);
    if p_ip_key is null or length(p_ip_key) <> 32 then
        perform onepass_mailbox._fail('malformed');
    end if;
    v_retry := onepass_mailbox._hit(
        extensions.digest(extensions.digest(extensions.digest(p_ip_key, 'sha256'), 'sha256'), 'sha256'),
        interval '1 minute', 1200);
    if v_retry is not null then
        return query select 'rate_limited'::text, v_retry;
        return;
    end if;
    return query select 'ok'::text, null::integer;
end
$$;

reset role;

revoke all on function onepass_mailbox.ip_gate(bytea) from public, anon, authenticated, service_role;
grant execute on function onepass_mailbox.ip_gate(bytea) to onepass_mailbox_api;
