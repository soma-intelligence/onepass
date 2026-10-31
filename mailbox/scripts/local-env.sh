#!/usr/bin/env bash
# Local secrets for the mailbox edge functions, after `supabase start`:
#
#   cd mailbox && npx --yes supabase@2.122.0 start
#   mailbox/scripts/local-env.sh
#   npx --yes supabase@2.122.0 functions serve mailbox --env-file supabase/.env.local
#
# Gives the LOGIN roles onepass_mailbox_api and onepass_mailbox_janitor
# (created by the schema migration without a password) fresh random
# passwords, and writes mailbox/supabase/.env.local (ignored by git,
# mode 600). Run it again after every `supabase start` on a new volume or
# `db reset`: it rotates both passwords. Local stack only: nothing here
# talks to a hosted project.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
supa="$root/mailbox/supabase"
config="$supa/config.toml"
out="$supa/.env.local"

project="$(awk -F'"' '/^project_id *=/ { print $2; exit }' "$config")"
api_port="$(awk '/^\[api\]/ { s = 1; next } /^\[/ { s = 0 } s && /^port *=/ { print $3; exit }' "$config")"
db_port="$(awk '/^\[db\]/ { s = 1; next } /^\[/ { s = 0 } s && /^port *=/ { print $3; exit }' "$config")"
db_container="supabase_db_${project}"

if ! docker inspect -f '{{.State.Running}}' "$db_container" 2>/dev/null | grep -q true; then
    echo "$db_container is not running: start the stack first (npx --yes supabase@2.122.0 start, from mailbox/)" >&2
    exit 1
fi

# The publishable (anon) key of the local stack, read from a service
# container: `supabase status` leaves it out while Auth is disabled.
publishable=""
for c in "supabase_kong_${project}" "supabase_storage_${project}" "supabase_rest_${project}"; do
    publishable="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null \
        | awk -F= '$1 == "ANON_KEY" || $1 == "SUPABASE_ANON_KEY" { sub(/^[^=]*=/, ""); print; exit }')" || true
    [ -n "$publishable" ] && break
done
if [ -z "$publishable" ]; then
    echo "could not read the local anon key from the stack containers" >&2
    exit 1
fi

api_pw="$(openssl rand -hex 24)"
janitor_pw="$(openssl rand -hex 24)"
ip_secret="$(openssl rand -hex 32)"

# Passwords go through stdin, never through the command line.
docker exec -i "$db_container" psql -q -X -v ON_ERROR_STOP=1 -U supabase_admin -d postgres >/dev/null <<SQL
alter role onepass_mailbox_api login password '${api_pw}';
alter role onepass_mailbox_janitor login password '${janitor_pw}';
SQL

umask 077
{
    echo "# Written by mailbox/scripts/local-env.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Local stack only."
    echo "# Seen from the edge runtime container (functions serve):"
    # `db` is the database's alias on the stack network (a container name
    # with underscores does not resolve from Deno).
    echo "MAILBOX_DB_URL=postgresql://onepass_mailbox_api:${api_pw}@db:5432/postgres"
    echo "MAILBOX_JANITOR_DB_URL=postgresql://onepass_mailbox_janitor:${janitor_pw}@db:5432/postgres"
    echo "MAILBOX_IP_HMAC_SECRET=${ip_secret}"
    echo "MAILBOX_OPEN_SIGNUP=true"
    echo "MAILBOX_PUBLISHABLE_KEY=${publishable}"
    echo "MAILBOX_REALTIME_URL=ws://127.0.0.1:${api_port}/realtime/v1"
    echo "MAILBOX_STORAGE_PUBLIC_URL=http://127.0.0.1:${api_port}"
    echo "# Seen from the host (deno test of the edge function against the stack):"
    echo "MAILBOX_TEST_DB_URL=postgresql://onepass_mailbox_api:${api_pw}@127.0.0.1:${db_port}/postgres"
} >"$out"
chmod 600 "$out"
echo "wrote $out"
