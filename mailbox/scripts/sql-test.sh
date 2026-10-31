#!/usr/bin/env bash
# Runs the mailbox SQL tests on a throwaway Postgres 17.
#
#   mailbox/scripts/sql-test.sh [test.sql...]
#
# With no argument, every mailbox/supabase/tests/*_test.sql runs. The server
# is created with initdb in a temporary directory and listens on TCP only, on
# a free local port: no Unix socket (the socket path of a deep temporary
# directory is too long on macOS). Order: tests/shims.sql (Supabase stand-ins
# and test helpers), migrations/*.sql by name, seed.sql, then each test file in
# its own transaction, rolled back at the end. Each assertion prints
# `ok <name>`; the first failure stops the run with a non-zero exit code.
#
# Postgres binaries: $PG_BIN if set, else Homebrew postgresql@17, else PATH.
# Temporary directory: under $SQL_TEST_TMP if set, else under $TMPDIR.
set -euo pipefail

# Postgres refuses to start on macOS without a valid locale in the environment.
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
supa="$root/mailbox/supabase"

if [ -z "${PG_BIN:-}" ]; then
    if [ -x /opt/homebrew/opt/postgresql@17/bin/postgres ]; then
        PG_BIN=/opt/homebrew/opt/postgresql@17/bin
    elif [ -x /usr/lib/postgresql/17/bin/postgres ]; then
        PG_BIN=/usr/lib/postgresql/17/bin
    else
        PG_BIN="$(dirname "$(command -v postgres)")"
    fi
fi
major="$("$PG_BIN/postgres" --version | sed -E 's/.* ([0-9]+)\..*/\1/')"
if [ "$major" != "17" ]; then
    echo "need Postgres 17, $PG_BIN/postgres is $major" >&2
    exit 1
fi

if [ "$#" -gt 0 ]; then
    tests=("$@")
else
    tests=()
    for f in "$supa"/tests/*_test.sql; do
        [ -e "$f" ] && tests+=("$f")
    done
fi

tmp="$(mktemp -d "${SQL_TEST_TMP:-${TMPDIR:-/tmp}}/onepass-sql.XXXXXX")"
data="$tmp/data"
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$data" -U postgres --auth=trust -E UTF8 --no-locale >"$tmp/initdb.log" 2>&1 || {
    cat "$tmp/initdb.log" >&2
    exit 1
}
"$PG_BIN/pg_ctl" -D "$data" -l "$tmp/server.log" -w \
    -o "-c listen_addresses=127.0.0.1 -c port=$port -c unix_socket_directories= -c fsync=off" \
    start >/dev/null || {
    cat "$tmp/server.log" >&2
    exit 1
}

run_psql() {
    PGOPTIONS='--client-min-messages=notice' \
        "$PG_BIN/psql" -X -q -h 127.0.0.1 -p "$port" -U postgres -d postgres \
        -v ON_ERROR_STOP=1 -v VERBOSITY=terse -o /dev/null "$@"
}

# psql prints notices as `NOTICE:  ok <name>`: keep the assertion lines as
# `ok <name>`, pass everything else through.
filter() {
    sed -E 's/^(psql:[^ ]+ )?NOTICE:  (ok .*)$/\2/'
}

load() {
    local f="$1"
    if ! run_psql -f "$f" 2>&1 | filter; then
        echo "FAILED loading $f" >&2
        exit 1
    fi
}

load "$supa/tests/shims.sql"
for m in "$supa"/migrations/*.sql; do
    [ -e "$m" ] || continue
    load "$m"
done
if [ -e "$supa/seed.sql" ]; then
    load "$supa/seed.sql"
fi

if [ "${#tests[@]}" -eq 0 ]; then
    echo "no test files" >&2
    exit 1
fi

for t in "${tests[@]}"; do
    echo "# $(basename "$t")"
    # Every test starts with open signup switched on in the database (the
    # fixtures create mailboxes without invites); open_signup_test.sql turns
    # it off itself to test the switch.
    if ! { printf 'begin;\ninsert into onepass_mailbox.settings (name, value) values ('\''open_signup'\'', '\''on'\'');\n\\i '\''%s'\''\nrollback;\n' "$t" | run_psql 2>&1 | filter; }; then
        echo "FAILED $(basename "$t")" >&2
        exit 1
    fi
done
