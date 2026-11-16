#!/usr/bin/env bash
# Runs one heavy command (a workspace cargo build or test, build-core.sh,
# xcodebuild, swift test) at a time on this Mac, whatever the checkout or
# session that starts it:
#
#   scripts/heavy.sh <command> [args...]
#
# The queue is a flock(2) on $ONEPASS_HEAVY_LOCK (default
# ~/Library/Caches/onepass-heavy.lock), taken through perl since macOS ships
# no flock binary. The kernel drops the lock when its holder dies, so a
# crashed or killed run never leaves a stale lock behind. While it waits,
# the script prints who holds the lock (pid, checkout, command).
#
# - ONEPASS_NO_QUEUE=1 runs the command at once, without the lock.
# - Nested calls run at once: the outer call already holds the lock.
# - The command does not inherit the lock's file descriptor, so a daemon it
#   starts (the sccache server, Xcode's build service) never keeps the lock.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 64
fi

if [ "${ONEPASS_NO_QUEUE:-0}" = 1 ] || [ "${ONEPASS_HEAVY_HELD:-}" = 1 ]; then
  exec "$@"
fi

LOCK="${ONEPASS_HEAVY_LOCK:-$HOME/Library/Caches/onepass-heavy.lock}"
INFO="$LOCK.holder"
mkdir -p "$(dirname "$LOCK")"

exec 9>>"$LOCK"
# perl shares bash's open file description on fd 9: the lock outlives perl
# and is held until this script exits.
perl -MFcntl=:flock -e '
  open(my $fh, ">&=", 9) or die "heavy: fd 9: $!\n";
  my ($info, $last) = (shift, "");
  until (flock($fh, LOCK_EX | LOCK_NB)) {
    my $holder = "an unknown process";
    if (open(my $in, "<", $info)) { local $/; $holder = <$in> // $holder; chomp $holder; }
    if ($holder ne $last) { print STDERR "heavy: waiting for $holder\n"; $last = $holder; }
    sleep 2;
  }
' "$INFO"

printf 'pid %s in %s since %s: %s\n' "$$" "$PWD" "$(date '+%H:%M:%S')" "$*" > "$INFO"
export ONEPASS_HEAVY_HELD=1
status=0
"$@" 9>&- || status=$?
exit "$status"
