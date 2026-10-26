#!/usr/bin/env bash
# Runs the ProVerif models and checks every result against formal/expected.txt.
#
# Usage: formal/run.sh [file.pv ...]
#   No argument: every formal/proverif/*.pv.
#
# Environment:
#   PROVERIF      ProVerif binary (default: proverif in PATH, then ~/.local/bin/proverif)
#   FORMAL_TIMEOUT  seconds per file (default 300)
#
# Exit status 1 on any mismatch: a result different from the expected one,
# "cannot be proved", a timeout or a ProVerif error, a RESULT line absent from
# expected.txt, or an expected.txt line (for a file that was run) without a
# result. Writes docs/security/formal/results.md on every run.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMAL="$ROOT/formal"
LIB="$FORMAL/proverif/common.pvl"
EXPECTED="$FORMAL/expected.txt"
OUT="$FORMAL/out"
RESULTS_MD="$ROOT/docs/security/formal/results.md"
LIMIT="${FORMAL_TIMEOUT:-300}"

if [ -z "${PROVERIF:-}" ]; then
  if command -v proverif >/dev/null 2>&1; then
    PROVERIF="proverif"
  elif [ -x "$HOME/.local/bin/proverif" ]; then
    PROVERIF="$HOME/.local/bin/proverif"
  else
    echo "formal: proverif not found (set PROVERIF)" >&2
    exit 1
  fi
fi

# Portable timeout: GNU timeout, then gtimeout (Homebrew coreutils), then a
# perl alarm (SIGALRM survives exec). Exit status 124 or 142 means timed out.
run_limited() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$LIMIT" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$LIMIT" "$@"
  else
    perl -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$LIMIT" "$@"
  fi
}

# Milliseconds since the epoch, portable (macOS date has no %N).
now_ms() {
  perl -MTime::HiRes=time -e 'printf("%d\n", time() * 1000)'
}

if [ ! -f "$EXPECTED" ]; then
  echo "formal: $EXPECTED missing" >&2
  exit 1
fi

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  FILES=()
  for f in "$FORMAL"/proverif/*.pv; do
    [ -e "$f" ] && FILES+=("$f")
  done
fi
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "formal: no model to run" >&2
  exit 1
fi

mkdir -p "$OUT" "$(dirname "$RESULTS_MD")"
# One line per query: file<TAB>query<TAB>outcome<TAB>seconds
ACTUAL="$OUT/actual.tsv"
: > "$ACTUAL"
RAN="$OUT/ran.txt"
: > "$RAN"

for f in "${FILES[@]}"; do
  base="$(basename "$f")"
  log="$OUT/${base%.pv}.log"
  echo "$base" >> "$RAN"
  printf 'formal: %s ... ' "$base"
  t0="$(now_ms)"
  run_limited "$PROVERIF" -lib "$LIB" "$f" > "$log" 2>&1
  rc=$?
  t1="$(now_ms)"
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf("%.1f", (b - a) / 1000) }')"
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 142 ]; then
    echo "timeout after ${LIMIT}s"
    printf '%s\t%s\t%s\t%s\n' "$base" "*" "timeout" "$secs" >> "$ACTUAL"
    continue
  fi
  if [ "$rc" -ne 0 ]; then
    echo "proverif error (exit $rc), see $log"
    tail -n 20 "$log" >&2
    printf '%s\t%s\t%s\t%s\n' "$base" "*" "error" "$secs" >> "$ACTUAL"
    continue
  fi
  echo "${secs}s"
  # Result lines: "RESULT <query> is true." / "is false." / "cannot be
  # proved." Supplemental lines ("RESULT (query encoded as ...",
  # "RESULT (but ...", "RESULT (even ...") repeat a query in another form
  # and are skipped. Anything else after RESULT is reported as unknown.
  awk -v file="$base" -v secs="$secs" '
    /^RESULT \((query encoded as|but|even) / { next }
    /^RESULT / {
      line = substr($0, 8)
      if (line ~ / is true\.$/)            { q = substr(line, 1, length(line) - 9);  o = "true" }
      else if (line ~ / is false\.$/)      { q = substr(line, 1, length(line) - 10); o = "false" }
      else if (line ~ / cannot be proved\.$/) { q = substr(line, 1, length(line) - 18); o = "cannot be proved" }
      else                                 { q = line; o = "unknown" }
      printf("%s\t%s\t%s\t%s\n", file, q, o, secs)
    }
    /^PARTIAL RESULT / {
      printf("%s\t%s\t%s\t%s\n", file, substr($0, 16), "unknown", secs)
    }
  ' "$log" >> "$ACTUAL"
done

# Compare with expected.txt and write results.md. expected.txt lines:
#   file.pv | query text as printed by ProVerif | true|false
# The query may itself contain "|" (ProVerif disjunction "||"): the file is
# the text before the first " | ", the expectation the text after the last.
STATUS="$OUT/status.txt"
awk -v expected="$EXPECTED" -v ran="$RAN" -v md="$RESULTS_MD" -v status="$STATUS" '
  function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
  function mdesc(s) { gsub(/\|/, "\\|", s); return s }
  BEGIN {
    FS = "\t"
    while ((getline l < ran) > 0) ran_set[l] = 1
    n_exp = 0
    while ((getline l < expected) > 0) {
      t = trim(l); if (t == "" || substr(t, 1, 1) == "\043") continue
      i = index(l, " | ")
      j = 0
      for (k = length(l) - 2; k > 0; k--) if (substr(l, k, 3) == " | ") { j = k; break }
      if (i == 0 || j <= i) { print "formal: malformed expected line: " l > "/dev/stderr"; bad_exp = 1; continue }
      f = trim(substr(l, 1, i - 1))
      q = trim(substr(l, i + 3, j - i - 3))
      e = trim(substr(l, j + 3))
      if (e != "true" && e != "false") { print "formal: expectation must be true or false: " l > "/dev/stderr"; bad_exp = 1; continue }
      if (!(f in ran_set)) continue
      key = f SUBSEP q
      if (key in want) { print "formal: duplicate expected line: " l > "/dev/stderr"; bad_exp = 1; continue }
      want[key] = e
      n_exp++
      order_f[n_exp] = f; order_q[n_exp] = q
    }
    fail = bad_exp
    print "# Résultats du modèle formel (généré par formal/run.sh, ne pas modifier à la main)" > md
    print "" > md
    print "| fichier | requête | attendu | obtenu | secondes |" > md
    print "| --- | --- | --- | --- | --- |" > md
  }
  {
    f = $1; q = $2; o = $3; s = $4
    key = f SUBSEP q
    if (q == "*") {
      file_failed[f] = o
      file_secs[f] = s
      next
    }
    if (key in seen) {
      print "formal: " f ": query printed twice: " q > "/dev/stderr"; fail = 1
    }
    seen[key] = 1
    e = (key in want) ? want[key] : "absent"
    mark = ""
    if (e == "absent") {
      print "formal: " f ": query not in expected.txt: " q " (" o ")" > "/dev/stderr"; fail = 1; mark = " (écart)"
    } else if (o != e) {
      print "formal: " f ": expected " e ", got " o ": " q > "/dev/stderr"; fail = 1; mark = " (écart)"
    }
    printf("| %s | `%s` | %s | %s%s | %s |\n", f, mdesc(q), e, o, mark, s) > md
  }
  END {
    for (n = 1; n <= n_exp; n++) {
      f = order_f[n]; q = order_q[n]; key = f SUBSEP q
      if (key in seen) continue
      o = (f in file_failed) ? file_failed[f] : "absent"
      s = (f in file_secs) ? file_secs[f] : ""
      print "formal: " f ": no result for expected query: " q " (" o ")" > "/dev/stderr"
      printf("| %s | `%s` | %s | %s (écart) | %s |\n", f, mdesc(q), want[key], o, s) > md
      fail = 1
    }
    for (f in file_failed) {
      has = 0
      for (n = 1; n <= n_exp; n++) if (order_f[n] == f) has = 1
      if (!has) {
        printf("| %s | `*` | | %s (écart) | %s |\n", f, file_failed[f], file_secs[f]) > md
        fail = 1
      }
    }
    print fail + 0 > status
  }
' "$ACTUAL"

if [ "$(cat "$STATUS")" != "0" ]; then
  echo "formal: FAILED (see messages above and $RESULTS_MD)" >&2
  exit 1
fi
echo "formal: all results match formal/expected.txt"
