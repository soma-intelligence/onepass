#!/usr/bin/env bash
# Runs the ProVerif models and checks every result against formal/expected.txt.
#
# Usage: formal/run.sh [file.pv ...]
#   No argument (full run): every formal/proverif/*.pv, and every file named
#   in expected.txt must have run.
#
# Environment:
#   PROVERIF        ProVerif binary (default: proverif in PATH, then ~/.local/bin/proverif)
#   FORMAL_TIMEOUT  whole seconds per file, >= 1 (default 300)
#
# Exit status 1 on any mismatch: a result different from the expected one,
# "cannot be proved", a timeout or a ProVerif error, a RESULT line absent from
# expected.txt, an expected.txt line (for a file that was run) without a
# result, a model that ran with no expected line, or, in a full run, a file
# named in expected.txt that did not run. Any internal failure of the checker
# is also a failure: the script is never green by default.
#
# Outputs: formal/out/results.md (with timings) on every run; a full run also
# writes docs/security/formal/results.md (no timings, so the committed file
# only changes when results change).

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMAL="$ROOT/formal"
LIB="$FORMAL/proverif/common.pvl"
EXPECTED="$FORMAL/expected.txt"
OUT="$FORMAL/out"
DOC_MD="$ROOT/docs/security/formal/results.md"
OUT_MD="$OUT/results.md"
LIMIT="${FORMAL_TIMEOUT:-300}"

fail() {
  echo "formal: $*" >&2
  exit 1
}

# Whole seconds only: the perl fallback (alarm) truncates fractions, and
# alarm(0) would mean no limit at all.
case "$LIMIT" in
  ''|*[!0-9]*|0*) fail "FORMAL_TIMEOUT must be a whole number of seconds >= 1, got '$LIMIT'" ;;
esac

if [ -z "${PROVERIF:-}" ]; then
  if command -v proverif >/dev/null 2>&1; then
    PROVERIF="proverif"
  elif [ -x "$HOME/.local/bin/proverif" ]; then
    PROVERIF="$HOME/.local/bin/proverif"
  else
    fail "proverif not found (set PROVERIF)"
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

[ -f "$EXPECTED" ] || fail "$EXPECTED missing"

if [ "$#" -gt 0 ]; then
  FULL=0
  FILES=("$@")
else
  FULL=1
  FILES=()
  for f in "$FORMAL"/proverif/*.pv; do
    [ -e "$f" ] && FILES+=("$f")
  done
fi
[ "${#FILES[@]}" -gt 0 ] || fail "no model to run"

mkdir -p "$OUT" || fail "cannot create $OUT"
# One line per query: file<TAB>query<TAB>outcome<TAB>seconds
ACTUAL="$OUT/actual.tsv"
RAN="$OUT/ran.txt"
rm -f "$ACTUAL" "$RAN" "$OUT_MD" "$OUT/doc_results.md"
: > "$ACTUAL" || fail "cannot write $ACTUAL"
: > "$RAN" || fail "cannot write $RAN"

for f in "${FILES[@]}"; do
  [ -f "$f" ] || fail "no such model: $f"
  base="$(basename "$f")"
  log="$OUT/${base%.pv}.log"
  echo "$base" >> "$RAN"
  printf 'formal: %s ... ' "$base"
  # Extra libraries: a model may name, one per line, a library of
  # formal/proverif loaded after common.pvl, with the exact line
  # "(* formal-lib: name.pvl *)" (account_core.pvl for the account models).
  extra=()
  missing=""
  while IFS= read -r l; do
    if [ -f "$FORMAL/proverif/$l" ]; then
      extra+=(-lib "$FORMAL/proverif/$l")
    else
      missing="$l"
    fi
  done < <(sed -n 's/^(\* formal-lib: \([A-Za-z0-9_-]*\.pvl\) \*)$/\1/p' "$f")
  if [ -n "$missing" ]; then
    echo "missing library $missing"
    printf '%s\t%s\t%s\t%s\n' "$base" "*" "error" "0.0" >> "$ACTUAL"
    continue
  fi
  t0="$(now_ms)"
  run_limited "$PROVERIF" -lib "$LIB" ${extra[@]+"${extra[@]}"} "$f" > "$log" 2>&1
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
  ' "$log" >> "$ACTUAL" || fail "cannot parse $log"
done

# Compare with expected.txt and write the result tables. expected.txt lines:
#   file.pv | query text as printed by ProVerif | true|false
# The query may itself contain "|" (ProVerif disjunction "||"): the file is
# the text before the first " | ", the expectation the text after the last.
# The awk exit status is the verdict: 0 only if everything matched.
awk -v expected="$EXPECTED" -v ran="$RAN" -v full="$FULL" \
    -v outmd="$OUT_MD" -v docmd="$OUT/doc_results.md" '
  function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
  function mdesc(s) { gsub(/\|/, "\\|", s); return s }
  function row(f, q, e, o, mark, s) {
    printf("| %s | `%s` | %s | %s%s | %s |\n", f, mdesc(q), e, o, mark, s) > outmd
    printf("| %s | `%s` | %s | %s%s |\n", f, mdesc(q), e, o, mark) > docmd
  }
  BEGIN {
    FS = "\t"
    fail = 0
    while ((r = (getline l < ran)) > 0) ran_set[l] = 1
    if (r < 0) { print "formal: cannot read " ran > "/dev/stderr"; fail = 1 }
    n_exp = 0
    while ((r = (getline l < expected)) > 0) {
      t = trim(l); if (t == "" || substr(t, 1, 1) == "\043") continue
      i = index(l, " | ")
      j = 0
      for (k = length(l) - 2; k > 0; k--) if (substr(l, k, 3) == " | ") { j = k; break }
      if (i == 0 || j <= i) { print "formal: malformed expected line: " l > "/dev/stderr"; fail = 1; continue }
      f = trim(substr(l, 1, i - 1))
      q = trim(substr(l, i + 3, j - i - 3))
      e = trim(substr(l, j + 3))
      if (e != "true" && e != "false") { print "formal: expectation must be true or false: " l > "/dev/stderr"; fail = 1; continue }
      if (!(f in ran_set)) {
        if (full == 1 && !(f in not_run)) {
          print "formal: " f " is named in expected.txt but did not run" > "/dev/stderr"
          not_run[f] = 1
          fail = 1
        }
        continue
      }
      key = f SUBSEP q
      if (key in want) { print "formal: duplicate expected line: " l > "/dev/stderr"; fail = 1; continue }
      want[key] = e
      has_expected[f] = 1
      n_exp++
      order_f[n_exp] = f; order_q[n_exp] = q
    }
    if (r < 0) { print "formal: cannot read " expected > "/dev/stderr"; fail = 1 }
    header = "# Résultats du modèle formel (généré par formal/run.sh, ne pas modifier à la main)"
    print header > outmd
    print "" > outmd
    print "| fichier | requête | attendu | obtenu | secondes |" > outmd
    print "| --- | --- | --- | --- | --- |" > outmd
    print header > docmd
    print "" > docmd
    print "| fichier | requête | attendu | obtenu |" > docmd
    print "| --- | --- | --- | --- |" > docmd
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
    row(f, q, e, o, mark, s)
  }
  END {
    for (n = 1; n <= n_exp; n++) {
      f = order_f[n]; q = order_q[n]; key = f SUBSEP q
      if (key in seen) continue
      o = (f in file_failed) ? file_failed[f] : "absent"
      s = (f in file_secs) ? file_secs[f] : ""
      print "formal: " f ": no result for expected query: " q " (" o ")" > "/dev/stderr"
      row(f, q, want[key], o, " (écart)", s)
      fail = 1
    }
    # Every model that ran needs expected lines (at least its sanity query).
    for (f in ran_set) {
      if (f in has_expected) continue
      o = (f in file_failed) ? file_failed[f] : "no expected line"
      print "formal: " f ": ran but has no line in expected.txt (" o ")" > "/dev/stderr"
      row(f, "*", "", o, " (écart)", (f in file_secs) ? file_secs[f] : "")
      fail = 1
    }
    exit (fail ? 1 : 0)
  }
' "$ACTUAL"
verdict=$?

if [ "$FULL" -eq 1 ] && [ -s "$OUT/doc_results.md" ]; then
  mkdir -p "$(dirname "$DOC_MD")" && cp "$OUT/doc_results.md" "$DOC_MD" \
    || fail "cannot write $DOC_MD"
fi

if [ "$verdict" -ne 0 ]; then
  fail "FAILED (checker exit $verdict; see messages above and $OUT_MD)"
fi
if [ "$FULL" -eq 1 ]; then
  echo "formal: all results match formal/expected.txt (written to $DOC_MD)"
else
  echo "formal: all results match formal/expected.txt (subset run, written to $OUT_MD)"
fi
