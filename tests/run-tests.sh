#!/usr/bin/env bash
# Tests for the log analyzers using the synthetic samples in samples/.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail() { echo "FAIL: $*"; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

echo "== bash: auth.log sample"
./analyze-linux-logs.sh -o "$W/ips.csv" samples/auth.log.sample > "$W/out.txt"; rc=$?
cat "$W/out.txt"
[[ $rc -eq 1 ]] || fail "alerts expected -> exit 1 (got $rc)"
grep -Eq 'Failed SSH logins +18$' "$W/out.txt" || fail "failed-login count (12 lines + 'repeated 3 times' + 3 = 18)"
grep -Eq 'Invalid-user attempts +8$' "$W/out.txt" || fail "invalid-user count"
grep -q '\[BRUTE-FORCE\] 203.0.113.50: 15 failed' "$W/out.txt" || fail "brute force not detected"
grep -q '\[SUCCESS-AFTER-FAILURES\] 198.51.100.23 logged in as bob' "$W/out.txt" || fail "success-after-failures not detected"
grep -q "\[SUDO-FAILURE\] user 'bob': not in sudoers" "$W/out.txt" || fail "sudo failure not detected"
grep -q '^203.0.113.50,15,7,0,.*,yes$' "$W/ips.csv" || fail "CSV row wrong"

echo "== bash: threshold, gzip input, validation"
out=$(./analyze-linux-logs.sh -t 100 samples/auth.log.sample); grep -q BRUTE-FORCE <<< "$out" && fail "threshold ignored"
gzip -c samples/auth.log.sample > "$W/auth.log.1.gz"
out=$(./analyze-linux-logs.sh -f "$W/auth.log.1.gz"); grep -Eq 'Failed SSH logins +18$' <<< "$out" || fail ".gz input"
./analyze-linux-logs.sh -t abc samples/auth.log.sample >/dev/null 2>&1; [[ $? -eq 2 ]] || fail "bad -t accepted"
./analyze-linux-logs.sh /nonexistent >/dev/null 2>&1; [[ $? -eq 2 ]] || fail "missing file accepted"

if command -v pwsh >/dev/null 2>&1; then
    echo "== pwsh: Windows CSV sample"
    pwsh -NoProfile -File ./analyze-windows-logs.ps1 -CsvPath samples/windows-security.sample.csv -ExportCsv "$W/w.csv" > "$W/w.txt"; rc=$?
    cat "$W/w.txt"
    [[ $rc -eq 1 ]] || fail "pwsh: alerts expected -> exit 1 (got $rc)"
    for pat in '\[BRUTE-FORCE\] 203.0.113.50: 8 failed' '\[SUCCESS-AFTER-FAILURES\] 198.51.100.23 logged on as jdoe' \
               "\[ADMIN-GROUP-ADD\] 'svc-helper' added to 'Administrators'" '\[LOG-CLEARED\]' "\[LOCKOUT\] account 'administrator'" \
               "\[USER-CREATED\] 'svc-helper'"; do
        grep -q "$pat" "$W/w.txt" || fail "pwsh missing: $pat"
    done
    grep -q '"203.0.113.50","8","0"' "$W/w.csv" || fail "pwsh CSV export"
    pwsh -NoProfile -File ./analyze-windows-logs.ps1 -CsvPath samples/windows-security.sample.csv -Since 2026-11-10T10:00:00 > "$W/w2.txt"
    grep -Eq 'Failed logons \(4625\) +3$' "$W/w2.txt" || fail "pwsh -Since filter"
fi
echo "All tests passed."
