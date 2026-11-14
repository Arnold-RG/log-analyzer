#!/usr/bin/env bash
# =============================================================================
# analyze-linux-logs.sh - Find suspicious authentication activity in Linux logs
# -----------------------------------------------------------------------------
# Purpose : Parse /var/log/auth.log (Debian/Ubuntu), /var/log/secure (RHEL/
#           Fedora) or the systemd journal and report: failed SSH passwords,
#           invalid users, successful logins, brute-force sources over a
#           threshold, logins that SUCCEEDED after failures, top offending IPs
#           and usernames, sudo usage and sudo failures.
# Usage   : ./analyze-linux-logs.sh [-f FILE]... [-t 5] [-n 10] [-o ips.csv]
#                                   [-s "24 hours ago"] [-J]
#           ./analyze-linux-logs.sh samples/auth.log.sample
#           ./analyze-linux-logs.sh -h
# Requires: bash 4+, awk, sort. Optional: zcat (for .gz), journalctl.
#           Reading system logs normally needs root or the 'adm' group.
# Author  : Arnold Rurangwa - MIT License
# =============================================================================
set -uo pipefail

FILES=()
THRESHOLD=5
TOP=10
CSV=""
SINCE=""
FORCE_JOURNAL=0

usage() {
    cat <<USAGE
Usage: $(basename "$0") [options] [FILE...]

Report failed logins, brute-force sources and sudo activity from auth logs.

  -f FILE   log file to read (repeatable; .gz supported). Positional FILEs work too.
            Default: /var/log/auth.log or /var/log/secure, else the journal.
  -t N      brute-force threshold: failed attempts per IP (default: $THRESHOLD)
  -n N      how many top IPs/users to show (default: $TOP)
  -o FILE   export per-IP statistics to CSV
  -s WHEN   journal only: --since value, e.g. "24 hours ago" or "2026-11-01"
  -J        read the systemd journal even if log files exist
  -h        show this help

Examples:
  $(basename "$0") samples/auth.log.sample
  sudo $(basename "$0") -f /var/log/auth.log -f /var/log/auth.log.1 -t 10 -o offenders.csv
  sudo $(basename "$0") -J -s "today"
USAGE
}
die() { echo "Error: $*" >&2; exit 2; }
is_int_between() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }

while getopts ":f:t:n:o:s:Jh" opt; do
    case "$opt" in
        f) FILES+=("$OPTARG") ;;
        t) THRESHOLD="$OPTARG" ;;
        n) TOP="$OPTARG" ;;
        o) CSV="$OPTARG" ;;
        s) SINCE="$OPTARG" ;;
        J) FORCE_JOURNAL=1 ;;
        h) usage; exit 0 ;;
        :) die "option -$OPTARG needs a value (see -h)" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
shift $((OPTIND - 1))
FILES+=("$@")
is_int_between "$THRESHOLD" 1 100000 || die "-t must be a positive number"
is_int_between "$TOP" 1 1000 || die "-n must be 1-1000"
[[ -z "$SINCE" || "$SINCE" =~ ^[A-Za-z0-9\ :+-]+$ ]] || die "-s contains unexpected characters"

# ---- choose the input ----------------------------------------------------------
if (( ! FORCE_JOURNAL )) && (( ${#FILES[@]} == 0 )); then
    for f in /var/log/auth.log /var/log/secure; do [[ -e "$f" ]] && FILES+=("$f"); done
fi
for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || die "no such file: $f"
    [[ -r "$f" ]] || die "cannot read $f (try sudo, or add your user to the 'adm' group)"
done

SOURCE=""
read_input() {
    if (( ${#FILES[@]} > 0 )) && (( ! FORCE_JOURNAL )); then
        local f
        for f in "${FILES[@]}"; do
            case "$f" in *.gz) zcat -- "$f" ;; *) cat -- "$f" ;; esac
        done
    else
        command -v journalctl >/dev/null 2>&1 || die "no auth log file found and journalctl is not available"
        local args=(--no-pager -o short -q _COMM=sshd _COMM=sshd-session _COMM=sudo)
        [[ -n "$SINCE" ]] && args+=(--since "$SINCE")
        journalctl "${args[@]}"
    fi
}
if (( ${#FILES[@]} > 0 )) && (( ! FORCE_JOURNAL )); then SOURCE="${FILES[*]}"
else SOURCE="systemd journal${SINCE:+ since $SINCE}"; fi

# ---- parse -----------------------------------------------------------------------
# awk emits one tab-separated record per interesting event:
#   FAIL  ip user time      INVALID ip user time     ACCEPT ip user method time
#   SUDO  user command      SUDOFAIL user reason
WORK=$(mktemp); trap 'rm -f "$WORK"' EXIT
read_input | awk '
    # Timestamp = first 3 fields (syslog) or first field (ISO 8601 / RFC 3339).
    function stamp() { return ($1 ~ /^[0-9]{4}-/) ? $1 : $1 " " $2 " " $3 }
    function after(word,   i) { for (i = 1; i < NF; i++) if ($i == word) return $(i + 1); return "" }
    /sshd(-session)?\[[0-9]+\]:/ || / sshd: / {
        reps = 1
        if ($0 ~ /message repeated [0-9]+ times/) { match($0, /repeated [0-9]+/); reps = substr($0, RSTART + 9, RLENGTH - 9) + 0 }
        if ($0 ~ /Failed (password|publickey|keyboard-interactive)/) {
            user = ($0 ~ /for invalid user/) ? after("user") : after("for")
            for (r = 0; r < reps; r++) printf "FAIL\t%s\t%s\t%s\n", after("from"), user, stamp()
        } else if ($0 ~ /Invalid user /) {
            printf "INVALID\t%s\t%s\t%s\n", after("from"), after("user"), stamp()
        } else if ($0 ~ /Accepted (password|publickey|keyboard-interactive)/) {
            match($0, /Accepted [a-z-]+/); method = substr($0, RSTART + 9, RLENGTH - 9)
            printf "ACCEPT\t%s\t%s\t%s\t%s\n", after("from"), after("for"), method, stamp()
        }
        next
    }
    /sudo(\[[0-9]+\])?:/ {
        line = $0; sub(/.*sudo(\[[0-9]+\])?: +/, "", line)
        split(line, parts, " : ")
        user = parts[1]; gsub(/ /, "", user)
        if (line ~ /incorrect password attempt/) { printf "SUDOFAIL\t%s\tincorrect password\n", user }
        else if (line ~ /NOT in sudoers/) { printf "SUDOFAIL\t%s\tnot in sudoers\n", user }
        else if (line ~ /COMMAND=/) { cmd = line; sub(/.*COMMAND=/, "", cmd); printf "SUDO\t%s\t%s\n", user, cmd }
    }' > "$WORK"

count() { awk -F'\t' -v t="$1" '$1 == t' "$WORK" | wc -l; }
FAILS=$(count FAIL); INVALID=$(count INVALID); ACCEPTS=$(count ACCEPT)
SUDOS=$(count SUDO); SUDOFAILS=$(count SUDOFAIL)

line() { printf '%s\n' "------------------------------------------------------------"; }
echo "Linux authentication log analysis"
echo "Source   : $SOURCE"
echo "Threshold: $THRESHOLD failed attempts per IP"
line
printf '%-34s %6d\n' "Failed SSH logins" "$FAILS" "Invalid-user attempts" "$INVALID" \
    "Successful SSH logins" "$ACCEPTS" "sudo commands" "$SUDOS" "sudo failures" "$SUDOFAILS"
printf '%-34s %6d\n' "Distinct attacking IPs" "$(awk -F'\t' '$1 == "FAIL" || $1 == "INVALID" {print $2}' "$WORK" | sort -u | wc -l)"

# Per-IP statistics: ip failed invalid accepted first last
STATS=$(awk -F'\t' '
    $1 == "FAIL" || $1 == "INVALID" || $1 == "ACCEPT" {
        ip = $2; t = ($1 == "ACCEPT") ? $5 : $4
        if (!(ip in first)) first[ip] = t
        last[ip] = t
        if ($1 == "FAIL") f[ip]++; else if ($1 == "INVALID") inv[ip]++; else a[ip]++
    }
    END { for (ip in first) printf "%s\t%d\t%d\t%d\t%s\t%s\n", ip, f[ip], inv[ip], a[ip], first[ip], last[ip] }
' "$WORK" | sort -t$'\t' -k2,2nr -k3,3nr)

echo; echo "Top $TOP source IPs by failed logins"; line
printf '%-18s %7s %8s %8s  %s\n' IP FAILED INVALID ACCEPTED "FIRST SEEN -> LAST SEEN"
awk -F'\t' -v n="$TOP" '($2 + $3) > 0 && c++ < n {printf "%-18s %7d %8d %8d  %s -> %s\n", $1, $2, $3, $4, $5, $6}' <<< "$STATS"

echo; echo "Top $TOP targeted usernames (failed logins)"; line
awk -F'\t' '$1 == "FAIL" {print $3}' "$WORK" | sort | uniq -c | sort -k1,1nr -k2 | head -n "$TOP" |
    awk '{printf "%-24s %6d\n", $2, $1}'

echo; echo "Invalid (non-existent) usernames tried"; line
awk -F'\t' '$1 == "INVALID" {print $3}' "$WORK" | sort -u | paste -sd' ' - | fold -s -w 60

echo; echo "ALERTS"; line
# An "Invalid user" line is usually followed by a "Failed password for invalid
# user" line for the SAME attempt, so attempts = the larger of the two counts
# (not the sum) to avoid double counting.
attempts() { if (( $1 > $2 )); then echo "$1"; else echo "$2"; fi; }
alerts=0
while IFS=$'\t' read -r ip f inv acc first last; do
    [[ -n "$ip" ]] || continue
    if (( $(attempts "$f" "$inv") >= THRESHOLD )); then
        echo "[BRUTE-FORCE] $ip: $f failed logins, $inv with invalid usernames ($first -> $last)"
        alerts=$((alerts + 1))
    fi
    if (( f > 0 && acc > 0 )); then
        users=$(awk -F'\t' -v ip="$ip" '$1 == "ACCEPT" && $2 == ip {print $3 " (" $4 ")"}' "$WORK" | sort -u | paste -sd, -)
        echo "[SUCCESS-AFTER-FAILURES] $ip logged in as $users after $f failed attempt(s) - verify this was legitimate"
        alerts=$((alerts + 1))
    fi
done <<< "$STATS"
while IFS=$'\t' read -r _ user reason; do
    [[ -n "$user" ]] || continue
    echo "[SUDO-FAILURE] user '$user': $reason"
    alerts=$((alerts + 1))
done < <(awk -F'\t' '$1 == "SUDOFAIL"' "$WORK")
(( alerts == 0 )) && echo "No alerts."

echo; echo "Successful SSH logins"; line
awk -F'\t' '$1 == "ACCEPT" {print $3 "\t" $2 "\t" $4}' "$WORK" | sort | uniq -c |
    awk -F'\t' '{split($1, a, " "); printf "%-14s from %-18s %-10s x%d\n", a[2], $2, $3, a[1]}'

echo; echo "sudo usage (user: command)"; line
awk -F'\t' '$1 == "SUDO" {print $2 ": " $3}' "$WORK" | sort | uniq -c | sort -k1,1nr | head -n "$TOP" | sed 's/^ *//'

if [[ -n "$CSV" ]]; then
    {
        echo "ip,failed,invalid_user,accepted,first_seen,last_seen,brute_force"
        while IFS=$'\t' read -r ip f inv acc first last; do
            [[ -n "$ip" ]] || continue
            bf=no; (( $(attempts "$f" "$inv") >= THRESHOLD )) && bf=yes
            echo "$ip,$f,$inv,$acc,$first,$last,$bf"
        done <<< "$STATS"
    } > "$CSV" || die "cannot write $CSV"
    echo; echo "Per-IP statistics written to $CSV"
fi

# Exit 1 when alerts were raised, so the script can drive cron/monitoring.
(( alerts > 0 )) && exit 1
exit 0
