# log-analyzer

Spot suspicious authentication activity in **Windows Security event logs**
(PowerShell) and **Linux auth logs** (bash): failed logons, brute-force
sources, logins that succeeded after failures, lockouts, new accounts, admin
group changes, cleared logs and sudo misuse. Read-only - logs are never
modified.

| Script | Platform | Reads |
|--------|----------|-------|
| `analyze-windows-logs.ps1` | Windows PowerShell 5.1+ / PowerShell 7+ | live Security log, an exported `.evtx`, or a CSV (any OS) |
| `analyze-linux-logs.sh` | bash 4+ | `/var/log/auth.log`, `/var/log/secure`, rotated `.gz` files, or `journalctl` |

`samples/` contains **synthetic** logs (documentation IP ranges only) so you
can try both scripts without real data - see [samples/README.md](samples/README.md).

## What is detected

### Windows (`analyze-windows-logs.ps1`)

| Event ID | Meaning | Report |
|----------|---------|--------|
| 4625 | Failed logon | totals, top source IPs, top usernames, `[BRUTE-FORCE]` at >= threshold per IP |
| 4624 | Successful logon | count per logon type (2 Interactive, 3 Network, 10 RDP...), `[SUCCESS-AFTER-FAILURES]` when an IP that failed later succeeds |
| 4740 | Account locked out | `[LOCKOUT]` |
| 4720 | User account created | `[USER-CREATED]` with the creator |
| 4732 | Member added to a local group | `[GROUP-ADD]`, `[ADMIN-GROUP-ADD]` for Administrators |
| 1102 | Security log cleared | `[LOG-CLEARED]` with the account that cleared it |

### Linux (`analyze-linux-logs.sh`)

| Log line | Report |
|----------|--------|
| `Failed password for [invalid user] X from IP` (incl. `message repeated N times`) | failed-login totals, top IPs, top usernames |
| `Invalid user X from IP` | invalid usernames tried |
| `Accepted password/publickey for X from IP` | successful logins, `[SUCCESS-AFTER-FAILURES]` |
| per-IP failures >= threshold | `[BRUTE-FORCE]` |
| `sudo: user : ... COMMAND=...` | sudo usage per user |
| `sudo: ... incorrect password attempts` / `NOT in sudoers` | `[SUDO-FAILURE]` |

Both scripts exit with **1 when alerts were raised** and 0 otherwise (2 for
usage errors in bash), so they can drive a scheduled task or cron job.

## Requirements

- **Windows:** Windows PowerShell 5.1 or PowerShell 7+. Reading the live
  Security log needs an **elevated** prompt (or membership of *Event Log
  Readers*). Event 4625 only exists if failed-logon auditing is on:
  `auditpol /get /subcategory:"Logon"`.
- **Linux:** bash 4+, awk, coreutils. Optional: `zcat`, `journalctl`. Reading
  `/var/log/auth.log` usually needs `sudo` or the `adm` group.

## Usage

### Windows

```powershell
Get-Help .\analyze-windows-logs.ps1 -Full

# Elevated PowerShell - live Security log
.\analyze-windows-logs.ps1                         # last 24 hours
.\analyze-windows-logs.ps1 -Hours 168 -Threshold 10 -ExportCsv offenders.csv
.\analyze-windows-logs.ps1 -Since '2026-11-01 00:00'

# Exported log file
.\analyze-windows-logs.ps1 -EvtxPath .\Security-export.evtx

# Save normalised events and analyse them anywhere (also on Linux/macOS with pwsh)
.\analyze-windows-logs.ps1 -Hours 72 -ExportEventsCsv events.csv
pwsh ./analyze-windows-logs.ps1 -CsvPath ./events.csv

# The script also returns per-IP objects
.\analyze-windows-logs.ps1 | Where-Object BruteForce
```

### Linux

```bash
chmod +x analyze-linux-logs.sh
./analyze-linux-logs.sh -h

sudo ./analyze-linux-logs.sh                                  # auth.log / secure, else journal
sudo ./analyze-linux-logs.sh -f /var/log/auth.log -f /var/log/auth.log.1 -t 10 -o offenders.csv
sudo ./analyze-linux-logs.sh -J -s "24 hours ago"            # systemd journal
./analyze-linux-logs.sh -n 5 samples/auth.log.sample          # options go before file names
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-f FILE` / `FILE...` | auth.log or secure | log files (`.gz` OK) |
| `-t N` | 5 | brute-force threshold (failed attempts per IP) |
| `-n N` | 10 | top N IPs / usernames |
| `-o FILE` | - | per-IP CSV: `ip,failed,invalid_user,accepted,first_seen,last_seen,brute_force` |
| `-s WHEN` | - | journal `--since` value |
| `-J` | off | force the systemd journal |

## Example output

Both outputs below are real runs against the synthetic samples (from
`tests/run-tests.sh`).

### Linux

```
$ ./analyze-linux-logs.sh -o ips.csv samples/auth.log.sample
Linux authentication log analysis
Source   : samples/auth.log.sample
Threshold: 5 failed attempts per IP
------------------------------------------------------------
Failed SSH logins                      18
Invalid-user attempts                   8
Successful SSH logins                   3
sudo commands                           2
sudo failures                           2
Distinct attacking IPs                  3

Top 10 source IPs by failed logins
------------------------------------------------------------
IP                  FAILED  INVALID ACCEPTED  FIRST SEEN -> LAST SEEN
203.0.113.50            15        7        0  Nov 10 09:15:10 -> Nov 10 09:16:00
198.51.100.23            3        0        1  Nov 10 10:02:11 -> Nov 10 10:02:26
198.51.100.77            0        1        0  Nov 10 10:30:00 -> Nov 10 10:30:00

Top 10 targeted usernames (failed logins)
------------------------------------------------------------
root                          7
bob                           3
admin                         2
guest                         1
oracle                        1
pi                            1
postgres                      1
test                          1
ubuntu                        1

Invalid (non-existent) usernames tried
------------------------------------------------------------
admin deploy guest oracle pi postgres test

ALERTS
------------------------------------------------------------
[BRUTE-FORCE] 203.0.113.50: 15 failed logins, 7 with invalid usernames (Nov 10 09:15:10 -> Nov 10 09:16:00)
[SUCCESS-AFTER-FAILURES] 198.51.100.23 logged in as bob (password) after 3 failed attempt(s) - verify this was legitimate
[SUDO-FAILURE] user 'bob': incorrect password
[SUDO-FAILURE] user 'bob': not in sudoers

Successful SSH logins
------------------------------------------------------------
alice          from 192.0.2.10         publickey  x2
bob            from 198.51.100.23      password   x1

sudo usage (user: command)
------------------------------------------------------------
1 alice: /usr/bin/apt update
1 alice: /usr/bin/systemctl restart nginx

Per-IP statistics written to ips.csv
```

### Windows (sample CSV, run with PowerShell 7)

```
PS> ./analyze-windows-logs.ps1 -CsvPath samples/windows-security.sample.csv -ExportCsv offenders.csv
Windows Security log analysis
Source   : samples/windows-security.sample.csv
Window   : all events in the file
Threshold: 5 failed logons per IP
------------------------------------------------------------
Failed logons (4625)                   11
Successful logons (4624)                3
Account lockouts (4740)                 1
Accounts created (4720)                 1
Added to local group (4732)             2
Security log cleared (1102)             1

Top 10 source IPs by failed logons
------------------------------------------------------------

IP            Failed Successful First          Last           Users
--            ------ ---------- -----          ----           -----
203.0.113.50       8          0 11-10 09:15:10 11-10 09:15:38 administrator;admin;user1;backup;test
198.51.100.23      3          1 11-10 10:02:11 11-10 10:02:21 jdoe


Top 10 targeted usernames (failed logons)
------------------------------------------------------------
administrator                 4
jdoe                          3
admin                         1
backup                        1
test                          1
user1                         1

Successful logons by type
------------------------------------------------------------
RemoteInteractive (RDP)           1
Interactive                       1
Service                           1

ALERTS
------------------------------------------------------------
[BRUTE-FORCE] 203.0.113.50: 8 failed logons for administrator;admin;user1;backup;test (2026-11-10T09:15:10 -> 2026-11-10T09:15:38)
[SUCCESS-AFTER-FAILURES] 198.51.100.23 logged on as jdoe (RemoteInteractive (RDP)) at 2026-11-10T10:02:30 after 3 failure(s) - verify
[LOCKOUT] account 'administrator' locked out at 2026-11-10T09:20:00
[USER-CREATED] 'svc-helper' created by 'jdoe' at 2026-11-10T10:10:00
[ADMIN-GROUP-ADD] 'svc-helper' added to 'Administrators' by 'jdoe' at 2026-11-10T10:10:30
[GROUP-ADD] 'bob' added to 'Remote Desktop Users' by 'alice' at 2026-11-10T10:12:00
[LOG-CLEARED] Security log cleared by 'jdoe' at 2026-11-10T10:15:00

Per-IP statistics written to offenders.csv
```

## Tests

```bash
bash tests/run-tests.sh   # bash analyzer on the sample (+ .gz); pwsh analyzer on the CSV sample if pwsh is installed
```

CI (GitHub Actions) runs ShellCheck, PSScriptAnalyzer and these tests on every push.

## Limitations

- The live-log and `.evtx` paths of `analyze-windows-logs.ps1` use `Get-WinEvent`
  and need Windows; they were not run on a real Windows machine for this
  repository. The analysis logic is the same one tested with the CSV sample.
- Linux parsing targets OpenSSH and sudo messages in the standard syslog and
  ISO-timestamp formats; other services (FTP, web apps) are not parsed.
- "Brute force" is a simple per-IP count over the whole input, not a sliding
  window; distributed attacks from many IPs show up in the username table instead.
- `SUCCESS-AFTER-FAILURES` may be a user who mistyped their password - verify before acting.

## Legal and ethical use

Analyse only logs from systems you own or administer, and handle them as
personal data (they contain usernames and IP addresses).

## License

[MIT](LICENSE) - Copyright (c) 2026 Arnold Rurangwa
