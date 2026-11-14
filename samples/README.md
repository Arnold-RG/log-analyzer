# Sample logs (synthetic)

Everything in this folder is **made up** for demos and tests. No real system,
person or attack is represented.

- All IP addresses come from the RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which are never
  routed on the internet.
- Host names (`demo-server`, `DEMO-PC`) and users (`alice`, `bob`, `jdoe`, ...)
  are fictional.

| File | Used by | Scenario |
|------|---------|----------|
| `auth.log.sample` | `analyze-linux-logs.sh` | Debian/Ubuntu `auth.log` format: SSH brute force from 203.0.113.50 (incl. invalid users and a "message repeated" line), 3 failures then a successful password login from 198.51.100.23, normal key logins, sudo usage and sudo failures |
| `windows-security.sample.csv` | `analyze-windows-logs.ps1 -CsvPath` | Normalised Security-log events: 4625 failed logons (brute force + success after failures over RDP), 4740 lockout, 4720 user created, 4732 added to Administrators, 1102 log cleared |

The CSV columns are exactly what `analyze-windows-logs.ps1 -ExportEventsCsv`
writes, so you can export real events on Windows and analyse them elsewhere:

`TimeCreated,EventId,TargetUserName,IpAddress,LogonType,SubjectUserName,GroupName,MemberName`
