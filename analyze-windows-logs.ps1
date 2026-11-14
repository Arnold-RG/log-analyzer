<#
.SYNOPSIS
    Find suspicious activity in the Windows Security event log.

.DESCRIPTION
    analyze-windows-logs.ps1 reads Security log events and reports:

      4625  failed logons          -> top source IPs / usernames, brute force
      4624  successful logons      -> by logon type (RDP, network, ...)
      4740  account lockouts
      4720  user accounts created
      4732  members added to a local group (Administrators is flagged)
      1102  the Security log was cleared

    It also flags IPs that logged on successfully AFTER failing (possible
    password-guessing success).

    Input, in order of preference:
      -CsvPath  : a CSV in the format of samples/windows-security.sample.csv
                  (also what -ExportEventsCsv writes) - works on any OS
      -EvtxPath : an exported .evtx file (Windows)
      (default) : the live Security log (Windows, elevated)

    Read-only: nothing is changed or cleared.

    Author : Arnold Rurangwa - MIT License

.PARAMETER Hours
    Only look at events from the last N hours (default 24 for the live log).
    For -CsvPath / -EvtxPath all events are used unless -Hours or -Since is given.

.PARAMETER Since
    Only look at events after this date/time (overrides -Hours).

.PARAMETER Threshold
    Failed logons per source IP that count as brute force (default 5).

.PARAMETER Top
    Number of top IPs / usernames to show (default 10).

.PARAMETER ExportCsv
    Write per-IP statistics to this CSV file.

.PARAMETER ExportEventsCsv
    Write the normalised events to this CSV (re-usable later with -CsvPath).

.EXAMPLE
    .\analyze-windows-logs.ps1                       # elevated: last 24 h of the live log

.EXAMPLE
    .\analyze-windows-logs.ps1 -Hours 168 -Threshold 10 -ExportCsv offenders.csv

.EXAMPLE
    .\analyze-windows-logs.ps1 -CsvPath .\samples\windows-security.sample.csv

.NOTES
    Requirements: Windows PowerShell 5.1+ or PowerShell 7+. Reading the live
    Security log requires an elevated prompt (or Event Log Readers membership).
    Failed-logon auditing must be enabled for 4625 events to exist
    (auditpol /get /subcategory:"Logon").
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [datetime]$Since,

    [ValidateRange(1, 100000)]
    [int]$Threshold = 5,

    [ValidateRange(1, 1000)]
    [int]$Top = 10,

    [string]$CsvPath,

    [string]$EvtxPath,

    [string]$ExportCsv,

    [string]$ExportEventsCsv
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$eventIds = 4625, 4624, 4740, 4720, 4732, 1102
$logonTypes = @{
    '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'; '7' = 'Unlock'
    '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive (RDP)'; '11' = 'CachedInteractive'
}

# ---- time window -----------------------------------------------------------------
$fileInput = [bool]($CsvPath -or $EvtxPath)
$start = $null
if ($PSBoundParameters.ContainsKey('Since')) { $start = $Since }
elseif ($PSBoundParameters.ContainsKey('Hours') -or -not $fileInput) { $start = (Get-Date).AddHours(-$Hours) }

# Turn an EventLogRecord into a flat object with the fields we need.
function ConvertFrom-EventRecord($Record) {
    $xml = [xml]$Record.ToXml()
    $data = @{}
    if ($xml.Event.PSObject.Properties['EventData'] -and $xml.Event.EventData) {
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $data[$d.Name] = $d.'#text' } }
    }
    $subject = $data['SubjectUserName']
    if ($Record.Id -eq 1102) {
        # 1102 keeps its fields under UserData/LogFileCleared
        try { $subject = $xml.Event.UserData.LogFileCleared.SubjectUserName } catch { $subject = '' }
    }
    [pscustomobject]@{
        TimeCreated     = $Record.TimeCreated
        EventId         = $Record.Id
        TargetUserName  = $data['TargetUserName']
        IpAddress       = $data['IpAddress']
        LogonType       = $data['LogonType']
        SubjectUserName = $subject
        GroupName       = $(if ($Record.Id -eq 4732) { $data['TargetUserName'] } else { '' })
        MemberName      = $(if ($Record.Id -eq 4732) { $data['MemberName'] } else { '' })
    }
}

# ---- load events -------------------------------------------------------------------
if ($CsvPath) {
    if (-not (Test-Path -LiteralPath $CsvPath)) { throw "File not found: $CsvPath" }
    $source = $CsvPath
    $events = @(Import-Csv -LiteralPath $CsvPath | ForEach-Object {
            $_.TimeCreated = [datetime]::Parse($_.TimeCreated, [Globalization.CultureInfo]::InvariantCulture)
            $_.EventId = [int]$_.EventId
            $_
        })
}
else {
    if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'Reading .evtx or the live Security log needs Windows. Use -CsvPath on other systems.'
    }
    $filter = @{ Id = $eventIds }
    if ($EvtxPath) {
        if (-not (Test-Path -LiteralPath $EvtxPath)) { throw "File not found: $EvtxPath" }
        $filter['Path'] = (Resolve-Path -LiteralPath $EvtxPath).Path; $source = $EvtxPath
    }
    else { $filter['LogName'] = 'Security'; $source = 'Security log (live)' }
    if ($start) { $filter['StartTime'] = $start }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object { ConvertFrom-EventRecord $_ })
    }
    catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') { $events = @() }
        elseif ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'unauthorized|denied') {
            throw 'Access denied: run PowerShell as Administrator to read the Security log.'
        }
        else { throw }
    }
}
if ($start) { $events = @($events | Where-Object { $_.TimeCreated -ge $start }) }

if ($ExportEventsCsv) {
    $events | Select-Object @{ n = 'TimeCreated'; e = { $_.TimeCreated.ToString('s') } }, EventId, TargetUserName, IpAddress, LogonType, SubjectUserName, GroupName, MemberName |
        Export-Csv -Path $ExportEventsCsv -NoTypeInformation
}

function Test-RealIp([string]$Ip) { return ($Ip -and $Ip -notin '-', '::1', '127.0.0.1', '') }

$failed = @($events | Where-Object EventId -eq 4625)
$success = @($events | Where-Object EventId -eq 4624)
$lockouts = @($events | Where-Object EventId -eq 4740)
$created = @($events | Where-Object EventId -eq 4720)
$groupAdds = @($events | Where-Object EventId -eq 4732)
$cleared = @($events | Where-Object EventId -eq 1102)

$sep = '-' * 60
Write-Host 'Windows Security log analysis'
Write-Host "Source   : $source"
if ($start) { Write-Host "Window   : since $($start.ToString('yyyy-MM-dd HH:mm'))" } else { Write-Host 'Window   : all events in the file' }
Write-Host "Threshold: $Threshold failed logons per IP"
Write-Host $sep
'{0,-34} {1,6}' -f 'Failed logons (4625)', $failed.Count | Write-Host
'{0,-34} {1,6}' -f 'Successful logons (4624)', $success.Count | Write-Host
'{0,-34} {1,6}' -f 'Account lockouts (4740)', $lockouts.Count | Write-Host
'{0,-34} {1,6}' -f 'Accounts created (4720)', $created.Count | Write-Host
'{0,-34} {1,6}' -f 'Added to local group (4732)', $groupAdds.Count | Write-Host
'{0,-34} {1,6}' -f 'Security log cleared (1102)', $cleared.Count | Write-Host

# ---- per-IP statistics ---------------------------------------------------------------
$ipStats = @($failed | Where-Object { Test-RealIp $_.IpAddress } | Group-Object IpAddress | ForEach-Object {
        $ip = $_.Name
        $times = $_.Group | Sort-Object TimeCreated
        $ok = @($success | Where-Object IpAddress -eq $ip)
        [pscustomobject]@{
            IP         = $ip
            Failed     = $_.Count
            Users      = (($_.Group | Select-Object -ExpandProperty TargetUserName -Unique) -join ';')
            Successful = $ok.Count
            FirstSeen  = $times[0].TimeCreated
            LastSeen   = $times[-1].TimeCreated
            BruteForce = ($_.Count -ge $Threshold)
        }
    } | Sort-Object Failed -Descending)

Write-Host "`nTop $Top source IPs by failed logons"; Write-Host $sep
$ipStats | Select-Object -First $Top IP, Failed, Successful, @{ n = 'First'; e = { $_.FirstSeen.ToString('MM-dd HH:mm:ss') } }, @{ n = 'Last'; e = { $_.LastSeen.ToString('MM-dd HH:mm:ss') } }, Users |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host "Top $Top targeted usernames (failed logons)"; Write-Host $sep
$failed | Group-Object TargetUserName | Sort-Object Count -Descending | Select-Object -First $Top |
    ForEach-Object { '{0,-24} {1,6}' -f $_.Name, $_.Count } | Write-Host

Write-Host "`nSuccessful logons by type"; Write-Host $sep
$success | Group-Object LogonType | Sort-Object Count -Descending | ForEach-Object {
    $name = $logonTypes["$($_.Name)"]; if (-not $name) { $name = "Type $($_.Name)" }
    '{0,-28} {1,6}' -f $name, $_.Count
} | Write-Host

# ---- alerts ----------------------------------------------------------------------------
Write-Host "`nALERTS"; Write-Host $sep
$alerts = New-Object System.Collections.Generic.List[string]
foreach ($s in $ipStats) {
    if ($s.BruteForce) { $alerts.Add("[BRUTE-FORCE] $($s.IP): $($s.Failed) failed logons for $($s.Users) ($($s.FirstSeen.ToString('s')) -> $($s.LastSeen.ToString('s')))") }
    $after = @($success | Where-Object { $_.IpAddress -eq $s.IP -and $_.TimeCreated -gt $s.FirstSeen })
    foreach ($a in $after) {
        $type = $logonTypes["$($a.LogonType)"]; if (-not $type) { $type = "type $($a.LogonType)" }
        $alerts.Add("[SUCCESS-AFTER-FAILURES] $($s.IP) logged on as $($a.TargetUserName) ($type) at $($a.TimeCreated.ToString('s')) after $($s.Failed) failure(s) - verify")
    }
}
foreach ($e in $lockouts) { $alerts.Add("[LOCKOUT] account '$($e.TargetUserName)' locked out at $($e.TimeCreated.ToString('s'))") }
foreach ($e in $created) { $alerts.Add("[USER-CREATED] '$($e.TargetUserName)' created by '$($e.SubjectUserName)' at $($e.TimeCreated.ToString('s'))") }
foreach ($e in $groupAdds) {
    $level = 'GROUP-ADD'; if ($e.GroupName -match '^(Administrators|Administratoren|Administrateurs|Administradores)$') { $level = 'ADMIN-GROUP-ADD' }
    $alerts.Add("[$level] '$($e.MemberName)' added to '$($e.GroupName)' by '$($e.SubjectUserName)' at $($e.TimeCreated.ToString('s'))")
}
foreach ($e in $cleared) { $alerts.Add("[LOG-CLEARED] Security log cleared by '$($e.SubjectUserName)' at $($e.TimeCreated.ToString('s'))") }

if ($alerts.Count -eq 0) { Write-Host 'No alerts.' }
else {
    foreach ($a in $alerts) {
        $color = 'Yellow'; if ($a -match '^\[(BRUTE-FORCE|SUCCESS-AFTER|ADMIN-GROUP|LOG-CLEARED)') { $color = 'Red' }
        Write-Host $a -ForegroundColor $color
    }
}

if ($ExportCsv) {
    $ipStats | Select-Object IP, Failed, Successful, @{ n = 'FirstSeen'; e = { $_.FirstSeen.ToString('s') } }, @{ n = 'LastSeen'; e = { $_.LastSeen.ToString('s') } }, BruteForce, Users |
        Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "`nPer-IP statistics written to $ExportCsv"
}

# Objects for further processing, e.g. | Where-Object BruteForce
$ipStats
# Exit 1 when alerts were raised (useful for scheduled tasks and monitoring).
if ($alerts.Count -gt 0) { exit 1 }
