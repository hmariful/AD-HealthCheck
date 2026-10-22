#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Daily Active Directory system-state backup with Windows Server Backup (wbadmin).

.DESCRIPTION
    1. Checks prerequisites (Windows Server Backup installed, target volume present, not the system drive, free space).
    2. Runs:  wbadmin start systemstatebackup -backupTarget:<volume> -quiet
    3. Verifies the new version is listed by wbadmin.
    4. Keeps only the newest -KeepVersions system-state backups on the target.
    5. Optionally mirrors the latest backup to a network share (-CopyToPath).
    6. Writes a log file and, with -MailOnFailure, e-mails the log if anything fails.

    A successful run updates the "last backup" stamp of every AD partition
    (visible with: repadmin /showbackup), which the health-check script reports.

.PARAMETER BackupTarget
    Dedicated local volume for the backups, e.g. 'D:'. Must not be C: (the system volume).
    Windows Server Backup keeps older versions as shadow copies on this volume.

.PARAMETER KeepVersions
    Number of system-state backup versions to keep on the target. Must stay well below the
    tombstone lifetime (180 days) - a backup older than that cannot be restored.

.PARAMETER CopyToPath
    Optional UNC path. The latest backup is mirrored to <CopyToPath>\<COMPUTERNAME>.
    The computer account (scheduled task runs as SYSTEM) needs Modify rights on the share.

.PARAMETER ConfigFile
    Shared settings file (default: ADHealthCheck.config.psd1 next to the script, if present).
    The top-level SmtpServer / SmtpPort / UseSsl / From / To and the keys of the Backup = @{...} section are used.
    Parameters given on the command line win over the file.

.EXAMPLE
    .\Backup-ADSystemState.ps1 -BackupTarget D: -KeepVersions 14 -MailOnFailure

.NOTES
    Script      : Backup-ADSystemState.ps1
    Version     : 1.1
    Author      : Md Ariful Haque
    E-mail      : hmariful@outlook.com
    Website     : https://ariful.me

    Backups contain ntds.dit (all password hashes). Restrict access to the target volume and the copy share
    to Domain Admins / Backup Operators and SYSTEM only.
    Exit code: 0 = success, 1 = backup OK but cleanup/copy warning, 2 = backup failed.
#>
[CmdletBinding()]
param(
    [string]$BackupTarget = 'D:',
    [int]   $KeepVersions = 14,
    [int]   $MinFreeGB    = 30,
    [string]$CopyToPath,
    [string]$LogFolder    = 'C:\Scripts\Logs\ADBackup',
    [int]   $KeepLogsDays = 60,

    [switch]  $MailOnFailure,
    [switch]  $MailOnSuccess,
    [string]  $SmtpServer,
    [int]     $SmtpPort   = 25,
    [bool]    $UseSsl     = $false,
    [string]  $From,
    [string[]]$To,
    [string]  $ConfigFile
)

# ---------- Configuration file (shared with Invoke-ADHealthCheck.ps1) ----------
$cfgPath = if ($ConfigFile) { $ConfigFile } elseif ($PSScriptRoot) { Join-Path $PSScriptRoot 'ADHealthCheck.config.psd1' } else { $null }
if ($cfgPath -and (Test-Path -LiteralPath $cfgPath)) {
    $cfgData = Import-PowerShellDataFile -LiteralPath $cfgPath -ErrorAction Stop
    $settings = @{}
    foreach ($k in 'SmtpServer', 'SmtpPort', 'UseSsl', 'From', 'To') { if ($cfgData.ContainsKey($k)) { $settings[$k] = $cfgData[$k] } }
    if ($cfgData['Backup'] -is [System.Collections.IDictionary]) { foreach ($k in $cfgData['Backup'].Keys) { $settings[$k] = $cfgData['Backup'][$k] } }
    $paramNames = @($MyInvocation.MyCommand.Parameters.Keys)
    foreach ($k in $settings.Keys) {
        if ($paramNames -contains $k -and -not $PSBoundParameters.ContainsKey($k)) { Set-Variable -Name $k -Value $settings[$k] }
    }
}
elseif ($ConfigFile) { Write-Error "Config file '$ConfigFile' not found."; exit 2 }

$ErrorActionPreference = 'Stop'
$start = Get-Date
$BackupTarget = $BackupTarget.TrimEnd('\')
if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
$logFile = Join-Path $LogFolder ("ADBackup_{0}_{1}.log" -f $env:COMPUTERNAME, $start.ToString('yyyy-MM-dd_HHmmss'))
$script:status = 'Success'

function Write-Log([string]$msg, [string]$level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $level, $msg
    Add-Content -LiteralPath $logFile -Value $line
    $c = switch ($level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $c
}

function Send-Report {
    if (-not ($MailOnFailure -and $script:status -ne 'Success') -and -not $MailOnSuccess) { return }
    if (-not $SmtpServer -or -not $From -or -not $To) { Write-Log 'E-mail not sent: SmtpServer, From and To are not set (parameters or config file).' 'WARN'; return }
    try {
        $mail = @{
            SmtpServer = $SmtpServer; Port = $SmtpPort; From = $From; To = $To
            Subject    = "[$($script:status.ToUpper())] AD system-state backup - $env:COMPUTERNAME - $($start.ToString('yyyy-MM-dd HH:mm'))"
            Body       = (Get-Content -LiteralPath $logFile -Raw)
            ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue'
        }
        if ($UseSsl) { $mail.UseSsl = $true }
        Send-MailMessage @mail
    }
    catch { Write-Log "E-mail failed: $($_.Exception.Message)" 'WARN' }
}

function Stop-Backup([string]$msg) {
    Write-Log $msg 'ERROR'
    $script:status = 'Failed'
    Send-Report
    exit 2
}

Write-Log "AD system-state backup started on $env:COMPUTERNAME (target $BackupTarget, keep $KeepVersions versions)"

# ---------- 1. Prerequisites ----------
if (-not (Get-Command wbadmin.exe -ErrorAction SilentlyContinue)) {
    Stop-Backup 'wbadmin.exe not found. Install it with: Install-WindowsFeature Windows-Server-Backup'
}
if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) { Write-Log 'This server is not a domain controller - backup continues, but it contains no AD database.' 'WARN' }
if ($BackupTarget -ieq $env:SystemDrive) { Stop-Backup "Backup target $BackupTarget is the system drive. Use a dedicated volume." }

$vol = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $BackupTarget)
if (-not $vol) { Stop-Backup "Backup target volume $BackupTarget not found." }
if ($vol.DriveType -ne 3) { Stop-Backup "Backup target $BackupTarget is not a fixed local disk (DriveType $($vol.DriveType))." }
$freeGB = [math]::Round($vol.FreeSpace / 1GB, 1)
Write-Log ("Target {0}: {1} GB free of {2} GB" -f $BackupTarget, $freeGB, [math]::Round($vol.Size / 1GB, 1))
if ($freeGB -lt $MinFreeGB) { Stop-Backup "Less than $MinFreeGB GB free on $BackupTarget. Lower -KeepVersions or enlarge the volume." }

$ntdsPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue).'DSA Database file'
if ($ntdsPath -and $ntdsPath.Substring(0, 2) -ieq $BackupTarget) {
    Stop-Backup "The AD database ($ntdsPath) is on the backup target $BackupTarget. Use a different volume."
}

# ---------- 2. Backup ----------
Write-Log 'Running: wbadmin start systemstatebackup'
$out = & wbadmin.exe start systemstatebackup "-backupTarget:$BackupTarget" -quiet 2>&1 | ForEach-Object { "$_" }
$rc = $LASTEXITCODE
$out | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*(Creating a shadow copy|Found \(\d+\) files|\d+% of)' } | ForEach-Object { Write-Log "  wbadmin: $_" }
if ($rc -ne 0) { Stop-Backup "wbadmin failed with exit code $rc. See the wbadmin lines above and the Microsoft-Windows-Backup event log." }
Write-Log "Backup finished in $([int]((Get-Date) - $start).TotalMinutes) min"

# ---------- 3. Verify ----------
$versions = (& wbadmin.exe get versions "-backupTarget:$BackupTarget" 2>&1 | ForEach-Object { "$_" }) -join "`n"
$ids = @([regex]::Matches($versions, 'Version identifier:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
if ($ids.Count -eq 0) { Stop-Backup "Backup reported success but no version is listed on $BackupTarget." }
Write-Log "Versions on target: $($ids.Count); newest: $($ids[-1])"

# ---------- 4. Retention ----------
if ($ids.Count -gt $KeepVersions) {
    Write-Log "Deleting older system-state versions (keeping $KeepVersions)"
    $del = & wbadmin.exe delete systemstatebackup "-keepVersions:$KeepVersions" "-backupTarget:$BackupTarget" -quiet 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { Write-Log "Cleanup failed (exit $LASTEXITCODE): $($del -join ' ')" 'WARN'; $script:status = 'Warning' }
}

# ---------- 5. Optional off-server copy ----------
if ($CopyToPath) {
    $src = Join-Path $BackupTarget "WindowsImageBackup\$env:COMPUTERNAME"
    $dst = Join-Path $CopyToPath $env:COMPUTERNAME
    Write-Log "Mirroring $src -> $dst"
    & robocopy.exe $src $dst /MIR /R:2 /W:30 /NP /NFL /NDL /LOG+:"$logFile" | Out-Null
    if ($LASTEXITCODE -ge 8) { Write-Log "robocopy failed (exit $LASTEXITCODE)" 'WARN'; $script:status = 'Warning' }
    else { Write-Log 'Copy completed' }
}

# ---------- 6. Housekeeping ----------
Get-ChildItem -LiteralPath $LogFolder -Filter 'ADBackup_*.log' |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepLogsDays) } | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Log "Result: $($script:status)"
Send-Report
exit $(if ($script:status -eq 'Success') { 0 } else { 1 })
