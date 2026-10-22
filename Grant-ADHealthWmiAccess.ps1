#Requires -Version 5.1
<#
.SYNOPSIS
    Grants the read-only rights the AD health check needs when it runs as a non-admin account (gMSA).
    Run once, as a Domain Admin, in an elevated Windows PowerShell 5.1 on a DC.

.DESCRIPTION
    Always (WMI):
      "Enable Account" + "Remote Enable" on these WMI namespaces on every DC:
        root\cimv2         OS, CPU, memory, disks, services
        root\default       registry provider (NTDS / SYSVOL paths)
        root\microsoftdfs  DFSR SYSVOL state

    -Services (read-only service status):
      Adds a read-only entry for the group to the Service Control Manager and to the AD-related services
      on every DC (query status / configuration only - NOT start, stop or change):
        scmanager : (A;;CCLCRPRC;;;<SID>)      connect, enumerate, query lock status, read
        services  : (A;;CCLCSWLOCRRC;;;<SID>)  query config/status, enumerate dependents, interrogate, read
      Note: a GPO with "System Services" security settings would overwrite these entries.

    -ReplicationMonitor (replication status / queue, dcdiag Replications):
      Grants the extended right "Monitor Active Directory Replication" on every naming context.
      This is a READ right for replication status. It is NOT "Replicating Directory Changes" (DCSync),
      which is never granted by this script.

    Existing permissions are never removed. Entries that are already present are left alone,
    so the script can be run again safely.

.EXAMPLE
    .\Grant-ADHealthWmiAccess.ps1 -Group 'CONTOSO\ADHC-Readers' -Services -ReplicationMonitor -WhatIf
    .\Grant-ADHealthWmiAccess.ps1 -Group 'CONTOSO\ADHC-Readers' -Services -ReplicationMonitor

.NOTES
    Script      : Grant-ADHealthWmiAccess.ps1
    Version     : 1.2
    Author      : Md Ariful Haque
    E-mail      : hmariful@outlook.com
    Website     : https://ariful.me

    The Schema partition can only be changed by an elevated member of Schema Admins. If that line fails,
    run the dsacls command from docs/gmsa-setup.md in an elevated window as a Schema Admin.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Group,
    [string[]]$ComputerName,
    [string[]]$Namespace = @('root\cimv2', 'root\default', 'root\microsoftdfs'),
    [switch]  $Services,
    [string[]]$ServiceName = @('NTDS', 'Netlogon', 'Kdc', 'ADWS', 'W32Time', 'DFSR', 'IsmServ', 'LanmanServer',
        'LanmanWorkstation', 'RpcSs', 'EventLog', 'Dnscache', 'DNS', 'NtFrs'),
    [switch]  $ReplicationMonitor
)

if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this in Windows PowerShell 5.1 (it uses the WMI security methods).' }

$sid = (New-Object System.Security.Principal.NTAccount($Group)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Group $Group = $sid" -ForegroundColor Cyan

if (-not $ComputerName -or $ReplicationMonitor) { Import-Module ActiveDirectory -ErrorAction Stop }
if (-not $ComputerName) { $ComputerName = @(Get-ADDomainController -Filter * | ForEach-Object { $_.HostName }) }

function Write-Row([string]$tag, [string]$label, [string]$color, [string]$extra = '') {
    $t = ('[{0,-8}]' -f $tag)
    if ($extra) { Write-Host "$t $label : $extra" -ForegroundColor $color } else { Write-Host "$t $label" -ForegroundColor $color }
}

# =================== 1. WMI namespaces ===================
Write-Host "`n--- WMI namespace permissions ---" -ForegroundColor Cyan
$ENABLE = 0x1; $REMOTE_ENABLE = 0x20; $CONTAINER_INHERIT = 0x2; $ACCESS_ALLOWED = 0x0
$mask = $ENABLE -bor $REMOTE_ENABLE

foreach ($c in $ComputerName) {
    foreach ($ns in $Namespace) {
        $label = "\\$c\$ns"
        try {
            # -WhatIf:$false: the calls always run; only the write below is gated by ShouldProcess
            $wmi = @{ ComputerName = $c; Namespace = $ns; Path = '__SystemSecurity=@'; ErrorAction = 'Stop'; WhatIf = $false; Confirm = $false }
            $get = Invoke-WmiMethod @wmi -Name GetSecurityDescriptor
            if ($get.ReturnValue -ne 0) { throw "GetSecurityDescriptor returned $($get.ReturnValue)" }
            $sd = $get.Descriptor

            $existing = @($sd.DACL | Where-Object { $_.Trustee.SidString -eq $sid -and $_.AceType -eq $ACCESS_ALLOWED -and (($_.AccessMask -band $mask) -eq $mask) })
            if ($existing) { Write-Row 'OK' "$label already granted" Green; continue }

            if ($PSCmdlet.ShouldProcess($label, "Grant Enable Account + Remote Enable to $Group")) {
                $trustee = (New-Object System.Management.ManagementClass('Win32_Trustee')).CreateInstance()
                $trustee.SidString = $sid
                $ace = (New-Object System.Management.ManagementClass('Win32_Ace')).CreateInstance()
                $ace.AccessMask = $mask
                $ace.AceFlags = $CONTAINER_INHERIT
                $ace.AceType = $ACCESS_ALLOWED
                $ace.Trustee = $trustee
                $sd.DACL += $ace.PsObject.ImmediateBaseObject

                $set = Invoke-WmiMethod @wmi -Name SetSecurityDescriptor -ArgumentList $sd.PsObject.ImmediateBaseObject
                if ($set.ReturnValue -ne 0) { throw "SetSecurityDescriptor returned $($set.ReturnValue)" }
                Write-Row 'GRANTED' $label Yellow
            }
            else { Write-Row 'WHATIF' "$label would be granted" Cyan }
        }
        catch {
            if ($_.Exception.Message -match 'Invalid namespace') { Write-Row 'SKIPPED' "$label does not exist on this server" DarkGray }
            else { Write-Row 'FAILED' $label Red $_.Exception.Message }
        }
    }
}

# =================== 2. Read-only service permissions ===================
if ($Services) {
    Write-Host "`n--- Read-only service permissions ---" -ForegroundColor Cyan
    foreach ($c in $ComputerName) {
        foreach ($svc in @('scmanager') + $ServiceName) {
            $label = "\\$c service $svc"
            $newAce = if ($svc -eq 'scmanager') { "(A;;CCLCRPRC;;;$sid)" } else { "(A;;CCLCSWLOCRRC;;;$sid)" }
            $show = @(& sc.exe "\\$c" sdshow $svc 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            $sddl = $show | Where-Object { $_ -match '^(O:|G:|D:)' } | Select-Object -Last 1
            if (-not $sddl) {
                if (($show -join ' ') -match '1060') { Write-Row 'SKIPPED' "$label not installed" DarkGray }
                else { Write-Row 'FAILED' $label Red ($show -join ' ') }
                continue
            }
            if ($sddl -match [regex]::Escape(";;;$sid)")) { Write-Row 'OK' "$label already has an entry for the group" Green; continue }

            $i = $sddl.IndexOf('S:')
            $newSddl = if ($i -ge 0) { $sddl.Insert($i, $newAce) } else { $sddl + $newAce }
            if ($PSCmdlet.ShouldProcess($label, "Add read-only entry $newAce")) {
                $r = (& sc.exe "\\$c" sdset $svc $newSddl 2>&1 | ForEach-Object { "$_" }) -join ' '
                if ($r -match 'SUCCESS') { Write-Row 'GRANTED' $label Yellow }
                else { Write-Row 'FAILED' $label Red $r.Trim() }
            }
            else { Write-Row 'WHATIF' "$label would get $newAce" Cyan }
        }
    }
}

# =================== 3. Monitor Active Directory Replication ===================
if ($ReplicationMonitor) {
    Write-Host "`n--- Monitor Active Directory Replication ---" -ForegroundColor Cyan
    if (-not (Get-Command dsacls.exe -ErrorAction SilentlyContinue)) { Write-Row 'FAILED' 'dsacls.exe not found - run this on a DC' Red }
    else {
        foreach ($nc in @((Get-ADRootDSE).namingContexts)) {
            $current = (& dsacls.exe $nc 2>&1 | ForEach-Object { "$_" }) -join "`n"
            $short = $Group.Split('\')[-1]
            if ($current -match "(?m)^Allow\s+\S*\\?$([regex]::Escape($short))\s+SPECIAL ACCESS for Monitor Active Directory Replication") {
                Write-Row 'OK' "$nc already granted" Green; continue
            }
            if ($PSCmdlet.ShouldProcess($nc, "Grant 'Monitor Active Directory Replication' to $Group")) {
                $r = (& dsacls.exe $nc /G "$($Group):CA;Monitor Active Directory Replication" 2>&1 | ForEach-Object { "$_" }) -join ' '
                if ($r -match 'completed successfully') { Write-Row 'GRANTED' $nc Yellow }
                else { Write-Row 'FAILED' $nc Red ((($r -split '\s{2,}') | Select-Object -Last 3) -join ' ') }
            }
            else { Write-Row 'WHATIF' "$nc would be granted 'Monitor Active Directory Replication'" Cyan }
        }
    }
}

Write-Host "`nNo restart needed. The next run of the health check uses the new permissions." -ForegroundColor Cyan
