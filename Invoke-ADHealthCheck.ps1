#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Active Directory health check: colour-coded HTML report, CSV export and optional e-mail.

.DESCRIPTION
    Every check writes one row with a status of OK, Warning, Critical or Info. The report shows
    what is healthy, not only what is broken.

    FOREST LEVEL
      - Forest functional level, schema version, Global Catalog inventory
      - FSMO role holders online (Schema Master, Domain Naming Master)
      - AD Recycle Bin enabled, tombstone lifetime
      - Sites: subnets defined, Global Catalog in every site that has DCs
      - Forest-wide replication summary (repadmin /replsummary)
      - Last backup of the Configuration and Schema partitions
      - _gc SRV records (missing / stale)

    DOMAIN LEVEL
      - Domain functional level, DC inventory
      - FSMO role holders online (PDC Emulator, RID Master, Infrastructure Master)
      - RID pool consumption
      - Last backup of the domain partition
      - KRBTGT password age
      - SYSVOL replication mechanism (FRS -> DFSR migration state)
      - DC locator SRV records (_ldap._tcp.dc._msdcs, _kerberos._tcp): missing and stale
      - Trust verification (nltest /sc_verify)
      - GPO consistency between AD (GPC) and SYSVOL (GPT)
      - Privileged group membership (Administrators, Domain/Enterprise/Schema Admins)

    PER DOMAIN CONTROLLER
      - Ping, TCP ports (Kerberos, RPC, LDAP, SMB, kpasswd, ADWS, DNS, GC), LDAP bind,
        isSynchronized, isGlobalCatalogReady, WMI/CIM access
      - Services: NTDS, Netlogon, KDC, ADWS, W32Time, DFSR, IsmServ, LanmanServer, LanmanWorkstation,
        RpcSs, EventLog, Dnscache, DNS, NtFrs (with start mode)
      - Uptime, CPU load, free memory, free space on every fixed disk, NTDS database size and paths
      - SYSVOL and NETLOGON shares, DFSR SYSVOL replicated-folder state
      - Inbound replication per partner (all partitions), replication failures, replication queue
      - DNS A-record consistency (incl. multi-homed DCs), DNS server answering queries
      - Time source and time offset against the PDC hierarchy
      - Critical/Error events in Directory Service, DFS Replication, DNS Server and System logs
      - Clients without a site (NO_CLIENT_SITE in netlogon.log = missing subnets)
      - LDAPS certificate expiry
      - Full dcdiag (all default tests + DNS test), each test reported separately with failure details

.PARAMETER ReportFolder
    Folder for the HTML and CSV reports. Default: the script's folder.

.PARAMETER DomainController
    Only test these DCs (short name or FQDN). Default: all DCs in all domains.

.PARAMETER Domain
    Only test these domains. Default: all domains in the forest.

.PARAMETER IncludeAllSystemEvents
    By default the System log is filtered to AD DS / DNS sources (-SystemLogProviders, plus Service Control
    Manager events for the services in -AdServiceDisplayNames) and dcdiag runs with /skip:SystemLog.
    This switch restores the unfiltered System log and the dcdiag SystemLog test.

.PARAMETER DcdiagSkip
    dcdiag tests to skip, e.g. -DcdiagSkip Services (useful when the run account is not an administrator).

.PARAMETER FullDcdiag
    When the script runs without administrator rights (e.g. as a gMSA) it skips the dcdiag tests that
    need admin rights (NetLogons, SysVolCheck, Services, DNS). This switch runs them anyway.

.PARAMETER NtpServer
    NTP servers to test from the script host (UDP 123). Used in addition to the PDC's configured peers,
    or instead of them when the PDC's W32Time configuration cannot be read (least-privilege run).

.PARAMETER IgnoreEventId
    Event IDs to leave out of the event-log checks (e.g. 7034). Ignored events are counted in the result.

.PARAMETER IgnoreEventPattern
    Regex matched against the event message; matching events are left out of the event-log checks
    and of the dcdiag SystemLog test. Example: 'MonitoringAgent|OtherAgent'

.PARAMETER NoClientSiteDays
    Only report NO_CLIENT_SITE entries from netlogon.log newer than this many days (default 7).

.PARAMETER ConfigFile
    PowerShell data file (.psd1) with your environment's settings (SMTP, recipients, report title, NTP servers,
    author footer...). Default: ADHealthCheck.config.psd1 next to the script, if it exists.
    Keys are parameter names; a parameter given on the command line always wins over the config file.
    See ADHealthCheck.config.example.psd1.

.PARAMETER SendEmail
    Send the report by e-mail. Needs -SmtpServer, -From and -To (on the command line or in the config file).
    No authentication is used unless -SmtpCredentialFile / -SmtpCredential is given.

.PARAMETER SmtpCredentialFile
    Optional. Only needed if the relay requires authentication.
    Path to a credential saved with:  Get-Credential | Export-Clixml <path>
    (It can only be decrypted by the same user on the same machine, which suits a scheduled task.)

.PARAMETER EmailOnlyOnIssues
    Only send the e-mail when at least one Warning or Critical result exists.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1
    Runs every check and writes ADHealth_<date>.html / .csv next to the script.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -SendEmail
    Runs every check and mails the report using the settings in ADHealthCheck.config.psd1.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -SendEmail -SmtpServer smtp.contoso.com -SmtpPort 587 -UseSsl $true `
        -From adreport@contoso.com -To admin1@contoso.com, admin2@contoso.com `
        -ReportTitle 'Contoso Prod Active Directory Health Check Report'

.NOTES
    Script      : Invoke-ADHealthCheck.ps1
    Version     : 2.9
    Author      : Md Ariful Haque
    E-mail      : hmariful@outlook.com
    Website     : https://ariful.me

    Change history: see CHANGELOG.md

    Run as Domain Admin (or equivalent) on a DC or a management server with RSAT AD DS tools
    (ActiveDirectory module, dcdiag.exe, repadmin.exe, nltest.exe, w32tm.exe).
    dcdiag / repadmin output is parsed in English; on other OS languages those rows are flagged as "not parsed".
    Exit code: 0 = all OK, 1 = warnings, 2 = critical issues, 3 = could not start.
#>
[CmdletBinding()]
param(
    [string]  $ReportFolder,
    [string]  $ReportTitle = 'Active Directory Health Check Report',
    [string]  $ConfigFile,
    [string[]]$DomainController,
    [string[]]$Domain,

    [int]     $DcdiagTimeoutSeconds = 300,
    [int]     $MaxParallelDcdiag    = 6,
    [switch]  $SkipDcdiagDns,
    [string[]]$DcdiagSkip,
    [switch]  $FullDcdiag,
    [string[]]$NtpServer,

    [int]     $EventLogHours        = 24,
    [switch]  $IncludeAllSystemEvents,
    [string[]]$SystemLogProviders = @(
        'NETLOGON', 'Microsoft-Windows-Kerberos-Key-Distribution-Center', 'Microsoft-Windows-Security-Kerberos',
        'Microsoft-Windows-Time-Service', 'Microsoft-Windows-DNS-Client', 'LsaSrv', 'Microsoft-Windows-Directory-Services-SAM',
        'Microsoft-Windows-GroupPolicy', 'Microsoft-Windows-ActiveDirectory_DomainService', 'DfsSrv', 'Microsoft-Windows-DFSN-Server'),
    [string[]]$AdServiceDisplayNames = @(
        'Active Directory Domain Services', 'Netlogon', 'Kerberos Key Distribution Center', 'Active Directory Web Services',
        'Windows Time', 'DFS Replication', 'Intersite Messaging', 'DNS Server', 'DNS Client'),
    [int[]]   $IgnoreEventId,
    [string]  $IgnoreEventPattern,
    [int]     $NoClientSiteDays     = 7,
    [int]     $DiskWarnPercent      = 20,
    [int]     $DiskCritPercent      = 10,
    [int]     $MemoryWarnPercent    = 10,
    [int]     $CpuWarnPercent       = 90,
    [int]     $ReplWarnMinutes      = 240,
    [int]     $ReplCritMinutes      = 1440,
    [int]     $ReplQueueWarn        = 50,
    [double]  $TimeSkewWarnSeconds  = 5,
    [double]  $TimeSkewCritSeconds  = 120,
    [int]     $UptimeWarnDays       = 90,
    [int]     $CertWarnDays         = 30,
    [int]     $KrbtgtWarnDays       = 180,
    [int]     $BackupWarnDays       = 7,
    [int]     $BackupCritDays       = 30,
    [int]     $PrivilegedWarnCount  = 10,
    [int]     $KeepReportsDays      = 30,

    [switch]  $SendEmail,
    [switch]  $EmailOnlyOnIssues,
    [string]  $SmtpServer,
    [int]     $SmtpPort = 25,
    [bool]    $UseSsl = $false,
    [string]  $From,
    [string[]]$To,
    [pscredential]$SmtpCredential,
    [string]  $SmtpCredentialFile
)

#region ======================= Configuration file =======================
# Environment-specific settings live in ADHealthCheck.config.psd1 (not in source control).
# Keys are parameter names. Anything passed on the command line wins over the file.
$script:ConfigAuthor = $null
$script:ConfigLoaded = $null
$cfgPath = if ($ConfigFile) { $ConfigFile } elseif ($PSScriptRoot) { Join-Path $PSScriptRoot 'ADHealthCheck.config.psd1' } else { $null }
if ($cfgPath -and (Test-Path -LiteralPath $cfgPath)) {
    try { $cfgData = Import-PowerShellDataFile -LiteralPath $cfgPath -ErrorAction Stop }
    catch { Write-Error "Config file '$cfgPath' could not be read: $($_.Exception.Message)"; exit 3 }
    $paramNames = @($MyInvocation.MyCommand.Parameters.Keys)
    foreach ($key in $cfgData.Keys) {
        if ($key -eq 'Author') { $script:ConfigAuthor = $cfgData[$key]; continue }
        if ($key -eq 'Backup') { continue }   # section used by Backup-ADSystemState.ps1
        if ($paramNames -notcontains $key) { Write-Warning "Config file: unknown setting '$key' ignored."; continue }
        if ($PSBoundParameters.ContainsKey($key)) { continue }
        Set-Variable -Name $key -Value $cfgData[$key]
    }
    $script:ConfigLoaded = $cfgPath
}
elseif ($ConfigFile) { Write-Error "Config file '$ConfigFile' not found."; exit 3 }
#endregion

#region ======================= Helpers =======================

$script:Results     = New-Object System.Collections.Generic.List[object]
$script:Rank        = @{ 'Critical' = 3; 'Warning' = 2; 'OK' = 1; 'Info' = 0; 'N/A' = -1 }
$script:Offsets     = @{}
$script:ReplSummary = ''

function Add-Result {
    param(
        [Parameter(Mandatory)][ValidateSet('Forest', 'Domain', 'DC')][string]$Scope,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('OK', 'Warning', 'Critical', 'Info')][string]$Status,
        [string]$Value = '',
        [string]$Details = ''
    )
    $script:Results.Add([pscustomobject]@{
            Scope    = $Scope
            Target   = $Target
            Category = $Category
            Check    = $Check
            Status   = $Status
            Value    = $Value
            Details  = $Details
        })
    $color = switch ($Status) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Critical' { 'Red' } default { 'Cyan' } }
    Write-Host ('[{0,-8}] {1,-20} {2,-13} {3} : {4}' -f $Status, $Target, $Category, $Check, $Value) -ForegroundColor $color
}

# Runs one check; any unexpected error becomes a Warning row instead of stopping the script.
function Invoke-Check {
    param([string]$icScope, [string]$icTarget, [string]$icCategory, [string]$icCheck, [scriptblock]$icBlock)
    $ErrorActionPreference = 'Stop'
    try { & $icBlock }
    catch { Add-Result $icScope $icTarget $icCategory $icCheck 'Warning' 'Check could not run' $_.Exception.Message }
}

function Merge-Status([string]$a, [string]$b) {
    if (-not $a) { return $b }
    if (-not $b) { return $a }
    if ($script:Rank[$b] -gt $script:Rank[$a]) { return $b } else { return $a }
}

function Invoke-Native {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList)
    $ErrorActionPreference = 'Continue'
    $out = & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" }
    return ($out -join "`r`n")
}

function Format-Age($ts) {
    if ($null -eq $ts) { return 'never' }
    if ($ts.TotalDays -ge 1) { return ('{0:N1} days' -f $ts.TotalDays) }
    if ($ts.TotalHours -ge 1) { return ('{0:N1} hours' -f $ts.TotalHours) }
    return ('{0:N0} min' -f $ts.TotalMinutes)
}

function Get-ShortName([string]$dn) { return ($dn -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1') }

function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000, [int]$Attempts = 2)
    # Two attempts: the first connection of a fresh logon can be slow (name resolution, Kerberos)
    for ($a = 1; $a -le $Attempts; $a++) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
                $client.EndConnect($iar)
                return $true
            }
        }
        catch { }
        finally { $client.Close() }
    }
    return $false
}

function Get-LdapsCertificate {
    param([string]$ComputerName, [int]$Port = 636, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -or -not $client.Connected) { return $null }
        $client.EndConnect($iar)
        $client.ReceiveTimeout = 5000; $client.SendTimeout = 5000
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] { $true }
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
        $ssl.ReadTimeout = 5000; $ssl.WriteTimeout = 5000
        $ssl.AuthenticateAsClient($ComputerName)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $ssl.Dispose()
        return $cert
    }
    catch { return $null }
    finally { $client.Close() }
}

function New-DcCimSession {
    param([string]$ComputerName)
    try { return New-CimSession -ComputerName $ComputerName -OperationTimeoutSec 30 -ErrorAction Stop }
    catch {
        try {
            $opt = New-CimSessionOption -Protocol Dcom
            return New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec 30 -ErrorAction Stop
        }
        catch { return $null }
    }
}

function Get-RemoteRegValue {
    param($CimSession, [string]$Key, [string]$Name)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace 'root/default' -ClassName StdRegProv -MethodName GetStringValue `
        -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = $Key; sValueName = $Name } -ErrorAction Stop
    if ($r.ReturnValue -eq 0) { return $r.sValue }
    return $null
}

function Get-TimeOffset {
    param([string]$ComputerName)
    $o = Invoke-Native 'w32tm.exe' @('/stripchart', "/computer:$ComputerName", '/samples:1', '/dataonly')
    $m = [regex]::Matches($o, ',\s*([+-]?\d+[\.,]\d+)s')
    if ($m.Count -gt 0) {
        $v = $m[$m.Count - 1].Groups[1].Value.Replace(',', '.')
        return [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)
    }
    return $null
}

function Get-CachedOffset([string]$ComputerName) {
    if (-not $script:Offsets.ContainsKey($ComputerName)) { $script:Offsets[$ComputerName] = Get-TimeOffset $ComputerName }
    return $script:Offsets[$ComputerName]
}

# "a,b,c" (one string from -File), arrays, and w32tm lists like "a,0x8 b,0x9" -> a, b, c
function Split-NtpServerList($List) {
    @($List | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ -and $_ -notmatch '^0x[0-9a-fA-F]+$' } | Sort-Object -Unique)
}

function Test-FsmoHolder {
    param([string]$Scope, [string]$Target, [string]$Role, [string]$Holder)
    if (-not $Holder) { Add-Result $Scope $Target 'FSMO' $Role 'Critical' 'No holder found'; return }
    # Reuse the reachability test from the start of the run (taken before the dcdiag jobs start);
    # otherwise test now with a longer timeout - job start-up can delay socket callbacks.
    $known = @($script:reach.Keys | Where-Object { $_ -ieq $Holder }) | Select-Object -First 1
    $online = ($known -and $script:reach[$known].Ldap) -or (Test-TcpPort $Holder 389 -TimeoutMs 5000 -Attempts 3)
    if ($online) { Add-Result $Scope $Target 'FSMO' $Role 'OK' $Holder 'Role holder online (LDAP 389 reachable)' }
    else { Add-Result $Scope $Target 'FSMO' $Role 'Critical' $Holder 'Role holder NOT reachable on LDAP 389' }
}

function Test-NcBackup {
    param([string]$Scope, [string]$Target, [string]$NcDn, [string]$Server, [string]$Label)
    $md = Get-ADReplicationAttributeMetadata -Object $NcDn -Server $Server -Properties dSASignature -ErrorAction Stop |
        Where-Object { $_.AttributeName -eq 'dSASignature' } | Select-Object -First 1
    $chk = "Last backup: $Label"
    if (-not $md -or -not $md.LastOriginatingChangeTime -or $md.LastOriginatingChangeTime.Year -lt 1990) {
        Add-Result $Scope $Target 'Backup' $chk 'Critical' 'No backup recorded' 'No system-state backup has been recorded for this partition.'
        return
    }
    $when = $md.LastOriginatingChangeTime
    $age = (Get-Date) - $when
    $val = "$(Format-Age $age) ago ($($when.ToString('yyyy-MM-dd HH:mm')))"
    $hint = 'Date is set only by AD-aware system-state backups (Windows Server Backup or a VSS/AD-aware backup product). VM snapshots or file backups do not update it.'
    if ($age.TotalDays -gt $BackupCritDays) { Add-Result $Scope $Target 'Backup' $chk 'Critical' $val "Older than $BackupCritDays days. $hint" }
    elseif ($age.TotalDays -gt $BackupWarnDays) { Add-Result $Scope $Target 'Backup' $chk 'Warning' $val "Older than $BackupWarnDays days. $hint" }
    else { Add-Result $Scope $Target 'Backup' $chk 'OK' $val }
}

function Test-SrvRecords {
    param([string]$Scope, [string]$Target, [string]$Name, [string[]]$Expected, [string[]]$Allowed)
    $recs = @(Resolve-DnsName -Name $Name -Type SRV -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'SRV' } |
            ForEach-Object { $_.NameTarget.TrimEnd('.').ToLower() } | Sort-Object -Unique)
    $exp = @($Expected | ForEach-Object { $_.ToLower() })
    $alw = @($Allowed | ForEach-Object { $_.ToLower() })
    $missing = @($exp | Where-Object { $recs -notcontains $_ })
    $extra = @($recs | Where-Object { $alw -notcontains $_ })
    $val = "$($recs.Count) registered, $($missing.Count) missing, $($extra.Count) unexpected"
    $det = @()
    if ($missing) { $det += "Missing: $($missing -join ', ')" }
    if ($extra) { $det += "Unexpected / stale: $($extra -join ', ')" }
    $st = if ($missing) { 'Critical' } elseif ($extra) { 'Warning' } else { 'OK' }
    Add-Result $Scope $Target 'DNS' "SRV $Name" $st $val ($det -join "`n")
}

# ---- dcdiag background jobs (run in parallel while the other checks execute) ----
# Least-privilege run (e.g. a gMSA): skip the dcdiag tests that only work with administrator rights.
# The script's own checks cover the same ground (services, SYSVOL shares/DFSR, DNS records).
try { $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
catch { $script:IsAdmin = $false }
$script:AutoSkipped = @()
if (-not $script:IsAdmin -and -not $FullDcdiag) {
    $script:AutoSkipped = @('NetLogons', 'SysVolCheck', 'Services', 'DNS')
    $SkipDcdiagDns = [switch]$true
}
$script:DcdiagSkipList = @(@($DcdiagSkip) + @($script:AutoSkipped | Where-Object { $_ -ne 'DNS' }) + $(if (-not $IncludeAllSystemEvents) { 'SystemLog' }) | Where-Object { $_ } | Sort-Object -Unique)
$script:DcdiagQueue = New-Object System.Collections.Queue
$script:DcdiagJobs  = @{}
$script:DcdiagStart = @{}
$script:DcdiagBlock = {
    param($Server, $RunDns, $SkipTests)
    $dcArgs = @("/s:$Server")
    foreach ($t in @($SkipTests)) { if ($t) { $dcArgs += "/skip:$t" } }
    $out = (& dcdiag.exe @dcArgs 2>&1 | Out-String)
    if ($RunDns) { $out += "`r`n" + (& dcdiag.exe "/s:$Server" '/test:DNS' 2>&1 | Out-String) }
    $out
}
function Start-PendingDcdiag {
    foreach ($k in @($script:DcdiagJobs.Keys)) {
        $j = $script:DcdiagJobs[$k]
        if ($j.State -eq 'Running' -and ((Get-Date) - $script:DcdiagStart[$k]).TotalSeconds -gt $DcdiagTimeoutSeconds) { Stop-Job $j }
    }
    while ($script:DcdiagQueue.Count -gt 0) {
        $running = @($script:DcdiagJobs.Values | Where-Object { $_.State -eq 'Running' }).Count
        if ($running -ge $MaxParallelDcdiag) { break }
        $srv = $script:DcdiagQueue.Dequeue()
        $script:DcdiagJobs[$srv] = Start-Job -Name "dcdiag_$srv" -ScriptBlock $script:DcdiagBlock -ArgumentList $srv, (-not $SkipDcdiagDns), $script:DcdiagSkipList
        $script:DcdiagStart[$srv] = Get-Date
    }
}

#endregion Helpers

#region ======================= Preparation =======================

$ScriptVersion = '2.9'

# ---- Author information (report footer). Can also be set with Author = @{...} in the config file.
#      Values still in <angle brackets> are not shown.
$script:Author = [ordered]@{
    'Author'  = 'Md Ariful Haque'
    'E-mail'  = 'hmariful@outlook.com'
    'Website' = 'https://ariful.me'
}
if ($script:ConfigAuthor -is [System.Collections.IDictionary]) {
    foreach ($k in $script:ConfigAuthor.Keys) { $script:Author[$k] = $script:ConfigAuthor[$k] }
}
$scriptStart = Get-Date
$stamp = $scriptStart.ToString('yyyy-MM-dd_HHmmss')
if (-not $ReportFolder) { $ReportFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
if (-not (Test-Path -LiteralPath $ReportFolder)) { New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null }
$htmlPath = Join-Path $ReportFolder "ADHealth_$stamp.html"
$csvPath  = Join-Path $ReportFolder "ADHealth_$stamp.csv"

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error 'ActiveDirectory PowerShell module not found. Install RSAT AD DS tools.'; exit 3 }

$tools = @{}
foreach ($t in 'dcdiag', 'repadmin', 'w32tm', 'nltest') { $tools[$t] = [bool](Get-Command "$t.exe" -ErrorAction SilentlyContinue) }

Write-Host 'Discovering forest topology...' -ForegroundColor Cyan
try {
    $forest  = Get-ADForest -ErrorAction Stop
    $rootDse = Get-ADRootDSE -ErrorAction Stop
}
catch { Write-Error "Cannot read the AD forest: $($_.Exception.Message)"; exit 3 }

$F = $forest.Name
foreach ($t in $tools.Keys) {
    if (-not $tools[$t]) { Add-Result 'Forest' $F 'Tools' "$t.exe" 'Warning' 'Not found' "Checks that need $t.exe are skipped. Install RSAT AD DS / run on a DC." }
}

$domainList = if ($Domain) { @($Domain) } else { @($forest.Domains) }
$domainInfo = @{}
$allDCs = New-Object System.Collections.Generic.List[object]
foreach ($d in $domainList) {
    try {
        $domainInfo[$d] = Get-ADDomain -Server $d -ErrorAction Stop
        Get-ADDomainController -Filter * -Server $d -ErrorAction Stop | ForEach-Object { $allDCs.Add($_) }
    }
    catch { Add-Result 'Domain' $d 'Connectivity' 'Domain discovery' 'Critical' 'Cannot contact domain' $_.Exception.Message }
}

$dcsToTest = [object[]]$allDCs.ToArray()
if ($DomainController) {
    $dcsToTest = @($allDCs | Where-Object { $DomainController -contains $_.Name -or $DomainController -contains $_.HostName })
}

$forestRootPdc = $null
try {
    $forestRootPdc = if ($domainInfo.ContainsKey($forest.RootDomain)) { $domainInfo[$forest.RootDomain].PDCEmulator }
    else { (Get-ADDomain -Server $forest.RootDomain -ErrorAction Stop).PDCEmulator }
}
catch { }

try { $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = "$env:USERDOMAIN\$env:USERNAME" }
if ($script:ConfigLoaded) { Add-Result 'Forest' $F 'Run account' 'Config file' 'Info' (Split-Path $script:ConfigLoaded -Leaf) $script:ConfigLoaded }
else { Add-Result 'Forest' $F 'Run account' 'Config file' 'Info' 'None (defaults / command line)' 'Copy ADHealthCheck.config.example.psd1 to ADHealthCheck.config.psd1 next to the script to set SMTP, recipients, title and NTP servers.' }
if ($script:IsAdmin) { Add-Result 'Forest' $F 'Run account' 'Run account' 'Info' "$who (administrator)" }
else {
    $skipText = if ($script:AutoSkipped) { "dcdiag tests skipped (need admin, covered by this script's own checks): $($script:AutoSkipped -join ', '). Use -FullDcdiag to run them anyway." } else { '' }
    Add-Result 'Forest' $F 'Run account' 'Run account' 'Info' "$who (least privilege)" ("Checks that need administrator rights on the DCs are reported as Info 'Not readable by run account'.`n" + $skipText)
}

# Reachability first, so dcdiag can start in the background straight away
Write-Host "Testing reachability of $($dcsToTest.Count) domain controller(s)..." -ForegroundColor Cyan
$reach = @{}
foreach ($dcObj in $dcsToTest) {
    $h = $dcObj.HostName
    $ping = [bool](Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue)
    $ldap = Test-TcpPort $h 389
    $reach[$h] = [pscustomobject]@{ Ping = $ping; Ldap = $ldap; Up = ($ping -or $ldap) }
    if ($reach[$h].Up -and $tools['dcdiag']) { $script:DcdiagQueue.Enqueue($h) }
}
Start-PendingDcdiag

#endregion Preparation

#region ======================= Forest checks =======================

Write-Host "`n=== Forest: $F ===" -ForegroundColor Cyan
Add-Result 'Forest' $F 'Configuration' 'Forest functional level' 'Info' "$($forest.ForestMode)"
Add-Result 'Forest' $F 'Configuration' 'Domains' 'Info' "$(@($forest.Domains).Count)" (@($forest.Domains) -join ', ')
Add-Result 'Forest' $F 'Configuration' 'Global Catalogs' 'Info' "$(@($forest.GlobalCatalogs).Count)" (@($forest.GlobalCatalogs) -join ', ')

Invoke-Check 'Forest' $F 'Configuration' 'Schema version' {
    $v = [int](Get-ADObject $rootDse.schemaNamingContext -Properties objectVersion).objectVersion
    $map = @{ 30 = 'Windows Server 2003'; 31 = 'Windows Server 2003 R2'; 44 = 'Windows Server 2008'; 47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'; 69 = 'Windows Server 2012 R2'; 87 = 'Windows Server 2016'; 88 = 'Windows Server 2019/2022'; 91 = 'Windows Server 2025' }
    $label = if ($map.ContainsKey($v)) { $map[$v] } else { 'unknown' }
    Add-Result 'Forest' $F 'Configuration' 'Schema version' 'Info' "$v ($label)"
}

Test-FsmoHolder 'Forest' $F 'Schema Master' $forest.SchemaMaster
Test-FsmoHolder 'Forest' $F 'Domain Naming Master' $forest.DomainNamingMaster

Invoke-Check 'Forest' $F 'Configuration' 'AD Recycle Bin' {
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
    if ($rb -and @($rb.EnabledScopes).Count -gt 0) { Add-Result 'Forest' $F 'Configuration' 'AD Recycle Bin' 'OK' 'Enabled' }
    else { Add-Result 'Forest' $F 'Configuration' 'AD Recycle Bin' 'Warning' 'Disabled' 'Enable it (Enable-ADOptionalFeature) so deleted objects can be restored with all attributes.' }
}

Invoke-Check 'Forest' $F 'Configuration' 'Tombstone lifetime' {
    $ds = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.configurationNamingContext)" -Properties tombstoneLifetime
    $tsl = if ($ds.tombstoneLifetime) { [int]$ds.tombstoneLifetime } else { 60 }
    if ($tsl -lt 180) { Add-Result 'Forest' $F 'Configuration' 'Tombstone lifetime' 'Warning' "$tsl days" 'Recommended: 180 days.' }
    else { Add-Result 'Forest' $F 'Configuration' 'Tombstone lifetime' 'OK' "$tsl days" }
}

Invoke-Check 'Forest' $F 'Sites' 'Sites & subnets' {
    $sites = @(Get-ADReplicationSite -Filter *)
    $subnets = @(Get-ADReplicationSubnet -Filter *)
    Add-Result 'Forest' $F 'Sites' 'Site / subnet count' 'Info' "$($sites.Count) sites, $($subnets.Count) subnets"
    foreach ($s in $sites) {
        $sn = @($subnets | Where-Object { $_.Site -eq $s.DistinguishedName })
        $dcsInSite = @($allDCs | Where-Object { $_.Site -eq $s.Name })
        $gcsInSite = @($dcsInSite | Where-Object { $_.IsGlobalCatalog })
        $st = 'OK'; $notes = @()
        if ($dcsInSite.Count -eq 0) { $st = 'Info'; $notes += 'No DCs in this site (clients use site coverage)' }
        if ($sn.Count -eq 0) {
            $st = if ($dcsInSite.Count -gt 0) { 'Warning' } else { 'Info' }
            $notes += 'No subnets linked to this site'
        }
        if ($dcsInSite.Count -gt 0 -and $gcsInSite.Count -eq 0) { $st = Merge-Status $st 'Warning'; $notes += 'No Global Catalog in this site' }
        $val = "$($dcsInSite.Count) DC(s), $($gcsInSite.Count) GC(s), $($sn.Count) subnet(s)"
        Add-Result 'Forest' $F 'Sites' "Site $($s.Name)" $st $val ($notes -join "`n")
    }
}

if ($tools['repadmin']) {
    Invoke-Check 'Forest' $F 'Replication' 'Forest replication summary' {
        $script:ReplSummary = Invoke-Native 'repadmin.exe' @('/replsummary')
        $bad = @()
        foreach ($line in ($script:ReplSummary -split "`r?`n")) {
            if ($line -match '^\s*(\S+)\s+.*?\s(\d+)\s*/\s*(\d+)\s+(\d+)\s*(.*)$') {
                if ([int]$matches[2] -gt 0) { $bad += "$($matches[1]): $($matches[2])/$($matches[3]) links failing $($matches[5])".Trim() }
            }
        }
        if ($script:ReplSummary -match '(?s)operational errors.*') {
            $bad += 'repadmin could not contact some DCs: ' + (($matches[0] -split "`r?`n" | Select-Object -First 6) -join ' | ')
        }
        if ($bad) { Add-Result 'Forest' $F 'Replication' 'Forest replication summary' 'Critical' "$($bad.Count) problem line(s)" ($bad -join "`n") }
        elseif ($script:ReplSummary -match 'Source DSA|Destination DSA') { Add-Result 'Forest' $F 'Replication' 'Forest replication summary' 'OK' 'No failing replication links' }
        else { Add-Result 'Forest' $F 'Replication' 'Forest replication summary' 'Warning' 'Output not parsed' $script:ReplSummary.Substring(0, [math]::Min(800, $script:ReplSummary.Length)) }
    }
}

if ($forestRootPdc) {
    Invoke-Check 'Forest' $F 'Backup' 'Last backup: Configuration' { Test-NcBackup 'Forest' $F $rootDse.configurationNamingContext $forestRootPdc 'Configuration partition' }
    Invoke-Check 'Forest' $F 'Backup' 'Last backup: Schema' { Test-NcBackup 'Forest' $F $rootDse.schemaNamingContext $forestRootPdc 'Schema partition' }
}

if (-not $Domain) {
    Invoke-Check 'Forest' $F 'DNS' "SRV _gc._tcp.$($forest.RootDomain)" {
        $exp = @($allDCs | Where-Object { $_.IsGlobalCatalog -and -not $_.IsReadOnly } | ForEach-Object { $_.HostName })
        $alw = @($allDCs | Where-Object { $_.IsGlobalCatalog } | ForEach-Object { $_.HostName })
        Test-SrvRecords 'Forest' $F "_gc._tcp.$($forest.RootDomain)" $exp $alw
    }
}

#endregion Forest checks

#region ======================= Domain checks =======================

foreach ($d in $domainList) {
    if (-not $domainInfo.ContainsKey($d)) { continue }
    Write-Host "`n=== Domain: $d ===" -ForegroundColor Cyan
    $dom = $domainInfo[$d]; $dn = $dom.DistinguishedName; $pdc = $dom.PDCEmulator
    $domDCs = @($allDCs | Where-Object { $_.Domain -eq $d })

    Add-Result 'Domain' $d 'Configuration' 'Domain functional level' 'Info' "$($dom.DomainMode)"
    $dcList = $domDCs | ForEach-Object {
        $tags = @(); if ($_.IsGlobalCatalog) { $tags += 'GC' }; if ($_.IsReadOnly) { $tags += 'RODC' }
        "$($_.Name) [$($_.Site)$(if ($tags) { ', ' + ($tags -join ', ') })]"
    }
    Add-Result 'Domain' $d 'Configuration' 'Domain controllers' 'Info' "$($domDCs.Count)" ($dcList -join "`n")

    Test-FsmoHolder 'Domain' $d 'PDC Emulator' $dom.PDCEmulator
    Test-FsmoHolder 'Domain' $d 'RID Master' $dom.RIDMaster
    Test-FsmoHolder 'Domain' $d 'Infrastructure Master' $dom.InfrastructureMaster

    Invoke-Check 'Domain' $d 'Configuration' 'RID pool' {
        $rid = Get-ADObject "CN=RID Manager`$,CN=System,$dn" -Properties rIDAvailablePool -Server $dom.RIDMaster
        $pool = [int64]$rid.rIDAvailablePool
        $total = [int64]($pool -shr 32)
        $issued = $pool -band [int64]4294967295
        $pct = if ($total -gt 0) { [math]::Round($issued / $total * 100, 2) } else { 0 }
        $val = '{0:N0} of {1:N0} RIDs issued ({2}%)' -f $issued, $total, $pct
        $st = if ($pct -ge 90) { 'Critical' } elseif ($pct -ge 75) { 'Warning' } else { 'OK' }
        Add-Result 'Domain' $d 'Configuration' 'RID pool' $st $val
    }

    Invoke-Check 'Domain' $d 'Backup' 'Last backup: Domain' { Test-NcBackup 'Domain' $d $dn $pdc 'Domain partition' }

    Invoke-Check 'Domain' $d 'Security' 'KRBTGT password age' {
        $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet -Server $d
        $age = [int]((Get-Date) - $k.PasswordLastSet).TotalDays
        $det = "Last set: $($k.PasswordLastSet)"
        if ($age -gt $KrbtgtWarnDays) { Add-Result 'Domain' $d 'Security' 'KRBTGT password age' 'Warning' "$age days" "$det. Reset periodically (twice, allowing replication in between)." }
        else { Add-Result 'Domain' $d 'Security' 'KRBTGT password age' 'OK' "$age days" $det }
    }

    Invoke-Check 'Domain' $d 'SYSVOL' 'SYSVOL migration state' {
        $g = Get-ADObject -LDAPFilter '(name=DFSR-GlobalSettings)' -SearchBase "CN=System,$dn" -SearchScope OneLevel -Properties 'msDFSR-Flags' -Server $pdc
        $flags = if ($g) { $g.'msDFSR-Flags' } else { $null }
        $map = @{ 0 = 'Start (still FRS)'; 16 = 'Prepared'; 32 = 'Redirected'; 48 = 'Eliminated (DFSR)' }
        if ($flags -eq 48) { Add-Result 'Domain' $d 'SYSVOL' 'SYSVOL migration state' 'OK' 'DFSR (Eliminated)' }
        elseif ($null -eq $flags) { Add-Result 'Domain' $d 'SYSVOL' 'SYSVOL migration state' 'Info' 'Not set' 'Domain may have been created with DFSR natively - see per-DC "DFSR SYSVOL state" rows.' }
        else {
            $label = if ($map.ContainsKey([int]$flags)) { $map[[int]$flags] } else { "Flags $flags" }
            Add-Result 'Domain' $d 'SYSVOL' 'SYSVOL migration state' 'Warning' $label 'FRS is deprecated and unsupported on Windows Server 2019+. Complete dfsrmig to Eliminated.'
        }
    }

    $writable = @($domDCs | Where-Object { -not $_.IsReadOnly } | ForEach-Object { $_.HostName })
    $allNames = @($domDCs | ForEach-Object { $_.HostName })
    Invoke-Check 'Domain' $d 'DNS' "SRV _ldap._tcp.dc._msdcs.$d" { Test-SrvRecords 'Domain' $d "_ldap._tcp.dc._msdcs.$d" $writable $allNames }
    Invoke-Check 'Domain' $d 'DNS' "SRV _kerberos._tcp.$d" { Test-SrvRecords 'Domain' $d "_kerberos._tcp.$d" $writable $allNames }

    Invoke-Check 'Domain' $d 'Trusts' 'Trusts' {
        $trusts = @(Get-ADTrust -Filter * -Server $d)
        if ($trusts.Count -eq 0) { Add-Result 'Domain' $d 'Trusts' 'Trusts' 'Info' 'No trusts'; return }
        foreach ($tr in $trusts) {
            $chk = "Trust $($tr.Target)"
            $dir = "$($tr.Direction)"
            $desc = "Direction: $dir; Type: $($tr.TrustType); Forest trust: $($tr.ForestTransitive); Intra-forest: $($tr.IntraForest)"
            if ($dir -eq 'Disabled') { Add-Result 'Domain' $d 'Trusts' $chk 'Warning' 'Disabled' $desc; continue }
            if ($dir -notin 'Outbound', 'BiDirectional') { Add-Result 'Domain' $d 'Trusts' $chk 'Info' 'Inbound only' "$desc. Verify from the trusting domain."; continue }
            if (-not $tools['nltest']) { Add-Result 'Domain' $d 'Trusts' $chk 'Info' 'Not verified (nltest missing)' $desc; continue }
            $o = Invoke-Native 'nltest.exe' @("/server:$pdc", "/sc_verify:$($tr.Target)")
            $codes = [regex]::Matches($o, 'Status = (\d+) (0x[0-9a-fA-F]+)')
            if ($codes.Count -eq 0) { Add-Result 'Domain' $d 'Trusts' $chk 'Warning' 'Verification result not parsed' ("$desc`n" + $o) }
            elseif (@($codes | Where-Object { $_.Groups[1].Value -ne '0' }).Count -gt 0) { Add-Result 'Domain' $d 'Trusts' $chk 'Critical' 'Verification failed' ("$desc`n" + $o) }
            else { Add-Result 'Domain' $d 'Trusts' $chk 'OK' 'Secure channel verified' $desc }
        }
    }

    Invoke-Check 'Domain' $d 'GroupPolicy' 'GPO AD vs SYSVOL consistency' {
        $gpc = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$dn" -SearchScope OneLevel -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName -Server $pdc)
        $adIds = @($gpc | ForEach-Object { $_.Name.ToUpper() })
        $path = "\\$pdc\SYSVOL\$d\Policies"
        $fsIds = @(Get-ChildItem -LiteralPath $path -Directory | Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' } | ForEach-Object { $_.Name.ToUpper() })
        $noFolder = @($gpc | Where-Object { $fsIds -notcontains $_.Name.ToUpper() } | ForEach-Object { "$($_.displayName) $($_.Name)" })
        $orphan = @($fsIds | Where-Object { $adIds -notcontains $_ })
        $val = "$($gpc.Count) GPOs, $($noFolder.Count) missing in SYSVOL, $($orphan.Count) orphaned folders"
        $det = @()
        if ($noFolder) { $det += "GPOs without SYSVOL folder: $($noFolder -join ', ')" }
        if ($orphan) { $det += "Orphaned SYSVOL folders: $($orphan -join ', ')" }
        $st = if ($noFolder) { 'Critical' } elseif ($orphan) { 'Warning' } else { 'OK' }
        Add-Result 'Domain' $d 'GroupPolicy' 'GPO AD vs SYSVOL consistency' $st $val ($det -join "`n")
    }

    $sid = $dom.DomainSID.Value
    $groups = [ordered]@{ 'Administrators' = 'S-1-5-32-544'; 'Domain Admins' = "$sid-512" }
    if ($d -eq $forest.RootDomain) { $groups['Enterprise Admins'] = "$sid-519"; $groups['Schema Admins'] = "$sid-518" }
    foreach ($g in $groups.Keys) {
        Invoke-Check 'Domain' $d 'Security' "Members of $g" {
            $m = @(Get-ADGroupMember -Identity $groups[$g] -Recursive -Server $d)
            $names = ($m | Select-Object -First 25 | ForEach-Object { $_.SamAccountName }) -join ', '
            if ($m.Count -gt 25) { $names += ', ...' }
            $st = if ($m.Count -gt $PrivilegedWarnCount) { 'Warning' } else { 'Info' }
            Add-Result 'Domain' $d 'Security' "Members of $g" $st "$($m.Count) (recursive)" $names
        }
    }
}

#endregion Domain checks

#region ======================= Domain controller checks =======================

$svcRules = [ordered]@{
    'NTDS' = 'Required'; 'Netlogon' = 'Required'; 'Kdc' = 'Required'; 'ADWS' = 'Required'; 'W32Time' = 'Required'
    'DFSR' = 'Required'; 'IsmServ' = 'Required'; 'LanmanServer' = 'Required'; 'LanmanWorkstation' = 'Required'
    'RpcSs' = 'Required'; 'EventLog' = 'Required'; 'Dnscache' = 'Required'; 'DNS' = 'Optional'; 'NtFrs' = 'Optional'
}

$i = 0
foreach ($dcObj in $dcsToTest) {
    $i++
    Start-PendingDcdiag
    $h = $dcObj.HostName; $n = $dcObj.Name
    Write-Progress -Activity 'AD Health Check' -Status "Domain controller $n ($i of $($dcsToTest.Count))" -PercentComplete ([math]::Min(100, $i / [math]::Max(1, $dcsToTest.Count) * 100))
    Write-Host "`n=== Domain controller: $n ($h) ===" -ForegroundColor Cyan

    $roles = ($dcObj.OperationMasterRoles | ForEach-Object { "$_" }) -join ', '
    Add-Result 'DC' $n 'Info' 'Domain / Site' 'Info' "$($dcObj.Domain) / $($dcObj.Site)" ("IP: {0}; GC: {1}; RODC: {2}; FSMO: {3}; OS: {4}" -f $dcObj.IPv4Address, $dcObj.IsGlobalCatalog, $dcObj.IsReadOnly, $(if ($roles) { $roles } else { 'none' }), $dcObj.OperatingSystem)

    $r = $reach[$h]
    if ($r.Ping) { Add-Result 'DC' $n 'Connectivity' 'Ping (ICMP)' 'OK' 'Reply received' }
    elseif ($r.Ldap) { Add-Result 'DC' $n 'Connectivity' 'Ping (ICMP)' 'Warning' 'No reply' 'ICMP blocked? LDAP 389 is reachable, so checks continue.' }
    else { Add-Result 'DC' $n 'Connectivity' 'Ping (ICMP)' 'Critical' 'Unreachable' 'No ICMP reply and LDAP 389 closed. All other checks for this DC were skipped.'; continue }

    $ctx = @{ DnsInstalled = $false }
    $cs = New-DcCimSession $h
    if ($cs) { Add-Result 'DC' $n 'Connectivity' 'WMI/CIM access' 'OK' "Connected ($($cs.Protocol))" }
    else { Add-Result 'DC' $n 'Connectivity' 'WMI/CIM access' 'Warning' 'Failed' 'Service, disk, memory, NTDS and DFSR checks via CIM unavailable. Check WinRM/DCOM firewall and permissions.' }

    # ---- Services ----
    Invoke-Check 'DC' $n 'Services' 'Service status' {
        if ($cs) {
            $filter = ($svcRules.Keys | ForEach-Object { "Name='$_'" }) -join ' OR '
            try { $svcs = @(Get-CimInstance -CimSession $cs -ClassName Win32_Service -Filter $filter -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode) }
            catch {
                if ($_.Exception.Message -match '(?i)denied') {
                    Add-Result 'DC' $n 'Services' 'Service status' 'Warning' 'Access denied' 'The run account cannot read service status. Run Grant-ADHealthWmiAccess.ps1 -Services (read-only service permissions). Ports and LDAP checks still show whether NTDS, KDC, DNS and ADWS answer.'
                    return
                }
                throw
            }
        }
        elseif ((Get-Command Get-Service).Parameters.ContainsKey('ComputerName')) {
            $svcs = @(Get-Service -ComputerName $h -Name @($svcRules.Keys) -ErrorAction SilentlyContinue |
                    Select-Object Name, DisplayName, @{ n = 'State'; e = { "$($_.Status)" } }, @{ n = 'StartMode'; e = { "$($_.StartType)" } })
        }
        else { throw 'No remote method available to query services (CIM failed).' }

        foreach ($s in $svcRules.Keys) {
            $svc = $svcs | Where-Object { $_.Name -eq $s } | Select-Object -First 1
            if (-not $svc) {
                # Dnscache has a Windows-protected security descriptor: a non-admin account can never read it
                if (-not $script:IsAdmin -and $s -eq 'Dnscache' -and $svcs.Count -gt 0) {
                    Add-Result 'DC' $n 'Services' "Service $s" 'Info' 'Not readable by run account' 'The DNS Client service permissions are protected by Windows and cannot be delegated. Not AD-critical.'
                }
                elseif ($svcRules[$s] -eq 'Required') { Add-Result 'DC' $n 'Services' "Service $s" 'Critical' 'Not installed / not found' }
                elseif ($s -eq 'DNS') { Add-Result 'DC' $n 'Services' 'Service DNS' 'Info' 'Not installed' 'DNS is hosted elsewhere' }
                continue
            }
            if ($s -eq 'DNS') { $ctx.DnsInstalled = $true }
            $label = "Service $($svc.DisplayName) ($s)"
            if ($svc.State -eq 'Running') {
                if ($svc.StartMode -notmatch '^Auto') { Add-Result 'DC' $n 'Services' $label 'Warning' "Running (start mode: $($svc.StartMode))" 'Start mode should be Automatic' }
                else { Add-Result 'DC' $n 'Services' $label 'OK' 'Running' }
            }
            elseif ($svcRules[$s] -eq 'Optional' -and $svc.StartMode -match 'Disabled|Manual') { Add-Result 'DC' $n 'Services' $label 'Info' "$($svc.State) ($($svc.StartMode))" }
            else { Add-Result 'DC' $n 'Services' $label 'Critical' "$($svc.State)" "Start mode: $($svc.StartMode)" }
        }
    }

    # ---- Ports ----
    Invoke-Check 'DC' $n 'Connectivity' 'TCP ports' {
        $ports = [ordered]@{ 'Kerberos (88)' = 88; 'RPC endpoint mapper (135)' = 135; 'LDAP (389)' = 389; 'SMB (445)' = 445; 'Kerberos kpasswd (464)' = 464; 'AD Web Services (9389)' = 9389 }
        if ($ctx.DnsInstalled) { $ports['DNS (53)'] = 53 }
        if ($dcObj.IsGlobalCatalog) { $ports['Global Catalog (3268)'] = 3268 }
        foreach ($p in $ports.GetEnumerator()) {
            if (Test-TcpPort $h $p.Value) { Add-Result 'DC' $n 'Connectivity' "Port $($p.Key)" 'OK' 'Open' }
            else { Add-Result 'DC' $n 'Connectivity' "Port $($p.Key)" 'Critical' 'Closed or filtered' }
        }
    }

    # ---- LDAP functional ----
    Invoke-Check 'DC' $n 'Connectivity' 'LDAP bind / RootDSE' {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$h/RootDSE")
        $dnc = "$($de.Properties['defaultNamingContext'].Value)"
        $isSync = "$($de.Properties['isSynchronized'].Value)"
        $gcReady = "$($de.Properties['isGlobalCatalogReady'].Value)"
        $de.Dispose()
        if (-not $dnc) { throw 'RootDSE returned no defaultNamingContext' }
        Add-Result 'DC' $n 'Connectivity' 'LDAP bind / RootDSE' 'OK' 'Bind succeeded' $dnc
        if ($isSync -eq 'TRUE') { Add-Result 'DC' $n 'Replication' 'isSynchronized' 'OK' 'TRUE' 'DC has completed initial synchronization' }
        else { Add-Result 'DC' $n 'Replication' 'isSynchronized' 'Critical' "$isSync" 'DC has not completed initial synchronization and may not advertise' }
        if ($dcObj.IsGlobalCatalog) {
            if ($gcReady -eq 'TRUE') { Add-Result 'DC' $n 'Replication' 'isGlobalCatalogReady' 'OK' 'TRUE' }
            else { Add-Result 'DC' $n 'Replication' 'isGlobalCatalogReady' 'Critical' "$gcReady" 'GC partitions not fully replicated' }
        }
    }

    # ---- LDAPS certificate ----
    Invoke-Check 'DC' $n 'Certificates' 'LDAPS certificate (636)' {
        $cert = Get-LdapsCertificate $h
        if (-not $cert) { Add-Result 'DC' $n 'Certificates' 'LDAPS certificate (636)' 'Info' 'LDAPS not available' 'No certificate presented on port 636 (no DC certificate, or port blocked).'; return }
        $days = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $det = "Subject: $($cert.Subject)`nIssuer: $($cert.Issuer)`nExpires: $($cert.NotAfter.ToString('yyyy-MM-dd'))`nThumbprint: $($cert.Thumbprint)"
        if ($days -lt 0) { Add-Result 'DC' $n 'Certificates' 'LDAPS certificate (636)' 'Critical' "Expired $(-$days) days ago" $det }
        elseif ($days -lt $CertWarnDays) { Add-Result 'DC' $n 'Certificates' 'LDAPS certificate (636)' 'Warning' "Expires in $days days" $det }
        else { Add-Result 'DC' $n 'Certificates' 'LDAPS certificate (636)' 'OK' "Valid, $days days left" $det }
    }

    # ---- OS, resources, NTDS, DFSR (CIM) ----
    if ($cs) {
        Invoke-Check 'DC' $n 'Resources' 'Operating system / memory' {
            $os = Get-CimInstance -CimSession $cs -ClassName Win32_OperatingSystem
            Add-Result 'DC' $n 'Info' 'Operating system' 'Info' "$($os.Caption)" "Version $($os.Version)"
            $up = (Get-Date) - $os.LastBootUpTime
            $upVal = "$([int]$up.TotalDays) days (last boot $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')))"
            if ($up.TotalDays -gt $UptimeWarnDays) { Add-Result 'DC' $n 'Resources' 'Uptime' 'Warning' $upVal "No reboot for more than $UptimeWarnDays days - check patching." }
            else { Add-Result 'DC' $n 'Resources' 'Uptime' 'OK' $upVal }
            $freePct = [math]::Round($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100, 1)
            $memVal = '{0:N1} GB free of {1:N1} GB ({2}%)' -f ($os.FreePhysicalMemory / 1MB), ($os.TotalVisibleMemorySize / 1MB), $freePct
            if ($freePct -lt ($MemoryWarnPercent / 2)) { Add-Result 'DC' $n 'Resources' 'Free memory' 'Critical' $memVal }
            elseif ($freePct -lt $MemoryWarnPercent) { Add-Result 'DC' $n 'Resources' 'Free memory' 'Warning' $memVal }
            else { Add-Result 'DC' $n 'Resources' 'Free memory' 'OK' $memVal }
        }

        Invoke-Check 'DC' $n 'Resources' 'CPU load' {
            $load = [math]::Round((Get-CimInstance -CimSession $cs -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 0)
            if ($load -ge $CpuWarnPercent) { Add-Result 'DC' $n 'Resources' 'CPU load' 'Warning' "$load %" 'Single sample - re-check if persistent.' }
            else { Add-Result 'DC' $n 'Resources' 'CPU load' 'OK' "$load %" }
        }

        Invoke-Check 'DC' $n 'Resources' 'Disk space' {
            foreach ($dk in @(Get-CimInstance -CimSession $cs -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
                if (-not $dk.Size) { continue }
                $pct = [math]::Round($dk.FreeSpace / $dk.Size * 100, 1)
                $val = '{0:N1} GB free of {1:N1} GB ({2}%)' -f ($dk.FreeSpace / 1GB), ($dk.Size / 1GB), $pct
                $st = if ($pct -lt $DiskCritPercent) { 'Critical' } elseif ($pct -lt $DiskWarnPercent) { 'Warning' } else { 'OK' }
                Add-Result 'DC' $n 'Resources' "Disk $($dk.DeviceID)" $st $val
            }
        }

        Invoke-Check 'DC' $n 'Resources' 'NTDS database' {
            $key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $dbFile = Get-RemoteRegValue $cs $key 'DSA Database file'
            $logPath = Get-RemoteRegValue $cs $key 'Database log files path'
            $sysvol = Get-RemoteRegValue $cs 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SysVol'
            $size = ''
            if ($dbFile) {
                $f = Get-CimInstance -CimSession $cs -ClassName CIM_DataFile -Filter ("Name='{0}'" -f $dbFile.Replace('\', '\\'))
                if ($f) { $size = ' ({0:N2} GB)' -f ($f.FileSize / 1GB) }
            }
            if (-not $dbFile) { Add-Result 'DC' $n 'Resources' 'NTDS database' 'Info' 'Not readable by run account' "The NTDS registry key needs administrator rights.`nSYSVOL: $sysvol" }
            else { Add-Result 'DC' $n 'Resources' 'NTDS database' 'Info' "$dbFile$size" "Logs: $logPath`nSYSVOL: $sysvol" }
        }

        Invoke-Check 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' {
            $rf = $null
            try { $rf = Get-CimInstance -CimSession $cs -Namespace 'root/microsoftdfs' -ClassName DfsrReplicatedFolderInfo -Filter "ReplicatedFolderName='SYSVOL Share'" -ErrorAction Stop | Select-Object -First 1 }
            catch {
                if ($_.Exception.Message -match '(?i)denied') {
                    Add-Result 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' 'Info' 'Not readable by run account' 'The DFSR WMI provider requires administrator rights. SYSVOL replication errors are still covered by the DFS Replication event log check and dcdiag DFSREvent.'
                }
                else { Add-Result 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' 'Warning' 'Could not query DFSR WMI' "root\microsoftdfs: $($_.Exception.Message)" }
                return
            }
            if (-not $rf -and -not $script:IsAdmin) {
                # The DFSR provider returns no rows (instead of an error) to non-admin callers
                Add-Result 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' 'Info' 'Not readable by run account' 'The DFSR WMI provider only returns data to administrators. SYSVOL replication errors are still covered by the DFS Replication event log check, dcdiag DFSREvent and the domain SYSVOL migration state (DFSR).'
                return
            }
            if (-not $rf) {
                Add-Result 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' 'Warning' 'SYSVOL not replicated by DFSR' 'Domain may still use FRS (deprecated, unsupported on Server 2019+), or the DFSR WMI provider is not reachable.'
                return
            }
            $map = @{ 0 = 'Uninitialized'; 1 = 'Initialized'; 2 = 'Initial sync'; 3 = 'Auto recovery'; 4 = 'Normal'; 5 = 'In error' }
            $state = [int]$rf.State
            $label = if ($map.ContainsKey($state)) { $map[$state] } else { "State $state" }
            $st = switch ($state) { 4 { 'OK' } 2 { 'Warning' } 3 { 'Warning' } default { 'Critical' } }
            Add-Result 'DC' $n 'SYSVOL' 'DFSR SYSVOL state' $st $label
        }
    }

    # ---- Shares ----
    Invoke-Check 'DC' $n 'SYSVOL' 'SYSVOL & NETLOGON shares' {
        foreach ($sh in 'SYSVOL', 'NETLOGON') {
            if (Test-Path -LiteralPath "\\$h\$sh") { Add-Result 'DC' $n 'SYSVOL' "Share $sh" 'OK' 'Shared and accessible' }
            else { Add-Result 'DC' $n 'SYSVOL' "Share $sh" 'Critical' 'Not accessible' 'Missing share = DC is not advertising / SYSVOL not initialized.' }
        }
    }

    # ---- Replication ----
    Invoke-Check 'DC' $n 'Replication' 'Inbound replication' {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $h -Partition * -PartnerType Inbound)
        if ($meta.Count -eq 0) {
            if ($allDCs.Count -le 1) { Add-Result 'DC' $n 'Replication' 'Inbound replication' 'Info' 'No partners (single DC forest)' }
            else { Add-Result 'DC' $n 'Replication' 'Inbound replication' 'Warning' 'No inbound replication partners found' }
            return
        }
        foreach ($g in ($meta | Group-Object { Get-ShortName $_.Partner })) {
            $st = 'OK'; $notes = @(); $oldest = $null
            foreach ($m in $g.Group) {
                $nc = $m.Partition
                if ($m.LastReplicationResult -ne 0) {
                    $st = 'Critical'
                    $notes += "$nc : last result $($m.LastReplicationResult), $($m.ConsecutiveReplicationFailures) consecutive failures"
                }
                if (-not $m.LastReplicationSuccess -or $m.LastReplicationSuccess.Year -lt 1990) {
                    $st = 'Critical'; $notes += "$nc : never replicated successfully"; continue
                }
                $age = (Get-Date) - $m.LastReplicationSuccess
                if ($null -eq $oldest -or $age -gt $oldest) { $oldest = $age }
                if ($age.TotalMinutes -gt $ReplCritMinutes) { $st = Merge-Status $st 'Critical'; $notes += "$nc : last success $(Format-Age $age) ago" }
                elseif ($age.TotalMinutes -gt $ReplWarnMinutes) { $st = Merge-Status $st 'Warning'; $notes += "$nc : last success $(Format-Age $age) ago" }
            }
            $val = "Oldest last success $(Format-Age $oldest) ago ($($g.Count) partitions)"
            Add-Result 'DC' $n 'Replication' "Inbound from $($g.Name)" $st $val ($notes -join "`n")
        }
    }

    Invoke-Check 'DC' $n 'Replication' 'Replication failures' {
        $fails = @(Get-ADReplicationFailure -Target $h | Where-Object { $_.FailureCount -gt 0 })
        if ($fails.Count -eq 0) { Add-Result 'DC' $n 'Replication' 'Replication failures' 'OK' 'None recorded' }
        foreach ($f in $fails) {
            Add-Result 'DC' $n 'Replication' "Replication failure from $(Get-ShortName $f.Partner)" 'Critical' "$($f.FailureCount) failure(s)" "First failure: $($f.FirstFailureTime)`nLast error: $($f.LastError)"
        }
    }

    if ($tools['repadmin']) {
        Invoke-Check 'DC' $n 'Replication' 'Replication queue' {
            $q = Invoke-Native 'repadmin.exe' @('/queue', $h)
            if ($q -match 'contains\s+(\d+)\s+items') {
                $cnt = [int]$matches[1]
                if ($cnt -gt $ReplQueueWarn) { Add-Result 'DC' $n 'Replication' 'Replication queue' 'Warning' "$cnt items" }
                else { Add-Result 'DC' $n 'Replication' 'Replication queue' 'OK' "$cnt items" }
            }
            else { Add-Result 'DC' $n 'Replication' 'Replication queue' 'Warning' 'Could not read queue' $q.Substring(0, [math]::Min(400, $q.Length)) }
        }
    }

    # ---- DNS ----
    Invoke-Check 'DC' $n 'DNS' 'DNS host (A) record' {
        $a = @(Resolve-DnsName -Name $h -Type A -DnsOnly | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
        $val = "$h -> $($a -join ', ')"
        if ($a.Count -eq 0) { Add-Result 'DC' $n 'DNS' 'DNS host (A) record' 'Critical' 'No A record' }
        elseif ($a -notcontains $dcObj.IPv4Address) { Add-Result 'DC' $n 'DNS' 'DNS host (A) record' 'Critical' $val "AD lists IP $($dcObj.IPv4Address)" }
        elseif ($a.Count -gt 1) { Add-Result 'DC' $n 'DNS' 'DNS host (A) record' 'Warning' $val 'Multiple A records - multi-homed DCs cause replication and client issues.' }
        else { Add-Result 'DC' $n 'DNS' 'DNS host (A) record' 'OK' $val }
    }
    if ($ctx.DnsInstalled) {
        Invoke-Check 'DC' $n 'DNS' 'DNS server answers queries' {
            $q = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($dcObj.Domain)" -Type SRV -Server $h -DnsOnly -QuickTimeout | Where-Object { $_.Type -eq 'SRV' })
            if ($q.Count -gt 0) { Add-Result 'DC' $n 'DNS' 'DNS server answers queries' 'OK' "Returned $($q.Count) DC locator records" }
            else { Add-Result 'DC' $n 'DNS' 'DNS server answers queries' 'Critical' 'No DC locator records returned' }
        }
    }

    # ---- Time source ----
    if ($tools['w32tm']) {
        Invoke-Check 'DC' $n 'Time' 'Time source' {
            $src = (Invoke-Native 'w32tm.exe' @('/query', "/computer:$h", '/source')).Trim()
            $isRootPdc = ($forestRootPdc -and $h -ieq $forestRootPdc)
            if ($src -match 'Access is denied|0x80070005') { Add-Result 'DC' $n 'Time' 'Time source' 'Info' 'Not readable by run account' 'w32tm /query against a DC needs administrator rights. The time offset row below is still measured (NTP, no rights needed).' }
            elseif ($src -match 'error|0x800') { Add-Result 'DC' $n 'Time' 'Time source' 'Warning' 'Query failed' $src }
            elseif ($src -match 'Local CMOS Clock|Free-running System Clock') {
                $msg = if ($isRootPdc) { 'Forest root PDC should sync from a reliable external NTP source.' } else { 'DC should sync from the domain hierarchy (NT5DS).' }
                Add-Result 'DC' $n 'Time' 'Time source' 'Warning' $src $msg
            }
            elseif ($src -match 'VM IC Time Synchronization Provider') { Add-Result 'DC' $n 'Time' 'Time source' 'Warning' $src 'Hypervisor time sync is in control. DCs should sync via the domain hierarchy.' }
            else { Add-Result 'DC' $n 'Time' 'Time source' 'OK' $src $(if ($isRootPdc) { 'Forest root PDC (authoritative time source)' } else { '' }) }
        }
        $null = Get-CachedOffset $h

        # Forest root PDC: show the W32Time configuration and test every configured NTP peer
        if ($forestRootPdc -and $h -ieq $forestRootPdc) {
            Invoke-Check 'DC' $n 'Time' 'NTP peers' {
                $cfg = Invoke-Native 'w32tm.exe' @('/query', "/computer:$h", '/configuration')
                if ($cfg -match 'Access is denied|0x80070005') {
                    # Not readable without admin rights: test the servers given with -NtpServer instead
                    $peers = @(Split-NtpServerList $NtpServer)
                    $det = 'w32tm /query /configuration needs administrator rights on the DC.'
                    $det += if ($peers) { " Testing the servers given with -NtpServer: $($peers -join ', ')" } else { ' Set NtpServer in the config file (or pass -NtpServer) to test the NTP servers anyway.' }
                    Add-Result 'DC' $n 'Time' 'W32Time configuration' 'Info' 'Not readable by run account' $det
                    if ($peers.Count -eq 0) { return }
                }
                else {
                    $type = if ($cfg -match '(?m)^\s*Type:\s*(\S+)') { $matches[1] } else { 'unknown' }
                    $ntp = if ($cfg -match '(?m)^\s*NtpServer:\s*(.+?)\s*(\((Local|Policy)\))?\s*$') { $matches[1].Trim() } else { '' }
                    $origin = if ($cfg -match '(?m)^\s*NtpServer:.*\((Local|Policy)\)') { $matches[1] } else { '' }
                    $vmic = if ($cfg -match '(?s)VMICTimeProvider.*?Enabled:\s*(\d)') { $matches[1] } else { '' }
                    $det = "Type: $type; NtpServer: $ntp"
                    if ($origin -eq 'Policy') { $det += "`nSet by Group Policy - change the GPO, local 'w32tm /config' is overridden." }
                    if ($vmic -eq '1') { $det += "`nVM time provider (VMICTimeProvider) is enabled." }
                    $st = if ($type -match 'NTP|AllSync') { 'Info' } else { 'Warning' }
                    Add-Result 'DC' $n 'Time' 'W32Time configuration' $st "Type $type ($origin)" $det

                    $peers = @(Split-NtpServerList (@($ntp) + @($NtpServer)))
                    if ($type -notmatch 'NTP|AllSync' -or $peers.Count -eq 0) { return }
                }
                $ok = 0
                foreach ($p in $peers) {
                    $off = Get-TimeOffset $p
                    $where = "Tested with w32tm /stripchart (UDP 123) from $env:COMPUTERNAME"
                    if ($null -eq $off) { Add-Result 'DC' $n 'Time' "NTP peer $p" 'Warning' 'No response' "$where. Check firewall / security group for UDP 123 and that $p is an NTP server." ; continue }
                    $ok++
                    $abs = [math]::Abs($off)
                    $val = 'Responding, local clock offset {0:+0.000;-0.000} s' -f $off
                    $pst = if ($abs -ge $TimeSkewCritSeconds) { 'Critical' } elseif ($abs -ge $TimeSkewWarnSeconds) { 'Warning' } else { 'OK' }
                    Add-Result 'DC' $n 'Time' "NTP peer $p" $pst $val $where
                }
                if ($ok -eq 0) { Add-Result 'DC' $n 'Time' 'NTP peers reachable' 'Critical' "0 of $($peers.Count)" 'The forest time source has no working NTP peer.' }
                else { Add-Result 'DC' $n 'Time' 'NTP peers reachable' 'OK' "$ok of $($peers.Count)" }
            }
        }
    }

    # ---- Event logs ----
    Invoke-Check 'DC' $n 'EventLogs' 'Event logs' {
        $since = (Get-Date).AddHours(-$EventLogHours)
        $ms = [int64]$EventLogHours * 3600000
        foreach ($log in 'Directory Service', 'DFS Replication', 'DNS Server', 'Active Directory Web Services', 'System') {
            if ($log -eq 'DNS Server' -and -not $ctx.DnsInstalled) { continue }
            # The System log is shared with every application, so by default only AD DS / DNS related sources are read
            $adOnly = ($log -eq 'System' -and -not $IncludeAllSystemEvents)
            $chk = if ($adOnly) { "AD DS / DNS errors in 'System' (last $EventLogHours h)" } else { "Errors in '$log' (last $EventLogHours h)" }
            try {
                if ($adOnly) {
                    $prov = ($SystemLogProviders | ForEach-Object { "@Name='$_'" }) -join ' or '
                    $svc = ($AdServiceDisplayNames | ForEach-Object { "Data='$_'" }) -join ' or '
                    $xp = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= $ms]] and (System[Provider[$prov]] or (System[Provider[@Name='Service Control Manager']] and EventData[$svc]))]"
                    try { $ev = @(Get-WinEvent -ComputerName $h -LogName 'System' -FilterXPath $xp -MaxEvents 2000 -ErrorAction Stop) }
                    catch {
                        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { throw }
                        # Fallback if the XPath query is rejected: read all errors and filter here
                        $all = @(Get-WinEvent -ComputerName $h -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop)
                        $svcRx = ($AdServiceDisplayNames | ForEach-Object { [regex]::Escape($_) }) -join '|'
                        $ev = @($all | Where-Object {
                                $SystemLogProviders -contains $_.ProviderName -or
                                ($_.ProviderName -eq 'Service Control Manager' -and "$($_.Message)" -match "^The ($svcRx) service")
                            })
                    }
                }
                else {
                    $ev = @(Get-WinEvent -ComputerName $h -FilterHashtable @{ LogName = $log; Level = 1, 2; StartTime = $since } -MaxEvents 2000 -ErrorAction Stop)
                }
            }
            catch {
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev = @() }
                elseif ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { continue }
                else { Add-Result 'DC' $n 'EventLogs' $chk 'Warning' 'Could not read log' $_.Exception.Message; continue }
            }
            $capped = ($ev.Count -ge 2000)
            $ignored = 0
            if ($ev.Count -gt 0 -and ($IgnoreEventId -or $IgnoreEventPattern)) {
                $kept = @($ev | Where-Object {
                        -not (($IgnoreEventId -and $IgnoreEventId -contains $_.Id) -or ($IgnoreEventPattern -and "$($_.Message)" -match $IgnoreEventPattern))
                    })
                $ignored = $ev.Count - $kept.Count
                $ev = $kept
            }
            $ignText = if ($ignored -gt 0) { ", $ignored ignored" } else { '' }
            if ($ev.Count -eq 0) { Add-Result 'DC' $n 'EventLogs' $chk 'OK' "No errors$ignText"; continue }
            $crit = @($ev | Where-Object { $_.Level -eq 1 }).Count
            $cntText = if ($capped -and $ignored -eq 0) { "2000+ (read limit)" } else { "$($ev.Count)" }
            $top = $ev | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                $s = $_.Group[0]
                $msg = ("$($s.Message)" -split "`r?`n")[0]
                if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
                "ID $($_.Name) x$($_.Count) [$($s.ProviderName)] $msg"
            }
            $st = if ($crit -gt 0) { 'Critical' } else { 'Warning' }
            Add-Result 'DC' $n 'EventLogs' $chk $st "$cntText error(s), $crit critical$ignText" ($top -join "`n")
        }
    }

    # ---- Clients without a site ----
    Invoke-Check 'DC' $n 'Sites' 'Clients without site (NO_CLIENT_SITE)' {
        $nl = "\\$h\admin`$\debug\netlogon.log"
        $nlOk = $false
        try { $nlOk = Test-Path -LiteralPath $nl -ErrorAction Stop } catch { }
        if (-not $nlOk) { Add-Result 'DC' $n 'Sites' 'Clients without site (NO_CLIENT_SITE)' 'Info' 'Not readable by run account' "netlogon.log is read through \\$h\admin`$, which needs administrator rights."; return }
        # netlogon.log lines look like: "10/21 22:42:03 [1234] CONTOSO: NO_CLIENT_SITE: HOSTNAME 10.1.2.3" (no year)
        $now = Get-Date; $cut = $now.AddDays(-$NoClientSiteDays)
        $hits = @{}
        foreach ($mm in @(Select-String -LiteralPath $nl -Pattern '^(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}) .*NO_CLIENT_SITE:\s+(\S+)\s+(\S+)')) {
            $g = $mm.Matches[0].Groups
            try { $ts = Get-Date -Year $now.Year -Month ([int]$g[1].Value) -Day ([int]$g[2].Value) -Hour ([int]$g[3].Value) -Minute ([int]$g[4].Value) -Second ([int]$g[5].Value) }
            catch { continue }
            if ($ts -gt $now.AddDays(1)) { $ts = $ts.AddYears(-1) }
            if ($ts -lt $cut) { continue }
            $hits[$g[7].Value] = "$($g[6].Value) ($($g[7].Value))"
        }
        $chk = "Clients without site (NO_CLIENT_SITE, last $NoClientSiteDays days)"
        if ($hits.Count -eq 0) { Add-Result 'DC' $n 'Sites' $chk 'OK' 'None' }
        else {
            $list = (@($hits.Values | Sort-Object) | Select-Object -First 30) -join ', '
            if ($hits.Count -gt 30) { $list += ', ...' }
            $ranges = @($hits.Keys | Where-Object { $_ -match '^(\d+\.\d+\.\d+)\.\d+$' } | ForEach-Object { "$($matches[1]).0/24" } | Sort-Object -Unique) -join ', '
            Add-Result 'DC' $n 'Sites' $chk 'Warning' "$($hits.Count) client IP(s)" "Clients: $list`nCreate AD subnets (and link them to a site) covering these addresses. /24 ranges seen: $ranges"
        }
    }

    if ($cs) { Remove-CimSession $cs -ErrorAction SilentlyContinue }
}

# ---- Time offsets (relative to the PDC hierarchy) ----
if ($tools['w32tm']) {
    Write-Host "`n=== Time offsets ===" -ForegroundColor Cyan
    foreach ($dcObj in $dcsToTest) {
        $h = $dcObj.HostName
        if (-not $reach[$h].Up) { continue }
        $dPdc = if ($domainInfo.ContainsKey($dcObj.Domain)) { $domainInfo[$dcObj.Domain].PDCEmulator } else { $null }
        if ($forestRootPdc -and $h -ieq $forestRootPdc) { $ref = $null }
        elseif ($dPdc -and $h -ieq $dPdc) { $ref = $forestRootPdc }
        else { $ref = $dPdc }

        $off = Get-CachedOffset $h
        if ($null -eq $off) { Add-Result 'DC' $dcObj.Name 'Time' 'Time offset' 'Warning' 'Could not measure' 'w32tm /stripchart failed (UDP 123 blocked?)'; continue }
        if (-not $ref) { Add-Result 'DC' $dcObj.Name 'Time' 'Time offset' 'Info' ('{0:+0.000;-0.000} s vs {1}' -f $off, $env:COMPUTERNAME) 'Reference clock of the forest (forest root PDC)'; continue }
        $refOff = Get-CachedOffset $ref
        if ($null -eq $refOff) { Add-Result 'DC' $dcObj.Name 'Time' 'Time offset' 'Warning' "Reference $ref not measurable"; continue }
        $rel = $off - $refOff
        $abs = [math]::Abs($rel)
        $val = '{0:+0.000;-0.000} s vs {1}' -f $rel, $ref.Split('.')[0]
        $st = if ($abs -ge $TimeSkewCritSeconds) { 'Critical' } elseif ($abs -ge $TimeSkewWarnSeconds) { 'Warning' } else { 'OK' }
        Add-Result 'DC' $dcObj.Name 'Time' 'Time offset' $st $val 'Kerberos fails above 300 s skew'
    }
}

# ---- dcdiag results ----
if ($tools['dcdiag']) {
    Write-Host "`n=== Collecting dcdiag results ===" -ForegroundColor Cyan
    $dcdiagWarnOnly = 'SystemLog', 'DFSREvent', 'FrsEvent', 'KccEvent'
    $dcdiagRegex = '\.{3,}\s*(?<target>\S+)\s+(?<result>passed|failed)\s+test\s+(?<test>\w+)'
    foreach ($dcObj in $dcsToTest) {
        $h = $dcObj.HostName; $n = $dcObj.Name
        if (-not $reach[$h].Up) { continue }
        while (-not $script:DcdiagJobs.ContainsKey($h)) { Start-PendingDcdiag; if (-not $script:DcdiagJobs.ContainsKey($h)) { Start-Sleep -Seconds 2 } }
        $job = $script:DcdiagJobs[$h]
        $remaining = $DcdiagTimeoutSeconds - ((Get-Date) - $script:DcdiagStart[$h]).TotalSeconds
        if ($remaining -gt 0) { Wait-Job $job -Timeout ([int][math]::Ceiling($remaining)) | Out-Null }
        if ($job.State -eq 'Running') { Stop-Job $job }
        if ($job.State -ne 'Completed') {
            Add-Result 'DC' $n 'DCDiag' 'dcdiag' 'Warning' "dcdiag $($job.State)" "Did not finish within $DcdiagTimeoutSeconds s"
            Remove-Job $job -Force; Start-PendingDcdiag; continue
        }
        $out = (Receive-Job $job) -join "`n"
        Remove-Job $job -Force
        Start-PendingDcdiag

        $ms = [regex]::Matches($out, $dcdiagRegex)
        if ($ms.Count -eq 0) {
            Add-Result 'DC' $n 'DCDiag' 'dcdiag' 'Warning' 'Output not parsed' $out.Substring(0, [math]::Min(1200, $out.Length))
            continue
        }
        $seen = @{}
        foreach ($m in $ms) {
            $test = $m.Groups['test'].Value; $tgt = $m.Groups['target'].Value
            $label = if ($tgt -ieq $n) { "dcdiag $test" } else { "dcdiag $test [$tgt]" }
            if ($seen.ContainsKey($label)) { continue }
            $seen[$label] = $true
            if ($m.Groups['result'].Value -eq 'passed') { Add-Result 'DC' $n 'DCDiag' $label 'OK' 'Passed'; continue }
            $st = if ($dcdiagWarnOnly -contains $test) { 'Warning' } else { 'Critical' }
            $result = 'Failed'

            # Text of this test only: from the nearest "Starting test: X" before the "failed test X" line
            $startIdx = $out.LastIndexOf("Starting test: $test", $m.Index, [System.StringComparison]::OrdinalIgnoreCase)
            $raw = if ($startIdx -ge 0) { $out.Substring($startIdx, $m.Index - $startIdx) } else { '' }
            $lines = @($raw -split "`r?`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
                    Where-Object { $_ -and $_ -notmatch '^\.{3,}' -and $_ -notmatch '^Starting test' -and $_ -notmatch 'are running and not hung' })

            # A test that failed only because the run account lacks rights is not an AD fault
            if ($raw -match '(?i)access is denied|error 5\b|0x00000005\b|ERROR_ACCESS_DENIED') {
                $det = (@($lines | Where-Object { $_ -match '(?i)denied|error' }) | Select-Object -First 5) -join "`n"
                Add-Result 'DC' $n 'DCDiag' $label 'Warning' 'Access denied (run account lacks rights)' "$det`nGrant the right, or skip this test with -DcdiagSkip $test (the script has its own check for services, events and replication)."
                continue
            }

            if ($test -eq 'SystemLog') {
                $evs = @([regex]::Matches($raw, 'Event String:\s*\r?\n\s*(?<s>[^\r\n]+)') | ForEach-Object { $_.Groups['s'].Value.Trim() })
                $kept = @($evs | Where-Object { -not ($IgnoreEventPattern -and $_ -match $IgnoreEventPattern) })
                if ($evs.Count -gt 0 -and $kept.Count -eq 0) { Add-Result 'DC' $n 'DCDiag' $label 'OK' 'Passed (only ignored events)'; continue }
                $body = (@($kept | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "x$($_.Count) $($_.Name)" })) -join "`n"
                $body = "Error/warning events in the System log (last 60 min, grouped):`n$body"
            }
            elseif ($test -eq 'DNS') {
                $cols = 'Auth', 'Basc', 'Forw', 'Del', 'Dyn', 'RReg', 'Ext'
                $names = @{ Auth = 'Authentication'; Basc = 'Basic'; Forw = 'Forwarders/Root hints'; Del = 'Delegations'; Dyn = 'Dynamic update'; RReg = 'Record registration'; Ext = 'External name resolution' }
                $failed = @()
                foreach ($row in [regex]::Matches($raw, '(?m)^\s*\S+\s+((?:(?:PASS|FAIL|WARN|n/a)\s+){6}(?:PASS|FAIL|WARN|n/a))\s*$')) {
                    $vals = $row.Groups[1].Value -split '\s+'
                    for ($c = 0; $c -lt $cols.Count; $c++) { if ($vals[$c] -match 'FAIL|WARN') { $failed += $cols[$c] } }
                }
                $failed = @($failed | Sort-Object -Unique)
                $msgs = @($lines | Where-Object { $_ -match '^(Error|Warning):|failed on the DNS server|^DNS server:' } | Select-Object -Unique)
                if ($failed.Count -gt 0) {
                    $result = 'Failed: ' + (($failed | ForEach-Object { $names[$_] }) -join ', ')
                    # Forwarders / delegations / external resolution do not break AD itself
                    if (-not @($failed | Where-Object { $_ -in 'Auth', 'Basc', 'Dyn', 'RReg' })) { $st = 'Warning' }
                }
                $body = ($msgs | Select-Object -First 20) -join "`n"
            }
            else {
                $important = @($lines | Where-Object { $_ -match '(?i)error|warning|fail|invalid|could not|unable|denied|missing' })
                $body = if ($important) { $important -join "`n" } else { $lines -join "`n" }
            }
            if ($body.Length -gt 1500) { $body = $body.Substring(0, 1500) + ' ...' }
            Add-Result 'DC' $n 'DCDiag' $label $st $result $body
        }
    }
}
Write-Progress -Activity 'AD Health Check' -Completed

#endregion Domain controller checks

#region ======================= HTML report =======================

$duration = (Get-Date) - $scriptStart
$counts = @{}
foreach ($s in 'OK', 'Warning', 'Critical', 'Info') { $counts[$s] = @($script:Results | Where-Object { $_.Status -eq $s }).Count }
$overall = if ($counts['Critical'] -gt 0) { 'Critical' } elseif ($counts['Warning'] -gt 0) { 'Warning' } else { 'OK' }
$unreachable = @($dcsToTest | Where-Object { $_ -and $reach.ContainsKey($_.HostName) -and -not $reach[$_.HostName].Up }).Count

$colors = @{ 'OK' = '#C6EFCE'; 'Warning' = '#FFEB9C'; 'Critical' = '#FFC7CE'; 'Info' = '#DDEBF7'; 'N/A' = '#EEEEEE' }
$fore   = @{ 'OK' = '#006100'; 'Warning' = '#9C5700'; 'Critical' = '#9C0006'; 'Info' = '#1F4E79'; 'N/A' = '#888888' }

function ConvertTo-HtmlText([string]$s) { return ([System.Net.WebUtility]::HtmlEncode($s) -replace "`r?`n", '<br>') }
function Get-StatusCell([string]$s, [string]$text) {
    if (-not $text) { $text = $s }
    return "<td align='center' bgcolor='$($colors[$s])' style='background:$($colors[$s]);color:$($fore[$s]);font-weight:bold;white-space:nowrap'>$text</td>"
}

$sb = New-Object System.Text.StringBuilder
function W([string]$s) { [void]$sb.AppendLine($s) }

function Write-ResultTable($rows, [switch]$ShowTarget) {
    $head = if ($ShowTarget) { '<th>Scope</th><th>Target</th>' } else { '' }
    W "<table><tr><th>Status</th>$head<th>Category</th><th>Check</th><th>Result</th><th>Details</th></tr>"
    foreach ($r in $rows) {
        $tcols = if ($ShowTarget) { "<td>$($r.Scope)</td><td>$(ConvertTo-HtmlText $r.Target)</td>" } else { '' }
        W ("<tr>{0}{1}<td>{2}</td><td>{3}</td><td>{4}</td><td class='det'>{5}</td></tr>" -f (Get-StatusCell $r.Status), $tcols, (ConvertTo-HtmlText $r.Category), (ConvertTo-HtmlText $r.Check), (ConvertTo-HtmlText $r.Value), (ConvertTo-HtmlText $r.Details))
    }
    W '</table>'
}

$css = @'
body{font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#222;margin:10px}
h1{font-size:20px;margin:0 0 4px 0;color:#1F4E79}
h2{font-size:15px;color:#1F4E79;border-bottom:2px solid #1F4E79;padding-bottom:3px;margin-top:26px}
h3{font-size:13px;color:#333;margin:18px 0 6px 0}
table{border-collapse:collapse;width:100%;margin-bottom:10px}
th{background:#1F4E79;color:#fff;padding:5px;text-align:left;font-size:12px}
td{border:1px solid #CCC;padding:4px;vertical-align:top;font-size:12px}
td.det{color:#444;font-size:11px}
pre{background:#F4F4F4;border:1px solid #CCC;padding:6px;font-size:11px;white-space:pre-wrap}
.small{color:#666;font-size:11px}
'@

W '<!DOCTYPE html><html><head><meta charset="utf-8">'
W "<title>$(ConvertTo-HtmlText $ReportTitle)</title><style>$css</style></head><body>"
W "<h1>$(ConvertTo-HtmlText $ReportTitle)</h1>"
W "<div class='small'>Generated $($scriptStart.ToString('yyyy-MM-dd HH:mm:ss')) on $env:COMPUTERNAME by $env:USERDOMAIN\$env:USERNAME &middot; run time $([int]$duration.TotalMinutes) min $($duration.Seconds) s &middot; script v$ScriptVersion</div>"

W '<h2>Summary</h2><table>'
W "<tr><td width='25%'><b>Overall status</b></td>$(Get-StatusCell $overall)</tr>"
W "<tr><td><b>Forest</b></td><td>$(ConvertTo-HtmlText $F) ($($forest.ForestMode))</td></tr>"
W "<tr><td><b>Domains checked</b></td><td>$(ConvertTo-HtmlText ($domainList -join ', '))</td></tr>"
W "<tr><td><b>Domain controllers checked</b></td><td>$($dcsToTest.Count) ($unreachable unreachable)</td></tr>"
W "<tr><td><b>Results</b></td><td><span style='color:$($fore.Critical)'><b>$($counts.Critical) Critical</b></span> &nbsp; <span style='color:$($fore.Warning)'><b>$($counts.Warning) Warning</b></span> &nbsp; <span style='color:$($fore.OK)'><b>$($counts.OK) OK</b></span> &nbsp; <span style='color:$($fore.Info)'>$($counts.Info) Info</span></td></tr>"
W '</table>'

# DC overview matrix
$matrixCats = 'Connectivity', 'Services', 'Replication', 'SYSVOL', 'DNS', 'Time', 'Resources', 'EventLogs', 'Sites', 'Certificates', 'DCDiag'
W '<h2>Domain controller overview</h2><table><tr><th>Domain controller</th><th>Domain</th><th>Site</th>'
foreach ($c in $matrixCats) { W "<th style='text-align:center'>$c</th>" }
W '</tr>'
foreach ($dcObj in $dcsToTest) {
    W "<tr><td><b>$($dcObj.Name)</b></td><td>$($dcObj.Domain)</td><td>$($dcObj.Site)</td>"
    foreach ($c in $matrixCats) {
        $rows = @($script:Results | Where-Object { $_.Scope -eq 'DC' -and $_.Target -eq $dcObj.Name -and $_.Category -eq $c })
        if ($rows.Count -eq 0) { W (Get-StatusCell 'N/A'); continue }
        $worst = $null; foreach ($x in $rows) { $worst = Merge-Status $worst $x.Status }
        $bad = @($rows | Where-Object { $_.Status -in 'Warning', 'Critical' }).Count
        $text = if ($bad -gt 0) { "$worst ($bad)" } else { $worst }
        W (Get-StatusCell $worst $text)
    }
    W '</tr>'
}
W '</table><div class="small">Each cell shows the worst result in that category; the number is how many checks are not OK.</div>'

# Issues
$issues = @($script:Results | Where-Object { $_.Status -in 'Critical', 'Warning' } | Sort-Object @{ e = { $script:Rank[$_.Status] }; Descending = $true }, Scope, Target)
W "<h2>Issues requiring attention ($($issues.Count))</h2>"
if ($issues.Count -eq 0) { W "<table><tr>$(Get-StatusCell 'OK' 'No issues found - Active Directory is healthy')</tr></table>" }
else { Write-ResultTable $issues -ShowTarget }

# Forest & domain details
W '<h2>Forest and domain checks</h2>'
W "<h3>Forest: $(ConvertTo-HtmlText $F)</h3>"
Write-ResultTable @($script:Results | Where-Object { $_.Scope -eq 'Forest' })
foreach ($d in $domainList) {
    W "<h3>Domain: $(ConvertTo-HtmlText $d)</h3>"
    Write-ResultTable @($script:Results | Where-Object { $_.Scope -eq 'Domain' -and $_.Target -eq $d })
}

# Per-DC details
W '<h2>Domain controller details</h2>'
foreach ($dcObj in $dcsToTest) {
    $rows = @($script:Results | Where-Object { $_.Scope -eq 'DC' -and $_.Target -eq $dcObj.Name })
    $worst = $null; foreach ($x in $rows) { $worst = Merge-Status $worst $x.Status }
    W "<h3>$($dcObj.Name) &nbsp;<span style='background:$($colors[$worst]);color:$($fore[$worst]);padding:1px 6px'>$worst</span></h3>"
    Write-ResultTable $rows
}

if ($script:ReplSummary) {
    W '<h2>Appendix: repadmin /replsummary</h2>'
    W "<pre>$([System.Net.WebUtility]::HtmlEncode($script:ReplSummary))</pre>"
}

W '<h2>Thresholds used</h2><div class="small">'
W "Disk free: warn &lt; $DiskWarnPercent%, critical &lt; $DiskCritPercent% &middot; Memory free: warn &lt; $MemoryWarnPercent% &middot; CPU: warn &ge; $CpuWarnPercent% &middot; "
W "Replication age: warn &gt; $ReplWarnMinutes min, critical &gt; $ReplCritMinutes min &middot; Replication queue: warn &gt; $ReplQueueWarn &middot; "
W "Time skew: warn &ge; $TimeSkewWarnSeconds s, critical &ge; $TimeSkewCritSeconds s &middot; Uptime: warn &gt; $UptimeWarnDays days &middot; "
W "LDAPS cert: warn &lt; $CertWarnDays days &middot; KRBTGT: warn &gt; $KrbtgtWarnDays days &middot; Backup: warn &gt; $BackupWarnDays, critical &gt; $BackupCritDays days &middot; "
W "Event logs: last $EventLogHours h &middot; dcdiag timeout: $DcdiagTimeoutSeconds s</div>"
$authorParts = @($script:Author.GetEnumerator() | Where-Object { $_.Value -and $_.Value -notmatch '^<.*>$' } | ForEach-Object {
        $v = ConvertTo-HtmlText $_.Value
        if ($_.Key -eq 'E-mail') { $v = "<a href='mailto:$v'>$v</a>" }
        elseif ($_.Key -eq 'Website') { $href = if ($v -match '^https?://') { $v } else { "https://$v" }; $v = "<a href='$href'>$v</a>" }
        "<b>$($_.Key):</b> $v"
    })
if ($authorParts) {
    W "<hr style='border:none;border-top:1px solid #CCC;margin-top:24px'><div class='small'>$($authorParts -join ' &middot; ') &middot; Invoke-ADHealthCheck.ps1 v$ScriptVersion</div>"
}
W '</body></html>'

$html = $sb.ToString()
Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
$script:Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

#endregion HTML report

#region ======================= E-mail, cleanup, exit =======================

if ($SendEmail) {
    if (-not $SmtpServer -or -not $From -or -not $To) {
        Write-Warning 'E-mail not sent: -SmtpServer, -From and -To are required.'
    }
    elseif ($EmailOnlyOnIssues -and $overall -eq 'OK') {
        Write-Host 'No issues found - e-mail skipped (-EmailOnlyOnIssues).' -ForegroundColor Green
    }
    else {
        try {
            $subject = "[$($overall.ToUpper())] AD Health Check - $F - $($scriptStart.ToString('yyyy-MM-dd HH:mm')) ($($counts.Critical) critical, $($counts.Warning) warnings)"
            $mail = @{
                SmtpServer  = $SmtpServer
                Port        = $SmtpPort
                From        = $From
                To          = $To
                Subject     = $subject
                Body        = $html
                BodyAsHtml  = $true
                Encoding    = [System.Text.Encoding]::UTF8
                Attachments = $csvPath
                ErrorAction = 'Stop'
            }
            if ($UseSsl) { $mail.UseSsl = $true }
            if ($SmtpCredentialFile) { $SmtpCredential = Import-Clixml -LiteralPath $SmtpCredentialFile }
            if ($SmtpCredential) { $mail.Credential = $SmtpCredential }
            Send-MailMessage @mail -WarningAction SilentlyContinue
            Write-Host "E-mail sent to $($To -join ', ')" -ForegroundColor Green
        }
        catch { Write-Warning "E-mail failed: $($_.Exception.Message)" }
    }
}

if ($KeepReportsDays -gt 0) {
    Get-ChildItem -LiteralPath $ReportFolder -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^ADHealth_\d{4}-\d{2}-\d{2}_\d{6}\.(html|csv)$' -and $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepReportsDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "`n==================== Summary ====================" -ForegroundColor White
Write-Host "Overall status         : $overall" -ForegroundColor $(switch ($overall) { 'OK' { 'Green' } 'Warning' { 'Yellow' } default { 'Red' } })
Write-Host "Domain controllers     : $($dcsToTest.Count) checked, $unreachable unreachable"
Write-Host "Results                : $($counts.Critical) Critical, $($counts.Warning) Warning, $($counts.OK) OK, $($counts.Info) Info"
Write-Host "Run time               : $([int]$duration.TotalMinutes) min $($duration.Seconds) s"
Write-Host "HTML report            : $htmlPath"
Write-Host "CSV export             : $csvPath"

exit $(switch ($overall) { 'OK' { 0 } 'Warning' { 1 } default { 2 } })

#endregion
