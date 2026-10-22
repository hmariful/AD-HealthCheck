# AD-HealthCheck

PowerShell health check for Active Directory Domain Services and AD-integrated DNS.
It runs about 60 checks per forest, domain and domain controller and writes a colour-coded HTML report
(plus CSV) in which **every** result is shown as **OK, Warning, Critical or Info**, so you see what is
healthy as well as what is broken. The report can be e-mailed and the script is designed to run daily
as a **gMSA with read-only rights** (no Domain Admin service account).

| Script | Purpose |
|---|---|
| `Invoke-ADHealthCheck.ps1` | The health check and report |
| `Grant-ADHealthWmiAccess.ps1` | One-time grant of the read-only rights the health check needs as a non-admin account |
| `Backup-ADSystemState.ps1` | Daily AD system-state backup with Windows Server Backup (wbadmin) |
| `ADHealthCheck.config.example.psd1` | Template for your environment settings |

## What is checked

**Forest:** functional level, schema version, Global Catalogs, Schema / Domain Naming Master online,
AD Recycle Bin, tombstone lifetime, sites/subnets/GC coverage, `repadmin /replsummary`,
last backup of Configuration and Schema partitions, `_gc` SRV records.

**Domain:** functional level, DC inventory, PDC / RID / Infrastructure Master online, RID pool usage,
last backup of the domain partition, KRBTGT password age, SYSVOL FRS→DFSR migration state,
DC locator SRV records (missing and stale), trusts (`nltest /sc_verify`), GPO AD-vs-SYSVOL consistency,
privileged group membership.

**Each DC:** ping, AD ports (88, 135, 389, 445, 464, 9389, 53, 3268), LDAP bind, `isSynchronized`,
`isGlobalCatalogReady`, LDAPS certificate expiry, 14 services with start mode, uptime, CPU, memory, disks,
NTDS database, SYSVOL/NETLOGON shares, DFSR SYSVOL state, inbound replication per partner and partition,
replication failures and queue, DNS A record and DNS server response, time source and offset,
NTP server reachability (forest root PDC), AD DS / DNS errors in the event logs, clients without a site
(`NO_CLIENT_SITE`), and `dcdiag` with each test reported separately.

The System log is filtered to AD DS / DNS sources (Netlogon, Kerberos, KDC, W32Time, DNS Client, LSA, SAM,
Group Policy, DFS-N and the AD-related services), so monitoring agents or other applications do not
flood the report.

## Requirements

- Windows PowerShell 5.1, run on a DC or a management server with RSAT AD DS
  (`ActiveDirectory` module, `dcdiag.exe`, `repadmin.exe`, `nltest.exe`, `w32tm.exe`).
- English OS language (dcdiag / repadmin output is parsed in English).
- WinRM or DCOM/WMI and Remote Event Log access to the DCs.
- Either an administrator account, or a gMSA with the read-only rights from `Grant-ADHealthWmiAccess.ps1`.

## Quick start

```powershell
# 1. Copy the files to the server, e.g. D:\Scripts\ADHC, and unblock them once
Unblock-File D:\Scripts\ADHC\*.ps1

# 2. Create your settings file
Copy-Item D:\Scripts\ADHC\ADHealthCheck.config.example.psd1 D:\Scripts\ADHC\ADHealthCheck.config.psd1
notepad D:\Scripts\ADHC\ADHealthCheck.config.psd1

# 3. Run it (elevated, as an administrator, for the first test)
cd D:\Scripts\ADHC
.\Invoke-ADHealthCheck.ps1
```

The report (`ADHealth_<date>.html` and `.csv`) is written to `ReportFolder`, and e-mailed when
`SendEmail = $true` is set.

## Configuration

All environment-specific values live in `ADHealthCheck.config.psd1` next to the scripts. This file is in
`.gitignore`, so SMTP servers, addresses and IPs never reach the repository. Keys are parameter names;
anything passed on the command line wins. See [`ADHealthCheck.config.example.psd1`](ADHealthCheck.config.example.psd1).

Frequently used settings:

| Setting | Meaning |
|---|---|
| `ReportTitle`, `ReportFolder` | Report heading and output folder |
| `SendEmail`, `SmtpServer`, `SmtpPort`, `UseSsl`, `From`, `To` | E-mail (no authentication unless `SmtpCredentialFile`) |
| `EmailOnlyOnIssues` | Only mail when there is a Warning or Critical |
| `NtpServer` | NTP servers to test from the script host |
| `IgnoreEventPattern`, `IgnoreEventId`, `DcdiagSkip` | Noise filters |
| `BackupWarnDays`, `DiskWarnPercent`, `ReplWarnMinutes`, ... | Thresholds |
| `Author` | Footer of the report |
| `Backup` | Settings for `Backup-ADSystemState.ps1` |

Full parameter help: `Get-Help .\Invoke-ADHealthCheck.ps1 -Full`

## Running as a gMSA (recommended)

The health check does not need Domain Admin. Create a gMSA, add it to a reader group, grant read-only rights
once and schedule the task:

```powershell
.\Grant-ADHealthWmiAccess.ps1 -Group 'CONTOSO\ADHC-Readers' -Services -ReplicationMonitor
```

When the script runs without administrator rights it skips the dcdiag tests that need admin
(NetLogons, SysVolCheck, Services, DNS) - its own checks cover the same areas - and shows checks that cannot
be read as **Info "Not readable by run account"** instead of false warnings.

Step-by-step guide: [docs/gmsa-setup.md](docs/gmsa-setup.md)

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks OK |
| 1 | At least one Warning |
| 2 | At least one Critical |
| 3 | Could not start (module missing, forest not readable, bad config file) |

In Task Scheduler the exit code appears as *Last Run Result*; 1 and 2 are health findings, not task failures.

## Other guides

- [docs/gmsa-setup.md](docs/gmsa-setup.md) - gMSA, read-only rights, folder permissions, 08:30 daily task
- [docs/time-sync.md](docs/time-sync.md) - check and configure NTP on the forest root PDC
- [docs/ad-backup.md](docs/ad-backup.md) - requirements and steps for AD system-state backups

## Security notes

- Lock the script folder so only administrators can change the scripts - anyone who can edit them can run
  code as the scheduled-task account (see the gMSA guide).
- Never commit `ADHealthCheck.config.psd1`, `*.cred` files or generated reports; they are in `.gitignore`.
- The rights granted by `Grant-ADHealthWmiAccess.ps1` are read-only. It never grants
  "Replicating Directory Changes" (DCSync) rights.

## Author

**Md Ariful Haque**

- E-mail: [hmariful@outlook.com](mailto:hmariful@outlook.com)
- Website: [ariful.me](https://ariful.me) - Blog: [blog.ariful.me](https://blog.ariful.me)

## License

[MIT](LICENSE)
