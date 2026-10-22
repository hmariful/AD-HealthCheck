# Changelog

## Invoke-ADHealthCheck.ps1

### 2.9 - 2026-10-22
- Author block (script header and report footer) reduced to name, e-mail and website.
- Website shown as a link in the report footer.

### 2.8 - 2026-10-22
- Fix: `-NtpServer a,b,c` passed through `powershell.exe -File` (one string) now tests every server, not only the first.
- Fix: FSMO "role holder NOT reachable" false alarm while the dcdiag jobs start - the check reuses the
  reachability test from the start of the run and retries with a longer timeout.

### 2.7 - 2026-10-22
- Environment settings moved to `ADHealthCheck.config.psd1` (example file included, real file excluded from Git).
- Generic defaults in the script; no environment-specific values in source.
- Report shows which config file was used.

### 2.6 - 2026-10-22
- Configurable report title, author block in the script header and report footer.
- DFSR state shown as "Not readable by run account" for non-admin runs (the provider returns no rows).

### 2.5 - 2026-10-22
- Least-privilege support (gMSA): dcdiag tests that need admin rights are skipped automatically,
  rights-related results are reported as Info "Not readable by run account".
- DNS Client service handled as not delegable.
- Port test retries once (no false "FSMO role holder not reachable").
- Script version shown in the report header.

### 2.4 - 2026-10-22
- `-NtpServer` to test NTP servers when the PDC configuration cannot be read.
- Service-status access denied reported with a hint to the permission script.

### 2.3 - 2026-10-22
- dcdiag failures caused by "Access is denied" reported as Warning instead of Critical.
- `-DcdiagSkip`.

### 2.2 - 2026-10-22
- System log filtered to AD DS / DNS sources; dcdiag runs with `/skip:SystemLog`.
- Active Directory Web Services log checked.
- NTP peer test on the forest root PDC.
- Fix: time source `x.x.x.x,0x8` no longer reported as "Query failed".

### 2.1 - 2026-10-22
- dcdiag failure details reduced to the relevant error lines; DNS forwarder-only failures are Warning.
- Event read limit shown as `2000+`; `-IgnoreEventId` / `-IgnoreEventPattern`.
- NO_CLIENT_SITE limited to the last 7 days, with host names.
- E-mail without authentication by default.

### 2.0 - 2026-10-21
- Initial version: forest, domain and per-DC checks, colour-coded HTML report, CSV export, e-mail, exit codes.

## Backup-ADSystemState.ps1

### 1.1 - 2026-10-22
- Reads SMTP and backup settings from the shared config file.

### 1.0 - 2026-10-22
- Initial version: wbadmin system-state backup, verification, retention, optional copy, e-mail on failure.

## Grant-ADHealthWmiAccess.ps1

### 1.2 - 2026-10-22
- `-Services` (read-only service permissions) and `-ReplicationMonitor` ("Monitor Active Directory Replication").

### 1.1 - 2026-10-22
- Fix: WMI security descriptor read/write via `Invoke-WmiMethod`; `-WhatIf` no longer blocks the read.

### 1.0 - 2026-10-22
- Initial version: WMI namespace permissions on all DCs.
