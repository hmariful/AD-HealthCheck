# Active Directory system-state backup

The health check reports the last backup of every AD partition. That date is only updated by
**AD-aware system-state backups** (Windows Server Backup or a VSS/AD-aware backup product).
VM snapshots and file-level backups do **not** count.

`Backup-ADSystemState.ps1` runs `wbadmin start systemstatebackup`, verifies the result, keeps a fixed number
of versions, optionally copies the latest backup to a share and e-mails on failure.

## Requirements

| Item | Requirement |
|---|---|
| Which DCs | At least **two**, in different sites / availability zones |
| Feature | `Install-WindowsFeature Windows-Server-Backup` |
| Backup volume | A dedicated, **persistent** volume that is not C: and does not hold NTDS/SYSVOL (on cloud VMs avoid temporary / ephemeral disks) |
| Size | Plan ~100 GB; check after the first backups |
| Retention | E.g. 14 daily versions - always well below the tombstone lifetime (default 180 days) |
| Off-server copy | Recommended: a share on another platform, or let the backup platform collect `<volume>\WindowsImageBackup` |
| Security | Backups contain `ntds.dit` (all password hashes) - access for Domain Admins / Backup Operators / SYSTEM only |
| DSRM password | Required for every restore - set and store it for each DC |

## Steps (on each backup DC, elevated, Domain Admin)

1. **Install the feature**
   ```powershell
   Install-WindowsFeature Windows-Server-Backup
   ```
2. **Set the DSRM password** and store it in your password vault
   ```powershell
   ntdsutil "set dsrm password" "reset password on server null" q q
   ```
3. **Prepare the volume** (new disk example)
   ```powershell
   Get-Disk | Where-Object PartitionStyle -eq RAW | Initialize-Disk -PassThru |
       New-Partition -UseMaximumSize -DriveLetter D | Format-Volume -FileSystem NTFS -NewFileSystemLabel ADBackup
   ```
4. **Settings** - in `ADHealthCheck.config.psd1`:
   ```powershell
   Backup = @{ BackupTarget = 'D:'; KeepVersions = 14; MailOnFailure = $true }
   ```
5. **First backup (manual)** - usually 15-40 minutes
   ```powershell
   .\Backup-ADSystemState.ps1
   ```
6. **Verify**
   ```powershell
   wbadmin get versions -backupTarget:D:
   repadmin /showbackup          # today's date for every partition
   ```
7. **Schedule daily** (runs as SYSTEM; stagger start times between DCs)
   ```powershell
   $a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File D:\Scripts\ADHC\Backup-ADSystemState.ps1'
   $t = New-ScheduledTaskTrigger -Daily -At 01:30
   Register-ScheduledTask -TaskName 'AD System State Backup' -TaskPath '\ADHC\' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest
   ```
8. **Tighten the health-check alert** - in the config: `BackupWarnDays = 2; BackupCritDays = 7`.
9. **Test a restore every quarter - isolated network only**
   - restore the backup to a test VM, boot into DSRM: `bcdedit /set safeboot dsrepair`, reboot
   - `wbadmin start systemstaterecovery -version:<id> -quiet`
   - `bcdedit /deletevalue safeboot`, reboot and confirm AD starts.

   Single deleted objects are restored from the AD Recycle Bin, not from backup.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Backup succeeded |
| 1 | Backup succeeded, cleanup or copy warning |
| 2 | Backup failed |
