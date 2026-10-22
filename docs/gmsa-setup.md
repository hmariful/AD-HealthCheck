# Running the health check as a gMSA

This guide sets up a group Managed Service Account (gMSA) that runs `Invoke-ADHealthCheck.ps1` every day
at 08:30 with **read-only** rights - no Domain Admin service account and no stored password.

Names used below - replace them with your own:

| Placeholder | Meaning |
|---|---|
| `CONTOSO` / `contoso.com` | NetBIOS / DNS name of your domain |
| `svc_gmsa_adhc` | gMSA (account name `svc_gmsa_adhc$`) |
| `ADHC-Hosts` | Servers allowed to use the gMSA |
| `ADHC-Readers` | Read-only rights group (the gMSA is a member) |
| `DC01` | Task host - a DC (preferably the PDC) or a management server with RSAT |
| `D:\Scripts\ADHC` | Script folder on the task host |

Run every step on **DC01** in an **elevated** PowerShell window as a **Domain Admin**.

## Rights the gMSA gets

| For | Right |
|---|---|
| AD, replication summary, DNS, GPO, SYSVOL checks | Nothing extra (Authenticated Users can read) |
| Event logs on DCs | Built-in group **Event Log Readers** |
| Remote WMI | **Distributed COM Users**, **Remote Management Users**, WMI namespace permissions |
| Service status | Read-only entry on the Service Control Manager and the AD services |
| Replication status / queue | Extended right **Monitor Active Directory Replication** |
| Run a scheduled task on a DC | **Log on as a batch job** (via **Performance Log Users** on DCs) |

## 1. KDS root key (once per forest)

```powershell
Get-KdsRootKey
```
If nothing is returned: `Add-KdsRootKey -EffectiveImmediately`, then wait **10 hours** for replication
to all DCs before step 2.

## 2. Groups and gMSA

```powershell
$dc = 'DC01.contoso.com'
New-ADGroup -Server $dc -Name 'ADHC-Hosts'   -GroupScope Global -GroupCategory Security -Description 'Servers allowed to use svc_gmsa_adhc'
New-ADGroup -Server $dc -Name 'ADHC-Readers' -GroupScope Global -GroupCategory Security -Description 'Read-only rights for the AD health check'
Add-ADGroupMember -Server $dc -Identity 'ADHC-Hosts' -Members 'DC01$'

New-ADServiceAccount -Server $dc -Name 'svc_gmsa_adhc' -DNSHostName 'svc_gmsa_adhc.contoso.com' `
    -PrincipalsAllowedToRetrieveManagedPassword 'ADHC-Hosts' `
    -KerberosEncryptionType AES128,AES256 -Description 'Runs the daily AD health check'

Add-ADGroupMember -Server $dc -Identity 'ADHC-Readers' -Members 'svc_gmsa_adhc$'
```

## 3. Install the gMSA on the task host

```powershell
klist -li 0x3e7 purge            # pick up the new ADHC-Hosts membership without a reboot
Install-ADServiceAccount svc_gmsa_adhc
Test-ADServiceAccount svc_gmsa_adhc    # must return True (if not: reboot and retry)
```

## 4. Built-in groups (apply to all DCs)

```powershell
'Event Log Readers','Distributed COM Users','Remote Management Users','Performance Log Users' |
    ForEach-Object { Add-ADGroupMember -Identity $_ -Members 'ADHC-Readers' }
```

Check that Performance Log Users has **Log on as a batch job** on your DCs:
```powershell
secedit /export /cfg $env:TEMP\ur.inf /areas USER_RIGHTS | Out-Null
Select-String -Path $env:TEMP\ur.inf -Pattern 'SeBatchLogonRight'    # must contain *S-1-5-32-559
```
If it does not, add `CONTOSO\ADHC-Readers` to *Log on as a batch job* in the **Default Domain Controllers
Policy** - and **keep every existing entry**, because this setting replaces the whole list.

## 5. WMI, service and replication read rights

In **Windows PowerShell 5.1**:
```powershell
cd D:\Scripts\ADHC
.\Grant-ADHealthWmiAccess.ps1 -Group 'CONTOSO\ADHC-Readers' -Services -ReplicationMonitor -WhatIf
.\Grant-ADHealthWmiAccess.ps1 -Group 'CONTOSO\ADHC-Readers' -Services -ReplicationMonitor
```
Run it a second time to confirm: every line should show `[OK      ]`.

Expected failures:
- **Dnscache** - Windows protects this service; it cannot be delegated and is reported as Info.
- **Schema partition** - needs an **elevated** Schema Admin. Open a window as a Schema Admin, start an
  elevated one (`Start-Process powershell.exe -Verb RunAs`), check `whoami /groups | findstr /i Schema`
  shows *Enabled group*, then:
  ```powershell
  dsacls "CN=Schema,CN=Configuration,DC=contoso,DC=com" /G "CONTOSO\ADHC-Readers:CA;Monitor Active Directory Replication"
  ```

## 6. Script folder - only administrators may change the scripts

On a data volume, Windows gives *Authenticated Users* Modify by default. Anyone who can edit the script
could run code as the gMSA, so stop inheritance and set the permissions explicitly:

```powershell
$root = 'D:\Scripts'; $adhc = 'D:\Scripts\ADHC'; $reports = 'D:\Scripts\ADHC\Reports'
New-Item $reports -ItemType Directory -Force | Out-Null
# copy the scripts and ADHealthCheck.config.psd1 into $adhc, then:
Unblock-File "$adhc\*.ps1"

icacls $root /inheritance:r
icacls $root /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F'
icacls $root /setowner 'BUILTIN\Administrators' /T /C
icacls $adhc    /grant 'CONTOSO\svc_gmsa_adhc$:(OI)(CI)RX'
icacls $reports /grant 'CONTOSO\svc_gmsa_adhc$:(OI)(CI)M'
```
`icacls` on each folder should list only SYSTEM, Administrators and the gMSA.

## 7. Scheduled task (daily 08:30, server time)

All settings come from `ADHealthCheck.config.psd1`, so the task only needs the script path.

```powershell
Get-TimeZone
$arg = '-NoProfile -ExecutionPolicy Bypass -File "D:\Scripts\ADHC\Invoke-ADHealthCheck.ps1"'
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg -WorkingDirectory 'D:\Scripts\ADHC'
$trigger   = New-ScheduledTaskTrigger -Daily -At '08:30'
$principal = New-ScheduledTaskPrincipal -UserId 'CONTOSO\svc_gmsa_adhc$' -LogonType Password
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'AD Health Check' -TaskPath '\ADHC\' `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```
`-LogonType Password` is correct for a gMSA - Windows retrieves the password from AD, none is stored.

## 8. Test

```powershell
Start-ScheduledTask -TaskPath '\ADHC\' -TaskName 'AD Health Check'
Get-ScheduledTaskInfo -TaskPath '\ADHC\' -TaskName 'AD Health Check' | Select LastRunTime, LastTaskResult
```

| LastTaskResult | Meaning |
|---|---|
| 0 / 1 / 2 | Task ran; health result OK / Warning / Critical |
| 267009 | Still running |
| 2147942401 or 0x8007052E | gMSA could not log on - recheck steps 3 and 4 |

The report header shows `run ... by CONTOSO\svc_gmsa_adhc$` and the script version.

## Troubleshooting

| In the report | Fix |
|---|---|
| `Could not read log` for DNS Server / DFS Replication | On that DC: `wevtutil gl "DNS Server"`, copy `channelAccess`, then `wevtutil sl "DNS Server" /ca:"<value>(A;;0x1;;;S-1-5-32-573)"` |
| `Service status: Access denied` | Run step 5 with `-Services` |
| `Replication access was denied` (0x2105) | Run step 5 with `-ReplicationMonitor` (and the Schema command) |
| `WMI/CIM access: Failed` on one DC | Run step 5 on that DC with `-ComputerName localhost`; check WinRM 5985 / DCOM firewall |
| Info `Not readable by run account` | Expected for time source, netlogon.log, NTDS path and DFSR state as a non-admin |

## Adding another task host

```powershell
Add-ADGroupMember ADHC-Hosts -Members 'DC02$'
```
Then repeat steps 3, 6 and 7 on the new host.
