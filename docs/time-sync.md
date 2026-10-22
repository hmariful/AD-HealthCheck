# Time synchronisation on the forest root PDC

All DCs synchronise from the domain hierarchy; the **forest root PDC Emulator** is the only one that should
synchronise from external NTP servers. If it shows `Free-running System Clock` or `Local CMOS Clock`, the whole
forest is drifting without a reference.

Run on the **forest root PDC**, elevated, as an administrator. Replace `10.0.0.4 / .5 / .6` with your NTP servers.

## 1. Current configuration

```powershell
w32tm /query /status          # Source, Stratum, Last Successful Sync Time
w32tm /query /source
w32tm /query /peers
w32tm /query /configuration   # Type, NtpServer, AnnounceFlags, VMICTimeProvider
reg query HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters   # any value = a GPO controls time
```
If `NtpServer` ends in **(Policy)**, change the GPO - local `w32tm /config` is overwritten.

## 2. Connectivity to the NTP servers (UDP 123)

Ping and `Test-NetConnection` cannot test UDP. Use real NTP requests:
```powershell
foreach ($p in '10.0.0.4','10.0.0.5','10.0.0.6') { "== $p"; w32tm /stripchart /computer:$p /samples:3 /dataonly }
```
- Lines like `10:15:01, +00.0123456s` - the server answers; the value is the PDC's offset.
- `error: 0x800705B4` - timeout. Check that the servers really are NTP servers, the network firewall /
  cloud security group allows UDP 123 both ways (Windows uses source port 123), and
  `netstat -ano -p udp | findstr :123` shows W32Time listening.

Note the offset first. All DCs and clients follow the PDC in one step when it is corrected; plan a
maintenance window if it is more than a few minutes.

## 3. Configure

```powershell
w32tm /config /manualpeerlist:"10.0.0.4,0x8 10.0.0.5,0x8 10.0.0.6,0x8" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync /rediscover
```
On a VM, if `VMICTimeProvider Enabled: 1`, disable hypervisor time sync for the PDC:
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider /v Enabled /t REG_DWORD /d 0 /f
Restart-Service w32time
```
If stripchart answers but W32Time does not synchronise, try flag `0x9` instead of `0x8`.

## 4. Verify

```powershell
w32tm /query /status      # Source = your NTP server, Stratum 2-5
w32tm /query /peers       # State: Active
w32tm /monitor /domain:contoso.com
```

## 5. Other DCs

They must use the domain hierarchy:
```powershell
w32tm /config /syncfromflags:domhier /update; w32tm /resync
```

## 6. Survive a PDC role move

Put the NTP settings in a GPO linked to the Domain Controllers OU with a WMI filter that matches only the PDC:
`Select * from Win32_ComputerSystem where DomainRole = 5`

## In the health check

Set `NtpServer = @('10.0.0.4','10.0.0.5','10.0.0.6')` in `ADHealthCheck.config.psd1`. The report then shows
one row per NTP server (responding / offset) even when the run account cannot read the PDC configuration.
