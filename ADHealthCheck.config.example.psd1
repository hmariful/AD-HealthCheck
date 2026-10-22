# ADHealthCheck.config.example.psd1
#
# Copy this file to ADHealthCheck.config.psd1 in the same folder as the scripts and edit it.
# ADHealthCheck.config.psd1 is listed in .gitignore - your environment details never go to GitHub.
#
# Every key is a parameter name of Invoke-ADHealthCheck.ps1 (run Get-Help .\Invoke-ADHealthCheck.ps1 -Full).
# A parameter passed on the command line always wins over the value here.
# Lines starting with # are comments; remove the # to use a setting.
@{
    # ---------------- Report ----------------
    ReportTitle     = 'Contoso Prod Active Directory Health Check Report'
    ReportFolder    = 'D:\Scripts\ADHC\Reports'
    # KeepReportsDays = 30

    # ---------------- E-mail ----------------
    # No authentication is used unless SmtpCredentialFile is set.
    SendEmail  = $true
    SmtpServer = 'smtp.contoso.com'
    SmtpPort   = 587
    UseSsl     = $true
    From       = 'adreport@contoso.com'
    To         = @('ad-admins@contoso.com')
    # EmailOnlyOnIssues  = $true
    # SmtpCredentialFile = 'D:\Scripts\ADHC\smtp.cred'   # Get-Credential | Export-Clixml <path> (as the run account)

    # ---------------- Time ----------------
    # NTP servers of the forest root PDC. Tested from the script host over UDP 123.
    NtpServer = @('10.0.0.4', '10.0.0.5', '10.0.0.6')

    # ---------------- Thresholds (optional) ----------------
    # BackupWarnDays      = 2
    # BackupCritDays      = 7
    # DiskWarnPercent     = 20
    # DiskCritPercent     = 10
    # ReplWarnMinutes     = 240
    # ReplCritMinutes     = 1440
    # TimeSkewWarnSeconds = 5
    # CertWarnDays        = 30
    # KrbtgtWarnDays      = 180

    # ---------------- Noise filters (optional) ----------------
    # IgnoreEventPattern = 'MonitoringAgent|OtherAgent'
    # IgnoreEventId      = @(7034)
    # DcdiagSkip         = @('Services')

    # ---------------- Report footer ----------------
    # Overrides the author block in the script. Values in <angle brackets> are hidden.
    # Author = @{
    #     'Author'  = 'Your Name'
    #     'E-mail'  = 'you@example.com'
    #     'Website' = 'https://example.com'
    # }

    # ---------------- Backup-ADSystemState.ps1 ----------------
    # Uses SmtpServer / SmtpPort / UseSsl / From / To from above plus these settings.
    Backup = @{
        BackupTarget  = 'D:'
        KeepVersions  = 14
        MailOnFailure = $true
        # CopyToPath  = '\\backupserver\ADBackup'
        # LogFolder   = 'D:\Scripts\Logs\ADBackup'
    }
}
