<#
.SYNOPSIS
    3A1shOnWin - System Reconnaissance and Environment Mapping Module
.DESCRIPTION
    Gathers host, user, and network context for the USB-STk project and stores
    the resulting reports and JSON only under the removable USB project's data
    directory. It never transmits the information to external systems.
.NOTES
    Author: Blankstyxx
    Compliance: Non-destructive, audit-logged, USB-local storage only.
#>

$ErrorActionPreference = "Stop"

function Get-IsoTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Write-AuditEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $ProjectRoot = (Resolve-Path -Path $PSScriptRoot).Path
    $DataDir = Join-Path $ProjectRoot "data"
    $AuditDir = Join-Path $DataDir "log\audit"
    $AuditFile = Join-Path $AuditDir "audit"

    if (-not (Test-Path $AuditDir)) {
        New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null
    }

    $Timestamp = Get-IsoTimestamp
    "[$Timestamp] $Message" | Add-Content -LiteralPath $AuditFile -Encoding UTF8
}

try {
    $ProjectRoot = (Resolve-Path -Path $PSScriptRoot).Path
    $DataDir = Join-Path $ProjectRoot "data"
    $VulnDir = Join-Path $DataDir "vuln"
    $InfoDir = Join-Path $VulnDir "info"
    $ReportsDir = Join-Path $DataDir "reports"
    $AuditDir = Join-Path $DataDir "log\audit"
    $LogDir = Join-Path $DataDir "log\logs"

    foreach ($Dir in @($DataDir, $VulnDir, $InfoDir, $ReportsDir, $AuditDir, $LogDir)) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }

    if (-not (Test-Path $DataDir -PathType Container)) {
        throw "The USB project data directory is missing or invalid."
    }

    $WriteProbe = Join-Path $DataDir ".write-test"
    try {
        Set-Content -LiteralPath $WriteProbe -Value (Get-IsoTimestamp) -Encoding UTF8
        Remove-Item -LiteralPath $WriteProbe -Force -ErrorAction Stop
    }
    catch {
        throw "The USB project data directory is not writable: $($_.Exception.Message)"
    }

    $JsonOutputFile = Join-Path $InfoDir "host-enumeration.json"
    $ReportFile = Join-Path $ReportsDir "system-info.txt"

    Write-AuditEntry "[AUDIT] [Reconnaissance] Initialization started."

    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        throw "The Get-CimInstance command is unavailable on this Windows host."
    }

    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $CompSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]::new($Identity)
    $IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    $UserContext = [PSCustomObject]@{
        UserName           = $Identity.Name
        UserSID            = $Identity.User.Value
        IsRunningAsAdmin   = $IsAdmin
        AuthenticationType = $Identity.AuthenticationType
    }

    $NetworkAdapters = @()
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
        try {
            $NetworkAdapters = @(Get-NetIPAddress -ErrorAction Stop | Where-Object {
                    $_.AddressState -eq "Preferred" -and
                    $_.IPAddress -and
                    $_.IPAddress -notmatch '^127\.' -and
                    $_.IPAddress -notlike '169.254.*' -and
                    $_.IPAddress -ne '::1'
                } | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength)
        }
        catch {
            Write-AuditEntry "[WARN] [Reconnaissance] Get-NetIPAddress did not return network data."
            $NetworkAdapters = @()
        }
    }
    else {
        Write-AuditEntry "[WARN] [Reconnaissance] Get-NetIPAddress is unavailable."
    }

    $IPv4List = @($NetworkAdapters | Where-Object { $_.AddressFamily -eq 'IPv4' } | ForEach-Object { "$($_.IPAddress) (Interface: $($_.InterfaceAlias))" })
    $IPv6List = @($NetworkAdapters | Where-Object { $_.AddressFamily -eq 'IPv6' } | ForEach-Object { "$($_.IPAddress) (Interface: $($_.InterfaceAlias))" })

    $ReconPayload = [PSCustomObject]@{
        Framework    = "3A1shOnWin"
        TimestampUTC = (Get-IsoTimestamp)
        HostContext  = [PSCustomObject]@{
            ComputerName  = $env:COMPUTERNAME
            Domain        = $env:USERDNSDOMAIN
            Manufacturer  = $CompSystem.Manufacturer
            Model         = $CompSystem.Model
            TotalMemoryGB = [Math]::Round(($CompSystem.TotalPhysicalMemory / 1GB), 2)
        }
        UserContext = $UserContext
        OperatingSystem = [PSCustomObject]@{
            Caption      = $OS.Caption
            Version      = $OS.Version
            BuildNumber  = $OS.BuildNumber
            Architecture = $OS.OSArchitecture
            InstallDate  = $OS.InstallDate
        }
        PowerShellEnv = [PSCustomObject]@{
            PSVersion  = $PSVersionTable.PSVersion.ToString()
            PSEdition  = $PSVersionTable.PSEdition
            CLRVersion = $PSVersionTable.CLRVersion.ToString()
        }
        Network = [PSCustomObject]@{
            IPv4Addresses = $IPv4List
            IPv6Addresses = $IPv6List
        }
    }

    $ReconPayload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOutputFile -Encoding UTF8

    $FormattedIPv4 = if ($IPv4List.Count -gt 0) { ($IPv4List | ForEach-Object { "- $_" }) -join "`n" } else { "- None detected" }
    $FormattedIPv6 = if ($IPv6List.Count -gt 0) { ($IPv6List | ForEach-Object { "- $_" }) -join "`n" } else { "- None detected" }
    $DomainName = if ($ReconPayload.HostContext.Domain) { $ReconPayload.HostContext.Domain } else { "WORKGROUP" }

    $ReportContent = @"
================================================================================
3A1shOnWin - SYSTEM RECONNAISSANCE REPORT
Generated: $($ReconPayload.TimestampUTC) (UTC)
================================================================================

[HOST INFORMATION]
- Computer Name : $($ReconPayload.HostContext.ComputerName)
- Domain/Workgroup: $DomainName
- System Model  : $($ReconPayload.HostContext.Manufacturer) $($ReconPayload.HostContext.Model)
- RAM Capacity  : $($ReconPayload.HostContext.TotalMemoryGB) GB

[OPERATING SYSTEM]
- OS Caption    : $($ReconPayload.OperatingSystem.Caption)
- Version Build : $($ReconPayload.OperatingSystem.Version) (Build $($ReconPayload.OperatingSystem.BuildNumber))
- Architecture  : $($ReconPayload.OperatingSystem.Architecture)

[EXECUTION CONTEXT]
- Current User  : $($ReconPayload.UserContext.UserName)
- User SID      : $($ReconPayload.UserContext.UserSID)
- Elevated (Admin): $($ReconPayload.UserContext.IsRunningAsAdmin)
- PowerShell Ver: $($ReconPayload.PowerShellEnv.PSVersion)

[NETWORK CONFIGURATION]
- Active IPv4s  :
$FormattedIPv4
- Active IPv6s  :
$FormattedIPv6

================================================================================
Status: Reconnaissance completed successfully. No system modifications applied.
Artifact root: $DataDir
================================================================================
"@

    Set-Content -LiteralPath $ReportFile -Value $ReportContent -Encoding UTF8
    Write-AuditEntry "[AUDIT] [Reconnaissance] Success. Artifacts written to $DataDir."
    exit 0
}
catch {
    $ErrorMessage = $_.Exception.Message -replace '[\r\n]', ' '
    try {
        Write-AuditEntry "[ERROR] [Reconnaissance] Failed: $ErrorMessage"
    }
    catch {
    }
    exit 1
}
