<#
.SYNOPSIS
    3A1shOnWin - OpenSSH Service Orchestration & Key Authorization Module
.DESCRIPTION
    Validates or installs the OpenSSH client/server on the Windows host, ensures
    the sshd service is configured and running, authorizes the USB project's SSH
    public key, and writes diagnostics and fingerprints to the USB project data
    directories. This script only handles Windows system configuration required to
    enable SSH; all project artifacts remain in the USB project tree.
.NOTES
    Author: Blankstyxx
    Compliance: Audited, reversible, USB-local project artifacts.
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

$TempKeyFile = $null

try {
    $ProjectRoot = (Resolve-Path -Path $PSScriptRoot).Path
    $DataDir = Join-Path $ProjectRoot "data"
    $KeysDir = Join-Path $ProjectRoot "keys"
    $AuditDir = Join-Path $DataDir "log\audit"
    $VulnDir = Join-Path $DataDir "vuln"
    $SshKeyDir = Join-Path $VulnDir "ssh-key"
    $AuthKeySource = Join-Path $KeysDir "authorized_keys"
    $DiagnosticsFile = Join-Path $SshKeyDir "ssh-diagnostics.txt"
    $FingerprintFile = Join-Path $SshKeyDir "key-fingerprints.txt"

    foreach ($Dir in @($DataDir, $KeysDir, $AuditDir, $VulnDir, $SshKeyDir)) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }

    if (-not (Test-Path $DataDir -PathType Container)) {
        throw "The USB project data directory is missing or invalid."
    }

    Write-AuditEntry "[AUDIT] [SSH-Orchestration] Initialization started. Project data directory: $DataDir"

    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]::new($Identity)
    $IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        throw "Administrative privileges are required for OpenSSH installation and firewall changes."
    }

    $FeatureList = @("OpenSSH.Client~~~~0.0.1.0", "OpenSSH.Server~~~~0.0.1.0")
    foreach ($Feature in $FeatureList) {
        $Capability = Get-WindowsCapability -Online -Name $Feature -ErrorAction SilentlyContinue
        if ($null -eq $Capability) {
            Write-AuditEntry "[WARN] [SSH-Install] Windows capability '$Feature' was not reported by Get-WindowsCapability."
            continue
        }

        if ($Capability.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $Feature -ErrorAction Stop | Out-Null
            Write-AuditEntry "[AUDIT] [SSH-Install] Installed Windows capability: $Feature"
        }
        else {
            Write-AuditEntry "[AUDIT] [SSH-Install] Windows capability already installed: $Feature"
        }
    }

    $OpenSSHPath = Join-Path $env:SystemRoot "System32\OpenSSH"
    if ($env:PATH -notlike "*$OpenSSHPath*") {
        $env:PATH = "$env:PATH;$OpenSSHPath"
    }

    $SshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $SshdService) {
        throw "The OpenSSH Server service (sshd) is not available after installation."
    }

    Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop
    if ($SshdService.Status -ne "Running") {
        Start-Service -Name sshd -ErrorAction Stop
    }
    Write-AuditEntry "[AUDIT] [SSH-Service] sshd service is configured to Automatic and is running."

    $RuleName = "3A1shOnWin-SSH-LocalAccess"
    if (-not (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $RuleName `
            -DisplayName "3A1shOnWin SSH Local Subnet Access" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 22 `
            -RemoteAddress LocalSubnet `
            -Action Allow `
            -Enabled True `
            -Profile Private,Domain | Out-Null
        Write-AuditEntry "[AUDIT] [Firewall] Created rule '$RuleName' for inbound TCP/22 on LocalSubnet."
    }
    else {
        Set-NetFirewallRule -Name $RuleName -Enabled True -Profile Private,Domain
        Write-AuditEntry "[AUDIT] [Firewall] Updated rule '$RuleName' to allow TCP/22 for Private and Domain profiles."
    }

    if (-not (Test-Path $AuthKeySource)) {
        $DefaultPrivateKey = Join-Path $KeysDir "id_ed25519"
        $DefaultPublicKey = "$DefaultPrivateKey.pub"
        $SshKeyGen = Join-Path $env:SystemRoot "System32\OpenSSH\ssh-keygen.exe"
        if (-not (Test-Path $SshKeyGen)) {
            $SshKeyGen = (Get-Command ssh-keygen -ErrorAction Stop).Source
        }

        if (-not (Test-Path $DefaultPrivateKey)) {
            & $SshKeyGen -t ed25519 -f $DefaultPrivateKey -N "" -C "3A1shOnWin-Default" -q
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to generate the default SSH key pair in the USB project keys directory."
            }
        }

        if (Test-Path $DefaultPublicKey) {
            Copy-Item -LiteralPath $DefaultPublicKey -Destination $AuthKeySource -Force
            Write-AuditEntry "[AUDIT] [SSH-Keys] Generated default public key source at $AuthKeySource"
        }
        else {
            throw "The generated default public key could not be found at $DefaultPublicKey."
        }
    }

    $PublicKeyContent = (Get-Content -LiteralPath $AuthKeySource -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($PublicKeyContent)) {
        throw "The USB key source file is empty: $AuthKeySource"
    }

    $PublicKeyPattern = '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+.*)?$'
    if ($PublicKeyContent -notmatch $PublicKeyPattern) {
        throw "The key material in $AuthKeySource is invalid or not a supported SSH public key."
    }

    $TempKeyFile = Join-Path $SshKeyDir "temp_key.pub"
    Set-Content -LiteralPath $TempKeyFile -Value $PublicKeyContent -Encoding ASCII

    $SshKeyGen = Join-Path $env:SystemRoot "System32\OpenSSH\ssh-keygen.exe"
    if (-not (Test-Path $SshKeyGen)) {
        $SshKeyGen = (Get-Command ssh-keygen -ErrorAction Stop).Source
    }

    $FingerprintOutput = & $SshKeyGen -lf $TempKeyFile 2>&1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($FingerprintOutput | Out-String).Trim())) {
        throw "Fingerprint generation failed for the SSH public key."
    }
    Set-Content -LiteralPath $FingerprintFile -Value ($FingerprintOutput | Out-String) -Encoding UTF8

    $User = $Identity.Name
    $UserSID = $Identity.User.Value

    $IsAdminAccount = $false
    foreach ($Group in $Identity.Groups) {
        try {
            $ResolvedSid = $Group.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($ResolvedSid -eq 'S-1-5-32-544') {
                $IsAdminAccount = $true
                break
            }
        }
        catch {
        }
    }

    if ($IsAdminAccount) {
        $SshDir = Join-Path $env:ProgramData "ssh"
        $AuthFile = Join-Path $SshDir "administrators_authorized_keys"
    }
    else {
        $SshDir = Join-Path $env:USERPROFILE ".ssh"
        $AuthFile = Join-Path $SshDir "authorized_keys"
    }

    if (-not (Test-Path $SshDir)) {
        New-Item -ItemType Directory -Path $SshDir -Force | Out-Null
    }

    $ExistingKeys = @()
    if (Test-Path $AuthFile) {
        $ExistingKeys = @(Get-Content -LiteralPath $AuthFile)
    }

    if ($ExistingKeys -notcontains $PublicKeyContent) {
        Add-Content -LiteralPath $AuthFile -Value $PublicKeyContent -Encoding ASCII
    }

    if ($IsAdminAccount) {
        $AclGrant = 'Administrators:(R)'
        $SystemGrant = 'SYSTEM:(R)'
    }
    else {
        $AclGrant = "${User}:(R)"
        $SystemGrant = 'SYSTEM:(R)'
    }

    & icacls $AuthFile /inheritance:r /grant:r $AclGrant $SystemGrant | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to secure the SSH authorized_keys permissions via icacls."
    }

    $DefaultPrivateKey = Join-Path $KeysDir "id_ed25519"
    if (Test-Path $DefaultPrivateKey) {
        & icacls $DefaultPrivateKey /inheritance:r /grant:r $AclGrant $SystemGrant | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-AuditEntry "[WARN] [SSH-Keys] Unable to secure the default private key ACL for $DefaultPrivateKey"
        }
    }

    $ServiceStatus = (Get-Service -Name sshd -ErrorAction Stop).Status
    $DiagContent = @"
================================================================================
3A1shOnWin - SSH CONFIGURATION DIAGNOSTICS
Timestamp: $(Get-IsoTimestamp) (UTC)
================================================================================
- Target User     : $User
- User SID        : $UserSID
- Is Administrator: $IsAdminAccount
- Auth File Path  : $AuthFile
- Service Status  : $ServiceStatus
- Firewall Rule   : $RuleName (Private/Domain)
- USB Project Data: $DataDir
================================================================================
"@

    Set-Content -LiteralPath $DiagnosticsFile -Value $DiagContent -Encoding UTF8
    Write-AuditEntry "[AUDIT] [SSH-Orchestration] Success. SSH is configured and project artifacts remain in $DataDir."
    exit 0
}
catch {
    $ErrorMessage = $_.Exception.Message -replace '[\r\n]', ' '
    try {
        Write-AuditEntry "[ERROR] [SSH-Orchestration] Failed: $ErrorMessage"
    }
    catch {
    }
    exit 1
}
finally {
    if ($TempKeyFile -and (Test-Path $TempKeyFile)) {
        Remove-Item -LiteralPath $TempKeyFile -Force -ErrorAction SilentlyContinue
    }
}

