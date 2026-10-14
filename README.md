# USB Security Toolkit (USB-STk)

This project is a Windows automation toolkit intended for authorized lab testing, internal troubleshooting, and controlled IT administration scenarios. It is designed to run from a writable USB drive and stores all generated project artifacts beneath that USB project root. The launcher and its PowerShell worker processes are intended to run silently in the background without a visible console window.

> Use it only on systems you own or are explicitly authorized to evaluate !

## Files in this project

- `3A1shOnWin.bat` - master launcher that verifies administrator rights, requests UAC elevation when necessary, validates the removable USB root, initializes the full project tree, and runs the PowerShell modules in sequence.
- `info-3A1shOnWin.ps1` - gathers host, user, operating system, and network details and writes the system report and JSON payload to the USB project tree.
- `ssh-3A1shOnWin.ps1` - verifies or installs OpenSSH, starts the `sshd` service, creates the inbound firewall rule, and authorizes the project public key.
- `README.md` - project documentation.
- `keys/authorized_keys` - USB-local public key source file.
- `data/` - generated logs, reports, and SSH diagnostics stored under the USB project root.

## Project structure before run

```text
USB-STk/
├── 3A1shOnWin.bat
├── info-3A1shOnWin.ps1
├── ssh-3A1shOnWin.ps1
└──  README.md
```

## Project structure after run

```text
USB-STk/
├── 3A1shOnWin.bat
├── info-3A1shOnWin.ps1
├── ssh-3A1shOnWin.ps1
├── README.md
├── keys/
│   └── authorized_keys
└── data/
    ├── .lock
    ├── log/
    │   ├── logs/
    │   │   └── logs
    │   └── audit/
    │       └── audit
    ├── reports/
    │   └── system-info.txt
    └── vuln/
        ├── info/
        │   └── host-enumeration.json
        └── ssh-key/
            ├── ssh-diagnostics.txt
            └── key-fingerprints.txt
```

## Requirements

- Windows 10 or Windows 11
- Administrator privileges on the target machine
- A writable removable USB drive that contains the project files
- A valid SSH public key in `keys/authorized_keys` or a generated fallback key
- Explicit authorization for any target system under assessment

## How it works

1. The launcher resolves its own project directory from the USB drive containing `3A1shOnWin.bat`.
2. It checks whether the current user has administrator access.
3. If the user is not already elevated, it requests UAC elevation and exits if the request is denied or cancelled.
4. It validates that the project root is on a removable drive, then initializes the project tree beneath the USB `data` directory.
5. It creates a `.lock` file while the run is active and removes it on exit to prevent concurrent launches.
6. It creates a hidden `data` directory and explicitly verifies the hidden attribute was applied.
7. It runs `info-3A1shOnWin.ps1` first and then runs `ssh-3A1shOnWin.ps1` regardless of the reconnaissance result so the host context and SSH setup are always evaluated in the same run.
8. It stores all generated outputs under the USB root and never writes project output to a user-profile or temporary directory.
9. It records launcher and SSH events under `data/log/logs/logs` and `data/log/audit/audit`.

## Usage

1. Place or generate an SSH public key in `keys/authorized_keys`.
2. Insert the USB drive and run `3A1shOnWin.bat` on a Windows 10 or Windows 11 system.
3. If the launcher is not already elevated, it will request UAC elevation before continuing.
4. The launcher and PowerShell modules are intended to execute silently in the background while they write logs and reports to the USB project tree.
5. Review the generated output in the USB data folders.
6. Use the matching private key to connect from a trusted workstation:

```powershell
ssh -i <path-to-private-key> <username>@<target-ip>
```

If `keys/authorized_keys` is missing, the SSH script will generate a default ed25519 key pair in the USB-local `keys` directory.

## Generated artifacts

- `data/reports/system-info.txt` - human-readable host summary created by the reconnaissance script
- `data/vuln/info/host-enumeration.json` - machine-readable host enumeration payload
- `data/vuln/ssh-key/ssh-diagnostics.txt` - SSH diagnostics captured after configuration
- `data/vuln/ssh-key/key-fingerprints.txt` - fingerprint output for the authorized key
- `data/log/logs/logs` - execution log written by the launcher
- `data/log/audit/audit` - audit trail for both execution and SSH configuration events

## Security implications

This project intentionally changes Windows system configuration to enable OpenSSH and firewall rules. Those changes are limited to the necessary SSH service, firewall access, and SSH authorization paths. The project data itself remains under the USB project tree and is not stored in `C:\Users`, `%TEMP%`, or other local user directories.

## Cleanup

When testing is complete, typical cleanup steps are:

```powershell
Stop-Service sshd
Set-Service sshd -StartupType Manual
Remove-NetFirewallRule -Name "3A1shOnWin-SSH-LocalAccess"
```

You may also remove the authorized key from the system SSH configuration file and uninstall the OpenSSH Server capability if it is no longer needed.

## Validation and test status

The current project files were checked with PowerShell parsing on the available Linux host environment:

- `info-3A1shOnWin.ps1` -> `PARSE_OK`
- `ssh-3A1shOnWin.ps1` -> `PARSE_OK`

The Windows batch launcher itself is designed for a real Windows 10/11 host and must be tested there to confirm the UAC flow, removable-drive enforcement, lock cleanup, exit codes, and OpenSSH behavior. These Windows execution steps remain unperformed in this environment and are therefore not claimed as passed.

## Remaining limitations and risks

- Real Windows execution has not been performed in this Linux workspace, so runtime behavior on a Windows host is still unverified.
- The launcher enforces a removable drive root to keep all artifacts on the USB device; copying the project to a fixed disk will stop execution.
- `icacls`, firewall changes, and OpenSSH configuration are operating-system actions and should be reviewed in a controlled lab environment.
- The hidden `data` directory is not encryption; it only hides the folder from normal browsing.
- If the USB drive is removed or becomes unwritable, the launcher exits safely and reports the failure.

## Safety and legal use

This toolkit should only be used in environments where you have explicit permission to test or administer the system. Do not deploy it on machines you do not own or do not have authorization to manage.

## Disclaimer

This project is provided for educational, documentation, and authorized troubleshooting purposes. The maintainers are not responsible for misuse or unauthorized deployment.

