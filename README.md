<p align="center">
    <img src="images/logo.png" alt="CredsMRU logo: hooded figure breaking a blue data cube with a pickaxe" style="width: 400px;"/>
</p>

## Invoke-CredsMRU

**Invoke-CredsMRU** is a PowerShell script to query MRU-style registry keys on a remote Windows host using either **RPC (WMI/CIM)** or **WinRM (PowerShell remoting)**.

This is the first, raw-output version: it focuses on reliably collecting the data. Parsing, regex matching and pretty-printing will be added in later phases.

The script targets **per-user MRU** for:

- The **current authenticated user** (for WinRM, via `HKCU`).
- All loaded **user SIDs** under `HKEY_USERS` (e.g. `S-1-5-21-...`) using a fixed MRU sub-key:
  - `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

### Usage

1. **Get credentials**

```powershell
# Optional – only if you want to use alternate creds
$cred = Get-Credential
```

2. **Query via RPC (WMI/CIM + StdRegProv)**

```powershell
.\Invoke-CredsMRU.ps1 `
    -ComputerName TARGETHOST `
    -Method RPC  `
    -ManageRemoteRegistryService
```

3. **Query via WinRM (PowerShell remoting)**

```powershell
.\Invoke-CredsMRU.ps1 `
    -ComputerName TARGETHOST `
    -Method WinRM
```

### Parameters (high level)

- **ComputerName**: remote host to query.
- **Method**: `RPC` or `WinRM`.
- **Credential**: *optional* PSCredential object (use `Get-Credential`). If omitted, the current logon context is used.
- **ManageRemoteRegistryService**: when using `RPC`, optionally start/stop the `RemoteRegistry` service.
- **ExtractCredentials**: when enabled, searches MRU Data fields for credential patterns and extracts username/password pairs from common command-line tools.

### Examples with Credential Extraction

```powershell
# Extract credentials from MRU data via RPC
.\Invoke-CredsMRU.ps1 `
    -ComputerName TARGETHOST `
    -Method RPC `
    -ExtractCredentials `
    -ManageRemoteRegistryService

# Extract credentials from MRU data via WinRM
.\Invoke-CredsMRU.ps1 `
    -ComputerName TARGETHOST `
    -Method WinRM `
    -ExtractCredentials
```

### Notes

- You must be **local administrator** on the remote host.
- For **RPC**:
  - Uses **CIM over DCOM/RPC** and the `StdRegProv` provider.
  - Can start/stop the `RemoteRegistry` service for you.
- For **WinRM**:
  - Uses standard **PowerShell remoting** and reads the registry locally on the remote host.
- **ExtractCredentials**:
  - Searches MRU Data fields for credential patterns using regex.
  - Extracts username/password pairs from common command-line tools (net, wmic, psexec, sqlcmd, etc.).
  - Returns credential objects with Username, Password, and RawData fields.

## Credits

Credential extraction regex patterns are based on **Invoke-FindEventCreds** by [The-Viper-One](https://github.com/The-Viper-One).

- **Invoke-FindEventCreds**: https://github.com/The-Viper-One/Invoke-FindEventCreds


