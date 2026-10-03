#requires -Version 5.1

<#
.SYNOPSIS
Checks Active Directory user accounts for potential Kerberoasting exposure.
.DESCRIPTION
Read-only LDAP assessment of ordinary user accounts with service principal
names (SPNs). Reports encryption configuration, password age, nonexpiring
passwords, and adminCount markers. Uses built-in Windows .NET LDAP APIs;
no RSAT, external modules, downloads, or administrator privileges required.
Uses the current identity unless -Credential is supplied. Directory read
permissions and connectivity to a domain controller are still required.

This checks exposure and review priorities, not successful exploitation.
It does not harvest service tickets, export hashes, crack passwords, or change AD.
Unset encryption attributes depend on KDC policy and updates; they are not
reported as proof that RC4 tickets can be obtained. AES does not eliminate
offline guessing risk for weak service-account passwords.
.PARAMETER Server
Domain controller or domain DNS name. Defaults to the current AD domain.
.PARAMETER Argument
Optional positional server name, or the literal --help token.
.PARAMETER SearchBase
Optional distinguished name to limit the search to an OU or subtree.
.PARAMETER AccountName
Optional exact sAMAccountName to check. Wildcard characters are treated literally.
.PARAMETER Credential
Optional PSCredential for the directory query. Use Get-Credential.
.PARAMETER IncludeDisabled
Include disabled accounts as informational findings. Excluded by default.
.PARAMETER PasswordAgeDays
Password-age review threshold; default 180 days. Not a password-strength test.
.PARAMETER TimeoutSeconds
LDAP search timeout; default 30 seconds. Domain discovery/binding also follows
Windows networking timeouts, so this is not a whole-run deadline.
.PARAMETER OutputJson
JSON report destination (alias -oJ). Must not exist.
.PARAMETER OutputCsv
CSV destination (alias -oC). Must not exist.
.PARAMETER OutputText
Plain-text destination (alias -oN). Must not exist.
.PARAMETER OutputBase
Generate .json, .csv, and .txt reports from a basename (alias -oA).
.PARAMETER Help
Show the usage guide and exit without querying AD or writing reports.
Aliases: -h and --help.
.EXAMPLE
.\kerbtest.ps1
.EXAMPLE
.\kerbtest.ps1 -Server dc01.contoso.com -SearchBase 'OU=Services,DC=contoso,DC=com' -oA kerb-audit
.EXAMPLE
.\kerbtest.ps1 -AccountName svc_sql -Credential (Get-Credential) -oJ svc-sql.json
.NOTES
Only ordinary user accounts are assessed; computers, managed service accounts,
and krbtgt are excluded. adminCount=1 is a historical protection marker, not
proof of current privileged-group membership. Help flags do not contact AD.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0)][string] $Argument,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?$')][string] $Server,
    [ValidateScript({ $_ -match '=' -and $_ -notmatch '(?i)^[a-z]+://' -and $_ -notmatch '[\r\n\x00]' })][string] $SearchBase,
    [ValidateNotNullOrEmpty()][string] $AccountName,
    [PSCredential] $Credential,
    [switch] $IncludeDisabled,
    [ValidateRange(1, 36500)][int] $PasswordAgeDays = 180,
    [ValidateRange(1, 3600)][int] $TimeoutSeconds = 30,
    [Alias('oJ')][ValidateNotNullOrEmpty()][string] $OutputJson,
    [Alias('oC')][ValidateNotNullOrEmpty()][string] $OutputCsv,
    [Alias('oN')][ValidateNotNullOrEmpty()][string] $OutputText,
    [Alias('oA')][ValidateNotNullOrEmpty()][string] $OutputBase,
    [Alias('h')][switch] $Help
)

if ($Help -or $Argument -eq '--help') {
    @'
KerbTest - read-only Kerberoasting exposure check

Usage: .\kerbtest.ps1 [options]

  -Server <name[:port]>       Domain/controller name or IPv4; current domain by default
  -SearchBase <DN>            Limit search to an OU/subtree (distinguished name)
  -AccountName <name>         Exact sAMAccountName; wildcard characters are literal
  -Credential <PSCredential>  Alternate domain identity; use (Get-Credential)
  -IncludeDisabled           Include disabled accounts as informational findings
  -PasswordAgeDays <days>     Password-age review threshold (default: 180; 1-36500)
  -TimeoutSeconds <seconds>   LDAP search timeout (default: 30; 1-3600)
  -oJ, -OutputJson <file>     JSON report
  -oC, -OutputCsv <file>      CSV findings
  -oN, -OutputText <file>     Plain-text report
  -oA, -OutputBase <base>     Generate <base>.json, <base>.csv, and <base>.txt
  -h, --help, -Help          Show this guide and exit

Examples:
  .\kerbtest.ps1
  .\kerbtest.ps1 -Server dc01.contoso.com -oA kerb-audit
  .\kerbtest.ps1 -SearchBase 'OU=Services,DC=contoso,DC=com' -oJ audit.json
  .\kerbtest.ps1 -AccountName svc_sql -Credential (Get-Credential)

Requirements: Windows PowerShell 5.1 or PowerShell 7 on Windows, domain
connectivity, and directory read permissions. No RSAT, external modules,
downloads, or administrator privileges required. Uses built-in .NET LDAP APIs.

Checks ordinary SPN-bearing user accounts for encryption configuration,
password-age/nonexpiration indicators, and adminCount markers. Computers,
managed service accounts, and krbtgt are excluded. The report indicates
exposure for review; it does not prove weak passwords or successful exploitation.
No ticket harvesting, hash extraction, password guessing, or AD changes.

Output files must not exist; parent directories must exist. Choose -oA or
individual output paths. LDAP timeout is not a full-run discovery/bind deadline.
For detailed parameter help: Get-Help .\kerbtest.ps1 -Full
'@
    return
}
if ($Argument) {
    if ($Server) { throw "Unexpected positional argument '$Argument'. Use -h or --help for usage." }
    if ($Argument -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?$') { throw "Invalid server '$Argument'. Use -h or --help for usage." }
    $Server = $Argument
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertTo-KerbLdapValue([string] $Value) {
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-KerbProperty($User, [string] $Name) {
    $property = $User.PSObject.Properties[$Name]
    if ($null -ne $property) { $property.Value }
}

function New-KerbDirectoryEntry([string] $Path, [PSCredential] $BindCredential) {
    $authentication = [DirectoryServices.AuthenticationTypes]::Secure -bor
        [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
    if ($BindCredential) {
        $networkCredential = $BindCredential.GetNetworkCredential()
        [DirectoryServices.DirectoryEntry]::new($Path, $BindCredential.UserName, $networkCredential.Password, $authentication)
    } else {
        # Use the constructor so PowerShell's ADSI adapter does not trigger
        # a premature bind while setting AuthenticationType.
        [DirectoryServices.DirectoryEntry]::new($Path, $null, $null, $authentication)
    }
}

function New-KerbDirectorySearcher($Root) {
    [DirectoryServices.DirectorySearcher]::new($Root)
}

function Get-KerbLdapFirstValue($Properties, [string] $Name) {
    if ($Properties.Contains($Name) -and $Properties[$Name].Count -gt 0) { $Properties[$Name][0] }
}

function ConvertFrom-KerbLdapResult($Result) {
    $properties = $Result.Properties
    $lastSet = $null
    $fileTime = Get-KerbLdapFirstValue $properties 'pwdlastset'
    # DirectorySearcher returns Integer8 attributes as Int64. Zero means no
    # usable last-set date, rather than a date in 1601.
    if ($null -ne $fileTime -and [long]$fileTime -gt 0) { $lastSet = [DateTime]::FromFileTimeUtc([long]$fileTime) }
    $spns = @()
    if ($properties.Contains('serviceprincipalname')) { $spns = @($properties['serviceprincipalname']) }
    [pscustomobject]@{
        SamAccountName = Get-KerbLdapFirstValue $properties 'samaccountname'
        DistinguishedName = Get-KerbLdapFirstValue $properties 'distinguishedname'
        ServicePrincipalNames = $spns
        'msDS-SupportedEncryptionTypes' = Get-KerbLdapFirstValue $properties 'msds-supportedencryptiontypes'
        PasswordLastSet = $lastSet
        userAccountControl = Get-KerbLdapFirstValue $properties 'useraccountcontrol'
        adminCount = Get-KerbLdapFirstValue $properties 'admincount'
    }
}

function Get-KerbLdapUsers([string] $LDAPFilter, [string] $Server, [string] $SearchBase, [PSCredential] $Credential, [int] $TimeoutSeconds) {
    $rootDse = $null; $root = $null; $searcher = $null; $matches = $null
    try {
        $prefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
        $baseDn = $SearchBase
        if (-not $baseDn) {
            $rootDse = New-KerbDirectoryEntry ($prefix + 'RootDSE') $Credential
            $baseDn = [string]$rootDse.psbase.Properties['defaultNamingContext'].Value
            if ([string]::IsNullOrWhiteSpace($baseDn)) { throw 'No default domain naming context found. Specify -Server and optionally -SearchBase.' }
        }
        # A slash inside a DN must be escaped for the ADSI LDAP path syntax.
        $escapedDn = [regex]::Replace($baseDn, '(?<!\\)/', '\/')
        $root = New-KerbDirectoryEntry ($prefix + $escapedDn) $Credential
        $searcher = New-KerbDirectorySearcher $root
        $searcher.Filter = $LDAPFilter
        $searcher.SearchScope = [DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 500
        $searcher.SizeLimit = 0
        # Keep this assessment in the selected domain/subtree; do not chase
        # cross-domain referrals with the user's credentials.
        $searcher.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        foreach ($attribute in @('samAccountName', 'distinguishedName', 'servicePrincipalName',
            'msDS-SupportedEncryptionTypes', 'pwdLastSet', 'userAccountControl', 'adminCount')) {
            [void]$searcher.PropertiesToLoad.Add($attribute)
        }
        $matches = $searcher.FindAll()
        foreach ($result in $matches) { ConvertFrom-KerbLdapResult $result }
    } finally {
        if ($null -ne $matches) { $matches.Dispose() }
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $root) { $root.psbase.Dispose() }
        if ($null -ne $rootDse) { $rootDse.psbase.Dispose() }
    }
}

function ConvertTo-KerbFinding($User, [int] $AgeThreshold, [DateTime] $NowUtc) {
    $uacValue = Get-KerbProperty $User 'userAccountControl'
    $uac = if ($null -eq $uacValue) { 0L } else { [long]$uacValue }
    $enabled = ($uac -band 2) -eq 0
    $neverExpires = ($uac -band 65536) -ne 0
    $desOnly = ($uac -band 2097152) -ne 0
    $adminValue = Get-KerbProperty $User 'adminCount'
    $adminMarked = $null -ne $adminValue -and [int]$adminValue -eq 1
    $encValue = Get-KerbProperty $User 'msDS-SupportedEncryptionTypes'
    $enc = if ($null -eq $encValue) { $null } else { [long]$encValue }
    $defaultEncryption = $null -eq $enc -or $enc -eq 0
    $rc4 = if ($defaultEncryption) { $null } else { ($enc -band 4) -ne 0 }
    $aes = if ($defaultEncryption) { $null } else { ($enc -band 24) -ne 0 }
    $des = $desOnly -or (-not $defaultEncryption -and ($enc -band 3) -ne 0)
    $labels = [Collections.Generic.List[string]]::new()
    if ($defaultEncryption) { $labels.Add('Unspecified (KDC defaults)') }
    else {
        foreach ($flag in @(
            @{ Bit = 1; Name = 'DES-CRC' }, @{ Bit = 2; Name = 'DES-MD5' },
            @{ Bit = 4; Name = 'RC4' }, @{ Bit = 8; Name = 'AES128' },
            @{ Bit = 16; Name = 'AES256' }, @{ Bit = 32; Name = 'AES-session-key flag' }
        )) { if (($enc -band $flag.Bit) -ne 0) { $labels.Add($flag.Name) } }
        if (($enc -band 31) -eq 0) { $labels.Add('No legacy ticket-encryption bits set; review policy') }
    }
    $lastSetValue = Get-KerbProperty $User 'PasswordLastSet'
    $lastSetUtc = $null
    $age = $null
    if ($null -ne $lastSetValue) {
        $lastSetUtc = ([DateTime]$lastSetValue).ToUniversalTime()
        $age = [int][Math]::Floor(($NowUtc - $lastSetUtc).TotalDays)
    }
    $stale = $null -ne $age -and $age -ge $AgeThreshold
    $reasons = [Collections.Generic.List[string]]::new()
    $actions = [Collections.Generic.List[string]]::new()
    $reasons.Add('SPNs are registered on an ordinary user account; review service-password strength.')
    $actions.Add('Use a gMSA where supported, or a long randomly generated service password with managed rotation.')
    if ($defaultEncryption) {
        $reasons.Add('Encryption types are unset/zero; effective ticket encryption depends on KDC policy, available keys, and updates.')
        $actions.Add('Review KDC policy and event 4769 to establish actual ticket encryption; do not infer RC4 from an unset attribute.')
    } elseif ($rc4) {
        $reasons.Add('RC4 is explicitly advertised by the account; actual issuance still depends on KDC policy.')
        $actions.Add('Review service compatibility and remove RC4 configuration where supported; verify AES keys and actual ticket encryption.')
    }
    if ($des) { $reasons.Add('Legacy DES configuration is present.'); $actions.Add('Review and retire DES configuration after compatibility checks.') }
    if ($neverExpires) { $reasons.Add('Password is configured never to expire.'); $actions.Add('Review password rotation and credential ownership.') }
    if ($stale) { $reasons.Add("Password age meets or exceeds $AgeThreshold days; age alone does not measure password strength.") }
    if ($null -eq $lastSetUtc) { $reasons.Add('Password last-set date is unavailable; inspect password state manually.') }
    if ($null -ne $age -and $age -lt 0) { $reasons.Add('Password last-set date is in the future; review clock consistency.') }
    if ($adminMarked) {
        $reasons.Add('adminCount=1; this marker can persist after privileged group removal.')
        $actions.Add('Verify current group membership and reduce unnecessary service-account privileges.')
    }
    $priority = 'Medium'
    if ($adminMarked -or $des -or ($rc4 -and ($stale -or $neverExpires))) { $priority = 'High' }
    if (-not $enabled) { $priority = 'Informational'; $reasons.Add('Account is disabled; this is not treated as an active exposure finding.') }
    $spns = @((Get-KerbProperty $User 'ServicePrincipalNames') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
    [pscustomobject][ordered]@{
        accountName = [string](Get-KerbProperty $User 'SamAccountName')
        distinguishedName = [string](Get-KerbProperty $User 'DistinguishedName')
        enabled = $enabled; reviewPriority = $priority
        servicePrincipalNames = $spns; spnCount = $spns.Count
        supportedEncryptionTypes = $enc; encryptionConfiguration = $labels -join ', '
        rc4Configured = $rc4; aesConfigured = $aes; desConfigured = $des
        passwordLastSetUtc = if ($null -eq $lastSetUtc) { $null } else { $lastSetUtc.ToString('o') }
        passwordAgeDays = $age; passwordNeverExpires = $neverExpires
        adminCountMarked = $adminMarked
        reasons = $reasons.ToArray(); recommendations = $actions.ToArray()
    }
}

# Validate destinations before querying the directory; files are never replaced.
if ($OutputBase) {
    if ($OutputJson -or $OutputCsv -or $OutputText) { throw 'Choose -OutputBase/-oA or individual output paths.' }
    $OutputJson = $OutputBase + '.json'; $OutputCsv = $OutputBase + '.csv'; $OutputText = $OutputBase + '.txt'
}
$outputs = @{}
$paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($item in @(@{ Kind = 'json'; Path = $OutputJson }, @{ Kind = 'csv'; Path = $OutputCsv }, @{ Kind = 'text'; Path = $OutputText })) {
    if (-not $item.Path) { continue }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($item.Path)
    if (-not $paths.Add($full)) { throw 'Output paths must be different.' }
    if (Test-Path -LiteralPath $full) { throw "Output already exists: $full" }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container)) { throw "Output directory does not exist: $full" }
    $outputs[$item.Kind] = $full
}
if ($env:OS -ne 'Windows_NT') { throw 'kerbtest.ps1 requires Windows. It uses built-in .NET LDAP APIs.' }
Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

$filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))'
if (-not $IncludeDisabled) { $filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' }
if ($AccountName) { $filter += '(sAMAccountName=' + (ConvertTo-KerbLdapValue $AccountName) + ')' }
$filter += ')'
$query = @{
    LDAPFilter = $filter
    TimeoutSeconds = $TimeoutSeconds
}
if ($Server) { $query.Server = $Server }
if ($SearchBase) { $query.SearchBase = $SearchBase }
if ($Credential) { $query.Credential = $Credential }
$started = [DateTime]::UtcNow
Write-Host 'Reading SPN-bearing user accounts from Active Directory...'
try { $users = @(Get-KerbLdapUsers @query) } catch {
    throw "Active Directory LDAP query failed: $($_.Exception.GetBaseException().Message) Verify domain connectivity, -Server/-SearchBase, credentials, and directory read permissions."
}
$findings = [Collections.Generic.List[object]]::new()
try {
    for ($index = 0; $index -lt $users.Count; $index++) {
        Write-Progress -Id 2 -Activity 'Kerberoasting exposure check' -Status "$($index + 1) / $($users.Count) accounts" -PercentComplete ([int](100 * ($index + 1) / $users.Count))
        $finding = ConvertTo-KerbFinding $users[$index] $PasswordAgeDays $started
        # Defense in depth if a directory provider returns accounts outside the
        # disabled/SPN criteria. The LDAP filter handles account type and krbtgt.
        if ($finding.spnCount -gt 0 -and ($IncludeDisabled -or $finding.enabled)) { $findings.Add($finding) }
    }
} finally { Write-Progress -Id 2 -Activity 'Kerberoasting exposure check' -Completed }
$report = [pscustomobject][ordered]@{
    scanner = 'KerbTest'; schemaVersion = 1; assessment = 'Directory exposure review'
    startedUtc = $started.ToString('o'); finishedUtc = [DateTime]::UtcNow.ToString('o')
    server = $Server; searchBase = $SearchBase; accountNameFilter = $AccountName
    includeDisabled = $IncludeDisabled.IsPresent; passwordAgeThresholdDays = $PasswordAgeDays
    ldapTimeoutSeconds = $TimeoutSeconds
    accountCount = $findings.Count
    limitations = @(
        'No ticket harvesting, hash extraction, password guessing, or directory changes. Normal LDAP authentication uses the current or supplied identity.'
        'SPNs indicate exposure; this report does not prove successful Kerberoasting or password weakness.'
        'Encryption attributes do not establish issued ticket types or available account keys. Verify KDC policy and event 4769.'
        'AES does not eliminate offline guessing of weak passwords. adminCount does not establish current privileged membership.'
        'Computers, managed service accounts, and krbtgt are excluded. Password age is a review indicator only.'
    )
    findings = $findings.ToArray()
}
$csvRows = @($findings | Select-Object accountName, distinguishedName, enabled, reviewPriority, spnCount,
    @{ Name = 'servicePrincipalNames'; Expression = { $_.servicePrincipalNames -join '; ' } },
    supportedEncryptionTypes, encryptionConfiguration, rc4Configured, aesConfigured, desConfigured,
    passwordLastSetUtc, passwordAgeDays, passwordNeverExpires, adminCountMarked,
    @{ Name = 'reasons'; Expression = { $_.reasons -join ' | ' } },
    @{ Name = 'recommendations'; Expression = { $_.recommendations -join ' | ' } })
$lines = [Collections.Generic.List[string]]::new()
$lines.Add("KerbTest - directory exposure review - $($report.startedUtc)")
$lines.Add("Accounts assessed: $($report.accountCount)")
foreach ($finding in $findings) {
    $lines.Add('')
    $lines.Add("Account: $($finding.accountName) [$($finding.reviewPriority)]")
    $lines.Add("DN: $($finding.distinguishedName)")
    $lines.Add("SPNs: $($finding.servicePrincipalNames -join '; ')")
    $lines.Add("Encryption configuration: $($finding.encryptionConfiguration)")
    $lines.Add("Password age (days): $($finding.passwordAgeDays)")
    foreach ($reason in $finding.reasons) { $lines.Add("Finding: $reason") }
    foreach ($action in $finding.recommendations) { $lines.Add("Review: $action") }
}
$lines.Add(''); $lines.Add('Limitations:')
foreach ($limitation in $report.limitations) { $lines.Add($limitation) }
$utf8 = [Text.UTF8Encoding]::new($false)
foreach ($kind in $outputs.Keys) {
    $content = switch ($kind) {
        'json' { $report | ConvertTo-Json -Depth 8 }
        'text' { $lines -join [Environment]::NewLine }
        'csv' {
            if ($csvRows.Count -gt 0) { $csvRows | ConvertTo-Csv -NoTypeInformation }
            else { '"accountName","distinguishedName","enabled","reviewPriority","spnCount","servicePrincipalNames","supportedEncryptionTypes","encryptionConfiguration","rc4Configured","aesConfigured","desConfigured","passwordLastSetUtc","passwordAgeDays","passwordNeverExpires","adminCountMarked","reasons","recommendations"' }
        }
    }
    $bytes = $utf8.GetBytes((@($content) -join [Environment]::NewLine) + [Environment]::NewLine)
    $stream = [IO.File]::Open($outputs[$kind], [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    Write-Host "Saved $($outputs[$kind])"
}
if ($findings.Count -gt 0) {
    $findings | Format-Table accountName, reviewPriority, spnCount, encryptionConfiguration, passwordAgeDays, passwordNeverExpires, adminCountMarked -AutoSize | Out-Host
} else { Write-Host 'No matching SPN-bearing user accounts found in the requested scope.' }
Write-Host "Assessed $($findings.Count) accounts. Priorities are review indicators; ticket encryption and password strength are unverified."
$report
