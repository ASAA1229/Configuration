#requires -Version 7.0
# Creates an employee in the asaa realm through the Keycloak admin REST API.
#
# Temporary password: by default a random password that meets the realm policy (at least 12 characters with upper,
# lower, digit and symbol) is generated and shown ONCE on screen for the owner to hand over. It is never written to a
# file or log. Use -GenerateTempPassword:$false to type one instead.
#
# Secrets: the admin password, the one-time code and any typed temporary password are entered at prompts. None is a
# command-line argument. The user must change the password and enrol an authenticator app (TOTP) at first login.
#
# Inputs are validated strictly: no quotes, backslashes, control characters or shell metacharacters.
# Default group is 'employees'. Any other group must be named with -Group, and privileged groups also require
# typing CONFIRM <group>.
#
# Usage (from identity\scripts):
#   pwsh -File .\create-user.ps1 -Username jdoe -Email jdoe@example.invalid -FirstName Jane -LastName Doe
#   pwsh -File .\create-user.ps1 -Username ajones -Email ajones@example.invalid -FirstName Ann -LastName Jones -Group hr -GenerateTempPassword:$false

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Email,
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [string]$Group = 'employees',
    [bool]$GenerateTempPassword = $true
)

. (Join-Path $PSScriptRoot 'common.ps1')

$privileged = @('asaa-administrators', 'jarvis-owners', 'portfolio-admins', 'templates-owners', 'hr', 'payroll', 'finance', 'managers', 'auditors')
$allowedGroups = @('employees') + $privileged

function New-RealmCompliantPassword {
    # Random password: 20 characters, at least one of each class. Uses a cryptographic generator.
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digit = '23456789'
    $symbol = '!#%+-=?@^_'
    $all = $upper + $lower + $digit + $symbol
    $chars = [System.Collections.Generic.List[char]]::new()
    $chars.Add($upper[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($upper.Length)])
    $chars.Add($lower[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($lower.Length)])
    $chars.Add($digit[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($digit.Length)])
    $chars.Add($symbol[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($symbol.Length)])
    while ($chars.Count -lt 20) { $chars.Add($all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)]) }
    # Fisher-Yates shuffle with the same generator.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

Assert-SafeText -Value $Username -Field 'Username' -MaxLength 64
if ($Username -notmatch '^[a-z0-9._-]{3,64}$') { throw 'Username must be 3 to 64 characters: lowercase letters, digits, dot, underscore or hyphen.' }
Assert-SafeEmail -Value $Email
Assert-SafeText -Value $FirstName -Field 'FirstName' -MaxLength 64
Assert-SafeText -Value $LastName -Field 'LastName' -MaxLength 64
if ($Group -notin $allowedGroups) { throw "Group must be one of: $($allowedGroups -join ', ')." }
if ($Group -in $privileged) {
    $typed = Read-Host "Group '$Group' is privileged. Type CONFIRM $Group to continue"
    if ($typed -cne "CONFIRM $Group") { throw 'Confirmation did not match. Nothing was created.' }
}

$state = Get-StateNoSecrets
if ($state -in @('missing-file', 'placeholder', 'missing-key')) {
    throw 'identity/.env does not hold a valid admin setup. Run harden-master.ps1 first.'
}

$admin = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $admin
$admin = $null

if ($GenerateTempPassword) {
    $tempPlain = New-RealmCompliantPassword
} else {
    $tempSecure = Read-Host "Temporary password for $Username (must meet the realm policy: 12+ characters, upper, lower, digit, symbol)" -AsSecureString
    $tempPlain = ConvertTo-PlainText -Secure $tempSecure
    $tempSecure = $null
    if ($tempPlain.Length -lt 12) { throw 'Temporary password must be at least 12 characters. Nothing was created.' }
}

$created = $null
try {
    $body = @{
        username = $Username; email = $Email; firstName = $FirstName; lastName = $LastName
        enabled = $true; emailVerified = $false; requiredActions = @('UPDATE_PASSWORD', 'CONFIGURE_TOTP')
    }
    Invoke-KcApi -Token $token -Method POST -Path '/admin/realms/asaa/users' -Body $body | Out-Null
    $created = (Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/asaa/users?username=$Username&exact=true")[0].id
    Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/asaa/users/$created/reset-password" -Body @{ type = 'password'; value = $tempPlain; temporary = $true } | Out-Null
    $groupRep = (Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/asaa/groups?search=$Group&exact=true")[0]
    if (-not $groupRep) { throw "Group $Group was not found in realm asaa." }
    Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/asaa/users/$created/groups/$($groupRep.id)" | Out-Null
    Write-Host "OK   created '$Username' in group '$Group'. First login: change password, then enrol an authenticator app."
    if ($GenerateTempPassword) {
        Write-Host 'Temporary password (shown ONCE, hand it over now; it is not stored anywhere):'
        Write-Host $tempPlain
    }
} catch {
    if ($created) {
        try { Invoke-KcApi -Token $token -Method DELETE -Path "/admin/realms/asaa/users/$created" | Out-Null } catch { }
    }
    throw "User creation failed and was rolled back where possible: $($_.Exception.Message)"
} finally {
    $tempPlain = $null
    $token = $null
}
