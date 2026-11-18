#requires -Version 7.0
# Creates an employee in the asaa realm through the Keycloak admin REST API.
#
# Secrets: the admin password, the one-time code and the temporary password are typed at prompts. None is a command-line
# argument, none is written to a file, and none is printed. The temporary password is only held in memory for this run.
# The new user must change the password and enrol an authenticator app (TOTP) at first login.
#
# Inputs are validated strictly: no quotes, backslashes, control characters or shell metacharacters.
# The default group is 'employees'. Any other group must be named explicitly with -Group, and privileged groups also
# require typing CONFIRM <group>.
#
# Usage (from identity\scripts):
#   pwsh -File .\create-user.ps1 -Username jdoe -Email jdoe@example.invalid -FirstName Jane -LastName Doe
#   pwsh -File .\create-user.ps1 -Username ajones -Email ajones@example.invalid -FirstName Ann -LastName Jones -Group hr

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Email,
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [string]$Group = 'employees'
)

. (Join-Path $PSScriptRoot 'common.ps1')

$privileged = @('asaa-administrators', 'jarvis-owners', 'portfolio-admins', 'templates-owners', 'hr', 'payroll', 'finance', 'managers', 'auditors')
$allowedGroups = @('employees') + $privileged

Assert-SafeText -Value $Username -Field 'Username' -MaxLength 64
if ($Username -notmatch '^[a-z0-9._-]{3,64}$') { throw 'Username must be 3 to 64 characters: lowercase letters, digits, dot, underscore or hyphen.' }
Assert-SafeEmail -Value $Email
Assert-SafeText -Value $FirstName -Field 'FirstName' -MaxLength 64
Assert-SafeText -Value $LastName -Field 'LastName' -MaxLength 64
if ($Group -notin $allowedGroups) { throw "Group must be one of: $($allowedGroups -join ', ')." }
if ($Group -in $privileged) {
    $typed = Read-Host "Group '$Group' is privileged. Type CONFIRM $Group to continue"
    if ($typed -ne "CONFIRM $Group") { throw 'Confirmation did not match. Nothing was created.' }
}

$state = Get-StateNoSecrets
if ($state -eq 'missing-file' -or $state -eq 'placeholder' -or $state -eq 'too-short' -or $state -eq 'missing-key') {
    throw 'identity/.env does not hold a valid admin setup. Run harden-master.ps1 first.'
}

$admin = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $admin
$admin = $null

$tempSecure = Read-Host "Temporary password for $Username (the user must change it at first login)" -AsSecureString
$tempPlain = ConvertTo-PlainText -Secure $tempSecure
if ($tempPlain.Length -lt 12) { throw 'Temporary password must be at least 12 characters. Nothing was created.' }

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
    Write-Host "OK  created '$Username' in group '$Group'. First login: change password, then enrol an authenticator app."
} catch {
    if ($created) {
        try { Invoke-KcApi -Token $token -Method DELETE -Path "/admin/realms/asaa/users/$created" | Out-Null } catch { }
    }
    throw "User creation failed and was rolled back where possible: $($_.Exception.Message)"
} finally {
    $tempPlain = $null
    $tempSecure = $null
    $token = $null
}
