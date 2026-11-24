#requires -Version 7.0
# Creates or updates the owner's LOCAL DEMO login in the asaa realm (E3:D1.10). TEMPORARY / TEST DATA: the user is named
# 'Demo Owner TEMPORARY / TEST DATA' and carries the attribute data_class=TEMPORARY_TEST_DATA (E3:D1.11).
#
# One demo identity signs in to every project through the shared realm: ASAA (portal and API docs), JARVIS
# (jarvis-companion), Templates (templates-web, linked by verified email) and Portfolio (portfolio-admin).
#
# Local development only: the Keycloak base URL is pinned to loopback (common.ps1), and the script asks for typed
# confirmation because the demo user joins the privileged owner/administrator groups.
#
# Nothing personal is stored in the repository:
#   DEMO_USER_EMAIL     read from the environment or identity/.env (git-ignored), else prompted
#   DEMO_USER_PASSWORD  read from the environment or identity/.env (git-ignored), else prompted without echo
# The password must meet the realm policy (12+ characters with upper, lower, digit and symbol); Keycloak refuses it
# otherwise and nothing is changed. It is set as a permanent password and is never printed or logged.
# MFA stays on: the demo user enrols an authenticator app (TOTP) at first login, like every other user.
#
# Re-running is safe: an existing demo user keeps its id; password, verified email and groups are brought up to date.
#
# Usage (from identity\scripts):  pwsh -File .\create-demo-user.ps1

[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

$demoGroups = @('asaa-administrators', 'jarvis-owners', 'portfolio-admins', 'templates-owners')
# Every temporary identity is visibly labelled (owner rule: TEMPORARY / TEST DATA) and carries a machine-readable marker.
$demoFirstName = 'Demo Owner'
$demoLastName = 'TEMPORARY / TEST DATA'
$demoAttributes = @{ data_class = @('TEMPORARY_TEST_DATA') }

function Get-EnvFileValue([string]$Key) {
    if (-not (Test-Path -LiteralPath $script:EnvFile)) { return $null }
    $line = Get-Content -LiteralPath $script:EnvFile | Where-Object { $_ -match "^\s*$Key\s*=" } | Select-Object -First 1
    if (-not $line) { return $null }
    $value = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
    if ($value) { return $value } else { return $null }
}

$email = $env:DEMO_USER_EMAIL
if (-not $email) { $email = Get-EnvFileValue 'DEMO_USER_EMAIL' }
if (-not $email) { $email = Read-Host 'Demo user email' }
Assert-SafeEmail -Value $email
$username = ($email.Split('@')[0].ToLowerInvariant() -replace '[^a-z0-9._-]', '')
if ($username -notmatch '^[a-z0-9._-]{3,64}$') { throw 'Could not derive a valid username (3 to 64 of a-z 0-9 . _ -) from the email.' }

$typed = Read-Host "The demo user '$username' joins the privileged groups $($demoGroups -join ', ') in the LOCAL realm. Type CONFIRM DEMO to continue"
if ($typed -cne 'CONFIRM DEMO') { throw 'Confirmation did not match. Nothing was changed.' }

$state = Get-StateNoSecrets
if ($state -in @('missing-file', 'placeholder', 'missing-key')) {
    throw 'identity/.env does not hold a valid admin setup. Run harden-master.ps1 first.'
}

$passwordPlain = $env:DEMO_USER_PASSWORD
if (-not $passwordPlain) { $passwordPlain = Get-EnvFileValue 'DEMO_USER_PASSWORD' }
if (-not $passwordPlain) {
    $secure = Read-Host 'Demo user password (12+ characters with upper, lower, digit and symbol)' -AsSecureString
    $passwordPlain = ConvertTo-PlainText -Secure $secure
    $secure = $null
}
if ($passwordPlain.Length -lt 12) { $passwordPlain = $null; throw 'The demo password must be at least 12 characters (realm policy). Nothing was changed.' }

$admin = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $admin
$admin = $null

try {
    $existing = (Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/asaa/users?username=$username&exact=true")
    if ($existing -and $existing.Count -gt 0) {
        $userId = $existing[0].id
        Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/asaa/users/$userId" -Body @{ email = $email; emailVerified = $true; enabled = $true; firstName = $demoFirstName; lastName = $demoLastName; attributes = $demoAttributes } | Out-Null
        Write-Host "OK   demo user '$username' exists; updating it."
    } else {
        # Email is marked verified so Templates SSO can link the local owner account by verified email (local demo only).
        $body = @{ username = $username; email = $email; firstName = $demoFirstName; lastName = $demoLastName; attributes = $demoAttributes; enabled = $true; emailVerified = $true; requiredActions = @('CONFIGURE_TOTP') }
        Invoke-KcApi -Token $token -Method POST -Path '/admin/realms/asaa/users' -Body $body | Out-Null
        $userId = (Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/asaa/users?username=$username&exact=true")[0].id
        Write-Host "OK   created demo user '$username'."
    }
    Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/asaa/users/$userId/reset-password" -Body @{ type = 'password'; value = $passwordPlain; temporary = $false } | Out-Null
    foreach ($group in $demoGroups) {
        $groupRep = (Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/asaa/groups?search=$group&exact=true")[0]
        if (-not $groupRep) { throw "Group $group was not found in realm asaa. Apply the realm first (apply-realm.ps1)." }
        Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/asaa/users/$userId/groups/$($groupRep.id)" | Out-Null
    }
    Write-Host "OK   demo user '$username' ($email) is in $($demoGroups -join ', ')."
    Write-Host '     Sign in with the email or username and your password; enrol an authenticator app at first login (MFA).'
} catch {
    throw "Demo user setup failed: $($_.Exception.Message)"
} finally {
    $passwordPlain = $null
    $token = $null
}
