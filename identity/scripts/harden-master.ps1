#requires -Version 7.0
# Hardens the Keycloak master realm (administration realm). Run by the owner once, after the first start.
#
#   1. Enables brute-force protection on master.
#   2. Makes the authenticator-app setup (CONFIGURE_TOTP) a default required action in master and adds it to the
#      bootstrap admin, so every master admin must enrol an authenticator app. Once enrolled, OTP is required at login.
#   3. Creates a named permanent admin. The owner types the username and password; neither is passed on a command line.
#   4. Deletes the temporary bootstrap admin, but only with -DeleteBootstrap and a typed confirmation.
#
# Usage (owner, from identity\scripts):
#   pwsh -File .\harden-master.ps1 -AdminUsername <your-name>
#   pwsh -File .\harden-master.ps1 -AdminUsername <your-name> -DeleteBootstrap
#
# Not verified live in this build: the OTP enrolment flow must be tested by the owner with a real authenticator app.

#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AdminUsername,
    [switch]$DeleteBootstrap
)

. (Join-Path $PSScriptRoot 'common.ps1')

Assert-SafeText -Value $AdminUsername -Field 'AdminUsername' -MaxLength 64
if ($AdminUsername -eq 'admin') { throw 'Choose a name other than the bootstrap username "admin".' }

$state = Get-StateNoSecrets
if ($state -ne 'ok') { throw 'identity/.env does not hold a valid bootstrap password. Start the server once with the owner-set password first.' }

Write-Host 'Bootstrap admin login (typed here, not stored):'
$bootstrap = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $bootstrap
$bootstrap = $null

# 1. Brute-force protection on master.
$master = Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master'
$master.bruteForceProtected = $true
$master.failureFactor = 5
$master.permanentLockout = $false
$master.maxFailureWaitSeconds = 900
$master.waitIncrementSeconds = 60
$master.minimumQuickLoginWaitSeconds = 60
$master.quickLoginCheckMilliSeconds = 1000
$master.maxDeltaTimeSeconds = 43200
Invoke-KcApi -Token $token -Method PUT -Path '/admin/realms/master' -Body $master | Out-Null
Write-Host 'OK  brute-force protection enabled on master'

# 2. Authenticator-app enrolment is a default required action in master.
$totp = @{ alias = 'CONFIGURE_TOTP'; name = 'Configure OTP'; providerId = 'CONFIGURE_TOTP'; enabled = $true; defaultAction = $true; priority = 10 }
Invoke-KcApi -Token $token -Method PUT -Path '/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP' -Body $totp | Out-Null
$bootUser = (Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master/users?username=admin&exact=true')
if (@($bootUser).Count -gt 0) {
    $bu = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/master/users/$($bootUser[0].id)"
    $bu.requiredActions = @(@($bu.requiredActions) + 'CONFIGURE_TOTP' | Select-Object -Unique)
    Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/master/users/$($bootUser[0].id)" -Body $bu | Out-Null
}
Write-Host 'OK  CONFIGURE_TOTP is a default required action in master (and on the bootstrap admin)'

# 3. Named permanent admin.
$existing = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/master/users?username=$AdminUsername&exact=true"
if (@($existing).Count -eq 0) {
    $newUser = @{ username = $AdminUsername; enabled = $true; emailVerified = $false; requiredActions = @('CONFIGURE_TOTP', 'UPDATE_PASSWORD') }
    Invoke-KcApi -Token $token -Method POST -Path '/admin/realms/master/users' -Body $newUser | Out-Null
    $existing = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/master/users?username=$AdminUsername&exact=true"
}
$namedId = $existing[0].id

Write-Host "Set the password for the new admin '$AdminUsername' (typed here, not stored):"
$newPassword = Read-Host 'New admin password' -AsSecureString
$plain = ConvertTo-PlainText -Secure $newPassword
if ($plain.Length -lt 16) { throw 'Admin password must be at least 16 characters.' }
Invoke-KcApi -Token $token -Method PUT -Path "/admin/realms/master/users/$namedId/reset-password" -Body @{ type = 'password'; value = $plain; temporary = $true } | Out-Null
$plain = $null
$newPassword = $null
Write-Host "OK  named admin '$AdminUsername' created (must change password and enrol an authenticator app at first login)"

# Grant master administration rights through the master-realm client role 'admin'.
$masterClient = (Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master/clients?clientId=master-realm')[0]
$adminRole = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/master/clients/$($masterClient.id)/roles/admin"
Invoke-KcApi -Token $token -Method POST -Path "/admin/realms/master/users/$namedId/role-mappings/clients/$($masterClient.id)" -Body @($adminRole) | Out-Null
$check = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/master/users/$namedId/role-mappings/clients/$($masterClient.id)"
if (-not ($check | Where-Object { $_.name -eq 'admin' })) { throw 'Could not confirm admin role for the named admin. Bootstrap admin was kept.' }
Write-Host 'OK  named admin holds master-realm admin role'

# 4. Remove the bootstrap admin only on explicit request.
$bootstrapUsers = Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master/users?username=admin&exact=true'
if (@($bootstrapUsers).Count -gt 0) {
    if ($DeleteBootstrap) {
        $typed = Read-Host "Type 'DELETE bootstrap admin' to remove the temporary bootstrap admin (anything else keeps it)"
        if ($typed -ceq 'DELETE bootstrap admin') {
            Invoke-KcApi -Token $token -Method DELETE -Path "/admin/realms/master/users/$($bootstrapUsers[0].id)" | Out-Null
            Write-Host 'OK  bootstrap admin deleted'
        } else {
            Write-Host 'SKIP bootstrap admin kept (confirmation text did not match)'
        }
    } else {
        Write-Host 'NOTE bootstrap admin still exists. Log in as the named admin, confirm it works, then re-run with -DeleteBootstrap.'
    }
}

Write-Host 'Done. Remember: master hardening is not complete until the named admin has enrolled an authenticator app and logged in.'
