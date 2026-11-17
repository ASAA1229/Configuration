# Creates an employee in the asaa realm through kcadm inside the running Keycloak container.
#
# The temporary password is typed by the owner at the prompt and is never stored in a file or printed.
# The new user must change the password and enrol an authenticator app (TOTP) at first login.
# The admin password is read from identity/.env (not printed) and passed to kcadm inside the container.
#
# Usage (from any folder):
#   powershell -ExecutionPolicy Bypass -File identity\scripts\create-user.ps1 -Username jdoe -Email jdoe@example.invalid -FirstName Jane -LastName Doe
# Optional: -Group employees (default) or -Group asaa-administrators

param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9._-]{3,64}$')][string]$Username,
    [Parameter(Mandatory = $true)][ValidatePattern('^[^@\s]+@[^@\s]+$')][string]$Email,
    [Parameter(Mandatory = $true)][string]$FirstName,
    [Parameter(Mandatory = $true)][string]$LastName,
    [ValidateSet('employees', 'asaa-administrators')][string]$Group = 'employees'
)

. (Join-Path $PSScriptRoot 'common.ps1')

$state = Get-BootstrapPasswordState
if ($state -ne 'ok') {
    Write-PasswordStateHelp $state
    exit 1
}

# Read the admin password from .env without printing it.
$adminPassword = ((Get-Content -LiteralPath $script:EnvFile | Where-Object { $_ -match '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=' } | Select-Object -First 1) -replace '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=\s*', '').Trim().Trim('"', "'")

# The owner types the temporary password. It is held only in memory for this run.
$secure = Read-Host -AsSecureString "Temporary password for $Username (the user must change it at first login)"
$tempPassword = [System.Net.NetworkCredential]::new('', $secure).Password
if ($tempPassword.Length -lt 12) {
    Write-Host 'Temporary password must be at least 12 characters. Nothing was created.'
    exit 1
}

$kc = '/opt/keycloak/bin/kcadm.sh'
function Invoke-Kc {
    param([string[]]$KcArgs)
    $out = & docker compose -f $script:ComposeFile exec -T keycloak $kc @KcArgs 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($out -join "`n") }
}

$login = Invoke-Kc @('config', 'credentials', '--server', 'http://127.0.0.1:8080', '--realm', 'master', '--user', 'admin', '--password', $adminPassword)
$adminPassword = $null
if ($login.Code -ne 0) {
    Write-Host 'Admin login to Keycloak failed. Is the server running (identity/scripts/status.ps1)? Nothing was created.'
    exit 1
}

$create = Invoke-Kc @('create', 'users', '-r', $script:Realm, '-s', "username=$Username", '-s', "email=$Email",
    '-s', "firstName=$FirstName", '-s', "lastName=$LastName", '-s', 'enabled=true', '-s', 'emailVerified=false',
    '-s', 'requiredActions=["UPDATE_PASSWORD","CONFIGURE_TOTP"]', '-i')
if ($create.Code -ne 0) {
    Write-Host "User creation failed (it may already exist). Keycloak said: $($create.Output)"
    exit 1
}
$userId = $create.Output.Trim()

$pw = Invoke-Kc @('set-password', '-r', $script:Realm, '--userid', $userId, '--new-password', $tempPassword, '--temporary')
$tempPassword = $null
if ($pw.Code -ne 0) {
    Write-Host 'Setting the temporary password failed. Remove the partly created user in the admin console before retrying.'
    exit 1
}

$groupJson = Invoke-Kc @('get', 'groups', '-r', $script:Realm, '-q', "search=$Group", '--fields', 'id,name')
$groups = $groupJson.Output | ConvertFrom-Json
$groupId = ($groups | Where-Object { $_.name -eq $Group } | Select-Object -First 1).id
if (-not $groupId) {
    Write-Host "Group '$Group' was not found in realm $($script:Realm). The user was created without a group."
    exit 1
}
$join = Invoke-Kc @('update', "users/$userId/groups/$groupId", '-r', $script:Realm, '-s', 'realm=' + $script:Realm, '-s', "userId=$userId", '-s', "groupId=$groupId", '-n')
if ($join.Code -ne 0) {
    Write-Host "Adding the user to group $Group failed: $($join.Output)"
    exit 1
}

Write-Host "Created user '$Username' in group '$Group'. First login: change password, then enrol an authenticator app (Google Authenticator or Microsoft Authenticator)."
exit 0
