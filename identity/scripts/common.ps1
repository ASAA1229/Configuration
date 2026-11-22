#requires -Version 7.0
# Shared helpers for the identity scripts (PowerShell 7).
# Secrets are never printed, never written to files, and never placed on a command line.
# Admin calls use the Keycloak admin REST API from this host, so no container exec or kcadm arguments carry secrets.

Set-StrictMode -Version Latest

$script:IdentityDir = Split-Path -Parent $PSScriptRoot
$script:ComposeFile = Join-Path $script:IdentityDir 'docker-compose.yml'
$script:EnvFile = Join-Path $script:IdentityDir '.env'
$script:RealmFile = Join-Path $script:IdentityDir 'realm\asaa-realm.json'
$script:KeycloakBase = 'http://127.0.0.1:8280'
$script:Realm = 'asaa'
$script:RealmVersionAttribute = 'asaa.realmVersion'

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Push-Location $script:IdentityDir
    try {
        & docker compose -f $script:ComposeFile @Arguments
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

# Strict text validation: rejects quotes, backslashes, control characters and anything outside a short allow-list.
function Assert-SafeText {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Field, [int]$MaxLength = 128)
    if ($Value.Length -eq 0 -or $Value.Length -gt $MaxLength) { throw "$Field must be 1 to $MaxLength characters." }
    if ($Value -match '["''\\`$;|&<>]' -or $Value -match '[\x00-\x1F\x7F]') { throw "$Field contains characters that are not allowed." }
}

function Assert-SafeEmail {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Length -gt 254 -or $Value -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { throw 'Email is not in an acceptable format.' }
}

function ConvertTo-PlainText {
    # Converts a SecureString to plain text for the duration of one call. The caller must clear its variable afterwards.
    param([Parameter(Mandatory)][securestring]$Secure)
    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

# Prompts the owner for admin login details. Password and one-time code are typed, never passed as arguments.
function Read-AdminCredential {
    param([string]$DefaultUsername = 'admin')
    $user = Read-Host "Admin username (Enter for $DefaultUsername)"
    if ([string]::IsNullOrWhiteSpace($user)) { $user = $DefaultUsername }
    Assert-SafeText -Value $user -Field 'Admin username' -MaxLength 64
    $secure = Read-Host 'Admin password' -AsSecureString
    $otp = Read-Host 'Authenticator code (leave empty if OTP is not yet required for this admin)'
    if ($otp -and $otp -notmatch '^\d{6}$') { throw 'Authenticator code must be 6 digits.' }
    return [pscustomobject]@{ Username = $user; Password = $secure; Otp = $otp }
}

# Obtains an admin access token from the master realm. Returns the token string only.
function Get-AdminToken {
    param([Parameter(Mandatory)]$Credential)
    $plain = ConvertTo-PlainText -Secure $Credential.Password
    $body = @{ grant_type = 'password'; client_id = 'admin-cli'; username = $Credential.Username; password = $plain }
    if ($Credential.Otp) { $body['totp'] = $Credential.Otp }
    try {
        $response = Invoke-RestMethod -Method Post -Uri "$script:KeycloakBase/realms/master/protocol/openid-connect/token" -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 20
        return $response.access_token
    } catch {
        throw 'Admin login failed. Check the username, password and authenticator code.'
    } finally {
        $plain = $null
        $body = $null
    }
}

function Invoke-KcApi {
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body
    )
    $headers = @{ Authorization = "Bearer $Token" }
    $uri = "$script:KeycloakBase$Path"
    if ($null -ne $Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 20 -Compress) -TimeoutSec 30
    }
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -TimeoutSec 30
}

# Waits until the realm's OIDC discovery document answers on loopback. Returns $true when ready, $false on timeout.
function Wait-KeycloakReady {
    param([int]$TimeoutSec = 180, [int]$IntervalSec = 5)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $url = "$script:KeycloakBase/realms/$script:Realm/.well-known/openid-configuration"
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-RestMethod -Uri $url -TimeoutSec 5
            return $true
        } catch {
            Start-Sleep -Seconds $IntervalSec
        }
    }
    return $false
}

# Returns the compose service state: 'running', 'exited', 'missing' or another Docker state string.
function Get-KeycloakContainerState {
    $state = & docker inspect --format '{{.State.Status}}' asaa-keycloak 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $state) { return 'missing' }
    return $state.Trim()
}

# Replaces every credential-bearing field in an exported realm object with a mask, recursively.
function Remove-ExportSecrets {
    param($Node)
    if ($null -eq $Node) { return }
    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        foreach ($item in $Node) { Remove-ExportSecrets -Node $item }
        return
    }
    if ($Node -is [pscustomobject]) {
        foreach ($prop in @($Node.PSObject.Properties)) {
            if ($prop.Name -match '^(secret|hashedSaltedValue|salt|privateKey|clientSecret|password|secretData|credentialData)$' -and $prop.Value -is [string] -and $prop.Value -ne '') {
                $prop.Value = '**********'
            } elseif ($prop.Name -eq 'credentials') {
                $prop.Value = @()
            } else {
                Remove-ExportSecrets -Node $prop.Value
            }
        }
    }
}

function Get-StateNoSecrets {
    # Returns 'missing-file', 'missing-key', 'placeholder', 'too-short' or 'ok' for the bootstrap password in identity/.env.
    # The value itself is never returned.
    if (-not (Test-Path -LiteralPath $script:EnvFile)) { return 'missing-file' }
    $line = Get-Content -LiteralPath $script:EnvFile | Where-Object { $_ -match '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=' } | Select-Object -First 1
    if (-not $line) { return 'missing-key' }
    $value = ($line -replace '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=\s*', '').Trim().Trim('"', "'")
    if ([string]::IsNullOrEmpty($value) -or $value -eq 'REPLACE_WITH_YOUR_OWN_PASSWORD') { return 'placeholder' }
    if ($value.Length -lt 16) { return 'too-short' }
    return 'ok'
}
