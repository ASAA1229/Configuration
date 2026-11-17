# Shared helpers for the identity scripts. Never print the bootstrap password.
# Paths are resolved from this file, so the scripts work from any working directory.

$script:IdentityDir = Split-Path -Parent $PSScriptRoot
$script:EnvFile = Join-Path $script:IdentityDir '.env'
$script:EnvExample = Join-Path $script:IdentityDir '.env.example'
$script:ComposeFile = Join-Path $script:IdentityDir 'docker-compose.yml'
$script:KeycloakBase = 'http://127.0.0.1:8280'
$script:Realm = 'asaa'
$script:PlaceholderValue = 'REPLACE_WITH_YOUR_OWN_PASSWORD'

function Get-BootstrapPasswordState {
    # Returns 'missing-file', 'missing-key', 'placeholder', 'too-short' or 'ok'. The value itself is never returned or printed.
    if (-not (Test-Path -LiteralPath $script:EnvFile)) { return 'missing-file' }
    $line = Get-Content -LiteralPath $script:EnvFile | Where-Object { $_ -match '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=' } | Select-Object -First 1
    if (-not $line) { return 'missing-key' }
    $value = ($line -replace '^\s*KC_BOOTSTRAP_ADMIN_PASSWORD\s*=\s*', '').Trim().Trim('"', "'")
    if ([string]::IsNullOrEmpty($value) -or $value -eq $script:PlaceholderValue) { return 'placeholder' }
    if ($value.Length -lt 16) { return 'too-short' }
    return 'ok'
}

function Write-PasswordStateHelp([string]$State) {
    switch ($State) {
        'missing-file' { Write-Host "identity/.env does not exist. Copy identity/.env.example to identity/.env and set KC_BOOTSTRAP_ADMIN_PASSWORD yourself." }
        'missing-key' { Write-Host 'identity/.env has no KC_BOOTSTRAP_ADMIN_PASSWORD line. Add one yourself (the value is not shown here).' }
        'placeholder' { Write-Host 'KC_BOOTSTRAP_ADMIN_PASSWORD is still the placeholder. Set your own value in identity/.env (the value is not shown here).' }
        'too-short' { Write-Host 'KC_BOOTSTRAP_ADMIN_PASSWORD must be at least 16 characters (the value is not shown here).' }
    }
}

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
