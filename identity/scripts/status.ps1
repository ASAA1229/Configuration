# Checks the identity server: container state, OIDC discovery and JWKS on 127.0.0.1:8280.
# Read-only. Prints no secrets.

. (Join-Path $PSScriptRoot 'common.ps1')

$exitCode = 0

Write-Host '--- container'
& docker compose -f $script:ComposeFile ps 2>&1 | Out-Host

Write-Host '--- OIDC discovery'
$discoveryUrl = "$script:KeycloakBase/realms/$script:Realm/.well-known/openid-configuration"
try {
    $discovery = Invoke-RestMethod -Uri $discoveryUrl -TimeoutSec 10
    Write-Host "OK  issuer: $($discovery.issuer)"
    Write-Host "OK  authorization_endpoint: $($discovery.authorization_endpoint)"
    Write-Host "OK  code_challenge_methods_supported: $($discovery.code_challenge_methods_supported -join ', ')"
    $jwksUri = $discovery.jwks_uri
} catch {
    Write-Host "FAIL discovery not reachable at $discoveryUrl"
    $exitCode = 1
    $jwksUri = $null
}

Write-Host '--- JWKS'
if ($jwksUri) {
    try {
        $jwks = Invoke-RestMethod -Uri $jwksUri -TimeoutSec 10
        $sigKeys = @($jwks.keys | Where-Object { $_.use -eq 'sig' })
        Write-Host "OK  JWKS reachable, signing keys: $($sigKeys.Count), algorithms: $(($sigKeys | ForEach-Object { $_.alg } | Sort-Object -Unique) -join ', ')"
    } catch {
        Write-Host "FAIL JWKS not reachable at $jwksUri"
        $exitCode = 1
    }
} else {
    Write-Host 'SKIP JWKS (discovery failed)'
    $exitCode = 1
}

exit $exitCode
