#requires -Version 7.0
# Checks the identity server on 127.0.0.1:8280: container state, OIDC discovery and JWKS (no login needed).
# With -Admin it also logs in as an admin (typed at prompts) and reports only yes/no for:
#   master hardened, live realm drift (realm version marker differs from the repo), identity-sync guard.
# Prints no secrets and no key material.

[CmdletBinding()]
param([switch]$Admin)

. (Join-Path $PSScriptRoot 'common.ps1')

$exitCode = 0

Write-Host '--- container'
Invoke-Compose 'ps' | Out-Host

Write-Host '--- OIDC discovery'
$discoveryUrl = "$script:KeycloakBase/realms/$script:Realm/.well-known/openid-configuration"
try {
    $discovery = Invoke-RestMethod -Uri $discoveryUrl -TimeoutSec 10
    Write-Host "OK   issuer: $($discovery.issuer)"
    Write-Host "OK   code challenge methods: $($discovery.code_challenge_methods_supported -join ', ')"
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
        Write-Host "OK   JWKS reachable, signing keys: $($sigKeys.Count)"
    } catch {
        Write-Host 'FAIL JWKS not reachable'
        $exitCode = 1
    }
} else {
    Write-Host 'SKIP JWKS (discovery failed)'
    $exitCode = 1
}

if ($Admin) {
    Write-Host '--- admin checks (yes/no only)'
    try {
        $credential = Read-AdminCredential -DefaultUsername 'admin'
        $token = Get-AdminToken -Credential $credential
        $credential = $null

        $master = Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master'
        $totp = Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP'
        $bootstrap = Invoke-KcApi -Token $token -Method GET -Path '/admin/realms/master/users?username=admin&exact=true'
        $hardened = ($master.bruteForceProtected -eq $true) -and ($totp.defaultAction -eq $true) -and ($totp.enabled -eq $true) -and (@($bootstrap).Count -eq 0)
        Write-Host ("master hardened: " + ($(if ($hardened) { 'yes' } else { 'no' })))

        $realm = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/$script:Realm"
        $repoVersion = (Get-Content -LiteralPath $script:RealmFile -Raw | ConvertFrom-Json).attributes.'asaa.realmVersion'
        $liveVersion = $realm.attributes.'asaa.realmVersion'
        $drift = ($liveVersion -ne $repoVersion)
        Write-Host ("realm drift (live version differs from repo): " + ($(if ($drift) { 'yes' } else { 'no' })))

        $sync = Invoke-KcApi -Token $token -Method GET -Path "/admin/realms/$script:Realm/clients?clientId=asaa-identity-sync"
        $guardPending = -not ($realm.attributes.'asaa.identitySync.fgap' -eq 'applied')
        Write-Host ("identity-sync not yet restricted (do not use): " + ($(if ($guardPending) { 'yes' } else { 'no' })))
        $token = $null
    } catch {
        Write-Host "FAIL admin checks: $($_.Exception.Message)"
        $exitCode = 1
    }
}

exit $exitCode
