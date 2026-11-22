# Stops the ASAA identity server. Data in identity/data is kept.

. (Join-Path $PSScriptRoot 'common.ps1')

$code = Invoke-Compose 'stop'
if ($code -ne 0) {
    Write-Host "docker compose stop failed with exit code $code."
    exit $code
}
Write-Host 'Keycloak stopped. Identity data in identity/data is kept.'
exit 0
