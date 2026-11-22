#requires -Version 7.0
# Backs up or restores the local Keycloak data directory (identity/data, dev-file storage).
#
# Backup: stops the container if it runs (a consistent copy needs a stopped server), archives identity/data into
# backups/identity-data-<UTC>.zip (gitignored), writes a SHA-256 checksum next to it, and restarts the container if
# it was running. Restore: verifies the checksum, requires a typed confirmation, keeps the current data as a
# pre-restore archive, then replaces identity/data. Archives contain user and credential data: keep them on this
# laptop only and never commit or upload them.
#
# Usage (owner, from identity\scripts):
#   pwsh -File .\backup-data.ps1
#   pwsh -File .\backup-data.ps1 -Restore -Archive ..\..\backups\identity-data-20261122T101500Z.zip

[CmdletBinding()]
param(
    [switch]$Restore,
    [string]$Archive
)

. (Join-Path $PSScriptRoot 'common.ps1')

$dataDir = Join-Path $script:IdentityDir 'data'
$backupDir = Join-Path (Split-Path -Parent $script:IdentityDir) 'backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

function New-DataArchive {
    param([string]$Prefix)
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $zip = Join-Path $backupDir "$Prefix-$stamp.zip"
    Compress-Archive -Path (Join-Path $dataDir '*') -DestinationPath $zip -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$zip.sha256" -Value "$hash  $(Split-Path -Leaf $zip)" -Encoding ascii
    return $zip
}

$wasRunning = (Get-KeycloakContainerState) -eq 'running'
if ($wasRunning) {
    Write-Host 'Stopping Keycloak for a consistent copy ...'
    if ((Invoke-Compose 'stop') -ne 0) { Write-Host 'docker compose stop failed.'; exit 1 }
}

$exitCode = 0
try {
    if (-not $Restore) {
        if (-not (Test-Path -LiteralPath $dataDir) -or -not (Get-ChildItem -LiteralPath $dataDir -Force | Select-Object -First 1)) {
            Write-Host 'identity/data is empty: nothing to back up.'
        } else {
            $zip = New-DataArchive -Prefix 'identity-data'
            Write-Host "Backup written: backups/$(Split-Path -Leaf $zip) (+ .sha256). Contains credential data: keep it local."
        }
    } else {
        if (-not $Archive) { throw 'Restore needs -Archive <path to identity-data-*.zip>.' }
        $archivePath = (Resolve-Path -LiteralPath $Archive).Path
        $sumFile = "$archivePath.sha256"
        if (-not (Test-Path -LiteralPath $sumFile)) { throw 'The archive has no .sha256 checksum file; refusing to restore.' }
        $expected = ((Get-Content -LiteralPath $sumFile -Raw).Trim() -split '\s+')[0]
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -ne $actual) { throw 'Checksum mismatch; refusing to restore.' }
        $answer = Read-Host 'Type RESTORE to replace identity/data with this archive'
        if ($answer -ne 'RESTORE') { throw 'Restore cancelled.' }
        if ((Test-Path -LiteralPath $dataDir) -and (Get-ChildItem -LiteralPath $dataDir -Force | Select-Object -First 1)) {
            $pre = New-DataArchive -Prefix 'identity-data-prerestore'
            Write-Host "Current data kept as backups/$(Split-Path -Leaf $pre)."
            Remove-Item -LiteralPath $dataDir -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $dataDir
        Write-Host 'identity/data restored.'
    }
} catch {
    Write-Host "FAIL $($_.Exception.Message)"
    $exitCode = 1
} finally {
    if ($wasRunning) {
        Write-Host 'Starting Keycloak again ...'
        if ((Invoke-Compose 'up' '-d') -ne 0) { Write-Host 'docker compose up failed.'; $exitCode = 1 }
    }
}
exit $exitCode
