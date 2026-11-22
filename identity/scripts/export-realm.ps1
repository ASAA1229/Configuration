#requires -Version 7.0
# Exports the live configuration of realm asaa (roles, groups, clients, flows; no users) for review or recovery.
#
# The export uses Keycloak's partial-export admin API. Keycloak masks client secrets in a partial export; this script
# additionally masks every credential-bearing field before writing. The file goes to identity/export/ (gitignored) and
# is never committed. Compare it with identity/realm/asaa-realm.json to review live drift beyond the version marker.
#
# Usage (owner, from identity\scripts):
#   pwsh -File .\export-realm.ps1

[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

$exportDir = Join-Path $script:IdentityDir 'export'
New-Item -ItemType Directory -Force -Path $exportDir | Out-Null

$admin = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $admin
$admin = $null
try {
    $realm = Invoke-KcApi -Token $token -Method POST -Path "/admin/realms/$script:Realm/partial-export?exportClients=true&exportGroupsAndRoles=true"
} finally {
    $token = $null
}

Remove-ExportSecrets -Node $realm
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file = Join-Path $exportDir "asaa-realm-$stamp.json"
$realm | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $file -Encoding utf8NoBOM

$repoVersion = (Get-Content -LiteralPath $script:RealmFile -Raw | ConvertFrom-Json).attributes.'asaa.realmVersion'
$liveVersion = $realm.attributes.'asaa.realmVersion'
Write-Host "Export written: identity/export/$(Split-Path -Leaf $file) (credentials masked, no users)."
Write-Host ("Realm version marker: live " + ($(if ($liveVersion) { $liveVersion } else { 'unset' })) + ", repo $repoVersion" + ($(if ($liveVersion -ne $repoVersion) { ' (DRIFT)' } else { '' })))
exit 0
