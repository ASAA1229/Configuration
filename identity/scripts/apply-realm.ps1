#requires -Version 7.0
# Applies this repository's realm definition to a running server (idempotent).
#
# What it reconciles (create or overwrite, only for objects defined in identity/realm/asaa-realm.json):
#   - realm roles, including their descriptions
#   - groups, with exactly the realm roles listed in the repo (extra realm roles on those groups are removed)
#   - clients, with the full definition from the repo (objects not in the repo are left alone)
#   - the realm version marker attribute asaa.realmVersion
#
# What it does NOT reconcile (review and apply manually or by re-import): authentication flows, identity providers,
# client scopes, required actions, users, realm security settings and fine-grained admin permissions.
# status.ps1 -Admin reports live-vs-repo drift of the version marker.
#
# Secrets: the admin password and one-time code are typed at prompts. Client secrets are never written by this script.
# Usage (from identity\scripts), after start.ps1 and harden-master.ps1:
#   pwsh -File .\apply-realm.ps1

[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

$repo = Get-Content -LiteralPath $script:RealmFile -Raw | ConvertFrom-Json
$repoVersion = $repo.attributes.'asaa.realmVersion'
if (-not $repoVersion) { throw 'The repo realm file has no asaa.realmVersion attribute.' }

$admin = Read-AdminCredential -DefaultUsername 'admin'
$token = Get-AdminToken -Credential $admin
$admin = $null
$base = "/admin/realms/$script:Realm"
$changes = 0

# Realm roles
$repoRoleNames = @($repo.roles.realm | ForEach-Object { $_.name })
foreach ($role in $repo.roles.realm) {
    $rep = @{ name = $role.name; description = $role.description; composite = [bool]$role.composite; clientRole = $false }
    try {
        Invoke-KcApi -Token $token -Method GET -Path "$base/roles/$($role.name)" | Out-Null
        Invoke-KcApi -Token $token -Method PUT -Path "$base/roles/$($role.name)" -Body $rep | Out-Null
    } catch {
        Invoke-KcApi -Token $token -Method POST -Path "$base/roles" -Body $rep | Out-Null
        $changes++
    }
}
Write-Host "OK   realm roles reconciled ($($repoRoleNames.Count))"

# Groups and their realm role mappings
foreach ($group in $repo.groups) {
    $live = @(Invoke-KcApi -Token $token -Method GET -Path "$base/groups?search=$($group.name)&exact=true")
    if ($live.Count -eq 0) {
        Invoke-KcApi -Token $token -Method POST -Path "$base/groups" -Body @{ name = $group.name; attributes = $group.attributes } | Out-Null
        $live = @(Invoke-KcApi -Token $token -Method GET -Path "$base/groups?search=$($group.name)&exact=true")
        $changes++
    } else {
        Invoke-KcApi -Token $token -Method PUT -Path "$base/groups/$($live[0].id)" -Body @{ name = $group.name; attributes = $group.attributes } | Out-Null
    }
    $gid = $live[0].id
    $wanted = @($group.realmRoles)
    $current = @(Invoke-KcApi -Token $token -Method GET -Path "$base/groups/$gid/role-mappings/realm")
    $extra = @($current | Where-Object { $_.name -notin $wanted })
    if ($extra.Count -gt 0) {
        Invoke-KcApi -Token $token -Method DELETE -Path "$base/groups/$gid/role-mappings/realm" -Body $extra | Out-Null
        $changes++
    }
    $missing = @($wanted | Where-Object { $_ -notin @($current | ForEach-Object { $_.name }) })
    if ($missing.Count -gt 0) {
        $reps = @($missing | ForEach-Object { Invoke-KcApi -Token $token -Method GET -Path "$base/roles/$_" })
        Invoke-KcApi -Token $token -Method POST -Path "$base/groups/$gid/role-mappings/realm" -Body $reps | Out-Null
        $changes++
    }
}
Write-Host "OK   groups reconciled ($($repo.groups.Count))"

# Clients (full definition from the repo; secrets are kept by Keycloak and never written here)
foreach ($client in $repo.clients) {
    $rep = $client | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $live = @(Invoke-KcApi -Token $token -Method GET -Path "$base/clients?clientId=$($client.clientId)")
    if ($live.Count -eq 0) {
        Invoke-KcApi -Token $token -Method POST -Path "$base/clients" -Body $rep | Out-Null
        $changes++
    } else {
        Invoke-KcApi -Token $token -Method PUT -Path "$base/clients/$($live[0].id)" -Body $rep | Out-Null
        $changes++
    }
}
Write-Host "OK   clients reconciled ($($repo.clients.Count))"

# Realm version marker (merge, keep other attributes)
$realm = Invoke-KcApi -Token $token -Method GET -Path $base
if (-not $realm.attributes) { $realm | Add-Member -NotePropertyName attributes -NotePropertyValue @{} -Force }
$realm.attributes | Add-Member -NotePropertyName $script:RealmVersionAttribute -NotePropertyValue $repoVersion -Force
Invoke-KcApi -Token $token -Method PUT -Path $base -Body $realm | Out-Null
Write-Host "OK   realm version marker set to $repoVersion ($changes change(s) made)"
Write-Host 'NOTE flows, identity providers, client scopes, users and fine-grained admin permissions are not reconciled by this script.'
$token = $null
