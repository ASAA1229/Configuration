# ASAA Configuration

ASAA Configuration is the version-controlled policy and local-environment configuration repository for the ASAA1229 project ecosystem.

It holds the machine-local identity deployment definition, security and data-locality policies, dependency approval baseline, and read-only checks that validate the other project repositories against those policies.

## Scope

- **Identity configuration:** local Keycloak realm definition, loopback-only Compose configuration and PowerShell lifecycle/user-management scripts.
- **Data locality:** policy that keeps personal and employee data on the owner's laptop, restricts service binds to loopback, and disables external AI/speech and external identity-provider use unless the owner changes the policy.
- **Dependency governance:** owner-approved npm, Python and Docker dependency snapshot, approval records, and checks that reject unapproved additions or unpinned images.
- **Policy validation:** dependency-free Node.js checks that inspect the project repositories and report pass/fail without printing secret values.

This repository is policy/configuration infrastructure, not a general application runtime or a place to store live .env files, credentials, tokens, private employee records or production exports.

## Repository layout

| Path | Responsibility |
|---|---|
| `policy/data-locality-policy.json` | Local processing, loopback binding and external-provider restrictions |
| `policy/install-import-policy.json` | Owner approval rules for dependencies, tools, images and bulk imports |
| `policy/approved-dependencies.json` | Approved dependency snapshot |
| `policy/audit-policy.json` | Audit-related policy |
| `identity/realm/asaa-realm.json` | Keycloak realm configuration |
| `identity/docker-compose.yml` | Local identity service definition |
| `identity/scripts/` | PowerShell start/stop/status, realm application and user-management helpers |
| `checks/` | Read-only ecosystem policy checks and tests |

## Run policy checks

Requirements: Node.js with built-in modules only. No package installation is required by the checks.

From the repository root:

```powershell
node checks/check-all.mjs
node --test checks/test/compose.test.mjs
```

The checks are read-only. A failed dependency approval check means a new dependency, image, tool or import needs an owner approval record before the approved snapshot is changed. Do not bypass the check by editing the snapshot alone.

## Local identity service

The Keycloak definition is intended for local use only and binds to loopback. Review identity/.env.example and the scripts before operating it. Never commit the generated .env, credentials, exported realm secrets or user data.

External identity providers remain disabled by the current data-locality policy. TOTP and local realm operation do not imply that identity has been accepted for production use.

## Change control

1. Start changes on `new`.
2. Preserve the approved dependency baseline; obtain explicit owner approval before adding or changing packages, Docker images, tools or bulk imports.
3. Update policy and approval evidence together; never silently refresh the approved snapshot.
4. Run the read-only checks and record their output/commit.
5. Review and explicitly authorize promotion to `dev` or `main`; branch existence does not authorize a merge.

The five standard branches are `main`, `dev`, `new`, `fix`, and `test`.

## Current status

The current implementation is on `new` (23 tracked files at the 2026-11-19 audit snapshot). `main` and `dev` were documentation-only at that snapshot. The purpose and policy boundaries are described here; full operational acceptance, policy-owner review and integration into every consumer CI pipeline must be tracked separately.


## Organization policy status — 2026-11-20

The latest observed Organization Policy CI run on `new` failed: [run 44728022571](https://github.com/ASAA1229/Configuration/actions/runs/44728022571). Local policy checks recorded 10/10 unit tests passing and data-locality checks passing, while dependency approval failed with 22 findings. The approved dependency snapshot contains 187 entries; the current collected state contains 192, and 10 prior approved entries are no longer present.

The findings include newly observed dependencies and local Docker image references using variable-based tags instead of exact immutable pins. Do not weaken IIP-3 or treat the prior `APPROVAL-2026-11-20-001` as blanket approval for new dependencies or mutable image references. The snapshot refresh is approved but not yet executed; review the exact delta before writing the refreshed snapshot. See [Policy Status](reports/POLICY_STATUS_2026-11-20.md).
