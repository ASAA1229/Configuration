# Configuration Policy Status — 2026-11-20

**Branch assessed:** `new`  
**CI:** [Organization Policy CI run 44728022571](https://github.com/ASAA1229/Configuration/actions/runs/44728022571) — FAILED.  
**Release posture:** policy gate BLOCKED; no approval snapshot update or policy weakening performed.

## Verified checks

| Check | Result |
|---|---|
| Configuration unit tests | PASS — 10/10 |
| Data locality | PASS |
| Dependency approval | FAIL — 22 findings |
| Organization Policy CI | FAIL — run 44728022571 |

## Snapshot reconciliation

- Existing approved dependency snapshot: 187 entries.
- Current collected dependency state: 192 entries.
- Approved entries no longer present: 10.
- New or changed dependencies and image references require explicit review and approval.
- Existing approval `APPROVAL-2026-11-20-001` covers only its recorded scope. It is not a blanket waiver for subsequent dependencies or mutable image references.

## Key findings

1. New NPM/Python dependencies were observed that are not represented in the current snapshot.
2. Docker image references in local compose/rehearsal definitions use environment-variable substitutions instead of exact immutable version/digest pins. Examples include ASAA API/portal references and Templates local production image references.
3. External images that are already pinned by exact version and digest should remain pinned; do not replace them with floating tags.
4. The existing image policy data includes malformed/truncated-looking variable-interpolation entries; validate parser behavior and policy intent before changing any policy artifact.

## Required actions

1. Collect all five project repositories and Configuration at the exact intended `new` heads in one controlled workspace.
2. Inspect the complete proposed dependency snapshot diff, including additions, removals, version changes, image tags and digests.
3. Confirm each new dependency is necessary, licensed appropriately, supported and approved; record approval evidence for any scope beyond the existing approval record.
4. Resolve mutable image references by using immutable exact versions/digests or an approved policy-compliant mechanism. Do not weaken IIP-3.
5. Run `node checks/check-dependency-approval.mjs --snapshot --approval-id APPROVAL-2026-11-20-001` only after the reviewed inputs and approval scope are correct.
6. Run `node checks/check-all.mjs` and the full Organization Policy CI workflow; require a passing exact-head run before marking the policy gate green.

## Authorization and current state

The owner approved refreshing the snapshot against current `new` heads, but the refresh has not yet been executed. This document records the failure and procedure; it does not claim that the snapshot was refreshed, that all 22 findings were resolved, or that CI passed. Source code and configuration changes remain on hold under the current instruction.
