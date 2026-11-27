# Configuration — Project Status

**Updated:** 2026-11-27  
**Working branch:** new

## Current position

Configuration is the shared configuration, policy, dependency, secret-reference, data-locality, drift and identity foundation for ASAA projects.

## Last-known policy evidence

The 2026-11-25 policy run was reported as passing with 197 approved / 197 current dependencies, zero removed, and data-locality, secret-reference and drift checks passing. Treat this as dated evidence, not proof of a fresh run on the current head.

## Owner decisions

- Keep the repository public.
- Protect all secrets, sensitive configuration values and private infrastructure details.
- Use centralized ASAA identity with local login and optional individually configured SSO providers.
- Keep operation free/local until investment.
- The owner controls branch promotion timing; this is not a blocker.

## Remaining verification

Refresh policy checks on the exact current branch head; verify identity startup, local login, optional-provider-disabled behavior, backup/restore and operational procedures. Do not claim these are failures or owner blockers without a concrete failed check. No implementation or production status is promoted by this documentation update.
