# Configuration — Project Requirements

**Updated:** 2026-11-27  
**Scope:** shared ASAA configuration, policy, identity and security foundation.

## Purpose

Provide reusable, local-first configuration and policy capabilities for ASAA projects. Keep configuration consistent and auditable without exposing secrets or forcing paid services.

## Requirements

1. Maintain validated configuration schemas and environment overlays for local, CI and local-production-like use.
2. Keep secrets out of Git. Store only secret references/placeholders and document required variables without inventing real values.
3. Enforce dependency approval, data-locality, secret-reference and configuration-drift checks.
4. Preserve evidence and history for dependency approvals and policy decisions.
5. Provide shared identity foundations for ASAA projects. Local login is the default; optional external SSO providers can be enabled individually when configured and approved.
6. Support centralized ASAA identity, role-aware access and auditable lifecycle changes; project data access remains governed by each project's authorization boundary.
7. Use free/local tooling by default. No paid service activation without owner approval.
8. Keep the repository public by owner decision. Never commit secrets, sensitive configuration values, private infrastructure endpoints or security-sensitive operational data.
9. Preserve local-first operation and support controlled environment-specific activation without making unavailable integrations mandatory.

## Architecture constraints

- Configuration and policy are shared capabilities, not permission for unrestricted cross-project data access.
- Prefer versioned schemas, explicit validation and controlled changes.
- External identity providers remain optional and individually disabled until configured.
- Use least privilege, auditability and safe failure behavior.
- Do not store actual credentials in example files, policy documents or logs.

## Owner decisions

- Repository visibility: public, with sensitive configuration and secrets protected.
- Centralized ASAA identity service; local login plus optional external SSO.
- Zero operating cost until investment; prefer free/local solutions.
- Branch promotion is controlled by the owner and is not a blocker.
