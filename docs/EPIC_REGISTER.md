# Configuration — Epic Register

**Updated:** 2026-11-27  
**Rule:** preserve evidence; do not infer completion from the presence of files alone.

| Epic | Scope | Priority | Current evidence/status |
|---|---|---|---|
| CFG-E01 | Configuration schemas and environment profiles | High | Environment JSON profiles and validation tooling exist; full current acceptance not assessed here. |
| CFG-E02 | Dependency approval and inventory governance | High | 2026-11-25 policy evidence reported 197 approved / 197 current, zero removed. |
| CFG-E03 | Secret references and safe configuration handling | High | Secret-reference checks and examples exist; current policy gate reported passing 2026-11-25. |
| CFG-E04 | Data locality and configuration drift controls | High | Locality and drift checks exist; current policy gate reported passing 2026-11-25. |
| CFG-E05 | Central identity and SSO configuration | High | Identity realm, local scripts and compose assets exist; full provider/device acceptance remains unverified. |
| CFG-E06 | Audit history, diagnostics and policy evidence | Medium | Policy history, reports and diagnostics assets exist; end-to-end operational review remains unverified. |

## Constraints

- Local-first and zero-cost until investment.
- Repository remains public; no secrets or sensitive values in source control.
- Optional SSO providers must remain disabled until individually configured and approved.
- Existing implementation is preserved; this register does not authorize code changes or provider activation.
