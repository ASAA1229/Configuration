// Machine-readable policy findings. Standard library only. Pure functions: no I/O.
//
// Every check emits findings in one shape so CI, the organization governance validator and other tools can consume
// them without parsing console text. Findings never contain secret values.
//
// severity: "error"   - fails the policy gate
//           "warning" - reported, does not fail the gate
//           "info"    - context only

import { createHash } from "node:crypto";

export const FINDINGS_SCHEMA = "asaa.configuration.policy-findings.v1";
export const REPORT_SCHEMA = "asaa.configuration.policy-report.v1";

// Classification catalogue: code -> { category, rule, ownerAction }.
export const FINDING_CODES = {
  "DEP-NEW": { category: "dependency", rule: "IIP-2", ownerAction: "approve-or-remove" },
  "DEP-SPEC-CHANGED": { category: "dependency", rule: "IIP-2", ownerAction: "approve-or-revert" },
  "DEP-REMOVED": { category: "dependency", rule: "IIP-2", ownerAction: "refresh-snapshot" },
  "DEP-OCCURRENCE-CHANGED": { category: "dependency", rule: "IIP-2", ownerAction: "refresh-snapshot" },
  "IMG-INVALID": { category: "image", rule: "IIP-3", ownerAction: "fix-reference" },
  "IMG-UNPINNED": { category: "image", rule: "IIP-3", ownerAction: "pin-reference" },
  "IMG-NOT-APPROVED": { category: "image", rule: "IIP-4", ownerAction: "approve-or-remove" },
  "APR-RECORD-INVALID": { category: "approval", rule: "IIP-1", ownerAction: "fix-approval-record" },
  "APR-RECORD-DUPLICATE": { category: "approval", rule: "IIP-1", ownerAction: "fix-approval-record" },
  "APR-REFERENCE-MISSING": { category: "approval", rule: "IIP-1", ownerAction: "record-approval" },
  "APR-RECORD-CONFLICT": { category: "approval", rule: "IIP-1", ownerAction: "resolve-conflict" },
  "APR-REQUEST-PENDING": { category: "approval", rule: "IIP-1", ownerAction: "decide-request" },
  "APR-COVERED-PENDING-SNAPSHOT": { category: "approval", rule: "IIP-5", ownerAction: "refresh-snapshot" },
  "APR-IMAGE-CONFLICT": { category: "approval", rule: "IIP-4", ownerAction: "resolve-conflict" },
  "SCHEMA-INVALID": { category: "schema", rule: "CFG-SCHEMA", ownerAction: "fix-configuration" },
  "DL-VIOLATION": { category: "data-locality", rule: "DL", ownerAction: "fix-configuration" },
  "DL-RULE-UNENFORCED": { category: "data-locality", rule: "DL", ownerAction: "none" },
  "SECRET-LITERAL": { category: "secret", rule: "CFG-SECRET-REF", ownerAction: "rotate-and-reference" },
  "SECRET-REF-INVALID": { category: "secret", rule: "CFG-SECRET-REF", ownerAction: "fix-configuration" },
  "DRIFT-POLICY-UNRECORDED": { category: "drift", rule: "CFG-HISTORY", ownerAction: "record-or-revert" },
  "DRIFT-HISTORY-TAMPERED": { category: "drift", rule: "CFG-HISTORY", ownerAction: "investigate" },
  "DRIFT-ENV": { category: "drift", rule: "CFG-ENV", ownerAction: "fix-configuration" },
  "DRIFT-WORKTREE": { category: "drift", rule: "CFG-HISTORY", ownerAction: "commit-or-revert" },
  "ENV-INVALID": { category: "environment", rule: "CFG-ENV", ownerAction: "fix-configuration" },
};

export function createFinding({ code, severity = "error", subject, message, explanation = null, remediation = null, repo = null, inventoryId = null, file = null, policyRule = null, data = null }) {
  const meta = FINDING_CODES[code];
  if (!meta) throw new Error(`unknown finding code ${code}`);
  const id = `${code}:${createHash("sha256").update(`${code}|${repo ?? ""}|${file ?? ""}|${inventoryId ?? ""}|${subject}`).digest("hex").slice(0, 10)}`;
  return {
    id,
    code,
    category: meta.category,
    rule: policyRule ?? meta.rule,
    severity,
    repo,
    file,
    inventoryId,
    subject,
    message,
    explanation,
    remediation,
    ownerAction: meta.ownerAction,
    ...(data ? { data } : {}),
  };
}

export function summarize(findings) {
  const bySeverity = { error: 0, warning: 0, info: 0 };
  const byCategory = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory, gate: bySeverity.error === 0 ? "pass" : "fail" };
}

export function renderFinding(f) {
  const tag = f.severity === "error" ? "FAIL" : f.severity === "warning" ? "WARN" : "INFO";
  return `${tag}  [${f.code}] ${f.message}`;
}

export function sortFindings(findings) {
  const rank = { error: 0, warning: 1, info: 2 };
  return [...findings].sort((a, b) => (rank[a.severity] - rank[b.severity]) || a.code.localeCompare(b.code) || a.subject.localeCompare(b.subject));
}
