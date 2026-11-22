// Dependency approval engine. Standard library only.
//
// Responsibilities:
//   - validate owner approval records (policy/install-import-approvals.json and the inline copy in
//     policy/install-import-policy.json approvalRecords) and report missing fields, duplicates and conflicts
//   - check that every approval id cited by the policy (images, tools, snapshot) resolves to a record
//   - match dependency findings to approval records that explicitly cover them ("covers" selectors), so an approved
//     but not yet snapshotted change is explained instead of looking unapproved
//   - create pending approval requests for the owner and, only when the owner runs it explicitly, record an approval
//
// Agents never approve. recordApproval() refuses to run without an explicit owner confirmation flag, and policy intent
// (rules, approved image list) is never changed here.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createFinding } from "./findings.mjs";

export const REQUIRED_RECORD_FIELDS = ["id", "date", "what", "why", "approver"];
export const REQUESTS_SCHEMA = "asaa.configuration.approval-requests.v1";

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const RECORD_ID = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/;

// Validates a list of records. source names the file for messages.
export function validateRecords(records, source) {
  const findings = [];
  const seen = new Map();
  for (const [index, rec] of (records ?? []).entries()) {
    const subject = rec?.id ?? `${source}#${index}`;
    const missing = REQUIRED_RECORD_FIELDS.filter((f) => typeof rec?.[f] !== "string" || rec[f].trim() === "");
    if (missing.length) {
      findings.push(createFinding({ code: "APR-RECORD-INVALID", subject, file: source, message: `approval record ${subject} in ${source} is missing ${missing.join(", ")}`, remediation: "complete the record; approvals without every required field are not valid (IIP-1)" }));
    }
    if (rec?.date && !ISO_DATE.test(rec.date)) {
      findings.push(createFinding({ code: "APR-RECORD-INVALID", subject: `${subject}:date`, file: source, message: `approval record ${subject} date is not YYYY-MM-DD` }));
    }
    if (rec?.id && !RECORD_ID.test(rec.id)) {
      findings.push(createFinding({ code: "APR-RECORD-INVALID", severity: "warning", subject: `${subject}:id`, file: source, message: `approval record id ${rec.id} does not follow the PREFIX-... upper-case id format` }));
    }
    if (rec?.covers !== undefined && !Array.isArray(rec.covers)) {
      findings.push(createFinding({ code: "APR-RECORD-INVALID", subject: `${subject}:covers`, file: source, message: `approval record ${subject} covers must be a list of selectors` }));
    }
    if (rec?.id) {
      if (seen.has(rec.id)) findings.push(createFinding({ code: "APR-RECORD-DUPLICATE", subject: rec.id, file: source, message: `approval id ${rec.id} appears more than once in ${source}` }));
      seen.set(rec.id, rec);
    }
  }
  return findings;
}

const comparable = (rec) => JSON.stringify(REQUIRED_RECORD_FIELDS.map((f) => (rec[f] ?? "").trim()));

// Compares the authoritative record file with the inline copy in the install policy. Differences are conflicts the
// owner must resolve; neither copy is changed automatically.
export function compareRecordSources(primary, inline) {
  const findings = [];
  const byId = new Map((primary ?? []).map((r) => [r.id, r]));
  for (const rec of inline ?? []) {
    const other = byId.get(rec.id);
    if (!other) {
      findings.push(createFinding({ code: "APR-RECORD-CONFLICT", severity: "warning", subject: rec.id, file: "policy/install-import-policy.json", message: `approval ${rec.id} is listed inline in install-import-policy.json but not in install-import-approvals.json`, remediation: "record the approval in policy/install-import-approvals.json (the authoritative record file)" }));
      continue;
    }
    if (comparable(rec) !== comparable(other)) {
      const differing = REQUIRED_RECORD_FIELDS.filter((f) => (rec[f] ?? "").trim() !== (other[f] ?? "").trim());
      findings.push(createFinding({ code: "APR-RECORD-CONFLICT", severity: "warning", subject: rec.id, file: "policy/install-import-policy.json", message: `approval ${rec.id} differs between install-import-approvals.json and install-import-policy.json (fields: ${differing.join(", ")})`, explanation: "The two copies of the same approval record are not identical. The record file is treated as authoritative; the owner decides which wording is correct.", data: { differingFields: differing } }));
    }
  }
  return findings;
}

// Every approval id cited by the policy must resolve to a record.
export function checkCitedApprovals({ install, snapshot, records }) {
  const findings = [];
  const known = new Set((records ?? []).map((r) => r.id));
  const cite = (id, where) => {
    if (!id || known.has(id)) return;
    findings.push(createFinding({ code: "APR-REFERENCE-MISSING", severity: "warning", subject: `${id}@${where}`, file: "policy/install-import-policy.json", message: `${where} cites approval ${id}, which has no record in install-import-approvals.json`, explanation: "The approval is referenced but cannot be audited from the record file. It may predate the record file.", remediation: "the owner adds a record with id, date, what, why and approver for this approval" }));
  };
  for (const img of install?.approvedDockerImages ?? []) cite(img.approvalId, `approved image ${img.image}`);
  for (const tool of install?.approvedTools ?? []) cite(tool.approvalId, `approved tool ${tool.tool}`);
  if (snapshot) {
    if (!snapshot.approvalId) findings.push(createFinding({ code: "APR-REFERENCE-MISSING", subject: "snapshot", file: "policy/approved-dependencies.json", message: "the dependency snapshot does not cite an approval id (IIP-5)" }));
    else cite(snapshot.approvalId, "dependency snapshot");
  }
  return findings;
}

// Approved image list consistency: the same image must not be approved twice under different records.
export function checkImageApprovalConflicts(install) {
  const findings = [];
  const byImage = new Map();
  for (const img of install?.approvedDockerImages ?? []) {
    const ids = byImage.get(img.image) ?? new Set();
    ids.add(img.approvalId);
    byImage.set(img.image, ids);
  }
  for (const [image, ids] of byImage) {
    if (ids.size > 1) findings.push(createFinding({ code: "APR-IMAGE-CONFLICT", severity: "warning", subject: image, message: `image ${image} is approved under several records: ${[...ids].join(", ")}` }));
  }
  return findings;
}

// A selector matches a dependency record when every field it names is equal. "name" may end with "*" for a prefix.
export function selectorMatches(selector, rec) {
  if (!selector || typeof selector !== "object") return false;
  if (selector.inventoryId) return selector.inventoryId === rec.id;
  for (const field of ["repo", "ecosystem", "manifest", "section"]) {
    if (selector[field] !== undefined && selector[field] !== rec[field]) return false;
  }
  if (selector.name !== undefined) {
    if (selector.name.endsWith("*")) { if (!rec.name.startsWith(selector.name.slice(0, -1))) return false; }
    else if (selector.name !== rec.name) return false;
  }
  if (selector.spec !== undefined && !(rec.specs ?? []).includes(selector.spec)) return false;
  return Object.keys(selector).some((k) => ["repo", "ecosystem", "manifest", "section", "name", "spec"].includes(k));
}

export function findCoveringRecord(records, rec) {
  return (records ?? []).find((r) => Array.isArray(r.covers) && r.covers.some((s) => selectorMatches(s, rec))) ?? null;
}

// Pending requests -------------------------------------------------------------------------------------------------

export function loadRequests(path) {
  if (!existsSync(path)) return { schema: REQUESTS_SCHEMA, requests: [] };
  return JSON.parse(readFileSync(path, "utf8"));
}

// Builds a request for the owner from dependency or image findings. A request is not an approval.
export function buildApprovalRequest(findings, { requestedBy, reason, now = new Date() }) {
  const items = findings
    .filter((f) => ["dependency", "image"].includes(f.category))
    .map((f) => ({ findingId: f.id, code: f.code, inventoryId: f.inventoryId, repo: f.repo, subject: f.subject, ownerAction: f.ownerAction }));
  if (items.length === 0) return null;
  const digest = createHash("sha256").update(JSON.stringify(items)).digest("hex").slice(0, 8).toUpperCase();
  const date = now.toISOString().slice(0, 10);
  return {
    id: `REQ-${date.replace(/-/g, "")}-${digest}`,
    status: "pending-owner",
    createdAt: now.toISOString(),
    requestedBy: requestedBy ?? "automation",
    reason: reason ?? "dependency or image changes detected by check-dependency-approval",
    items,
    // Suggested covers selectors the owner can copy into an approval record if they approve.
    suggestedCovers: items.filter((i) => i.inventoryId).map((i) => ({ inventoryId: i.inventoryId })),
  };
}

export function addRequest(path, request) {
  const store = loadRequests(path);
  if (store.requests.some((r) => r.id === request.id)) return { added: false, store };
  store.requests.push(request);
  writeFileSync(path, JSON.stringify(store, null, 2) + "\n");
  return { added: true, store };
}

export function pendingRequestFindings(store) {
  return (store.requests ?? []).filter((r) => r.status === "pending-owner").map((r) => createFinding({
    code: "APR-REQUEST-PENDING", severity: "info", subject: r.id, file: "policy/approval-requests.json",
    message: `approval request ${r.id} (${r.items.length} item(s)) is waiting for an owner decision`,
  }));
}

// Owner-only recording --------------------------------------------------------------------------------------------

// Appends an approval record to the record file. Requires ownerConfirmed=true, which the CLI only sets when the
// owner passes --owner-confirmed. Marks a matching pending request as approved.
export function recordApproval({ approvalsPath, requestsPath, record, ownerConfirmed, requestId }) {
  if (ownerConfirmed !== true) return { ok: false, error: "recording an approval requires explicit owner confirmation (--owner-confirmed)" };
  const store = JSON.parse(readFileSync(approvalsPath, "utf8"));
  const problems = validateRecords([record], "new record").filter((f) => f.severity === "error");
  if (problems.length) return { ok: false, error: problems.map((p) => p.message).join("; ") };
  if ((store.records ?? []).some((r) => r.id === record.id)) return { ok: false, error: `approval id ${record.id} already exists` };
  store.records = [...(store.records ?? []), record];
  writeFileSync(approvalsPath, JSON.stringify(store, null, 2) + "\n");
  if (requestId && requestsPath && existsSync(requestsPath)) {
    const requests = loadRequests(requestsPath);
    const req = requests.requests.find((r) => r.id === requestId);
    if (req) {
      req.status = "approved";
      req.decidedBy = record.approver;
      req.decidedAt = record.date;
      req.approvalId = record.id;
      writeFileSync(requestsPath, JSON.stringify(requests, null, 2) + "\n");
    }
  }
  return { ok: true };
}
