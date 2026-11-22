// Dependency and image approval check (policy/install-import-policy.json).
//   --snapshot --approval-id <id> : records every npm, Python and Docker dependency found in the four project
//                                   repositories and this configuration project into policy/approved-dependencies.json.
//                                   The id must match a record in policy/install-import-approvals.json.
//   (default)                     : compares the current state with the snapshot and fails on any new or changed
//                                   dependency, and on any Docker image that is unapproved or not pinned to a version or digest.
//   --json                        : prints the machine-readable findings and snapshot difference instead of text.
//   --request [--requested-by <who>] [--discrepancies]
//                                 : records a pending owner request for the current dependency/image findings, or with
//                                   --discrepancies for approval-record conflicts and missing approval records
//                                   (policy/approval-requests.json). A request is not an approval or a resolution.
//
// Every finding is classified (lib/findings.mjs), linked to a dependency inventory record id and explained. An
// approval record whose "covers" selectors match a finding marks it approved-but-not-snapshotted; it still fails until
// the snapshot is refreshed (IIP-5). Policy intent and approvals are never changed by this check.
// Read-only against the project repositories. Standard library only.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, readJson, walkFiles } from "./lib/env.mjs";
import { classifyImageRef, isFixedTag, tagVariableName } from "./lib/docker-ref.mjs";
import { diffSnapshot, inventoryId } from "./lib/inventory.mjs";
import { createFinding, renderFinding, sortFindings, summarize } from "./lib/findings.mjs";
import {
  addRequest, annotateWithRequests, buildApprovalRequest, buildDiscrepancyRequest, checkCitedApprovals,
  checkImageApprovalConflicts, compareRecordSources, findCoveringRecord, loadRequests, pendingRequestFindings,
  syncDiscrepancyRequests, validateRecords,
} from "./lib/approvals.mjs";
import { appendEntry } from "./lib/history.mjs";

const SNAPSHOT_PATH = join(CONFIG_ROOT, "policy", "approved-dependencies.json");
const INSTALL_POLICY_PATH = join(CONFIG_ROOT, "policy", "install-import-policy.json");
const APPROVALS_PATH = join(CONFIG_ROOT, "policy", "install-import-approvals.json");
const REQUESTS_PATH = join(CONFIG_ROOT, "policy", "approval-requests.json");

const ALL_REPOS = [...PROJECT_REPOS, { name: "configuration", path: CONFIG_ROOT }];
const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const TEMPLATE_LOCAL_IMAGE = "templates-local-prod:${TEMPLATES_IMAGE_TAG:?set by common.ps1 (version-derived tag)}";

function collectNpm(repo) {
  const found = [];
  for (const file of walkFiles(repo.path, (name) => name === "package.json")) {
    const manifest = readJson(file);
    for (const section of NPM_SECTIONS) {
      for (const [name, spec] of Object.entries(manifest[section] ?? {})) {
        found.push({ repo: repo.name, ecosystem: "npm", manifest: relative(repo.path, file).replace(/\\/g, "/"), section, name, spec: String(spec) });
      }
    }
  }
  return found;
}

// PEP 508 strings: name, optional extras, then version specifier.
function parsePep508(item) {
  const m = /^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$/.exec(item);
  return m ? { name: m[1], spec: `${m[2] ?? ""}${m[3] ?? ""}`.trim() } : null;
}

function collectPython(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => name === "pyproject.toml" || /^requirements.*\.txt$/.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8").replace(/^﻿/, "");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    if (basename(file) === "pyproject.toml") {
      // [project] dependencies = [ ... ] (possibly multi-line)
      for (const block of text.matchAll(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/gm)) {
        for (const item of block[1].matchAll(/"([^"]+)"/g)) {
          const dep = parsePep508(item[1]);
          if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: "dependencies", name: dep.name, spec: dep.spec });
        }
      }
      // [project.optional-dependencies] groups: name = [ ... ]
      const optional = /\[project\.optional-dependencies\]([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text);
      if (optional) {
        for (const block of optional[1].matchAll(/^\s*([A-Za-z0-9_.-]+)\s*=\s*\[([\s\S]*?)\]/gm)) {
          for (const item of block[2].matchAll(/"([^"]+)"/g)) {
            const dep = parsePep508(item[1]);
            if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: `optional:${block[1]}`, name: dep.name, spec: dep.spec });
          }
        }
      }
    } else {
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.split("#")[0].trim();
        if (!line || line.startsWith("-")) continue;
        const dep = parsePep508(line);
        if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: "requirements", name: dep.name, spec: dep.spec });
      }
    }
  }
  return found;
}

function collectDocker(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => /^(Dockerfile(\..*)?|docker-compose.*\.ya?ml|compose.*\.ya?ml)$/i.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8").replace(/^﻿/, "");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    if (/^Dockerfile/i.test(basename(file))) {
      const stages = new Set();
      for (const m of text.matchAll(/^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/gim)) {
        const ref = m[1];
        // A FROM that names an earlier build stage is not an image.
        if (!stages.has(ref.toLowerCase())) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "FROM", name: ref });
        if (m[2]) stages.add(m[2].toLowerCase());
      }
    } else {
      for (const line of text.split(/\r?\n/)) {
        const image = parseComposeImage(line);
        if (image) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "image", name: image });
      }
    }
  }
  return found;
}

export function parseComposeImage(line) {
  const match = /^\s*image:\s*(?:"([^"]*)"|'([^']*)'|(.+?))\s*(?:#.*)?$/i.exec(line);
  return (match?.[1] ?? match?.[2] ?? match?.[3] ?? "").trim() || null;
}

export function collectAll() {
  const items = [];
  for (const repo of ALL_REPOS) {
    if (!existsSync(repo.path)) continue;
    items.push(...collectNpm(repo), ...collectPython(repo), ...collectDocker(repo));
  }
  return items.sort((a, b) => `${a.repo}|${a.ecosystem}|${a.manifest}|${a.name}|${a.section}`.localeCompare(`${b.repo}|${b.ecosystem}|${b.manifest}|${b.name}|${b.section}`));
}

// Compatibility wrapper kept for existing callers and tests: true when the reference is pinned (IIP-3).
export function isExactDockerTag(image, { versionDerivedTemplateTag = false } = {}) {
  const trusted = versionDerivedTemplateTag ? new Set([TEMPLATE_LOCAL_IMAGE]) : new Set();
  return classifyImageRef(image, { trustedRequiredTags: trusted }).pinned;
}

function hasVersionDerivedTemplateTagSource() {
  const templates = PROJECT_REPOS.find((repo) => repo.name === "Templates");
  if (!templates) return false;
  const sourcePath = join(templates.path, "deploy", "local-prod", "common.ps1");
  if (!existsSync(sourcePath)) return false;
  const source = readFileSync(sourcePath, "utf8");
  return source.includes("function Get-ImageVersionTag")
    && source.includes('return "$version-$sha"')
    && source.includes("$env:TEMPLATES_IMAGE_TAG = if ($runningTag) { $runningTag } else { Get-ImageVersionTag }");
}

function loadRecords() {
  return existsSync(APPROVALS_PATH) ? readJson(APPROVALS_PATH).records ?? [] : [];
}

function requireApproval(approvalId) {
  if (!approvalId) return "snapshot requires --approval-id <id> (see policy/install-import-approvals.json)";
  if (!existsSync(APPROVALS_PATH)) return `no approval record file at policy/install-import-approvals.json`;
  const rec = loadRecords().find((r) => r.id === approvalId);
  if (!rec) return `approval id ${approvalId} not found`;
  for (const f of ["id", "date", "what", "why", "approver"]) if (!rec[f]) return `approval ${approvalId} is missing field ${f}`;
  return null;
}

export function snapshot(approvalId, { actor = "owner" } = {}) {
  const problem = requireApproval(approvalId);
  if (problem) return { ok: false, lines: [`snapshot refused: ${problem}`] };
  const items = collectAll();
  const previous = existsSync(SNAPSHOT_PATH) ? readJson(SNAPSHOT_PATH) : null;
  const diff = previous ? diffSnapshot(previous.dependencies ?? [], items) : null;
  const body = {
    schema: "asaa.configuration.approved-dependencies.v2",
    description: "Owner-approved baseline of every npm, Python and Docker dependency in the ASAA project repositories at the time of this snapshot. Any later addition or change fails checks/check-dependency-approval.mjs until the owner approves it (policy/install-import-policy.json) and the snapshot is refreshed.",
    generatedBy: "checks/check-dependency-approval.mjs --snapshot --approval-id",
    approvalId,
    counts: items.reduce((acc, d) => ({ ...acc, [d.ecosystem]: (acc[d.ecosystem] ?? 0) + 1 }), {}),
    dependencies: items,
  };
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(body, null, 2) + "\n");
  const details = diff
    ? { added: diff.added.length, removed: diff.removed.length, specChanged: diff.specChanged.length, occurrenceChanged: diff.occurrenceChanged.length, entries: items.length }
    : { entries: items.length };
  appendEntry({ file: "policy/approved-dependencies.json", action: "snapshot", reason: "dependency snapshot refreshed", approvalId, actor, details });
  return { ok: true, lines: [`snapshot written: ${items.length} entries (approval ${approvalId})`, `counts: ${JSON.stringify(body.counts)}`, ...(diff ? [`changes captured: ${JSON.stringify(details)}`] : [])] };
}

// Full evaluation. Returns { ok, findings, diff, summary }.
export function evaluate() {
  const findings = [];
  if (!existsSync(SNAPSHOT_PATH)) {
    findings.push(createFinding({ code: "APR-REFERENCE-MISSING", subject: "snapshot", file: "policy/approved-dependencies.json", message: "no approved dependency snapshot exists; the owner must create one with --snapshot --approval-id <id>" }));
    return { ok: false, findings, diff: null, summary: summarize(findings) };
  }
  const snapshotDoc = readJson(SNAPSHOT_PATH);
  const install = readJson(INSTALL_POLICY_PATH);
  const records = loadRecords();
  const current = collectAll();
  const diff = diffSnapshot(snapshotDoc.dependencies ?? [], current);

  // Approval record integrity and cross-references.
  findings.push(...validateRecords(records, "policy/install-import-approvals.json"));
  findings.push(...compareRecordSources(records, install.approvalRecords));
  findings.push(...checkCitedApprovals({ install, snapshot: snapshotDoc, records }));
  findings.push(...checkImageApprovalConflicts(install));

  const withCoverage = (rec, base) => {
    const covering = findCoveringRecord(records, rec);
    if (!covering) return base;
    return {
      ...base,
      explanation: `${base.explanation ?? ""} Approval ${covering.id} covers this change; refresh the snapshot with that approval id to clear it (IIP-5).`.trim(),
      data: { ...(base.data ?? {}), coveredBy: covering.id },
    };
  };

  for (const a of diff.added) {
    findings.push(createFinding(withCoverage(a.record, {
      code: "DEP-NEW", repo: a.record.repo, inventoryId: a.record.id, subject: a.label, file: a.record.manifest,
      message: `NEW      ${a.label}${a.record.specs[0] ? ` ${a.record.specs[0]}` : ""}`,
      explanation: "This dependency is not in the approved snapshot.",
      remediation: "remove it, or the owner records an approval (IIP-1) and the snapshot is refreshed (IIP-5)",
      data: { specs: a.record.specs, occurrences: a.record.occurrences },
    })));
  }
  for (const c of diff.specChanged) {
    findings.push(createFinding(withCoverage(c.record, {
      code: "DEP-SPEC-CHANGED", repo: c.record.repo, inventoryId: c.record.id, subject: c.label, file: c.record.manifest,
      message: `CHANGED  ${c.label} (approved spec differs)`,
      explanation: "The dependency is approved, but its version specifier differs from the snapshot.",
      remediation: "revert to the approved specifier, or the owner approves the change and the snapshot is refreshed",
      data: { approvedSpecs: c.approvedSpecs, currentSpecs: c.currentSpecs },
    })));
  }
  for (const r of diff.removed) {
    findings.push(createFinding({
      code: "DEP-REMOVED", severity: "info", repo: r.record.repo, inventoryId: r.record.id, subject: r.label, file: r.record.manifest,
      message: `REMOVED  ${r.label} (no longer collected)`,
      explanation: "Removing a dependency needs no approval, but the snapshot still lists it until it is refreshed.",
    }));
  }
  for (const o of diff.occurrenceChanged) {
    findings.push(createFinding({
      code: "DEP-OCCURRENCE-CHANGED", severity: "info", repo: o.record.repo, inventoryId: o.record.id, subject: o.label, file: o.record.manifest,
      message: `COUNT    ${o.label} occurs ${o.currentOccurrences} time(s), snapshot has ${o.approvedOccurrences}`,
      explanation: "Same dependency and version, used a different number of times (for example by another Compose service). This changes entry totals without changing what is approved.",
    }));
  }

  // Docker images: approved list (IIP-4) and immutable or exact reference (IIP-3).
  const approvedImages = new Set(install.approvedDockerImages.map((i) => i.image));
  const trusted = hasVersionDerivedTemplateTagSource() ? new Set([TEMPLATE_LOCAL_IMAGE]) : new Set();
  const seen = new Set();
  for (const d of current.filter((x) => x.ecosystem === "docker")) {
    const id = `${d.repo} ${d.name}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const cls = classifyImageRef(d.name, { trustedRequiredTags: trusted });
    const invId = inventoryId(d);
    if (cls.level === "invalid") {
      findings.push(createFinding({ code: "IMG-INVALID", repo: d.repo, inventoryId: invId, file: d.manifest, subject: id, message: `INVALID    ${d.repo}: image ${d.name} (${cls.reason})`, remediation: "correct the image reference" }));
    } else if (!cls.pinned) {
      findings.push(createFinding({ code: "IMG-UNPINNED", repo: d.repo, inventoryId: invId, file: d.manifest, subject: id, message: `UNPINNED   ${d.repo}: image ${d.name} (exact tag or digest required, see IIP-3)`, explanation: cls.reason, remediation: "pin the image to an exact version tag or sha256 digest", data: { level: cls.level } }));
    }
    // A tag supplied by a variable is only as fixed as every value the repository assigns to that variable: an env file
    // that sets it to "latest" or a floating tag makes the image mutable (IIP-3).
    const tagVar = cls.level === "conditional" ? tagVariableName(d.name) : null;
    if (tagVar) {
      const repo = ALL_REPOS.find((r) => r.name === d.repo);
      for (const o of repo ? envOverrides(repo.path, tagVar) : []) {
        if (o.value === "" || isFixedTag(o.value)) continue;
        findings.push(createFinding({ code: "IMG-UNPINNED", repo: d.repo, inventoryId: invId, file: o.file, subject: `${id} ${tagVar}@${o.file}`, message: `UNPINNED   ${d.repo}: ${o.file} sets ${tagVar}=${o.value}, so image ${d.name} resolves to a tag that is not exact (IIP-3)`, remediation: `set ${tagVar} to an exact version tag or remove the override`, data: { variable: tagVar, value: o.value } }));
      }
    }
    if (!approvedImages.has(d.name)) {
      findings.push(createFinding({ code: "IMG-NOT-APPROVED", repo: d.repo, inventoryId: invId, file: d.manifest, subject: id, message: `NOT APPROVED ${d.repo}: image ${d.name} (owner approval record required, see IIP-4)`, remediation: "the owner approves the image and adds it to approvedDockerImages, or the reference is changed to an approved image", data: { level: cls.level } }));
    }
  }

  const requests = loadRequests(REQUESTS_PATH);
  findings.push(...pendingRequestFindings(requests));
  const sorted = sortFindings(annotateWithRequests(findings, requests));
  const summary = summarize(sorted);
  return { ok: summary.gate === "pass", findings: sorted, diff, summary };
}

// Values assigned to a variable in the repository's env files (.env, .env.*, *.env), commented lines excluded.
const envFileCache = new Map();
function envOverrides(root, name) {
  const out = [];
  // One directory walk per repository, however many variable-tagged images it has.
  if (!envFileCache.has(root)) envFileCache.set(root, walkFiles(root, (entry) => /^\.env(\..+)?$|\.env$|\.env\.(example|sample|template|dist)$/i.test(entry)));
  const files = envFileCache.get(root);
  for (const file of files) {
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (m && m[1] === name) out.push({ file: relative(root, file).split("\\").join("/"), value: m[2].trim().replace(/^["']|["']$/g, "") });
    }
  }
  return out;
}

export function run() {
  const result = evaluate();
  const lines = [];
  if (result.diff) {
    const t = result.diff.totals;
    lines.push(`approved entries: ${t.approvedEntries}, current entries: ${t.currentEntries}, removed since snapshot: ${result.diff.removed.length}`);
    lines.push(`inventory records: approved ${t.approvedRecords}, current ${t.currentRecords}; entry delta explained by added ${t.explainedDelta.added}, removed ${t.explainedDelta.removed}, occurrence ${t.explainedDelta.occurrence}, spec change ${t.explainedDelta.specChange}${t.unexplainedDelta ? `, UNEXPLAINED ${t.unexplainedDelta}` : ""}`);
  }
  for (const f of result.findings) if (f.severity !== "info" || f.category === "dependency") lines.push(renderFinding(f));
  const errors = result.summary.bySeverity.error;
  lines.push(errors === 0 ? "dependency-approval: PASS" : `dependency-approval: FAIL (${errors} item(s))`);
  return { ok: result.ok, lines, findings: result.findings, summary: result.summary, diff: result.diff };
}

export function serialiseDiff(diff) {
  if (!diff) return null;
  const strip = (list) => list.map(({ record, ...rest }) => ({ inventoryId: record.id, repo: record.repo, ecosystem: record.ecosystem, manifest: record.manifest, section: record.section, name: record.name, ...rest }));
  return { totals: diff.totals, added: strip(diff.added), removed: strip(diff.removed), specChanged: strip(diff.specChanged), occurrenceChanged: strip(diff.occurrenceChanged), unchanged: diff.unchanged };
}

export function requestApproval({ requestedBy, reason, discrepancies = false } = {}) {
  const result = evaluate();
  const request = (discrepancies ? buildDiscrepancyRequest : buildApprovalRequest)(result.findings, { requestedBy, reason });
  if (!request) return { ok: true, request: null, added: false };
  const { added } = addRequest(REQUESTS_PATH, request);
  if (added) appendEntry({ file: "policy/approval-requests.json", action: "request", reason: `${discrepancies ? "discrepancy" : "approval"} request ${request.id} created`, actor: request.requestedBy });
  return { ok: true, request, added };
}

// Closes discrepancy request items whose finding no longer occurs (for example after the owner recorded the missing
// approval). Never closes a dependency approval request.
export function syncRequests({ actor = "automation" } = {}) {
  if (!existsSync(REQUESTS_PATH)) return { changed: [] };
  const store = loadRequests(REQUESTS_PATH);
  const changed = syncDiscrepancyRequests(store, evaluate().findings);
  if (changed.length) {
    writeFileSync(REQUESTS_PATH, JSON.stringify(store, null, 2) + "\n");
    appendEntry({ file: "policy/approval-requests.json", action: "request", reason: `discrepancy items resolved: ${changed.join(", ")}`, actor });
  }
  return { changed };
}

if (process.argv[1]?.endsWith("check-dependency-approval.mjs")) {
  const argv = process.argv;
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes("--snapshot")) {
    const result = snapshot(arg("--approval-id"), { actor: arg("--actor") ?? "owner" });
    console.log(result.lines.join("\n"));
    process.exitCode = result.ok ? 0 : 1;
  } else if (argv.includes("--request")) {
    const { request, added } = requestApproval({ requestedBy: arg("--requested-by"), reason: arg("--reason"), discrepancies: argv.includes("--discrepancies") });
    if (!request) console.log("no dependency or image findings: nothing to request");
    else console.log(added ? `approval request ${request.id} recorded with ${request.items.length} item(s) (pending owner decision)` : `approval request ${request.id} already recorded`);
  } else {
    const result = run();
    if (argv.includes("--json")) {
      console.log(JSON.stringify({ schema: "asaa.configuration.policy-findings.v1", check: "dependency-approval", summary: result.summary, diff: serialiseDiff(result.diff), findings: result.findings }, null, 2));
    } else {
      console.log(result.lines.join("\n"));
    }
    process.exitCode = result.ok ? 0 : 1;
  }
}
