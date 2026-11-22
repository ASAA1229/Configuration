// Configuration command-line interface. Standard library only.
//
//   report   [--env <name>] [--out <file>]           full machine-readable policy report (JSON)
//   env      list | resolve <name>                     environment profiles (secret references are never resolved)
//   inventory [--json]                                 current dependency inventory with stable record ids
//   image    classify <reference>                      immutability classification of one image reference
//   approvals validate                                 approval record findings only
//   approvals request [--requested-by <who>] [--reason <text>]
//                                                      record a pending owner approval request (not an approval)
//   approvals record --id <id> --approver <who> --what <text> --why <text> [--date YYYY-MM-DD]
//                    [--request <REQ-id>] --owner-confirmed
//                                                      OWNER ONLY: append an approval record; covers are taken from
//                                                      the request's suggested selectors when --request is given
//   history  list <file> | verify | diff <file> <commit> [<commit>] | record <file> --reason <text> [--actor <who>]
//            rollback <file> <commit> --approval-id <id> --reason <text> [--actor <who>]
//
// Exit codes: 0 success / gate pass, 1 gate fail or refused operation, 2 usage error.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { runAll } from "./check-all.mjs";
import { collectAll, evaluate, requestApproval } from "./check-dependency-approval.mjs";
import { CONFIG_ROOT, readJson } from "./lib/env.mjs";
import { buildInventory } from "./lib/inventory.mjs";
import { classifyImageRef } from "./lib/docker-ref.mjs";
import { defaultEnvironmentName, listEnvironments, resolveEnvironment } from "./lib/environments.mjs";
import { loadRequests, recordApproval } from "./lib/approvals.mjs";
import { TRACKED_FILES, appendEntry, jsonDiff, listVersions, loadLedger, readVersion, rollback, verifyLedger } from "./lib/history.mjs";

const APPROVALS_PATH = join(CONFIG_ROOT, "policy", "install-import-approvals.json");
const REQUESTS_PATH = join(CONFIG_ROOT, "policy", "approval-requests.json");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const positional = argv.filter((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1].startsWith("--") && !["--json", "--owner-confirmed"].includes(argv[i - 1])));
const print = (value) => console.log(typeof value === "string" ? value : JSON.stringify(value, null, 2));

function usage(message) {
  if (message) console.error(message);
  console.error("usage: node checks/config-cli.mjs <report|env|inventory|image|approvals|history> ... (see header of this file)");
  process.exitCode = 2;
}

function requireTracked(file) {
  if (!TRACKED_FILES.includes(file)) { usage(`${file} is not a tracked configuration file: ${TRACKED_FILES.join(", ")}`); return false; }
  return true;
}

const [command, sub, ...rest] = positional;

switch (command) {
  case "report": {
    const report = runAll(opt("--env") ?? defaultEnvironmentName());
    print(report);
    process.exitCode = report.gate === "pass" ? 0 : 1;
    break;
  }
  case "env": {
    if (sub === "list") print(listEnvironments());
    else if (sub === "resolve" && rest[0]) {
      const r = resolveEnvironment(rest[0]);
      print(r);
      process.exitCode = r.ok ? 0 : 1;
    } else usage("env list | env resolve <name>");
    break;
  }
  case "inventory": {
    const records = [...buildInventory(collectAll()).values()];
    if (flag("--json")) print({ schema: "asaa.configuration.dependency-inventory.v1", records });
    else for (const r of records) console.log(`${r.id}  ${r.repo} ${r.ecosystem} ${r.manifest} [${r.section}] ${r.name}${r.specs[0] ? ` ${r.specs.join(" | ")}` : ""}${r.occurrences > 1 ? ` x${r.occurrences}` : ""}`);
    break;
  }
  case "image": {
    if (sub !== "classify" || !rest[0]) { usage("image classify <reference>"); break; }
    const c = classifyImageRef(rest.join(" "));
    print({ reference: c.ref.raw, level: c.level, pinned: c.pinned, reason: c.reason, registry: c.ref.registry, repository: c.ref.repository, tag: c.ref.tag, digest: c.ref.digest });
    process.exitCode = c.pinned ? 0 : 1;
    break;
  }
  case "approvals": {
    if (sub === "validate") {
      const result = evaluate();
      const approvals = result.findings.filter((f) => f.category === "approval");
      print({ findings: approvals });
      process.exitCode = approvals.some((f) => f.severity === "error") ? 1 : 0;
    } else if (sub === "request") {
      const { request, added } = requestApproval({ requestedBy: opt("--requested-by"), reason: opt("--reason") });
      print(request ? { added, request } : { added: false, message: "no dependency or image findings: nothing to request" });
    } else if (sub === "record") {
      const requestId = opt("--request");
      let covers;
      if (requestId) {
        const req = loadRequests(REQUESTS_PATH).requests.find((r) => r.id === requestId);
        if (!req) { console.error(`request ${requestId} not found`); process.exitCode = 1; break; }
        if (req.status !== "pending-owner") { console.error(`request ${requestId} is ${req.status}`); process.exitCode = 1; break; }
        covers = req.suggestedCovers;
      }
      const record = {
        id: opt("--id"), date: opt("--date") ?? new Date().toISOString().slice(0, 10), approver: opt("--approver"), what: opt("--what"), why: opt("--why"),
        ...(covers?.length ? { covers } : {}),
      };
      const result = recordApproval({ approvalsPath: APPROVALS_PATH, requestsPath: REQUESTS_PATH, record, ownerConfirmed: flag("--owner-confirmed"), requestId });
      if (!result.ok) { console.error(`refused: ${result.error}`); process.exitCode = 1; break; }
      appendEntry({ file: "policy/install-import-approvals.json", action: "approval", reason: `approval ${record.id} recorded`, approvalId: record.id, actor: record.approver });
      if (requestId && existsSync(REQUESTS_PATH)) appendEntry({ file: "policy/approval-requests.json", action: "approval", reason: `request ${requestId} approved by ${record.id}`, approvalId: record.id, actor: record.approver });
      print({ recorded: record.id, covers: covers?.length ?? 0, next: `node checks/check-dependency-approval.mjs --snapshot --approval-id ${record.id}` });
    } else usage("approvals validate | request | record");
    break;
  }
  case "history": {
    if (sub === "verify") {
      const ledger = loadLedger();
      const v = verifyLedger(ledger);
      print({ entries: ledger.entries.length, ...v });
      process.exitCode = v.ok ? 0 : 1;
    } else if (sub === "list" && rest[0]) {
      if (!requireTracked(rest[0])) break;
      const ledger = loadLedger();
      print({ file: rest[0], commits: listVersions(rest[0]), ledger: ledger.entries.filter((e) => e.file === rest[0]) });
    } else if (sub === "diff" && rest[0] && rest[1]) {
      if (!requireTracked(rest[0])) break;
      const before = JSON.parse(readVersion(rest[0], rest[1]));
      const after = rest[2] ? JSON.parse(readVersion(rest[0], rest[2])) : JSON.parse(readFileSync(join(CONFIG_ROOT, rest[0]), "utf8"));
      print({ file: rest[0], from: rest[1], to: rest[2] ?? "working tree", changes: jsonDiff(before, after) });
    } else if (sub === "record" && rest[0]) {
      if (!requireTracked(rest[0])) break;
      const reason = opt("--reason");
      if (!reason) { usage("history record <file> --reason <text>"); break; }
      print(appendEntry({ file: rest[0], action: "record", reason, actor: opt("--actor") ?? "owner", approvalId: opt("--approval-id") ?? null }));
    } else if (sub === "rollback" && rest[0] && rest[1]) {
      if (!requireTracked(rest[0])) break;
      const records = readJson(APPROVALS_PATH).records ?? [];
      const result = rollback({ file: rest[0], commit: rest[1], approvalId: opt("--approval-id"), approvalIds: new Set(records.map((r) => r.id)), actor: opt("--actor") ?? "owner", reason: opt("--reason") });
      if (!result.ok) { console.error(`refused: ${result.error}`); process.exitCode = 1; break; }
      print({ rolledBack: rest[0], toCommit: rest[1], ledgerEntry: result.entry.seq, next: "review the change, run check-all, and commit it through the normal branch flow" });
    } else usage("history verify | list <file> | diff <file> <commit> [<commit>] | record <file> --reason | rollback <file> <commit> --approval-id --reason");
    break;
  }
  default:
    usage(command ? `unknown command ${command}` : undefined);
}
