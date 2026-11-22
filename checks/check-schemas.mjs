// Validates every policy, ledger and environment file against its JSON schema (policy/schemas).
// Usage: node checks/check-schemas.mjs [--json]
// Read-only. Standard library only. Messages name the path and rule, never the value.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_ROOT, readJson } from "./lib/env.mjs";
import { validate } from "./lib/schema.mjs";
import { validateProfiles } from "./lib/environments.mjs";
import { createFinding, renderFinding, summarize } from "./lib/findings.mjs";

export const SCHEMA_BINDINGS = [
  { file: "policy/approved-dependencies.json", schema: "approved-dependencies.schema.json", required: true },
  { file: "policy/install-import-policy.json", schema: "install-import-policy.schema.json", required: true },
  { file: "policy/install-import-approvals.json", schema: "approval-records.schema.json", required: true },
  { file: "policy/data-locality-policy.json", schema: "data-locality-policy.schema.json", required: true },
  { file: "policy/audit-policy.json", schema: "audit-policy.schema.json", required: true },
  { file: "policy/approval-requests.json", schema: "approval-requests.schema.json", required: false },
  { file: "policy/history/ledger.json", schema: "history-ledger.schema.json", required: false },
];

export function run() {
  const findings = [];
  const lines = [];
  for (const binding of SCHEMA_BINDINGS) {
    const full = join(CONFIG_ROOT, binding.file);
    if (!existsSync(full)) {
      if (binding.required) findings.push(createFinding({ code: "SCHEMA-INVALID", subject: binding.file, file: binding.file, message: `${binding.file} is missing` }));
      else lines.push(`SKIP  ${binding.file} (not present)`);
      continue;
    }
    let doc;
    try { doc = readJson(full); } catch (e) {
      findings.push(createFinding({ code: "SCHEMA-INVALID", subject: binding.file, file: binding.file, message: `${binding.file} is not valid JSON` }));
      continue;
    }
    const schema = readJson(join(CONFIG_ROOT, "policy", "schemas", binding.schema));
    const errors = validate(schema, doc);
    for (const e of errors) findings.push(createFinding({ code: "SCHEMA-INVALID", subject: `${binding.file}${e.path}`, file: binding.file, message: `${binding.file} ${e.path}: ${e.message}` }));
    lines.push(`${errors.length ? "FAIL" : "PASS"}  ${binding.file} (${binding.schema})`);
  }
  for (const { name, errors } of validateProfiles()) {
    for (const e of errors) findings.push(createFinding({ code: "ENV-INVALID", subject: `environments/${name}.json${e.path}`, file: `environments/${name}.json`, message: `environments/${name}.json ${e.path}: ${e.message}` }));
    lines.push(`${errors.length ? "FAIL" : "PASS"}  environments/${name}.json (environment.schema.json)`);
  }
  for (const f of findings) lines.push(renderFinding(f));
  const summary = summarize(findings);
  lines.push(summary.gate === "pass" ? "schemas: PASS" : `schemas: FAIL (${summary.bySeverity.error} error(s))`);
  return { ok: summary.gate === "pass", lines, findings, summary };
}

if (process.argv[1]?.endsWith("check-schemas.mjs")) {
  const result = run();
  console.log(process.argv.includes("--json") ? JSON.stringify({ check: "schemas", summary: result.summary, findings: result.findings }, null, 2) : result.lines.join("\n"));
  process.exitCode = result.ok ? 0 : 1;
}
