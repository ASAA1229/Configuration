// Runs every configuration check and exits non-zero if any check fails.
// Usage: node checks/check-all.mjs [--env <local|ci|local-prod>] [--json] [--out <file>]
//   --env   environment profile (default: ASAA_CONFIG_ENV, else "ci" under GitHub Actions, else "local")
//   --json  print the machine-readable policy report (asaa.configuration.policy-report.v1) instead of text
//   --out   also write the JSON report to a file (for CI artifacts and the organization governance validator)
// Read-only against the project repositories. Dependencies are never installed or imported by these checks.

import { writeFileSync } from "node:fs";
import { run as runSchemas } from "./check-schemas.mjs";
import { run as runDataLocality } from "./check-data-locality.mjs";
import { run as runDependencyApproval, serialiseDiff } from "./check-dependency-approval.mjs";
import { run as runSecretReferences } from "./check-secret-references.mjs";
import { run as runDrift } from "./check-drift.mjs";
import { defaultEnvironmentName, resolveEnvironment } from "./lib/environments.mjs";
import { REPORT_SCHEMA, summarize } from "./lib/findings.mjs";
import { configurationVersion } from "./lib/history.mjs";

export const CHECKS = [
  { id: "schemas", name: "configuration schemas", run: () => runSchemas() },
  { id: "dataLocality", name: "data locality", run: () => runDataLocality() },
  { id: "dependencyApproval", name: "dependency approval", run: () => runDependencyApproval() },
  { id: "secretReferences", name: "secret references", run: () => runSecretReferences() },
  { id: "drift", name: "configuration drift", run: (env) => runDrift({ envName: env }) },
];

// Runs all checks for an environment and returns the policy report object.
export function runAll(envName = defaultEnvironmentName(), now = new Date()) {
  const resolved = resolveEnvironment(envName);
  const results = [];
  for (const check of CHECKS) {
    const result = check.run(envName);
    results.push({ id: check.id, name: check.name, ok: result.ok, lines: result.lines, findings: result.findings ?? [], summary: result.summary ?? null, diff: result.diff ? serialiseDiff(result.diff) : undefined });
  }
  const findings = results.flatMap((r) => r.findings.map((f) => ({ check: r.id, ...f })));
  const summary = summarize(findings);
  const environmentErrors = resolved.ok ? [] : resolved.errors;
  const report = {
    schema: REPORT_SCHEMA,
    generatedAt: now.toISOString(),
    environment: { name: envName, ok: resolved.ok, chain: resolved.chain, errors: environmentErrors },
    // The configuration version this report was evaluated against, so consumers can record it and roll back to it.
    configurationVersion: configurationVersion(),
    gate: results.every((r) => r.ok) && resolved.ok ? "pass" : "fail",
    summary,
    checks: results.map(({ lines, findings: f, ...rest }) => ({ ...rest, findingCount: f.length })),
    findings,
  };
  // Console lines stay off the serialised report.
  Object.defineProperty(report, "consoleLines", { value: results.map((r) => ({ name: r.name, lines: r.lines })), enumerable: false });
  return report;
}

if (process.argv[1]?.endsWith("check-all.mjs")) {
  const argv = process.argv;
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const envName = arg("--env") ?? defaultEnvironmentName();
  const report = runAll(envName);
  const out = arg("--out");
  if (out) writeFileSync(out, JSON.stringify(report, null, 2) + "\n");
  if (argv.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`environment: ${envName}`);
    for (const e of report.environment.errors) console.log(`FAIL  environment: ${e}`);
    for (const { name, lines } of report.consoleLines) {
      console.log(`===== ${name}`);
      console.log(lines.join("\n"));
    }
    const failed = report.checks.filter((c) => !c.ok).length;
    console.log(report.gate === "pass" ? "\ncheck-all: PASS" : `\ncheck-all: FAIL (${failed} check group(s) failed)`);
  }
  process.exitCode = report.gate === "pass" ? 0 : 1;
}
