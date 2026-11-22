// Configuration drift detection.
//   1. Ledger integrity   - the history ledger hash chain is intact (tampering is an error).
//   2. Unrecorded change  - a tracked policy/configuration file differs from its last ledger entry.
//   3. Working tree       - tracked configuration files have uncommitted changes (profile option drift.worktree).
//   4. Project environment- project env example files and compose files disagree with the selected environment
//                           profile's expectations (for example an OIDC issuer that is not the shared ASAA realm).
// Usage: node checks/check-drift.mjs [--env <name>] [--json]
// Values of secret-named keys are never compared or printed; expectations only cover non-secret endpoints.

import { readFileSync } from "node:fs";
import { PROJECT_REPOS, parseEnvText, walkFiles } from "./lib/env.mjs";
import { TRACKED_FILES, fileSha, headEntry, loadLedger, verifyLedger, worktreeChanges } from "./lib/history.mjs";
import { defaultEnvironmentName, resolveEnvironment } from "./lib/environments.mjs";
import { isSecretKey } from "./lib/secret-ref.mjs";
import { createFinding, renderFinding, summarize } from "./lib/findings.mjs";
import { extractPairs } from "./check-secret-references.mjs";

const ENV_EXAMPLE = /^\.env(\..+)?\.example$|^\.env\.example$/i;
const COMPOSE = /^(docker-compose.*\.ya?ml|compose.*\.ya?ml)$/i;

export function run({ envName = defaultEnvironmentName() } = {}) {
  const findings = [];
  const lines = [];
  const resolved = resolveEnvironment(envName);
  if (!resolved.ok) {
    for (const e of resolved.errors) findings.push(createFinding({ code: "ENV-INVALID", subject: `${envName}:${e}`, message: `environment ${envName}: ${e}` }));
    const summary = summarize(findings);
    return { ok: false, lines: findings.map(renderFinding), findings, summary, environment: envName };
  }
  const profile = resolved.profile;
  const severity = profile.checks?.drift === "fail" ? "error" : "warning";
  lines.push(`environment: ${envName} (${resolved.chain.join(" <- ")}), drift severity: ${severity}`);

  if (profile.drift?.ledger !== false) {
    const ledger = loadLedger();
    const chain = verifyLedger(ledger);
    if (!chain.ok) {
      findings.push(createFinding({ code: "DRIFT-HISTORY-TAMPERED", severity: "error", subject: "policy/history/ledger.json", file: "policy/history/ledger.json", message: `history ledger chain is broken at entry ${chain.brokenAt} (${chain.reason})`, remediation: "investigate who edited the ledger; restore it from git history" }));
    }
    for (const file of TRACKED_FILES) {
      const head = headEntry(ledger, file);
      if (!head) continue;
      const sha = fileSha(file);
      if (sha !== head.sha256) {
        findings.push(createFinding({ code: "DRIFT-POLICY-UNRECORDED", severity, subject: file, file, message: `${file} changed since ledger entry ${head.seq} (${head.action}) without a recorded change`, remediation: "record the change through the tooling (snapshot, approval, rollback or 'history record' with a reason) or revert it", data: { ledgerSeq: head.seq } }));
      }
    }
    lines.push(`ledger: ${ledger.entries.length} entries, chain ${chain.ok ? "intact" : "BROKEN"}`);
  }

  if (profile.drift?.worktree) {
    for (const change of worktreeChanges()) {
      findings.push(createFinding({ code: "DRIFT-WORKTREE", severity: "warning", subject: change.file, file: change.file, message: `${change.file} has uncommitted changes (${change.status || "modified"})` }));
    }
  }

  if (profile.drift?.projectEnvironment !== false) {
    for (const repo of PROJECT_REPOS) {
      const expectations = profile.projects?.[repo.name]?.expect ?? [];
      if (!expectations.length) continue;
      const files = walkFiles(repo.path, (name) => ENV_EXAMPLE.test(name) || COMPOSE.test(name));
      for (const full of files) {
        const rel = full.slice(repo.path.length + 1).replace(/\\/g, "/");
        const text = readFileSync(full, "utf8").replace(/^﻿/, "");
        const pairs = ENV_EXAMPLE.test(rel.split("/").at(-1)) ? [...parseEnvText(text)] : extractPairs(text);
        for (const exp of expectations) {
          if (isSecretKey(exp.key)) continue;
          for (const [key, value] of pairs) {
            if (key !== exp.key) continue;
            if (exp.whenSet && (value === "" || value.startsWith("${"))) continue;
            // RFC 2606 .invalid hosts are deliberate non-resolvable placeholders (rehearsal configuration).
            if (/^[a-z]+:\/\/[^/]*\.invalid(?:[:/]|$)/i.test(value)) continue;
            if (value.replace(/\/+$/, "") !== exp.equals.replace(/\/+$/, "")) {
              findings.push(createFinding({ code: "DRIFT-ENV", severity, repo: repo.name, file: rel, subject: `${rel}:${key}`, message: `${repo.name} ${rel}: ${key} differs from the ${envName} environment profile`, remediation: `set ${key} to the shared value defined in environments/${envName}.json` }));
            }
          }
        }
      }
    }
  }

  for (const f of findings) lines.push(renderFinding(f));
  const summary = summarize(findings);
  lines.push(summary.gate === "pass" ? "drift: PASS" : `drift: FAIL (${summary.bySeverity.error} item(s))`);
  return { ok: summary.gate === "pass", lines, findings, summary, environment: envName };
}

if (process.argv[1]?.endsWith("check-drift.mjs")) {
  const i = process.argv.indexOf("--env");
  const result = run(i >= 0 ? { envName: process.argv[i + 1] } : {});
  console.log(process.argv.includes("--json") ? JSON.stringify({ check: "drift", environment: result.environment, summary: result.summary, findings: result.findings }, null, 2) : result.lines.join("\n"));
  process.exitCode = result.ok ? 0 : 1;
}
