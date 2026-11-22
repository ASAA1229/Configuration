// Secret-reference check. Tracked configuration must never hold a credential: secret-named settings in example env
// files, Compose files, wrangler configuration and environment profiles must be empty, a placeholder, or a secret
// reference (secret://env/NAME, secret://file/..., ${NAME}, env:NAME).
// Real local env files (.env, .env.local, .dev.vars) are gitignored, hold the owner's actual values and are NOT
// inspected here. Values are never printed: findings name the file and key only.
// Usage: node checks/check-secret-references.mjs [--json]

import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, parseEnvText, walkFiles } from "./lib/env.mjs";
import { classifySecretValue, isSecretKey } from "./lib/secret-ref.mjs";
import { createFinding, renderFinding, summarize } from "./lib/findings.mjs";
import { listEnvironments, loadProfile } from "./lib/environments.mjs";

const TEMPLATE_ENV = /^(\.env\.example|\.env\.sample|\.env\.template|\.dev\.vars\.example|.*\.env\.example)$/i;
const CONFIG_FILE = /^(docker-compose.*\.ya?ml|compose.*\.ya?ml|wrangler\.(jsonc|json|toml))$/i;

// Extracts key/value pairs from YAML, JSON(C) and TOML configuration text.
export function extractPairs(text) {
  const pairs = [];
  for (const m of text.matchAll(/^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|(\$\{[^}]*\}|[^\s#,]*))/gm)) pairs.push([m[1], m[2] ?? m[3] ?? m[4] ?? ""]);
  for (const m of text.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"]*)"/g)) pairs.push([m[1], m[2]]);
  return pairs;
}

export function checkPairs(pairs, { repo, file }) {
  const findings = [];
  for (const [key, value] of pairs) {
    if (!isSecretKey(key)) continue;
    const cls = classifySecretValue(value);
    if (cls === "literal") {
      findings.push(createFinding({ code: "SECRET-LITERAL", repo, file, subject: `${file}:${key}`, message: `${repo} ${file}: ${key} holds a literal value in tracked configuration`, explanation: "Tracked configuration may only hold an empty value, a placeholder or a secret reference.", remediation: "replace the value with a secret reference; if it was a real credential, rotate it" }));
    } else if (cls === "invalid-reference") {
      findings.push(createFinding({ code: "SECRET-REF-INVALID", repo, file, subject: `${file}:${key}`, message: `${repo} ${file}: ${key} is a malformed secret reference` }));
    }
  }
  return findings;
}

export function run() {
  const findings = [];
  const lines = [];
  const repos = [...PROJECT_REPOS, { name: "configuration", path: CONFIG_ROOT }];
  for (const repo of repos) {
    const files = walkFiles(repo.path, (name) => TEMPLATE_ENV.test(name) || CONFIG_FILE.test(name));
    for (const full of files) {
      const rel = full.slice(repo.path.length + 1).replace(/\\/g, "/");
      const text = readFileSync(full, "utf8").replace(/^﻿/, "");
      const pairs = TEMPLATE_ENV.test(basename(full)) ? [...parseEnvText(text)] : extractPairs(text);
      const found = checkPairs(pairs, { repo: repo.name, file: rel });
      findings.push(...found);
      lines.push(`${found.some((f) => f.severity === "error") ? "FAIL" : "PASS"}  ${repo.name} ${rel}`);
    }
  }
  for (const name of listEnvironments()) {
    const profile = loadProfile(name);
    const ref = profile.identity?.bootstrapAdminPasswordRef;
    if (ref !== undefined && classifySecretValue(ref) !== "reference") {
      findings.push(createFinding({ code: "SECRET-REF-INVALID", repo: "configuration", file: `environments/${name}.json`, subject: `environments/${name}.json:identity.bootstrapAdminPasswordRef`, message: `environments/${name}.json: identity.bootstrapAdminPasswordRef must be a secret reference` }));
    }
  }
  for (const f of findings) lines.push(renderFinding(f));
  const summary = summarize(findings);
  lines.push(summary.gate === "pass" ? "secret-references: PASS" : `secret-references: FAIL (${summary.bySeverity.error} item(s))`);
  return { ok: summary.gate === "pass", lines, findings, summary };
}

if (process.argv[1]?.endsWith("check-secret-references.mjs")) {
  const result = run();
  console.log(process.argv.includes("--json") ? JSON.stringify({ check: "secret-references", summary: result.summary, findings: result.findings }, null, 2) : result.lines.join("\n"));
  process.exitCode = result.ok ? 0 : 1;
}
