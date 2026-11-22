// Checks the four project repositories against policy/data-locality-policy.json.
// Read-only. Reports key names and pass/fail only. Values are never printed.
// Usage: node checks/check-data-locality.mjs

import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, isLoopbackUrl, isLoopbackHost, parseEnvText, readJson, walkFiles } from "./lib/env.mjs";
import { checkComposeBinds } from "./lib/compose.mjs";
import { createFinding, summarize } from "./lib/findings.mjs";

// Enforcement map: every policy rule id is enforced by at least one evaluator below. A policy rule without an entry
// here is reported as DL-RULE-UNENFORCED so a new rule cannot be added to the policy and silently skipped.
export const RULE_FOR_KEY = {
  OLLAMA_URL: "DL-AI-OLLAMA",
  JARVIS_AI_URL: "DL-AI-JARVIS-LOOPBACK",
  JARVIS_AI_BASE_URL: "DL-AI-JARVIS-LOOPBACK",
  AI_PROVIDER: "DL-AI-JARVIS-GATEWAY",
  JARVIS_CLOUD_OPENAI_API_KEY: "DL-CLOUD-KEYS-UNSET",
  JARVIS_CLOUD_ANTHROPIC_API_KEY: "DL-CLOUD-KEYS-UNSET",
  JARVIS_CLOUD_OPENAI_BASE_URL: "DL-CLOUD-KEYS-UNSET",
  JARVIS_CLOUD_ANTHROPIC_BASE_URL: "DL-CLOUD-KEYS-UNSET",
  JARVIS_CLOUD_ALLOWED_TASKS: "DL-CLOUD-ALLOWED-TASKS",
  JARVIS_ALLOW_CLOUD_SPEECH: "DL-CLOUD-SPEECH-OFF",
  JARVIS_SITE_GATEWAY_ALLOW_CLOUD: "DL-CLOUD-SITE-GATEWAY-OFF",
  JARVIS_AI_ALLOW_REMOTE: "DL-AI-JARVIS-LOOPBACK",
  PORTFOLIO_AI_ALLOW_PAID_FALLBACK: "DL-PAID-FALLBACK-OFF",
  OPENAI_API_KEY: "DL-OPENAI-KEY-UNSET",
  HOST: "DL-BIND-LOOPBACK",
  BIND_HOST: "DL-BIND-LOOPBACK",
  BIND_ADDRESS: "DL-BIND-LOOPBACK",
  LISTEN_HOST: "DL-BIND-LOOPBACK",
  ASAA_EVENTS_URL: "DL-BIND-LOOPBACK",
  ASAA_EVENTS_TOKEN_URL: "DL-BIND-LOOPBACK",
  JARVIS_OIDC_ISSUER: "DL-IDP-DISABLED",
  PORTFOLIO_OIDC_ISSUER: "DL-IDP-DISABLED",
  ASAA_IDENTITY_KEYCLOAK_URL: "DL-IDP-DISABLED",
};
const ENFORCED_RULES = new Set([...Object.values(RULE_FOR_KEY), "DL-IDP-DISABLED"]);

function ruleForLabel(label) {
  const key = /:\s(?:realm\s)?([A-Z_][A-Z0-9_]*)\s/.exec(label)?.[1];
  if (label.includes("realm identityProvider") || label.includes("realm self-registration")) return "DL-IDP-DISABLED";
  if (label.includes("published port must be loopback")) return "DL-BIND-LOOPBACK";
  if (label.includes("code default")) {
    if (label.includes("OLLAMA_URL")) return label.startsWith("JARVIS") ? "DL-AI-OLLAMA" : "DL-AI-JARVIS-GATEWAY";
    if (label.includes("JARVIS_AI_URL") || label.includes("AI_PROVIDER")) return "DL-AI-JARVIS-GATEWAY";
    if (label.includes("CLOUD_ALLOWED_TASKS")) return "DL-CLOUD-ALLOWED-TASKS";
    if (label.includes("paid fallback")) return "DL-PAID-FALLBACK-OFF";
  }
  return (key && RULE_FOR_KEY[key]) ?? "DL";
}

const ENV_FILE_NAMES = new Set([".env", ".env.local", ".env.local-prod", ".env.production", ".env.development", ".env.test", ".dev.vars", ".env.example"]);
const TRUTHY = new Set(["1", "true", "yes", "on"]);

// Keys whose value, when set, must point to a loopback host.
const LOOPBACK_URL_KEYS = new Set([
  "OLLAMA_URL", "JARVIS_AI_URL", "JARVIS_AI_BASE_URL", "JARVIS_CLOUD_OPENAI_BASE_URL", "JARVIS_CLOUD_ANTHROPIC_BASE_URL",
  "ASAA_EVENTS_URL", "ASAA_EVENTS_TOKEN_URL", "JARVIS_OIDC_ISSUER", "PORTFOLIO_OIDC_ISSUER", "ASAA_IDENTITY_KEYCLOAK_URL",
]);
// Keys that must be empty or off.
const MUST_BE_OFF = new Map([
  ["JARVIS_ALLOW_CLOUD_SPEECH", (v) => !TRUTHY.has(v.toLowerCase())],
  ["JARVIS_SITE_GATEWAY_ALLOW_CLOUD", (v) => v === "" || v.toLowerCase() === "false"],
  ["JARVIS_AI_ALLOW_REMOTE", (v) => !TRUTHY.has(v.toLowerCase())],
  ["PORTFOLIO_AI_ALLOW_PAID_FALLBACK", (v) => v.toLowerCase() !== "true"],
  ["JARVIS_CLOUD_ALLOWED_TASKS", (v) => v === ""],
  ["OPENAI_API_KEY", (v) => v === ""],
  ["JARVIS_CLOUD_OPENAI_API_KEY", (v) => v === ""],
  ["JARVIS_CLOUD_ANTHROPIC_API_KEY", (v) => v === ""],
]);
const BIND_KEYS = new Set(["HOST", "BIND_HOST", "BIND_ADDRESS", "LISTEN_HOST"]);

// Evaluate one key/value. Returns a list of { ok, rule } results. Values are used in memory only.
// skipBind: compose files get their bind checks per service (checkComposeBinds), not per key.
export function evaluate(rawKey, rawValue, skipBind = false) {
  const key = rawKey.toUpperCase();
  const value = String(rawValue).trim();
  const out = [];
  if (LOOPBACK_URL_KEYS.has(key) && value !== "") out.push({ ok: isLoopbackUrl(value), rule: `${key} is loopback` });
  if (MUST_BE_OFF.has(key)) out.push({ ok: MUST_BE_OFF.get(key)(value), rule: `${key} is off or empty` });
  if (key === "AI_PROVIDER" && value !== "") out.push({ ok: value === "ollama" || value === "jarvis", rule: "AI_PROVIDER is ollama or jarvis" });
  if (!skipBind && BIND_KEYS.has(key) && value !== "") out.push({ ok: isLoopbackHost(value), rule: `${key} is loopback` });
  return out;
}

function stripBom(text) {
  return text.replace(/^﻿/, "");
}

export function run() {
  const policy = readJson(join(CONFIG_ROOT, "policy", "data-locality-policy.json"));
  for (const name of policy.scannedFiles ?? []) ENV_FILE_NAMES.add(name);
  const failures = [];
  const lines = [];
  const findings = [];
  const record = (ok, label) => {
    lines.push(`${ok ? "PASS" : "FAIL"}  ${label}`);
    if (!ok) {
      failures.push(label);
      const repo = /^(ASAA|JARVIS|Templates|Portfolio)\b/.exec(label)?.[1] ?? null;
      const rule = ruleForLabel(label);
      const severity = (policy.rules.find((r) => r.id === rule)?.severity ?? "fail") === "fail" ? "error" : "warning";
      findings.push(createFinding({ code: "DL-VIOLATION", severity, repo, subject: label, policyRule: rule, message: label, remediation: policy.rules.find((r) => r.id === rule)?.requirement ?? null }));
    }
  };
  for (const rule of policy.rules) {
    if (!ENFORCED_RULES.has(rule.id)) {
      findings.push(createFinding({ code: "DL-RULE-UNENFORCED", severity: "warning", subject: rule.id, policyRule: rule.id, message: `policy rule ${rule.id} has no evaluator in check-data-locality.mjs` }));
      lines.push(`WARN  policy rule ${rule.id} has no evaluator`);
    }
  }

  for (const repo of PROJECT_REPOS) {
    lines.push(`--- ${repo.name}`);
    if (!existsSync(repo.path)) {
      record(false, `${repo.name}: repository folder not found`);
      continue;
    }
    // Env-style files anywhere in the repo (skipping dependency and build folders).
    const envFiles = walkFiles(repo.path, (name) => ENV_FILE_NAMES.has(name));
    // Compose and wrangler configuration.
    const configFiles = walkFiles(repo.path, (name) => /^(docker-compose.*\.ya?ml|compose.*\.ya?ml|wrangler\.(jsonc|json|toml))$/i.test(name));

    for (const file of envFiles) {
      const env = parseEnvText(stripBom(readFileSync(file, "utf8")));
      const rel = file.slice(repo.path.length + 1).replace(/\\/g, "/");
      lines.push(`    scanned ${rel} (${env.size} keys)`);
      for (const [k, v] of env) {
        for (const r of evaluate(k, v)) record(r.ok, `${repo.name} ${rel}: ${r.rule}`);
      }
    }

    for (const file of configFiles) {
      const text = stripBom(readFileSync(file, "utf8"));
      const rel = file.slice(repo.path.length + 1).replace(/\\/g, "/");
      const pairs = [];
      // YAML environment entries: "- KEY=value" or "KEY: value"; JSON/TOML: "KEY": "value" or KEY = "value".
      for (const m of text.matchAll(/^\s*-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["']?([^"'\s#,]*)["']?/gm)) pairs.push([m[1], m[2]]);
      for (const m of text.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"]*)"/g)) pairs.push([m[1], m[2]]);
      let checked = 0;
      const isCompose = /^docker-compose|^compose/i.test(basename(file));
      for (const [k, v] of pairs) {
        const results = evaluate(k, v, isCompose);
        checked += results.length;
        for (const r of results) record(r.ok, `${repo.name} ${rel}: ${r.rule}`);
      }
      if (isCompose) {
        for (const r of checkComposeBinds(text)) {
          checked += 1;
          record(r.ok, `${repo.name} ${rel}: ${r.rule}`);
        }
      }
      lines.push(`    scanned ${rel} (${checked} rule checks)`);
    }

    // Code defaults must exist and default to the policy.
    const codeDefaults = {
      Templates: [["apps/api/src/config/env.ts", "templates-defaults"]],
      JARVIS: [["src/ai/providerRouter.ts", "jarvis-router"], ["src/voice/providers.ts", "jarvis-speech"]],
      Portfolio: [["src/lib/ai-provider.ts", "portfolio-ai"]],
    }[repo.name] ?? [];
    for (const [rel] of codeDefaults) {
      record(existsSync(join(repo.path, rel)), `${repo.name} code-default file present: ${rel}`);
    }
  }

  lines.push("--- code defaults");
  const templatesEnv = join(PROJECT_REPOS[2].path, "apps", "api", "src", "config", "env.ts");
  if (existsSync(templatesEnv)) {
    const src = stripBom(readFileSync(templatesEnv, "utf8"));
    const ollama = /OLLAMA_URL:\s*z\.string\(\)\.url\(\)\.default\("([^"]+)"\)/.exec(src);
    const jarvis = /JARVIS_AI_URL:\s*z\.string\(\)\.url\(\)\.default\("([^"]+)"\)/.exec(src);
    const provider = /AI_PROVIDER:\s*z\.enum\(\[([^\]]+)\]\)\.default\("([^"]+)"\)/.exec(src);
    record(!!ollama && isLoopbackUrl(ollama[1]), "Templates code default OLLAMA_URL is loopback");
    record(!!jarvis && isLoopbackUrl(jarvis[1]), "Templates code default JARVIS_AI_URL is loopback");
    record(!!provider && ["ollama", "jarvis"].includes(provider[2]), "Templates code default AI_PROVIDER is ollama or jarvis");
  }
  const jarvisRouter = join(PROJECT_REPOS[1].path, "src", "ai", "providerRouter.ts");
  if (existsSync(jarvisRouter)) {
    const src = stripBom(readFileSync(jarvisRouter, "utf8"));
    const ollamaLine = src.split(/\r?\n/).find((line) => line.includes("env['OLLAMA_URL']")) ?? "";
    const literals = [...ollamaLine.matchAll(/'(https?:\/\/[^']+)'/g)].map((m) => m[1]);
    record(literals.length > 0 && literals.every(isLoopbackUrl), "JARVIS code default OLLAMA_URL is loopback");
    const tasks = /JARVIS_CLOUD_ALLOWED_TASKS'\]\s*\|\|\s*'([^']*)'/.exec(src);
    record(!!tasks && tasks[1] === "", "JARVIS code default JARVIS_CLOUD_ALLOWED_TASKS is empty");
  }
  const portfolioProvider = join(PROJECT_REPOS[3].path, "src", "lib", "ai-provider.ts");
  if (existsSync(portfolioProvider)) {
    const src = stripBom(readFileSync(portfolioProvider, "utf8"));
    record(/PORTFOLIO_AI_ALLOW_PAID_FALLBACK"\]\s*===\s*"true"/.test(src), "Portfolio paid fallback is opt-in only");
  }

  lines.push("--- identity (configuration project)");
  const realm = readJson(join(CONFIG_ROOT, "identity", "realm", "asaa-realm.json"));
  for (const idp of realm.identityProviders ?? []) record(idp.enabled === false, `realm identityProvider ${idp.alias} is disabled`);
  record(realm.registrationAllowed === false, "realm self-registration is off");

  lines.push(`policy rules loaded: ${policy.rules.length}, enforced: ${policy.rules.filter((r) => ENFORCED_RULES.has(r.id)).length}`);
  const summary = summarize(findings);
  lines.push(summary.gate === "pass" ? "data-locality: PASS" : `data-locality: FAIL (${failures.length} violation(s))`);
  return { ok: summary.gate === "pass", lines, findings, summary };
}

if (process.argv[1]?.endsWith("check-data-locality.mjs")) {
  const result = run();
  console.log(result.lines.join("\n"));
  process.exitCode = result.ok ? 0 : 1;
}
