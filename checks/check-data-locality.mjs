// Checks the four project repositories against policy/data-locality-policy.json.
// Read-only. Reports key names and pass/fail only. Values are never printed.
// Usage: node checks/check-data-locality.mjs

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, isLoopbackUrl, isLoopbackHost, parseEnvText, readJson } from "./lib/env.mjs";

const ENV_FILES = [".env", ".env.local", ".env.local-prod", ".dev.vars", ".env.example"];
const TRUTHY = new Set(["1", "true", "yes", "on"]);

export function run() {
  const policy = readJson(join(CONFIG_ROOT, "policy", "data-locality-policy.json"));
  const failures = [];
  const lines = [];
  const record = (ok, label) => {
    lines.push(`${ok ? "PASS" : "FAIL"}  ${label}`);
    if (!ok) failures.push(label);
  };

  // Rule evaluation over env files. A rule passes when every present value satisfies it.
  for (const repo of PROJECT_REPOS) {
    lines.push(`--- ${repo.name} (${repo.path})`);
    if (!existsSync(repo.path)) {
      record(false, `${repo.name}: repository folder not found`);
      continue;
    }
    for (const file of ENV_FILES) {
      const full = join(repo.path, file);
      if (!existsSync(full)) continue;
      const env = parseEnvText(readFileSync(full, "utf8"));
      const label = (text) => `${repo.name} ${file}: ${text}`;
      lines.push(`    scanned ${file} (${env.size} keys)`);

      if (repo.name === "JARVIS") {
        const ollama = env.get("OLLAMA_URL");
        if (ollama) record(isLoopbackUrl(ollama), label("OLLAMA_URL is loopback [DL-AI-OLLAMA]"));
        for (const key of ["JARVIS_CLOUD_OPENAI_API_KEY", "JARVIS_CLOUD_ANTHROPIC_API_KEY"]) {
          if (env.has(key)) record(env.get(key) === "", label(`${key} is empty [DL-CLOUD-KEYS-UNSET]`));
        }
        if (env.has("JARVIS_CLOUD_ALLOWED_TASKS")) record(env.get("JARVIS_CLOUD_ALLOWED_TASKS") === "", label("JARVIS_CLOUD_ALLOWED_TASKS is empty [DL-CLOUD-ALLOWED-TASKS]"));
        if (env.has("JARVIS_ALLOW_CLOUD_SPEECH")) record(!TRUTHY.has(env.get("JARVIS_ALLOW_CLOUD_SPEECH").toLowerCase()), label("JARVIS_ALLOW_CLOUD_SPEECH is off [DL-CLOUD-SPEECH-OFF]"));
        if (env.has("JARVIS_SITE_GATEWAY_ALLOW_CLOUD")) record(["", "false"].includes(env.get("JARVIS_SITE_GATEWAY_ALLOW_CLOUD").toLowerCase()), label("JARVIS_SITE_GATEWAY_ALLOW_CLOUD is false [DL-CLOUD-SITE-GATEWAY-OFF]"));
      }

      if (repo.name === "Templates") {
        const provider = env.get("AI_PROVIDER");
        if (provider !== undefined) record(provider === "ollama" || provider === "jarvis", label("AI_PROVIDER is ollama or jarvis [DL-AI-JARVIS-GATEWAY]"));
        for (const key of ["OLLAMA_URL", "JARVIS_AI_URL"]) {
          if (env.has(key)) record(isLoopbackUrl(env.get(key)), label(`${key} is loopback [DL-AI-JARVIS-GATEWAY]`));
        }
      }

      if (repo.name === "Portfolio") {
        if (env.has("JARVIS_AI_URL") && env.get("JARVIS_AI_URL") !== "") record(isLoopbackUrl(env.get("JARVIS_AI_URL")), label("JARVIS_AI_URL is loopback [DL-AI-JARVIS-LOOPBACK]"));
        if (env.has("PORTFOLIO_AI_ALLOW_PAID_FALLBACK")) record(env.get("PORTFOLIO_AI_ALLOW_PAID_FALLBACK").toLowerCase() !== "true", label("PORTFOLIO_AI_ALLOW_PAID_FALLBACK is not true [DL-PAID-FALLBACK-OFF]"));
        if (env.has("OPENAI_API_KEY")) record(env.get("OPENAI_API_KEY") === "", label("OPENAI_API_KEY is empty [DL-OPENAI-KEY-UNSET]"));
      }

      for (const key of ["HOST", "BIND_HOST", "BIND_ADDRESS", "LISTEN_HOST", "HOSTNAME"]) {
        if (env.has(key) && env.get(key) !== "") record(isLoopbackHost(env.get(key)), label(`${key} is loopback [DL-BIND-LOOPBACK]`));
      }
    }
  }

  // Static code defaults: a repo with no env file still must default to loopback.
  lines.push("--- code defaults");
  const templatesEnv = join(PROJECT_REPOS[2].path, "apps", "api", "src", "config", "env.ts");
  if (existsSync(templatesEnv)) {
    const src = readFileSync(templatesEnv, "utf8");
    const ollama = /OLLAMA_URL:\s*z\.string\(\)\.url\(\)\.default\("([^"]+)"\)/.exec(src);
    const jarvis = /JARVIS_AI_URL:\s*z\.string\(\)\.url\(\)\.default\("([^"]+)"\)/.exec(src);
    const provider = /AI_PROVIDER:\s*z\.enum\(\[([^\]]+)\]\)\.default\("([^"]+)"\)/.exec(src);
    record(!!ollama && isLoopbackUrl(ollama[1]), "Templates code default OLLAMA_URL is loopback [DL-AI-JARVIS-GATEWAY]");
    record(!!jarvis && isLoopbackUrl(jarvis[1]), "Templates code default JARVIS_AI_URL is loopback [DL-AI-JARVIS-GATEWAY]");
    record(!!provider && ["ollama", "jarvis"].includes(provider[2]), "Templates code default AI_PROVIDER is ollama or jarvis [DL-AI-JARVIS-GATEWAY]");
  } else {
    record(false, "Templates apps/api/src/config/env.ts not found (cannot verify defaults)");
  }

  const jarvisRouter = join(PROJECT_REPOS[1].path, "src", "ai", "providerRouter.ts");
  if (existsSync(jarvisRouter)) {
    const src = readFileSync(jarvisRouter, "utf8");
    const ollamaLine = src.split(/\r?\n/).find((line) => line.includes("env['OLLAMA_URL']")) ?? "";
    const literals = [...ollamaLine.matchAll(/'(https?:\/\/[^']+)'/g)].map((m) => m[1]);
    record(literals.length > 0 && literals.every(isLoopbackUrl), "JARVIS code default OLLAMA_URL is loopback [DL-AI-OLLAMA]");
    const tasks = /JARVIS_CLOUD_ALLOWED_TASKS'\]\s*\|\|\s*'([^']*)'/.exec(src);
    record(!!tasks && tasks[1] === "", "JARVIS code default JARVIS_CLOUD_ALLOWED_TASKS is empty [DL-CLOUD-ALLOWED-TASKS]");
  }

  const portfolioProvider = join(PROJECT_REPOS[3].path, "src", "lib", "ai-provider.ts");
  if (existsSync(portfolioProvider)) {
    const src = readFileSync(portfolioProvider, "utf8");
    record(/PORTFOLIO_AI_ALLOW_PAID_FALLBACK"\]\s*===\s*"true"/.test(src), "Portfolio paid fallback is opt-in only (=== \"true\") [DL-PAID-FALLBACK-OFF]");
  }

  // Identity providers in the realm file must be disabled.
  lines.push("--- identity (configuration project)");
  const realm = readJson(join(CONFIG_ROOT, "identity", "realm", "asaa-realm.json"));
  for (const idp of realm.identityProviders ?? []) {
    record(idp.enabled === false, `realm identityProvider ${idp.alias} is disabled [DL-IDP-DISABLED]`);
  }
  record(realm.registrationAllowed === false, "realm self-registration is off");

  lines.push(`policy rules loaded: ${policy.rules.length}`);
  lines.push(failures.length === 0 ? "data-locality: PASS" : `data-locality: FAIL (${failures.length} violation(s))`);
  return { ok: failures.length === 0, lines };
}

if (process.argv[1]?.endsWith("check-data-locality.mjs")) {
  const result = run();
  console.log(result.lines.join("\n"));
  process.exitCode = result.ok ? 0 : 1;
}
