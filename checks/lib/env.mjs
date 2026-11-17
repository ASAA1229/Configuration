// Shared helpers for the configuration checks. Node standard library only (no dependencies).
// Values read from env files are used in memory and never printed.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CONFIG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const WORKSPACE_ROOT = resolve(CONFIG_ROOT, "..");

export const PROJECT_REPOS = [
  { name: "ASAA", path: join(WORKSPACE_ROOT, "ASAA") },
  { name: "JARVIS", path: join(WORKSPACE_ROOT, "JARVIS") },
  { name: "Templates", path: join(WORKSPACE_ROOT, "Templates") },
  { name: "Portfolio", path: join(WORKSPACE_ROOT, "Portfolio") },
];

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function parseEnvText(text) {
  const values = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values.set(match[1], value);
  }
  return values;
}

export function isLoopbackUrl(value) {
  try {
    const host = new URL(value).hostname.replace(/^\[|\]$/g, "");
    return host === "127.0.0.1" || host === "localhost" || host === "::1";
  } catch {
    return false;
  }
}

export function isLoopbackHost(value) {
  return ["127.0.0.1", "localhost", "::1"].includes(value.trim());
}

// Walks a directory without entering dependency, build or VCS folders.
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "dist-ssr", ".output", ".venv", "venv", "__pycache__", "coverage", "test-results", "playwright-report"]);

export function walkFiles(root, predicate, out = []) {
  if (!existsSync(root)) return out;
  for (const entry of readdirSync(root)) {
    const full = join(root, entry);
    const info = statSync(full);
    if (info.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walkFiles(full, predicate, out);
    } else if (predicate(entry, full)) {
      out.push(full);
    }
  }
  return out;
}
