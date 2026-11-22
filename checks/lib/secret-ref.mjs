// Secret-reference handling. Standard library only.
//
// Configuration never stores credentials. A secret-bearing setting holds a reference that is resolved at run time:
//   secret://env/NAME            value of environment variable NAME
//   secret://file/relative/path  contents of a file under an allowed secrets directory (trailing newline removed)
//   ${NAME} / ${NAME:?message}   Compose/shell style environment reference
//   env:NAME                     short form of secret://env/NAME
// Resolution returns the value to the caller only; nothing here prints, logs or serialises a resolved value.

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const SECRET_KEY = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY|AUTH_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY|COOKIE_?KEY|SESSION_?KEY|DSN)/i;
// Keys that match SECRET_KEY by name but never carry secret material.
const NON_SECRET_KEY = /(_URL|_URI|_ENDPOINT|_ISSUER|_FILE|_PATH|_REF|_ID|_NAME|_HEADER|_CLAIM|_ROLE|_TTL|_EXPIR\w*|_LENGTH|_ALGORITHM|_ALG|_ENABLED|_REQUIRED|_MODE|_TYPE|_SCOPE|_AUDIENCE|_PREFIX)$/i;
const PLACEHOLDER = /^(?:REPLACE[_-]?(?:WITH|ME)\w*|CHANGE[_-]?ME\w*|<[^>]+>|\{\{[^}]+\}\}|x{3,}|\*{3,}|your[_-]\w+|example[_-]?\w*|placeholder|dummy|todo|set[_-]?me|fill[_-]?me[_-]?in|redacted|none|null|changeit)$/i;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isSecretKey(key) {
  return SECRET_KEY.test(key) && !NON_SECRET_KEY.test(key);
}

// Parses a reference. Returns { kind: "env"|"file", name|path } or null when the value is not a reference.
export function parseSecretRef(value) {
  const v = String(value ?? "").trim();
  let m = /^secret:\/\/env\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(v);
  if (m) return { kind: "env", name: m[1] };
  m = /^secret:\/\/file\/(.+)$/.exec(v);
  if (m) return { kind: "file", path: m[1] };
  m = /^env:([A-Za-z_][A-Za-z0-9_]*)$/.exec(v);
  if (m) return { kind: "env", name: m[1] };
  m = /^\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(?::?\?)[^}]*)?\}$/.exec(v);
  if (m) return { kind: "env", name: m[1] };
  m = /^\$([A-Za-z_][A-Za-z0-9_]*)$/.exec(v);
  if (m) return { kind: "env", name: m[1] };
  return null;
}

// Classifies a configured value without exposing it: "empty" | "reference" | "invalid-reference" | "placeholder" | "literal".
export function classifySecretValue(value) {
  const v = String(value ?? "").trim();
  if (v === "") return "empty";
  if (v.startsWith("secret://")) {
    const ref = parseSecretRef(v);
    if (!ref) return "invalid-reference";
    if (ref.kind === "file" && (isAbsolute(ref.path) || ref.path.split(/[\\/]/).includes(".."))) return "invalid-reference";
    return "reference";
  }
  if (parseSecretRef(v)) return "reference";
  // ${VAR:-literal} embeds a literal fallback, which is a stored value.
  const fallback = /^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$/.exec(v);
  if (fallback) return fallback[1] === "" ? "reference" : classifySecretValue(fallback[1]) === "placeholder" ? "placeholder" : "literal";
  if (PLACEHOLDER.test(v)) return "placeholder";
  return "literal";
}

// Resolves a reference at run time. secretsRoot bounds file references (no traversal, no symlink escape).
export function resolveSecretRef(value, { env = process.env, secretsRoot = null } = {}) {
  const ref = parseSecretRef(value);
  if (!ref) return { ok: false, error: "not a secret reference" };
  if (ref.kind === "env") {
    if (!ENV_NAME.test(ref.name)) return { ok: false, error: "invalid variable name" };
    const v = env[ref.name];
    return v === undefined || v === "" ? { ok: false, error: `environment variable ${ref.name} is not set` } : { ok: true, value: v };
  }
  if (!secretsRoot) return { ok: false, error: "file references need a configured secrets directory" };
  if (isAbsolute(ref.path)) return { ok: false, error: "file reference must be relative" };
  const root = resolve(secretsRoot);
  const target = resolve(root, ref.path);
  if (relative(root, target).startsWith("..")) return { ok: false, error: "file reference escapes the secrets directory" };
  if (!existsSync(target)) return { ok: false, error: "referenced secret file does not exist" };
  const real = realpathSync(target);
  if (relative(realpathSync(root), real).startsWith("..")) return { ok: false, error: "file reference escapes the secrets directory" };
  return { ok: true, value: readFileSync(real, "utf8").replace(/\r?\n$/, "") };
}

export function redact() {
  return "[redacted]";
}
