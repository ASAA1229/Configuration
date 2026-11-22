// Environment-specific configuration profiles (environments/*.json). Standard library only.
//
// A profile names the environment (local, ci, local-prod), may extend another profile, and holds shared identity
// endpoints, check severities, drift options and per-project expectations. Profiles are merged along the "extends"
// chain (objects merge, arrays and scalars of the child replace the parent). Expectations may reference resolved
// settings with ${path.to.setting}. Secret-bearing settings hold secret references only (see secret-ref.mjs).
//
// The schema forbids a profile from lowering a policy check below "fail", so environment selection can never weaken
// policy intent.

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_ROOT, readJson } from "./env.mjs";
import { validate } from "./schema.mjs";
import { classifySecretValue } from "./secret-ref.mjs";

export const ENVIRONMENTS_DIR = join(CONFIG_ROOT, "environments");
const SCHEMA_PATH = join(CONFIG_ROOT, "policy", "schemas", "environment.schema.json");

export function listEnvironments(dir = ENVIRONMENTS_DIR) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export function deepMerge(parent, child) {
  if (!isPlainObject(parent) || !isPlainObject(child)) return child === undefined ? parent : child;
  const out = { ...parent };
  for (const [k, v] of Object.entries(child)) out[k] = k in parent ? deepMerge(parent[k], v) : v;
  return out;
}

function getPath(obj, path) {
  return path.split(".").reduce((node, part) => (node == null ? undefined : node[part]), obj);
}

// Replaces ${a.b.c} in strings with resolved settings. Unknown paths are left as errors.
export function interpolate(value, context, errors, where) {
  if (typeof value === "string") {
    return value.replace(/\$\{([a-zA-Z][\w.]*)\}/g, (match, path) => {
      const resolved = getPath(context, path);
      if (typeof resolved !== "string") { errors.push(`${where}: unresolved reference ${match}`); return match; }
      return resolved;
    });
  }
  if (Array.isArray(value)) return value.map((v, i) => interpolate(v, context, errors, `${where}[${i}]`));
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, interpolate(v, context, errors, `${where}.${k}`)]));
  return value;
}

export function loadProfile(name, dir = ENVIRONMENTS_DIR) {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error(`invalid environment name ${name}`);
  const path = join(dir, `${name}.json`);
  if (!existsSync(path)) throw new Error(`environment ${name} is not defined (environments/${name}.json)`);
  return readJson(path);
}

// Validates every profile file on its own. Returns [{ name, errors: [{path, message}] }].
export function validateProfiles(dir = ENVIRONMENTS_DIR) {
  const schema = readJson(SCHEMA_PATH);
  return listEnvironments(dir).map((name) => {
    const profile = loadProfile(name, dir);
    const errors = validate(schema, profile);
    if (profile.name !== name) errors.push({ path: "$.name", message: `name must equal the file name (${name})` });
    return { name, errors };
  });
}

// Resolves a profile along its extends chain. Returns { ok, profile, chain, errors }.
export function resolveEnvironment(name, dir = ENVIRONMENTS_DIR) {
  const errors = [];
  const chain = [];
  let current = name;
  const layers = [];
  while (current) {
    if (chain.includes(current)) { errors.push(`extends cycle: ${[...chain, current].join(" -> ")}`); break; }
    chain.push(current);
    let profile;
    try { profile = loadProfile(current, dir); } catch (e) { errors.push(e.message); break; }
    layers.unshift(profile);
    current = profile.extends;
  }
  if (errors.length) return { ok: false, profile: null, chain, errors };

  let merged = {};
  for (const layer of layers) merged = deepMerge(merged, layer);
  merged.name = name;
  merged.abstract = layers.at(-1).abstract === true;
  delete merged.extends;
  if (merged.abstract) errors.push(`environment ${name} is abstract and cannot be selected`);

  const schema = readJson(SCHEMA_PATH);
  for (const e of validate(schema, merged)) errors.push(`${e.path}: ${e.message}`);

  // Secret-bearing identity setting must be a reference.
  const ref = merged.identity?.bootstrapAdminPasswordRef;
  if (ref !== undefined && classifySecretValue(ref) !== "reference") errors.push("identity.bootstrapAdminPasswordRef must be a secret reference");

  const resolved = { ...merged, projects: interpolate(merged.projects ?? {}, merged, errors, "projects") };
  return { ok: errors.length === 0, profile: resolved, chain, errors };
}

// Default environment: ASAA_CONFIG_ENV, else "ci" under GitHub Actions, else "local".
export function defaultEnvironmentName(env = process.env) {
  if (env.ASAA_CONFIG_ENV) return env.ASAA_CONFIG_ENV;
  return env.GITHUB_ACTIONS === "true" ? "ci" : "local";
}
