// Dependency and image approval check (policy/install-import-policy.json).
//   --snapshot : records every npm, Python and Docker dependency found in the four project repositories
//                (and this configuration project) into policy/approved-dependencies.json.
//   (default)  : compares the current state with that snapshot and fails on any new or changed dependency,
//                and on any Docker image that is not approved or not pinned to an exact tag.
// Read-only against the project repositories. Standard library only.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, readJson, walkFiles } from "./lib/env.mjs";

const SNAPSHOT_PATH = join(CONFIG_ROOT, "policy", "approved-dependencies.json");
const INSTALL_POLICY_PATH = join(CONFIG_ROOT, "policy", "install-import-policy.json");

const ALL_REPOS = [...PROJECT_REPOS, { name: "configuration", path: CONFIG_ROOT }];
const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

function collectNpm(repo) {
  const found = [];
  for (const file of walkFiles(repo.path, (name) => name === "package.json")) {
    const manifest = readJson(file);
    for (const section of NPM_SECTIONS) {
      for (const [name, spec] of Object.entries(manifest[section] ?? {})) {
        found.push({ repo: repo.name, ecosystem: "npm", manifest: relative(repo.path, file).replace(/\\/g, "/"), section, name, spec: String(spec) });
      }
    }
  }
  return found;
}

function collectPython(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => name === "pyproject.toml" || /^requirements.*\.txt$/.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    if (basename(file) === "pyproject.toml") {
      for (const block of text.matchAll(/dependencies\s*=\s*\[([\s\S]*?)\]/g)) {
        for (const item of block[1].matchAll(/"([^"]+)"/g)) {
          const [name, ...rest] = item[1].split(/(?=[<>=!~\[ ;])/);
          found.push({ repo: repo.name, ecosystem: "python", manifest, section: "dependencies", name: name.trim(), spec: rest.join("").trim() });
        }
      }
    } else {
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.split("#")[0].trim();
        if (!line || line.startsWith("-")) continue;
        const [name, ...rest] = line.split(/(?=[<>=!~\[ ;])/);
        found.push({ repo: repo.name, ecosystem: "python", manifest, section: "requirements", name: name.trim(), spec: rest.join("").trim() });
      }
    }
  }
  return found;
}

function collectDocker(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => /^(Dockerfile(\..*)?|docker-compose.*\.ya?ml|compose.*\.ya?ml)$/i.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    for (const m of text.matchAll(/^\s*FROM\s+(\S+)/gim)) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "FROM", name: m[1] });
    for (const m of text.matchAll(/^\s*image:\s*["']?([^"'\s#]+)/gim)) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "image", name: m[1] });
  }
  return found;
}

export function collectAll() {
  const items = [];
  for (const repo of ALL_REPOS) {
    if (!existsSync(repo.path)) continue;
    items.push(...collectNpm(repo), ...collectPython(repo), ...collectDocker(repo));
  }
  return items.sort((a, b) => `${a.repo}|${a.ecosystem}|${a.manifest}|${a.name}|${a.section}`.localeCompare(`${b.repo}|${b.ecosystem}|${b.manifest}|${b.name}|${b.section}`));
}

const key = (d) => `${d.repo}|${d.ecosystem}|${d.manifest}|${d.section}|${d.name}|${d.spec ?? ""}`;

export function snapshot() {
  const items = collectAll();
  const body = {
    schema: "asaa.configuration.approved-dependencies.v1",
    description: "Owner-approved baseline of every npm, Python and Docker dependency in the ASAA project repositories at the time of this snapshot. Any later addition or change fails checks/check-dependency-approval.mjs until the owner approves it (policy/install-import-policy.json) and the snapshot is refreshed.",
    generatedBy: "checks/check-dependency-approval.mjs --snapshot",
    counts: items.reduce((acc, d) => ({ ...acc, [d.ecosystem]: (acc[d.ecosystem] ?? 0) + 1 }), {}),
    dependencies: items,
  };
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(body, null, 2) + "\n");
  return { ok: true, lines: [`snapshot written: ${items.length} entries`, `counts: ${JSON.stringify(body.counts)}`, `file: ${SNAPSHOT_PATH}`] };
}

export function run() {
  const lines = [];
  const failures = [];
  if (!existsSync(SNAPSHOT_PATH)) {
    return { ok: false, lines: ["No approved snapshot found. Run: node checks/check-dependency-approval.mjs --snapshot (owner baseline only)."] };
  }
  const approved = readJson(SNAPSHOT_PATH).dependencies;
  const approvedKeys = new Set(approved.map(key));
  const approvedByIdentity = new Map(approved.map((d) => [`${d.repo}|${d.ecosystem}|${d.manifest}|${d.section}|${d.name}`, d.spec ?? ""]));
  const current = collectAll();

  for (const d of current) {
    if (approvedKeys.has(key(d))) continue;
    const identity = `${d.repo}|${d.ecosystem}|${d.manifest}|${d.section}|${d.name}`;
    const label = d.ecosystem === "docker"
      ? `${d.repo} ${d.manifest}: image ${d.name}`
      : `${d.repo} ${d.manifest} [${d.section}]: ${d.name}${d.spec ? ` ${d.spec}` : ""}`;
    failures.push(approvedByIdentity.has(identity)
      ? `CHANGED  ${label} (approved spec differs)`
      : `NEW      ${label}`);
  }
  const currentKeys = new Set(current.map(key));
  const removed = approved.filter((d) => !currentKeys.has(key(d)));

  // Docker images: must be on the approved list and pinned to an exact version tag (IIP-3, IIP-4).
  // Each distinct repo and image reference is reported once.
  const install = readJson(INSTALL_POLICY_PATH);
  const approvedImages = new Set(install.approvedDockerImages.map((i) => i.image));
  const seenImages = new Set();
  for (const d of current.filter((x) => x.ecosystem === "docker")) {
    const id = `${d.repo} ${d.name}`;
    if (seenImages.has(id)) continue;
    seenImages.add(id);
    const exactTag = /:\d+\.\d+(\.\d+)?(-[a-z0-9.]+)?$/.test(d.name) || /@sha256:[a-f0-9]{64}$/.test(d.name);
    if (!exactTag) failures.push(`UNPINNED   ${d.repo}: image ${d.name} (exact version tag or digest required, see IIP-3)`);
    if (!approvedImages.has(d.name)) failures.push(`NOT APPROVED ${d.repo}: image ${d.name} (owner approval record required, see IIP-4)`);
  }

  lines.push(`approved entries: ${approved.length}, current entries: ${current.length}, removed since snapshot: ${removed.length}`);
  for (const f of failures) lines.push(`FAIL  ${f}`);
  lines.push(failures.length === 0 ? "dependency-approval: PASS" : `dependency-approval: FAIL (${failures.length} item(s))`);
  return { ok: failures.length === 0, lines };
}

if (process.argv[1]?.endsWith("check-dependency-approval.mjs")) {
  if (process.argv.includes("--snapshot")) {
    const result = snapshot();
    console.log(result.lines.join("\n"));
    process.exitCode = 0;
  } else {
    const result = run();
    console.log(result.lines.join("\n"));
    process.exitCode = result.ok ? 0 : 1;
  }
}
