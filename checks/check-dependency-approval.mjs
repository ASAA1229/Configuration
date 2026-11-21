// Dependency and image approval check (policy/install-import-policy.json).
//   --snapshot --approval-id <id> : records every npm, Python and Docker dependency found in the four project
//                                   repositories and this configuration project into policy/approved-dependencies.json.
//                                   The id must match a record in policy/install-import-approvals.json.
//   (default)                     : compares the current state with the snapshot and fails on any new or changed
//                                   dependency, and on any Docker image that is unapproved or not pinned to a version or digest.
// Read-only against the project repositories. Standard library only.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { CONFIG_ROOT, PROJECT_REPOS, readJson, walkFiles } from "./lib/env.mjs";

const SNAPSHOT_PATH = join(CONFIG_ROOT, "policy", "approved-dependencies.json");
const INSTALL_POLICY_PATH = join(CONFIG_ROOT, "policy", "install-import-policy.json");
const APPROVALS_PATH = join(CONFIG_ROOT, "policy", "install-import-approvals.json");

const ALL_REPOS = [...PROJECT_REPOS, { name: "configuration", path: CONFIG_ROOT }];
const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const TEMPLATE_LOCAL_IMAGE = "templates-local-prod:${TEMPLATES_IMAGE_TAG:?set by common.ps1 (version-derived tag)}";

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

// PEP 508 strings: name, optional extras, then version specifier.
function parsePep508(item) {
  const m = /^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$/.exec(item);
  return m ? { name: m[1], spec: `${m[2] ?? ""}${m[3] ?? ""}`.trim() } : null;
}

function collectPython(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => name === "pyproject.toml" || /^requirements.*\.txt$/.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8").replace(/^﻿/, "");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    if (basename(file) === "pyproject.toml") {
      // [project] dependencies = [ ... ] (possibly multi-line)
      for (const block of text.matchAll(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/gm)) {
        for (const item of block[1].matchAll(/"([^"]+)"/g)) {
          const dep = parsePep508(item[1]);
          if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: "dependencies", name: dep.name, spec: dep.spec });
        }
      }
      // [project.optional-dependencies] groups: name = [ ... ]
      const optional = /\[project\.optional-dependencies\]([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text);
      if (optional) {
        for (const block of optional[1].matchAll(/^\s*([A-Za-z0-9_.-]+)\s*=\s*\[([\s\S]*?)\]/gm)) {
          for (const item of block[2].matchAll(/"([^"]+)"/g)) {
            const dep = parsePep508(item[1]);
            if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: `optional:${block[1]}`, name: dep.name, spec: dep.spec });
          }
        }
      }
    } else {
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.split("#")[0].trim();
        if (!line || line.startsWith("-")) continue;
        const dep = parsePep508(line);
        if (dep) found.push({ repo: repo.name, ecosystem: "python", manifest, section: "requirements", name: dep.name, spec: dep.spec });
      }
    }
  }
  return found;
}

function collectDocker(repo) {
  const found = [];
  const files = walkFiles(repo.path, (name) => /^(Dockerfile(\..*)?|docker-compose.*\.ya?ml|compose.*\.ya?ml)$/i.test(name));
  for (const file of files) {
    const text = readFileSync(file, "utf8").replace(/^﻿/, "");
    const manifest = relative(repo.path, file).replace(/\\/g, "/");
    if (/^Dockerfile/i.test(basename(file))) {
      const stages = new Set();
      for (const m of text.matchAll(/^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/gim)) {
        const ref = m[1];
        // A FROM that names an earlier build stage is not an image.
        if (!stages.has(ref.toLowerCase())) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "FROM", name: ref });
        if (m[2]) stages.add(m[2].toLowerCase());
      }
    } else {
      for (const line of text.split(/\r?\n/)) {
        const image = parseComposeImage(line);
        if (image) found.push({ repo: repo.name, ecosystem: "docker", manifest, section: "image", name: image });
      }
    }
  }
  return found;
}

export function parseComposeImage(line) {
  const match = /^\s*image:\s*(?:"([^"]*)"|'([^']*)'|(.+?))\s*(?:#.*)?$/i.exec(line);
  return (match?.[1] ?? match?.[2] ?? match?.[3] ?? "").trim() || null;
}

function isFixedTag(tag) {
  return /^\d+\.\d+(?:\.\d+)?(?:-[a-z0-9][a-z0-9.]*)?$/i.test(tag)
    || /^rehearsal-\d+$/i.test(tag);
}

function hasVersionDerivedTemplateTagSource() {
  const templates = PROJECT_REPOS.find((repo) => repo.name === "Templates");
  if (!templates) return false;
  const sourcePath = join(templates.path, "deploy", "local-prod", "common.ps1");
  if (!existsSync(sourcePath)) return false;
  const source = readFileSync(sourcePath, "utf8");
  return source.includes("function Get-ImageVersionTag")
    && source.includes('return "$version-$sha"')
    && source.includes("$env:TEMPLATES_IMAGE_TAG = if ($runningTag) { $runningTag } else { Get-ImageVersionTag }");
}

export function isExactDockerTag(image, { versionDerivedTemplateTag = false } = {}) {
  if (/@sha256:[a-f0-9]{64}$/.test(image)) return true;

  const variable = /:\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]+)|:\?([^}]+))\}$/.exec(image);
  if (variable) {
    if (variable[2] !== undefined) return isFixedTag(variable[2]);
    return image === TEMPLATE_LOCAL_IMAGE && versionDerivedTemplateTag;
  }

  const lastColon = image.lastIndexOf(":");
  if (lastColon <= image.lastIndexOf("/")) return false;
  return isFixedTag(image.slice(lastColon + 1));
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

function requireApproval(approvalId) {
  if (!approvalId) return "snapshot requires --approval-id <id> (see policy/install-import-approvals.json)";
  if (!existsSync(APPROVALS_PATH)) return `no approval record file at policy/install-import-approvals.json`;
  const records = readJson(APPROVALS_PATH).records ?? [];
  const rec = records.find((r) => r.id === approvalId);
  if (!rec) return `approval id ${approvalId} not found`;
  for (const f of ["id", "date", "what", "why", "approver"]) if (!rec[f]) return `approval ${approvalId} is missing field ${f}`;
  return null;
}

export function snapshot(approvalId) {
  const problem = requireApproval(approvalId);
  if (problem) return { ok: false, lines: [`snapshot refused: ${problem}`] };
  const items = collectAll();
  const body = {
    schema: "asaa.configuration.approved-dependencies.v2",
    description: "Owner-approved baseline of every npm, Python and Docker dependency in the ASAA project repositories at the time of this snapshot. Any later addition or change fails checks/check-dependency-approval.mjs until the owner approves it (policy/install-import-policy.json) and the snapshot is refreshed.",
    generatedBy: "checks/check-dependency-approval.mjs --snapshot --approval-id",
    approvalId,
    counts: items.reduce((acc, d) => ({ ...acc, [d.ecosystem]: (acc[d.ecosystem] ?? 0) + 1 }), {}),
    dependencies: items,
  };
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(body, null, 2) + "\n");
  return { ok: true, lines: [`snapshot written: ${items.length} entries (approval ${approvalId})`, `counts: ${JSON.stringify(body.counts)}`] };
}

export function run() {
  const lines = [];
  const failures = [];
  if (!existsSync(SNAPSHOT_PATH)) {
    return { ok: false, lines: ["No approved snapshot found. The owner must create one with --snapshot --approval-id <id>."] };
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
    failures.push(approvedByIdentity.has(identity) ? `CHANGED  ${label} (approved spec differs)` : `NEW      ${label}`);
  }
  const currentKeys = new Set(current.map(key));
  const removed = approved.filter((d) => !currentKeys.has(key(d)));

  // Docker images: approved list and exact version tag or digest (IIP-3, IIP-4).
  const install = readJson(INSTALL_POLICY_PATH);
  const approvedImages = new Set(install.approvedDockerImages.map((i) => i.image));
  const seenImages = new Set();
  const versionDerivedTemplateTag = hasVersionDerivedTemplateTagSource();
  for (const d of current.filter((x) => x.ecosystem === "docker")) {
    const id = `${d.repo} ${d.name}`;
    if (seenImages.has(id)) continue;
    seenImages.add(id);
    if (!isExactDockerTag(d.name, { versionDerivedTemplateTag })) failures.push(`UNPINNED   ${d.repo}: image ${d.name} (exact tag or digest required, see IIP-3)`);
    if (!approvedImages.has(d.name)) failures.push(`NOT APPROVED ${d.repo}: image ${d.name} (owner approval record required, see IIP-4)`);
  }

  lines.push(`approved entries: ${approved.length}, current entries: ${current.length}, removed since snapshot: ${removed.length}`);
  for (const f of failures) lines.push(`FAIL  ${f}`);
  lines.push(failures.length === 0 ? "dependency-approval: PASS" : `dependency-approval: FAIL (${failures.length} item(s))`);
  return { ok: failures.length === 0, lines };
}

if (process.argv[1]?.endsWith("check-dependency-approval.mjs")) {
  if (process.argv.includes("--snapshot")) {
    const idx = process.argv.indexOf("--approval-id");
    const result = snapshot(idx >= 0 ? process.argv[idx + 1] : undefined);
    console.log(result.lines.join("\n"));
    process.exitCode = result.ok ? 0 : 1;
  } else {
    const result = run();
    console.log(result.lines.join("\n"));
    process.exitCode = result.ok ? 0 : 1;
  }
}
