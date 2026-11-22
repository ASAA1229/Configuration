// Configuration versioning, audit ledger and rollback. Standard library only.
//
// Versions of every tracked policy/configuration file come from git history (the repository is the version store, so
// nothing is duplicated). On top of that, policy/history/ledger.json is an append-only, hash-chained ledger of every
// controlled change made through the tooling (snapshot refresh, approval record, rollback, baseline). The chain makes
// silent edits of the ledger detectable, and the per-file content hash makes unrecorded edits of policy files
// detectable (drift).
//
// Rollback restores a file to the content of an earlier commit. It requires an existing owner approval id, never
// rewrites git history, and records the rollback in the ledger. The change is then committed through the normal
// branch and review flow.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CONFIG_ROOT } from "./env.mjs";

export const LEDGER_SCHEMA = "asaa.configuration.history-ledger.v1";
export const LEDGER_PATH = join(CONFIG_ROOT, "policy", "history", "ledger.json");

// Files under version control by this mechanism (paths relative to the configuration root, forward slashes).
export const TRACKED_FILES = [
  "policy/approved-dependencies.json",
  "policy/install-import-policy.json",
  "policy/install-import-approvals.json",
  "policy/data-locality-policy.json",
  "policy/audit-policy.json",
  "identity/realm/asaa-realm.json",
  "environments/base.json",
  "environments/local.json",
  "environments/ci.json",
  "environments/local-prod.json",
];

const ACTIONS = new Set(["baseline", "snapshot", "approval", "request", "rollback", "record"]);

export function sha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

// Content hash with line endings normalised, so a CRLF checkout (core.autocrlf) is not reported as drift.
export function fileSha(rel, root = CONFIG_ROOT) {
  const full = join(root, rel);
  return existsSync(full) ? sha256(readFileSync(full, "utf8").replace(/\r\n/g, "\n")) : null;
}

export function loadLedger(path = LEDGER_PATH) {
  if (!existsSync(path)) return { schema: LEDGER_SCHEMA, entries: [] };
  return JSON.parse(readFileSync(path, "utf8"));
}

function entryHash(entry) {
  const { entryHash: _ignored, ...rest } = entry;
  return sha256(JSON.stringify(rest));
}

// Appends a ledger entry for a file. Returns the entry.
export function appendEntry({ file, action, reason, approvalId = null, actor = "automation", details = null, now = new Date() }, { path = LEDGER_PATH, root = CONFIG_ROOT } = {}) {
  if (!ACTIONS.has(action)) throw new Error(`unknown ledger action ${action}`);
  if (!reason) throw new Error("a ledger entry needs a reason");
  const ledger = loadLedger(path);
  const prev = ledger.entries.at(-1) ?? null;
  const entry = {
    seq: (prev?.seq ?? 0) + 1,
    file,
    sha256: fileSha(file, root),
    action,
    reason,
    approvalId,
    actor,
    recordedAt: now.toISOString(),
    ...(details ? { details } : {}),
    prevEntryHash: prev?.entryHash ?? null,
  };
  entry.entryHash = entryHash(entry);
  ledger.entries.push(entry);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(ledger, null, 2) + "\n");
  return entry;
}

// Verifies the hash chain. Returns { ok, brokenAt, reason }.
export function verifyLedger(ledger) {
  let prev = null;
  for (const [i, e] of ledger.entries.entries()) {
    if (e.seq !== i + 1) return { ok: false, brokenAt: e.seq ?? i + 1, reason: "sequence gap" };
    if ((e.prevEntryHash ?? null) !== (prev?.entryHash ?? null)) return { ok: false, brokenAt: e.seq, reason: "previous-hash mismatch" };
    if (entryHash(e) !== e.entryHash) return { ok: false, brokenAt: e.seq, reason: "entry hash mismatch" };
    prev = e;
  }
  return { ok: true, brokenAt: null, reason: null };
}

export function headEntry(ledger, file) {
  for (let i = ledger.entries.length - 1; i >= 0; i -= 1) if (ledger.entries[i].file === file) return ledger.entries[i];
  return null;
}

// Git-backed versions ---------------------------------------------------------------------------------------------

function git(args, root = CONFIG_ROOT) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 });
}

export function gitAvailable(root = CONFIG_ROOT) {
  try { git(["rev-parse", "--is-inside-work-tree"], root); return true; } catch { return false; }
}

// Lists committed versions of a file, newest first: [{ commit, date, subject }].
export function listVersions(file, root = CONFIG_ROOT) {
  if (!gitAvailable(root)) return [];
  const out = git(["log", "--follow", "--format=%H%x1f%cI%x1f%s", "--", file], root);
  return out.split("\n").filter(Boolean).map((line) => {
    const [commit, date, subject] = line.split("\x1f");
    return { commit, date, subject };
  });
}

export function readVersion(file, commit, root = CONFIG_ROOT) {
  if (!/^[0-9a-f]{7,40}$/i.test(commit)) throw new Error("commit must be a hexadecimal object id");
  return git(["show", `${commit}:${file}`], root);
}

// Files changed in the working tree or index relative to HEAD, limited to tracked configuration paths.
export function worktreeChanges(root = CONFIG_ROOT) {
  if (!gitAvailable(root)) return [];
  const out = git(["status", "--porcelain", "--", ...TRACKED_FILES.map((f) => f.split("/")[0]).filter((v, i, a) => a.indexOf(v) === i)], root);
  return out.split("\n").filter(Boolean).map((line) => ({ status: line.slice(0, 2).trim(), file: line.slice(3).trim().replace(/\\/g, "/") }))
    .filter((c) => TRACKED_FILES.includes(c.file) || c.file.startsWith("environments/") || c.file.startsWith("policy/"));
}

// Structural JSON diff: [{ path, change: "added"|"removed"|"changed", before?, after? }].
export function jsonDiff(before, after, path = "$", out = []) {
  if (Object.is(before, after)) return out;
  const isObj = (v) => v !== null && typeof v === "object";
  if (!isObj(before) || !isObj(after) || Array.isArray(before) !== Array.isArray(after)) {
    out.push({ path, change: "changed", before, after });
    return out;
  }
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const k of keys) {
    const p = Array.isArray(before) ? `${path}[${k}]` : `${path}.${k}`;
    if (!(k in after)) out.push({ path: p, change: "removed", before: before[k] });
    else if (!(k in before)) out.push({ path: p, change: "added", after: after[k] });
    else jsonDiff(before[k], after[k], p, out);
  }
  return out;
}

// Restores a tracked JSON file to the content it had at commit. Requires an approval id present in approvalIds.
export function rollback({ file, commit, approvalId, approvalIds, actor, reason }, { root = CONFIG_ROOT, ledgerPath = LEDGER_PATH } = {}) {
  if (!TRACKED_FILES.includes(file)) return { ok: false, error: `${file} is not a tracked configuration file` };
  if (!approvalId || !approvalIds.has(approvalId)) return { ok: false, error: "rollback requires an existing owner approval id (--approval-id)" };
  let content;
  try { content = readVersion(file, commit, root); } catch { return { ok: false, error: `${file} has no version at ${commit}` }; }
  try { JSON.parse(content); } catch { return { ok: false, error: `the version at ${commit} is not valid JSON` }; }
  const fromSha = fileSha(file, root);
  writeFileSync(join(root, file), content);
  const entry = appendEntry({ file, action: "rollback", reason: reason ?? `rollback to ${commit}`, approvalId, actor, details: { toCommit: commit, fromSha256: fromSha } }, { path: ledgerPath, root });
  return { ok: true, entry };
}
