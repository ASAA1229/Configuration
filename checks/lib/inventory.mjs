// Dependency inventory records and snapshot difference handling. Standard library only. Pure functions: no I/O.
//
// A collected dependency entry is { repo, ecosystem, manifest, section, name, spec? }. The same entry can occur several
// times (for example one Compose image used by two services), so the inventory aggregates entries by identity and keeps
// an occurrence count. Snapshot differences are reported per inventory record so every finding can cite a stable id.

import { createHash } from "node:crypto";

export const identityOf = (d) => `${d.repo}|${d.ecosystem}|${d.manifest}|${d.section}|${d.name}`;
export const entryKey = (d) => `${identityOf(d)}|${d.spec ?? ""}`;

export function inventoryId(d) {
  return `dep-${createHash("sha256").update(identityOf(d)).digest("hex").slice(0, 12)}`;
}

// Aggregates entries into inventory records keyed by identity.
export function buildInventory(entries) {
  const records = new Map();
  for (const d of entries) {
    const identity = identityOf(d);
    let rec = records.get(identity);
    if (!rec) {
      rec = { id: inventoryId(d), repo: d.repo, ecosystem: d.ecosystem, manifest: d.manifest, section: d.section, name: d.name, specs: [], occurrences: 0 };
      records.set(identity, rec);
    }
    rec.occurrences += 1;
    const spec = d.spec ?? "";
    if (!rec.specs.includes(spec)) rec.specs.push(spec);
  }
  return records;
}

function label(rec) {
  return rec.ecosystem === "docker"
    ? `${rec.repo} ${rec.manifest}: image ${rec.name}`
    : `${rec.repo} ${rec.manifest} [${rec.section}]: ${rec.name}`;
}

// Compares an approved snapshot with the current collection.
// Returns counts that explain entry-total differences and per-record changes:
//   added            - identity not in the snapshot
//   removed          - identity no longer collected
//   specChanged      - identity present in both, but the version specifier differs
//   occurrenceChanged- identity and specifier unchanged, but it occurs a different number of times
export function diffSnapshot(approvedEntries, currentEntries) {
  const approved = buildInventory(approvedEntries);
  const current = buildInventory(currentEntries);
  const added = [];
  const removed = [];
  const specChanged = [];
  const occurrenceChanged = [];
  let unchanged = 0;

  for (const [identity, cur] of current) {
    const old = approved.get(identity);
    if (!old) { added.push({ record: cur, label: label(cur) }); continue; }
    const sameSpecs = old.specs.length === cur.specs.length && old.specs.every((s) => cur.specs.includes(s));
    if (!sameSpecs) specChanged.push({ record: cur, approvedSpecs: old.specs, currentSpecs: cur.specs, label: label(cur) });
    else if (old.occurrences !== cur.occurrences) occurrenceChanged.push({ record: cur, approvedOccurrences: old.occurrences, currentOccurrences: cur.occurrences, label: label(cur) });
    else unchanged += 1;
  }
  for (const [identity, old] of approved) {
    if (!current.has(identity)) removed.push({ record: old, label: label(old) });
  }

  const totals = {
    approvedEntries: approvedEntries.length,
    currentEntries: currentEntries.length,
    approvedRecords: approved.size,
    currentRecords: current.size,
    duplicateApprovedEntries: approvedEntries.length - approved.size,
    duplicateCurrentEntries: currentEntries.length - current.size,
  };
  // Every unit of entry-count difference is attributed to a category so a total mismatch is always explained.
  const occurrenceDelta = occurrenceChanged.reduce((n, c) => n + (c.currentOccurrences - c.approvedOccurrences), 0);
  const addedEntries = added.reduce((n, a) => n + a.record.occurrences, 0);
  const removedEntries = removed.reduce((n, r) => n + r.record.occurrences, 0);
  const specEntryDelta = specChanged.reduce((n, c) => n + (c.record.occurrences - (approved.get(identityOf(c.record))?.occurrences ?? 0)), 0);
  totals.explainedDelta = { added: addedEntries, removed: -removedEntries, occurrence: occurrenceDelta, specChange: specEntryDelta };
  totals.unexplainedDelta = (currentEntries.length - approvedEntries.length) - (addedEntries - removedEntries + occurrenceDelta + specEntryDelta);

  return { added, removed, specChanged, occurrenceChanged, unchanged, totals, current, approved };
}
