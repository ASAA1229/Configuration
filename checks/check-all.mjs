// Runs every configuration check and exits non-zero if any check fails.
// Usage: node checks/check-all.mjs
// Read-only. Dependencies are never installed or imported by these checks.

import { run as runDataLocality } from "./check-data-locality.mjs";
import { run as runDependencyApproval } from "./check-dependency-approval.mjs";

const checks = [
  { name: "data locality", run: runDataLocality },
  { name: "dependency approval", run: runDependencyApproval },
];

let failed = 0;
for (const check of checks) {
  console.log(`===== ${check.name}`);
  const result = check.run();
  console.log(result.lines.join("\n"));
  if (!result.ok) failed += 1;
}

console.log(failed === 0 ? "\ncheck-all: PASS" : `\ncheck-all: FAIL (${failed} check group(s) failed)`);
process.exitCode = failed === 0 ? 0 : 1;
