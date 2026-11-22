// Programmatic interface of the Configuration project for other ASAA1229 tools (for example the organization
// governance validator). Everything here is read-only except the explicitly named write operations, which are only
// exposed through config-cli.mjs with their own safeguards.

export { runAll } from "./check-all.mjs";
export { evaluate as evaluateDependencies, collectAll as collectDependencies } from "./check-dependency-approval.mjs";
export { buildInventory, diffSnapshot, inventoryId } from "./lib/inventory.mjs";
export { classifyImageRef, parseImageRef } from "./lib/docker-ref.mjs";
export { listEnvironments, resolveEnvironment, defaultEnvironmentName } from "./lib/environments.mjs";
export { classifySecretValue, isSecretKey, parseSecretRef, resolveSecretRef } from "./lib/secret-ref.mjs";
export { loadLedger, verifyLedger, listVersions, TRACKED_FILES } from "./lib/history.mjs";
export { FINDING_CODES, REPORT_SCHEMA, FINDINGS_SCHEMA } from "./lib/findings.mjs";
export { validate as validateAgainstSchema } from "./lib/schema.mjs";
