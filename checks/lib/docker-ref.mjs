// Docker image reference parser and immutability classifier (IIP-3). Standard library only. Pure functions: no I/O.
//
// A reference is split into registry, repository, tag and digest following the distribution reference grammar, with
// support for Compose interpolation: ${VAR}, ${VAR:-default}, ${VAR-default}, ${VAR:?message}, ${VAR?message} and $VAR.
// Interpolation messages may contain spaces, colons and parentheses; braces are matched, not regex-guessed.
//
// Immutability levels, strongest first:
//   immutable   - pinned by a valid sha256 digest (the content can never change)
//   exact       - pinned to a fixed version tag (major.minor.patch[-suffix] or rehearsal-N)
//   conditional - the tag is a variable whose fallback is a fixed tag, or a required variable whose value comes from a
//                 trusted version-derived source supplied by the caller
//   mutable     - untagged, "latest", a free-form tag, a variable without a fixed fallback, or a variable repository
//   invalid     - the reference does not parse

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const COMPONENT = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const TAG = /^[\w][\w.-]{0,127}$/;
const HOST = /^(?:localhost|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+|\[[0-9a-fA-F:]+\])(?::\d{1,5})?$|^localhost(?::\d{1,5})?$/;

// An exact tag names one release: major.minor.patch (optional "v" prefix and a "-variant" or pre-release suffix), or a
// rehearsal build number. A major or major.minor tag (16, 1.25, 3.12-slim) follows later releases and is not exact.
export function isFixedTag(tag) {
  return /^v?\d+\.\d+\.\d+(?:-[a-z0-9][a-z0-9.]*)?$/i.test(tag) || /^rehearsal-\d+$/i.test(tag);
}

// Name of the variable that supplies the tag, when the reference is "conditional" on it.
export function tagVariableName(raw) {
  return parseImageRef(raw).tagVariable?.name ?? null;
}

// Splits a string into literal text and interpolation tokens. Returns null when braces are unbalanced.
export function tokenize(text) {
  const tokens = [];
  let i = 0;
  let literal = "";
  while (i < text.length) {
    const ch = text[i];
    if (ch === "$" && text[i + 1] === "$") { literal += "$"; i += 2; continue; }
    if (ch === "$" && text[i + 1] === "{") {
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        if (text[j] === "{") depth += 1;
        else if (text[j] === "}") depth -= 1;
        j += 1;
      }
      if (depth !== 0) return null;
      if (literal) { tokens.push({ type: "text", value: literal }); literal = ""; }
      tokens.push({ type: "var", ...parseVariable(text.slice(i + 2, j - 1)), raw: text.slice(i, j) });
      i = j;
      continue;
    }
    if (ch === "$" && /[A-Za-z_]/.test(text[i + 1] ?? "")) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(text.slice(i + 1));
      if (literal) { tokens.push({ type: "text", value: literal }); literal = ""; }
      tokens.push({ type: "var", name: m[0], operator: null, argument: null, raw: `$${m[0]}` });
      i += 1 + m[0].length;
      continue;
    }
    literal += ch;
    i += 1;
  }
  if (literal) tokens.push({ type: "text", value: literal });
  return tokens;
}

function parseVariable(body) {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?|:\+|\+)([\s\S]*))?$/.exec(body);
  if (!m) return { name: null, operator: null, argument: null, malformed: true };
  return { name: m[1], operator: m[2] ?? null, argument: m[3] ?? null };
}

// Splits "registry/ns/repo:tag@digest" at the top level, ignoring separators inside interpolation tokens.
function splitTopLevel(tokens) {
  // Rebuild a string where interpolation tokens are replaced by placeholders so separators can be located safely.
  const placeholders = [];
  let masked = "";
  for (const t of tokens) {
    if (t.type === "text") masked += t.value;
    else { masked += `\u0000${placeholders.length}\u0000`; placeholders.push(t); }
  }
  const restore = (s) => s.replace(/\u0000(\d+)\u0000/g, (_, n) => placeholders[Number(n)].raw);
  const vars = (s) => [...s.matchAll(/\u0000(\d+)\u0000/g)].map((m) => placeholders[Number(m[1])]);

  let digest = null;
  const at = masked.indexOf("@");
  if (at >= 0) { digest = masked.slice(at + 1); masked = masked.slice(0, at); }
  let tag = null;
  const lastSlash = masked.lastIndexOf("/");
  const lastColon = masked.lastIndexOf(":");
  if (lastColon > lastSlash) { tag = masked.slice(lastColon + 1); masked = masked.slice(0, lastColon); }
  let registry = null;
  let path = masked;
  const firstSlash = masked.indexOf("/");
  if (firstSlash > 0) {
    const first = masked.slice(0, firstSlash);
    if (first.includes(".") || first.includes(":") || first === "localhost" || first.startsWith("[")) {
      registry = first;
      path = masked.slice(firstSlash + 1);
    }
  }
  return {
    registry: registry === null ? null : restore(registry),
    repository: restore(path),
    tag: tag === null ? null : restore(tag),
    digest: digest === null ? null : restore(digest),
    repositoryVars: vars(path).concat(registry ? vars(registry) : []),
    tagVars: tag === null ? [] : vars(tag),
    tagIsSingleVar: tag !== null && /^\u0000\d+\u0000$/.test(tag),
    digestVars: digest === null ? [] : vars(digest),
  };
}

export function parseImageRef(raw) {
  const input = String(raw ?? "").trim();
  const errors = [];
  if (!input) return { raw: input, valid: false, errors: ["empty image reference"] };
  if (/\s/.test(input.replace(/\$\{[^}]*\}/g, ""))) errors.push("whitespace outside interpolation");
  const tokens = tokenize(input);
  if (!tokens) return { raw: input, valid: false, errors: ["unbalanced interpolation braces"] };
  for (const t of tokens) if (t.type === "var" && t.malformed) errors.push(`malformed interpolation ${t.raw}`);
  const parts = splitTopLevel(tokens);

  if (parts.repositoryVars.length === 0) {
    for (const component of parts.repository.split("/")) {
      if (!COMPONENT.test(component)) { errors.push(`invalid repository component "${component}"`); break; }
    }
  }
  if (parts.registry && parts.repositoryVars.length === 0 && !HOST.test(parts.registry)) errors.push(`invalid registry "${parts.registry}"`);
  if (parts.tag !== null && parts.tagVars.length === 0 && !TAG.test(parts.tag)) errors.push(`invalid tag "${parts.tag}"`);
  if (parts.digest !== null && parts.digestVars.length === 0 && !DIGEST.test(parts.digest)) errors.push("digest is not a full sha256 digest");

  return {
    raw: input,
    valid: errors.length === 0,
    errors,
    registry: parts.registry,
    repository: parts.repository,
    tag: parts.tag,
    digest: parts.digest,
    variables: tokens.filter((t) => t.type === "var").map(({ name, operator, argument }) => ({ name, operator, argument })),
    tagVariable: parts.tagIsSingleVar ? parts.tagVars[0] : null,
    repositoryIsVariable: parts.repositoryVars.length > 0,
    digestIsVariable: parts.digestVars.length > 0,
  };
}

// trustedRequiredTags: set of exact raw references whose required tag variable comes from a verified version-derived source.
export function classifyImageRef(raw, { trustedRequiredTags = new Set() } = {}) {
  const ref = parseImageRef(raw);
  const result = (level, reason) => ({ ref, level, reason, pinned: level === "immutable" || level === "exact" || level === "conditional" });
  if (!ref.valid) return result("invalid", ref.errors.join("; "));
  if (ref.repositoryIsVariable) return result("mutable", "repository or registry is supplied by a variable");
  if (ref.digest !== null) {
    if (ref.digestIsVariable) return result("mutable", "digest is supplied by a variable");
    return result("immutable", "pinned by sha256 digest");
  }
  if (ref.tag === null) return result("mutable", "no tag (resolves to latest)");
  if (ref.tagVariable) {
    const v = ref.tagVariable;
    if (v.operator === ":-" || v.operator === "-") {
      if (isFixedTag(v.argument ?? "")) return result("conditional", `variable ${v.name} with fixed fallback ${v.argument}`);
      return result("mutable", `variable ${v.name} fallback "${v.argument}" is not a fixed version tag`);
    }
    if ((v.operator === ":?" || v.operator === "?") && trustedRequiredTags.has(ref.raw)) {
      return result("conditional", `required variable ${v.name} set by a verified version-derived source`);
    }
    return result("mutable", `variable ${v.name} has no fixed fallback`);
  }
  if (ref.variables.length > 0) return result("mutable", "tag is partly interpolated");
  if (ref.tag.toLowerCase() === "latest") return result("mutable", "tag is latest");
  if (isFixedTag(ref.tag)) return result("exact", `fixed version tag ${ref.tag}`);
  return result("mutable", `tag "${ref.tag}" is not a fixed version tag`);
}
