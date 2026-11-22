// Minimal JSON Schema validator (draft 2020-12 subset). Standard library only. Pure functions: no I/O.
//
// Supported keywords: type, const, enum, required, properties, additionalProperties (boolean or schema), items,
// minItems, uniqueItems, minLength, maxLength, pattern, minimum, maximum, oneOf, anyOf, $ref (local "#/$defs/..."),
// and the custom keyword "x-uniqueBy" (array of objects unique by a property).
// Errors are returned as [{ path, message }]. Values are not echoed into messages, so secrets are never reflected.

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (Number.isInteger(v)) return "integer";
  return typeof v;
}

function typeMatches(expected, value) {
  const actual = typeOf(value);
  const list = Array.isArray(expected) ? expected : [expected];
  return list.some((t) => t === actual || (t === "number" && actual === "integer"));
}

function resolveRef(root, ref) {
  if (!ref.startsWith("#/")) throw new Error(`only local $ref is supported: ${ref}`);
  return ref.slice(2).split("/").reduce((node, part) => node?.[part.replace(/~1/g, "/").replace(/~0/g, "~")], root);
}

export function validate(schema, value, { root = schema, path = "$" } = {}) {
  const errors = [];
  const add = (message, p = path) => errors.push({ path: p, message });

  if (schema === true) return errors;
  if (schema === false) { add("no value is allowed here"); return errors; }
  if (schema.$ref) return validate(resolveRef(root, schema.$ref), value, { root, path });

  if (schema.type && !typeMatches(schema.type, value)) { add(`expected ${[].concat(schema.type).join(" or ")}, found ${typeOf(value)}`); return errors; }
  if ("const" in schema && JSON.stringify(schema.const) !== JSON.stringify(value)) add("value does not equal the required constant");
  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) add(`value is not one of the allowed values (${schema.enum.length})`);

  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) add(`shorter than ${schema.minLength} characters`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) add(`longer than ${schema.maxLength} characters`);
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) add("does not match the required pattern");
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) add(`less than ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) add(`greater than ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) add(`fewer than ${schema.minItems} items`);
    if (schema.uniqueItems) {
      const seen = new Set();
      for (const item of value) {
        const k = JSON.stringify(item);
        if (seen.has(k)) { add("items are not unique"); break; }
        seen.add(k);
      }
    }
    if (schema["x-uniqueBy"]) {
      const seen = new Set();
      for (const [i, item] of value.entries()) {
        const k = item?.[schema["x-uniqueBy"]];
        if (k === undefined) continue;
        if (seen.has(k)) add(`duplicate ${schema["x-uniqueBy"]}`, `${path}[${i}]`);
        seen.add(k);
      }
    }
    if (schema.items) value.forEach((item, i) => errors.push(...validate(schema.items, item, { root, path: `${path}[${i}]` })));
  }
  if (typeOf(value) === "object") {
    for (const req of schema.required ?? []) if (!(req in value)) add(`missing required property "${req}"`);
    const props = schema.properties ?? {};
    for (const [k, v] of Object.entries(value)) {
      if (props[k]) errors.push(...validate(props[k], v, { root, path: `${path}.${k}` }));
      else if (schema.additionalProperties === false) add(`unexpected property "${k}"`, `${path}.${k}`);
      else if (typeof schema.additionalProperties === "object") errors.push(...validate(schema.additionalProperties, v, { root, path: `${path}.${k}` }));
    }
  }
  if (schema.anyOf && !schema.anyOf.some((s) => validate(s, value, { root, path }).length === 0)) add("does not match any allowed shape");
  if (schema.oneOf && schema.oneOf.filter((s) => validate(s, value, { root, path }).length === 0).length !== 1) add("does not match exactly one allowed shape");
  return errors;
}
