// Per-service bind check for docker compose files. Standard library only. Pure functions: no I/O.
//
// A service may bind 0.0.0.0 INSIDE its container (normal for Docker) only if every published port of that service is
// bound to a loopback address. Services with no published ports are internal to Docker and are accepted.
// Values are returned as rule results only; nothing is printed here.

const BIND_KEY = /^\s*-?\s*(HOST|BIND_HOST|BIND_ADDRESS|LISTEN_HOST)\s*[:=]\s*["']?([^"'\s#,]*)/;

function indentOf(line) {
  return line.length - line.trimStart().length;
}

function stripQuotes(s) {
  return s.trim().replace(/^["']|["']$/g, "");
}

// Parses top-level "services:" into { name: { binds: [{key, value}], ports: [string] } }.
export function parseComposeServices(text) {
  const services = {};
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  let inServices = false;
  let servicesIndent = null;
  let current = null;
  let serviceIndent = null;
  let inPorts = false;
  let portsIndent = null;

  for (const raw of lines) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const ind = indentOf(raw);
    const trimmed = raw.trim();

    if (ind === 0) {
      inServices = /^services\s*:\s*$/.test(trimmed);
      current = null;
      inPorts = false;
      continue;
    }
    if (!inServices) continue;

    if (servicesIndent === null) servicesIndent = ind;
    if (ind === servicesIndent && /^[A-Za-z0-9_.-]+\s*:\s*$/.test(trimmed)) {
      current = trimmed.replace(/:\s*$/, "");
      serviceIndent = ind;
      services[current] = { binds: [], ports: [] };
      inPorts = false;
      continue;
    }
    if (!current) continue;
    if (ind <= serviceIndent) { current = null; continue; }

    // Inline ports list: ports: ["127.0.0.1:8201:8201", "8080:80"]
    const inlinePorts = /^ports\s*:\s*\[(.*)\]\s*$/.exec(trimmed);
    if (inlinePorts) {
      for (const item of inlinePorts[1].split(",")) {
        if (item.trim()) services[current].ports.push(stripQuotes(item));
      }
      inPorts = false;
      continue;
    }
    if (/^ports\s*:\s*$/.test(trimmed)) {
      inPorts = true;
      portsIndent = ind;
      continue;
    }
    if (inPorts) {
      if (ind > portsIndent && trimmed.startsWith("-")) {
        services[current].ports.push(stripQuotes(trimmed.slice(1)));
        continue;
      }
      if (ind > portsIndent) continue; // long-syntax mapping lines under a list item
      inPorts = false;
    }

    const bind = BIND_KEY.exec(raw);
    if (bind) services[current].binds.push({ key: bind[1].toUpperCase(), value: bind[2] });
  }
  return services;
}

// A published port is loopback only when it names a loopback host explicitly: "127.0.0.1:H:C", "[::1]:H:C" or "::1:H:C".
export function isLoopbackPort(entry) {
  const e = stripQuotes(entry);
  if (e.startsWith("[::1]:")) return true;
  if (e.startsWith("127.0.0.1:")) return e.split(":").length >= 3;
  return false;
}

// Returns [{ ok, rule }] for every service that sets a non-loopback bind key.
export function checkComposeBinds(text) {
  const results = [];
  const services = parseComposeServices(text);
  for (const [name, svc] of Object.entries(services)) {
    for (const bind of svc.binds) {
      if (bind.value === "") continue;
      const loopbackBind = ["127.0.0.1", "localhost", "::1"].includes(bind.value);
      if (loopbackBind) {
        results.push({ ok: true, rule: `${name}: ${bind.key} is loopback` });
        continue;
      }
      // Container-internal wildcard bind: acceptable only if every published port is loopback.
      const publishedOk = svc.ports.every((p) => isLoopbackPort(p));
      results.push({ ok: publishedOk, rule: `${name}: ${bind.key} is container-internal and every published port must be loopback` });
    }
  }
  return results;
}
