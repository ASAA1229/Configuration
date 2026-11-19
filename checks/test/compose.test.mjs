// Fixture tests for the compose bind rule. Run with: node --test checks/test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkComposeBinds, isLoopbackPort } from "../lib/compose.mjs";

const verdict = (text) => checkComposeBinds(text).map((r) => r.ok);

test("container-internal wildcard bind is accepted when the only published port is loopback", () => {
  const text = `services:
  app:
    image: example/app:1.2.3
    environment:
      HOST: 0.0.0.0
    ports: ["127.0.0.1:8201:8201"]
`;
  assert.deepEqual(verdict(text), [true]);
});

test("container-internal wildcard bind is flagged when a port is published without a loopback host", () => {
  const text = `services:
  app:
    image: example/app:1.2.3
    environment:
      HOST: 0.0.0.0
    ports:
      - "8201:8201"
`;
  assert.deepEqual(verdict(text), [false]);
});

test("container-internal wildcard bind is flagged when a port is published on 0.0.0.0", () => {
  const text = `services:
  app:
    environment:
      - HOST=0.0.0.0
    ports:
      - "0.0.0.0:8201:8201"
`;
  assert.deepEqual(verdict(text), [false]);
});

test("a wildcard bind with no published ports is internal to Docker and accepted", () => {
  const text = `services:
  app:
    environment:
      HOST: 0.0.0.0
`;
  assert.deepEqual(verdict(text), [true]);
});

test("an explicit loopback bind is accepted", () => {
  const text = `services:
  app:
    environment:
      HOST: 127.0.0.1
    ports: ["127.0.0.1:8080:8080"]
`;
  assert.deepEqual(verdict(text), [true]);
});

test("one unsafe port in an inline list fails the whole service", () => {
  const text = `services:
  app:
    environment:
      HOST: 0.0.0.0
    ports: ["127.0.0.1:8080:8080", "9000:9000"]
`;
  assert.deepEqual(verdict(text), [false]);
});

test("only the offending service is flagged in a multi-service file", () => {
  const text = `services:
  safe:
    environment:
      HOST: 0.0.0.0
    ports: ["127.0.0.1:8100:8100"]
  unsafe:
    environment:
      HOST: 0.0.0.0
    ports:
      - "8200:8200"
  db:
    image: postgres:16.16
`;
  const results = checkComposeBinds(text);
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.match(results[1].rule, /^unsafe:/);
});

test("long-syntax port entries are treated as not loopback (conservative)", () => {
  const text = `services:
  app:
    environment:
      HOST: 0.0.0.0
    ports:
      - target: 8080
        published: 8080
`;
  assert.deepEqual(verdict(text), [false]);
});

test("byte order mark and CRLF line endings are tolerated", () => {
  const text = "﻿services:\r\n  app:\r\n    environment:\r\n      HOST: 0.0.0.0\r\n    ports: [\"127.0.0.1:8201:8201\"]\r\n";
  assert.deepEqual(verdict(text), [true]);
});

test("isLoopbackPort accepts only explicit loopback hosts", () => {
  assert.equal(isLoopbackPort("127.0.0.1:8201:8201"), true);
  assert.equal(isLoopbackPort("[::1]:8080:8080"), true);
  assert.equal(isLoopbackPort("8201:8201"), false);
  assert.equal(isLoopbackPort("0.0.0.0:8201:8201"), false);
  assert.equal(isLoopbackPort("localhost:8201:8201"), false);
});
