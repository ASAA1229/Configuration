import { test } from "node:test";
import assert from "node:assert/strict";
import { isExactDockerTag, parseComposeImage } from "../check-dependency-approval.mjs";

test("compose image parsing retains interpolation error messages containing spaces", () => {
  assert.equal(
    parseComposeImage("  image: templates-local-prod:${TEMPLATES_IMAGE_TAG:?set by common.ps1 (version-derived tag)}"),
    "templates-local-prod:${TEMPLATES_IMAGE_TAG:?set by common.ps1 (version-derived tag)}",
  );
  assert.equal(parseComposeImage('  image: "node:24.22.3-alpine3.24" # pinned build image'), "node:24.22.3-alpine3.24");
  assert.equal(parseComposeImage("  command: node app.js"), null);
});

test("exact tags, including fixed Compose defaults, satisfy IIP-3", () => {
  assert.equal(isExactDockerTag("postgres:16.16@sha256:" + "a".repeat(64)), true);
  assert.equal(isExactDockerTag("node:24.22.3-alpine3.24"), true);
  assert.equal(isExactDockerTag("asaa-api:${API_IMAGE_TAG:-0.2.0}"), true);
  assert.equal(isExactDockerTag("asaa-api:${API_IMAGE_TAG:-rehearsal-1}"), true);
  assert.equal(isExactDockerTag("asaa-api:rehearsal-2"), true);
});

test("floating or unresolved tags do not satisfy IIP-3", () => {
  assert.equal(isExactDockerTag("postgres:latest"), false);
  assert.equal(isExactDockerTag("postgres"), false);
  assert.equal(isExactDockerTag("asaa-api:${API_IMAGE_TAG:-latest}"), false);
  assert.equal(isExactDockerTag("asaa-api:${API_IMAGE_TAG}"), false);
  assert.equal(isExactDockerTag("templates-local-prod:current"), false);
  assert.equal(isExactDockerTag("asaa-api:custom-tag"), false);
});

test("a required Templates image tag is accepted only with its version-derived source", () => {
  const image = "templates-local-prod:${TEMPLATES_IMAGE_TAG:?set by common.ps1 (version-derived tag)}";
  assert.equal(isExactDockerTag(image), false);
  assert.equal(isExactDockerTag(image, { versionDerivedTemplateTag: true }), true);
});

test("major and major.minor tags follow later releases and do not satisfy IIP-3 (E:D1.4)", () => {
  for (const ref of ["nginx:1.25", "postgres:16", "python:3.12-slim", "node:24-alpine", "app:${TAG:-1.2}"]) {
    assert.equal(isExactDockerTag(ref), false, ref);
  }
  for (const ref of ["nginx:1.25.3", "ghcr.io/org/app:v1.2.3", "node:24.22.3-alpine3.24", "app:${TAG:-1.2.3}"]) {
    assert.equal(isExactDockerTag(ref), true, ref);
  }
});
