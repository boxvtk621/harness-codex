#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA_ID = "transcript-view-v1";
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_CHUNK_BYTES = 16 * 1024 * 1024;
const MAX_TEXT_BYTES = 512 * 1024 * 1024;

const uuid = {
  type: "string",
  pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
};
const sha256 = { type: "string", pattern: "^[0-9a-f]{64}$" };
const safeInteger = { type: "integer", minimum: 0, maximum: MAX_SAFE_INTEGER };
const positiveInteger = { type: "integer", minimum: 1, maximum: MAX_SAFE_INTEGER };
const preview = {
  type: "string",
  maxLength: 65_536,
  "x-utf8MaxBytes": 65_536,
};

function object(properties, optional = []) {
  return {
    type: "object",
    properties,
    required: Object.keys(properties).filter((key) => !optional.includes(key)),
    additionalProperties: false,
  };
}

const source = {
  oneOf: [
    object({
      kind: { enum: ["assistant_message", "tool_input", "tool_result"] },
      id: uuid,
      index: { const: 0 },
      stream: { const: "none" },
    }),
    object({
      kind: { const: "tool_output" },
      id: uuid,
      index: safeInteger,
      stream: { enum: ["stdout", "stderr", "result", "diagnostic"] },
    }),
  ],
};

const chunk = object({
  index: safeInteger,
  offsetBytes: safeInteger,
  artifactId: uuid,
  sizeBytes: { type: "integer", minimum: 1, maximum: MAX_CHUNK_BYTES },
  sha256,
});

const manifestBase = {
  schemaId: { const: SCHEMA_ID },
  nodeId: uuid,
  dialogId: uuid,
  attemptId: uuid,
  generation: positiveInteger,
  textId: uuid,
  source,
  preview,
  previewTruncated: { type: "boolean" },
  redaction: { enum: ["none", "applied"] },
  sizeBytes: safeInteger,
  sha256,
};
const completeManifest = object({
  ...manifestBase,
  sizeBytes: { type: "integer", minimum: 0, maximum: MAX_TEXT_BYTES },
  complete: { const: true },
  chunks: { type: "array", items: chunk, maxItems: 64 },
});
const incompleteManifest = object({
  ...manifestBase,
  complete: { const: false },
  reason: { const: "output_limit_exceeded" },
  chunks: { type: "array", items: chunk, maxItems: 0 },
});
const manifest = { oneOf: [completeManifest, incompleteManifest] };

const candidate = object({
  source: { enum: ["delta", "final", "history", "replica"] },
  messageId: uuid,
  attemptId: uuid,
  generation: positiveInteger,
  revision: safeInteger,
  textHash: sha256,
  text: preview,
  final: { type: "boolean" },
});
const projectedMessage = object({
  messageId: uuid,
  attemptId: uuid,
  generation: positiveInteger,
  textHash: sha256,
  text: preview,
  final: { type: "boolean" },
  sources: {
    type: "array",
    items: { enum: ["delta", "final", "history", "replica"] },
    maxItems: 4,
  },
});
const projectionFixture = object({
  schemaId: { const: SCHEMA_ID },
  candidates: { type: "array", items: candidate, maxItems: 100 },
  expected: { type: "array", items: projectedMessage, maxItems: 100 },
});

const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://homelab.local/schemas/transcript-view-v1.schema.json",
  title: "Harness transcript view v1",
  description: "Versioned safe-text manifests and semantic projection fixtures. This does not extend harness-wire-v2.",
  oneOf: [{ $ref: "#/$defs/manifest" }, { $ref: "#/$defs/projectionFixture" }],
  $defs: { source, chunk, manifest, projectionFixture },
};

const ids = {
  node: "10000000-0000-4000-8000-000000000001",
  dialog: "20000000-0000-4000-8000-000000000001",
  attempt: "30000000-0000-4000-8000-000000000001",
  message: "40000000-0000-4000-8000-000000000001",
  secondMessage: "40000000-0000-4000-8000-000000000002",
  text: "50000000-0000-4000-8000-000000000001",
  artifact: "60000000-0000-4000-8000-000000000001",
};
const hashA = createHash("sha256").update("answer").digest("hex");
const complete = {
  schemaId: SCHEMA_ID,
  nodeId: ids.node,
  dialogId: ids.dialog,
  attemptId: ids.attempt,
  generation: 1,
  textId: ids.text,
  source: { kind: "assistant_message", id: ids.message, index: 0, stream: "none" },
  preview: "answer",
  previewTruncated: false,
  redaction: "none",
  complete: true,
  sizeBytes: 6,
  sha256: hashA,
  chunks: [{ index: 0, offsetBytes: 0, artifactId: ids.artifact, sizeBytes: 6, sha256: hashA }],
};
const fixtures = {
  schemaId: SCHEMA_ID,
  note: "Projection fixtures are consumer inputs only; they do not claim a running replica producer.",
  fixtures: [
    { name: "manifest.complete", contractType: "manifest", shapeValid: true, value: complete },
    {
      name: "manifest.limit",
      contractType: "manifest",
      shapeValid: true,
      value: { ...complete, complete: false, reason: "output_limit_exceeded", sizeBytes: MAX_TEXT_BYTES + 1, chunks: [] },
    },
    {
      name: "projection.delta_final_history_replica",
      contractType: "projectionFixture",
      shapeValid: true,
      value: {
        schemaId: SCHEMA_ID,
        candidates: [
          { source: "delta", messageId: ids.message, attemptId: ids.attempt, generation: 1, revision: 1, textHash: hashA, text: "answer", final: false },
          { source: "final", messageId: ids.message, attemptId: ids.attempt, generation: 1, revision: 2, textHash: hashA, text: "answer", final: true },
          { source: "history", messageId: ids.message, attemptId: ids.attempt, generation: 1, revision: 2, textHash: hashA, text: "answer", final: true },
          { source: "replica", messageId: ids.message, attemptId: ids.attempt, generation: 1, revision: 2, textHash: hashA, text: "answer", final: true },
          { source: "history", messageId: ids.secondMessage, attemptId: ids.attempt, generation: 1, revision: 3, textHash: hashA, text: "answer", final: true },
        ],
        expected: [
          { messageId: ids.message, attemptId: ids.attempt, generation: 1, textHash: hashA, text: "answer", final: true, sources: ["delta", "final", "history", "replica"] },
          { messageId: ids.secondMessage, attemptId: ids.attempt, generation: 1, textHash: hashA, text: "answer", final: true, sources: ["history"] },
        ],
      },
    },
    { name: "invalid.manifest_extra", contractType: "manifest", shapeValid: false, value: { ...complete, ownerId: "browser-owner" } },
    { name: "invalid.manifest_chunk_oversize", contractType: "manifest", shapeValid: false, value: { ...complete, chunks: [{ ...complete.chunks[0], sizeBytes: MAX_CHUNK_BYTES + 1 }] } },
  ],
};

const schemaText = `${JSON.stringify(schema, null, 2)}\n`;
const fixturesText = `${JSON.stringify(fixtures, null, 2)}\n`;
const manifestFile = {
  schemaId: SCHEMA_ID,
  schemaSHA256: createHash("sha256").update(schemaText).digest("hex"),
  fixturesSHA256: createHash("sha256").update(fixturesText).digest("hex"),
};
const manifestText = `${JSON.stringify(manifestFile, null, 2)}\n`;
const outputs = [
  ["transcript-view-v1.schema.json", schemaText],
  ["transcript-view-v1.fixtures.json", fixturesText],
  ["transcript-view-v1.manifest.json", manifestText],
];

if (process.argv.includes("--check")) {
  for (const [name, expected] of outputs) {
    let actual = "";
    try { actual = readFileSync(join(here, name), "utf8"); } catch {}
    if (actual !== expected) {
      console.error(`${name}: stale`);
      process.exitCode = 1;
    }
  }
} else {
  for (const [name, content] of outputs) writeFileSync(join(here, name), content);
}

console.log(JSON.stringify(manifestFile));
