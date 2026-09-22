#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = dirname(fileURLToPath(import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addKeyword({
  keyword: "x-utf8MaxBytes",
  type: "string",
  schemaType: "number",
  validate: (limit, value) => Buffer.byteLength(value, "utf8") <= limit,
});

const nodeId = "20000000-0000-4000-8000-000000000001";
const dialogId = "20000000-0000-4000-8000-000000000002";
const requestId = "20000000-0000-4000-8000-000000000003";
const attemptId = "20000000-0000-4000-8000-000000000004";
const toolCallId = "20000000-0000-4000-8000-000000000005";
const observedAt = "2026-09-21T00:00:00Z";

const cases = [
  {
    schema: "dialog-view-v1.schema.json",
    value: {
      protocolVersion: 1,
      schemaId: "dialog-view-v1",
      nodeId,
      epoch: 1,
      snapshotStateVersion: 2,
      lastEventSeq: 3,
      items: [{ dialogId, version: 1, createdAt: observedAt, lastActivityAt: observedAt, state: "idle" }],
      nextCursor: null,
      pageType: "dialogs",
    },
  },
  {
    schema: "tool-timeline-v1.schema.json",
    value: {
      protocolVersion: 1,
      schemaId: "tool-timeline-v1",
      nodeId,
      epoch: 1,
      stateVersion: 2,
      lastEventSeq: 3,
      dialogId,
      requestId,
      attemptId,
      toolCall: {
        toolCallId,
        toolName: "fixture.echo",
        state: "running",
        startedAt: observedAt,
        detailVersion: 1,
        input: { kind: "unavailable", reason: "provider_redacted", redaction: "applied", truncated: false },
        outputs: [],
        nextOutputCursor: null,
      },
    },
  },
];

for (const test of cases) {
  const schema = JSON.parse(readFileSync(join(here, test.schema), "utf8"));
  const validate = ajv.compile(schema);
  if (!validate(test.value)) {
    throw new Error(`${test.schema}: positive example failed: ${ajv.errorsText(validate.errors)}`);
  }
  const secretBearing = structuredClone(test.value);
  if (secretBearing.toolCall) secretBearing.toolCall.actionHash = "a".repeat(64);
  else secretBearing.items[0].reasoning = "private";
  if (validate(secretBearing)) {
    throw new Error(`${test.schema}: unexpected properties must be rejected`);
  }
}

console.log(JSON.stringify({ schemas: cases.length, verdict: "PASS" }));
