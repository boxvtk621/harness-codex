#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaBytes = readFileSync(join(here, "history-replica-v1.schema.json"));
const fixturesBytes = readFileSync(join(here, "history-replica-v1.fixtures.json"));
const schema = JSON.parse(schemaBytes);
const fixtures = JSON.parse(fixturesBytes);
const manifest = JSON.parse(readFileSync(join(here, "history-replica-v1.manifest.json"), "utf8"));

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
if (
  manifest.schemaId !== "harness-history-export-v1" ||
  manifest.schemaSHA256 !== sha256(schemaBytes) ||
  manifest.fixturesSHA256 !== sha256(fixturesBytes)
) {
  throw new Error("history replica manifest digest mismatch");
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
ajv.addKeyword({
  keyword: "x-utf8MaxBytes",
  type: "string",
  schemaType: "number",
  validate: (limit, value) => Buffer.byteLength(value, "utf8") <= limit,
});
const validate = ajv.compile(schema);
if (!validate(fixtures.validPage)) {
  throw new Error(`valid history export fixture rejected: ${ajv.errorsText(validate.errors)}`);
}
const validateImportResult = ajv.compile({ $ref: `${schema.$id}#/$defs/importResult` });

const page = fixtures.validPage;
if (page.schemaSHA256 !== manifest.schemaSHA256) throw new Error("history page schema pin mismatch");
const importResult = {
  schemaId: page.schemaId,
  streamId: page.streamId,
  importedThrough: page.checkpoint.throughSeq,
  sourceThrough: page.checkpoint.throughSeq,
  duplicate: false,
  complete: page.checkpoint.ready,
  observedAt: page.checkpoint.capturedAt,
};
if (!validateImportResult(importResult)) {
  throw new Error(`valid history import result rejected: ${ajv.errorsText(validateImportResult.errors)}`);
}
const identity = page.identity;
const streamInput = [identity.ownerId, identity.logicalDialogId, identity.nodeId, identity.nodeDialogId, String(identity.bindingGeneration)].join("\0");
const streamBytes = Buffer.from(sha256(Buffer.from(`history-stream-v1\0${streamInput}`)), "hex").subarray(0, 16);
streamBytes[6] = (streamBytes[6] & 0x0f) | 0x50;
streamBytes[8] = (streamBytes[8] & 0x3f) | 0x80;
const hex = streamBytes.toString("hex");
const streamId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
if (streamId !== page.streamId) throw new Error("history stream identity digest mismatch");

let previous = sha256(Buffer.from(`history-chain-genesis-v1\0${streamId}`));
for (const record of page.records) {
  const core = { type: record.type, recordId: record.recordId, entityId: record.entityId, revision: record.revision, payload: record.payload };
  if (sha256(Buffer.from(JSON.stringify(core))) !== record.recordHash) throw new Error("history record digest mismatch");
  const chain = sha256(Buffer.from(`history-chain-v1\0${streamId}\0${record.streamSeq}\0${previous}\0${record.recordHash}`));
  if (record.prevHash !== previous || record.chainHash !== chain) throw new Error("history chain digest mismatch");
  previous = chain;
}
const effects = page.checkpoint.effectsSummary;
const effectCount = Object.values(effects).reduce((total, value) => total + value, 0);
if (effectCount !== page.checkpoint.throughSeq || previous !== page.checkpoint.chainHash) {
  throw new Error("history checkpoint coverage mismatch");
}

const unknown = structuredClone(page);
unknown.unexpected = true;
if (validate(unknown)) throw new Error("history export accepted an unknown field");
const wrongType = structuredClone(page);
wrongType.records[0].streamSeq = "1";
if (validate(wrongType)) throw new Error("history export accepted a wrong field type");

console.log(JSON.stringify({ schemaId: manifest.schemaId, records: page.records.length, verdict: "PASS" }));
