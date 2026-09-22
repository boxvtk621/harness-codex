#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, "provider-auth-v1.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(schema);
const envelope = ajv.compile({ $ref: `${schema.$id}#/$defs/envelope` });
const valid = {
  schemaId: "harness-provider-auth-v1",
  nodeId: "10000000-0000-4000-8000-000000000001",
  revision: 2,
  state: "unauthenticated",
  checkedAt: "2026-09-21T12:00:00Z",
  reasonCode: null,
  capabilities: { methods: ["device_code"], canCheck: true, canLogout: true },
  operation: {
    operationId: "62000000-0000-4000-8000-000000000001",
    commandId: "61000000-0000-4000-8000-000000000001",
    method: "device_code",
    status: "pending",
    createdAt: "2026-09-21T12:00:00Z",
    updatedAt: "2026-09-21T12:00:00Z",
    reasonCode: null,
    verificationUrl: "https://auth.openai.com/codex/device",
    userCode: "ABCD-1234",
    expiresAt: null,
    timeoutAt: "2026-09-21T12:15:00Z"
  }
};
if (!envelope(valid)) throw new Error(`valid envelope rejected: ${ajv.errorsText(envelope.errors)}`);
for (const mutation of [
  (value) => { value.secret = "leak"; },
  (value) => { value.nodeId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"; },
  (value) => { value.operation.verificationUrl = "javascript:alert(1)"; }
]) {
  const invalid = structuredClone(valid);
  mutation(invalid);
  if (envelope(invalid)) throw new Error("invalid provider-auth envelope accepted");
}
console.log(JSON.stringify({ schemaId: "harness-provider-auth-v1", checked: 4, verdict: "PASS" }));
