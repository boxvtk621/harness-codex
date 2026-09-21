#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const PROTOCOL_VERSION = 1;
const SCHEMA_ID = "harness-wire-v2";
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;

const uuid = { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const timestamp = {
  type: "string",
  format: "date-time",
  pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$",
};
const safeInteger = { type: "integer", minimum: 0, maximum: MAX_SAFE_INTEGER };
const positiveInteger = { type: "integer", minimum: 1, maximum: MAX_SAFE_INTEGER };
const sha256 = { type: "string", pattern: "^[0-9a-f]{64}$" };
const actorIdentity = { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$" };
const shortText = { type: "string", minLength: 1, maxLength: 200, "x-utf8MaxBytes": 200 };
const messageText = { type: "string", minLength: 1, maxLength: 65_536, "x-utf8MaxBytes": 65_536 };

function object(properties, optional = []) {
  return {
    type: "object",
    properties,
    required: Object.keys(properties).filter((key) => !optional.includes(key)),
    additionalProperties: false,
  };
}

function array(items, maxItems = 100) {
  return { type: "array", items, maxItems };
}

const commandSpecs = [
  ["dialog.create", [], ["registryVersion"], { title: shortText }, ["title"]],
  ["message.enqueue", ["dialogId"], ["dialogVersion"], { text: messageText }, []],
  ["message.steer", ["dialogId", "attemptId", "messageId"], ["attemptGeneration", "messageVersion"], {}, []],
  ["request.cancel", ["requestId"], ["requestVersion"], {}, []],
  ["attempt.stop", ["attemptId"], ["attemptGeneration"], {}, []],
  ["queue.resume", [], ["queueVersion"], {}, []],
  ["attempt.retry", ["attemptId"], ["attemptGeneration"], { acknowledgeKnownEffects: { type: "boolean" } }, []],
  ["approval.respond", ["approvalId", "attemptId"], ["approvalVersion", "attemptGeneration"], {
    decision: { enum: ["allow_once", "deny"] }, actionHash: sha256,
  }, []],
  ["input.respond", ["inputRequestId", "attemptId"], ["inputVersion", "attemptGeneration"], { text: messageText }, []],
  ["dialog.delete", ["dialogId"], ["dialogVersion"], {}, []],
];

function commandSchema([kind, targetIDs, expectedVersions, payload, optionalPayload]) {
  return object({
    protocolVersion: { const: PROTOCOL_VERSION },
    schemaId: { const: SCHEMA_ID },
    commandId: uuid,
    kind: { const: kind },
    target: object(Object.fromEntries(["nodeId", ...targetIDs].map((name) => [name, uuid]))),
    expected: object(Object.fromEntries(expectedVersions.map((name) => [name, safeInteger]))),
    payload: object(payload, optionalPayload),
  });
}

const receiptReferences = {
  "dialog.create": ["dialogId"],
  "message.enqueue": ["dialogId", "messageId", "requestId"],
  "message.steer": ["dialogId", "messageId", "attemptId"],
  "request.cancel": ["requestId"],
  "attempt.stop": ["attemptId"],
  "queue.resume": ["nodeId"],
  "attempt.retry": ["priorAttemptId", "requestId"],
  "approval.respond": ["approvalId", "attemptId"],
  "input.respond": ["inputRequestId", "attemptId", "messageId"],
  "dialog.delete": ["dialogId"],
};

function receiptSchema(kind) {
  return object({
    protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID },
    commandId: uuid, commandKind: { const: kind }, receiptId: uuid, acceptedAt: timestamp,
    nodeId: uuid, eventSeq: positiveInteger, result: { enum: kind === "dialog.delete" ? ["deleted"] : ["admitted", "applied"] },
    blockingReason: blockedReason,
    references: object(Object.fromEntries(receiptReferences[kind].map((name) => [name, uuid]))),
  }, ["blockingReason"]);
}

const errorCodes = [
  "invalid", "no_session", "forbidden", "not_found", "stale", "id_conflict", "too_large",
  "queue_full", "node_unavailable", "not_durable", "unsupported", "protocol_mismatch", "schema_mismatch",
];
const errorBase = {
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID },
  safeMessage: { type: "string", minLength: 1, maxLength: 500, "x-utf8MaxBytes": 500 },
  correlationId: uuid, currentVersion: safeInteger,
  currentState: { enum: ["queued", "active", "paused", "blocked", "terminal", "unknown"] },
};
const errorSchema = { oneOf: [
  object({ ...errorBase, code: { enum: errorCodes.filter((code) => !["queue_full", "node_unavailable", "not_durable"].includes(code)) }, retryable: { const: false } }, ["currentVersion", "currentState"]),
  object({ ...errorBase, code: { enum: ["queue_full", "node_unavailable", "not_durable"] }, retryable: { const: true } }, ["currentVersion", "currentState"]),
] };

const blockedReason = { enum: [
  "engine_unavailable", "auth_unavailable", "quota_exhausted", "policy_unavailable", "capability_missing",
  "storage_unavailable", "execution_unknown", "adapter_protocol", "operator_pause",
] };
const nodeState = object({
  transportAvailability: { enum: ["online", "stale", "offline"] },
  engineReadiness: { enum: ["ready", "blocked", "unknown"] },
  occupancy: { enum: ["idle", "active", "unknown"] }, queuePaused: { type: "boolean" },
  queueVersion: safeInteger, pendingCount: safeInteger, blockedReasons: array(blockedReason, 16),
  activeAttemptId: { anyOf: [uuid, { type: "null" }] },
});
const dialogSummary = object({ dialogId: uuid, version: safeInteger, title: shortText, createdAt: timestamp }, ["title"]);
const userHistoryItem = object({
  messageId: uuid, role: { const: "user" }, dialogId: uuid, sequence: positiveInteger, version: safeInteger, createdAt: timestamp,
  text: messageText, disposition: { enum: ["queued", "steer_pending", "applied", "cancelled", "unknown"] },
  commandId: uuid, requestId: uuid,
});
const request = object({
  requestId: uuid, dialogId: uuid, inputMessageId: uuid, queueSequence: positiveInteger, version: safeInteger,
  status: { enum: ["queued", "cancelled", "dispatching", "active", "completed", "failed", "interrupted", "unknown"] },
});
const attempt = object({
  attemptId: uuid, dialogId: uuid, requestId: uuid, generation: positiveInteger, version: safeInteger,
  state: { enum: ["dispatching", "running", "waiting_input", "stopping", "completed", "failed", "interrupted", "unknown"] },
  effectStatus: { enum: ["none", "known", "unknown"] }, startedAt: timestamp, finishedAt: timestamp,
}, ["startedAt", "finishedAt"]);

const usage = object({
  source: { enum: ["per_attempt", "cumulative_process"] }, inputTokens: safeInteger,
  outputTokens: safeInteger, totalTokens: safeInteger,
});
const inlineSafeContent = object({
  kind: { const: "inline" }, content: { type: "string", maxLength: 65_536, "x-utf8MaxBytes": 65_536 },
  redaction: { enum: ["none", "applied"] }, truncated: { type: "boolean" },
});
const artifactSafeContent = object({
  kind: { const: "artifact" }, artifactId: uuid, sizeBytes: { type: "integer", minimum: 0, maximum: 16 * 1024 * 1024 },
  sha256, redaction: { enum: ["none", "applied"] }, truncated: { type: "boolean" },
});
const unavailableSafeContent = object({
  kind: { const: "unavailable" }, reason: { enum: ["not_observed", "provider_redacted", "output_limit", "unmapped"] },
  redaction: { enum: ["none", "applied", "unknown"] }, truncated: { type: "boolean" },
});
const safeContent = { oneOf: [inlineSafeContent, artifactSafeContent, unavailableSafeContent] };
const assistantHistoryItem = object({
  messageId: uuid, role: { const: "assistant" }, dialogId: uuid, sequence: positiveInteger, version: safeInteger, createdAt: timestamp,
  attemptId: uuid, content: safeContent, finishReason: { enum: ["complete", "length", "cancelled", "error"] },
});
const historyItem = { oneOf: [userHistoryItem, assistantHistoryItem] };
const pendingRequest = object({
  requestId: uuid, dialogId: uuid, inputMessageId: uuid, queueSequence: positiveInteger, version: safeInteger,
  status: { const: "queued" },
});
const eventPayloads = {
  "node.state_changed": nodeState,
  "queue.changed": object({ queueVersion: safeInteger, pendingCount: safeInteger, activeAttemptId: { anyOf: [uuid, { type: "null" }] }, queuePaused: { type: "boolean" } }),
  "message.accepted": object({ dialogId: uuid, messageId: uuid, requestId: uuid, sequence: positiveInteger, disposition: { const: "queued" } }),
  "message.disposition_changed": object({ messageId: uuid, from: { enum: ["queued", "steer_pending", "applied", "cancelled", "unknown"] }, to: { enum: ["queued", "steer_pending", "applied", "cancelled", "unknown"] }, reasonCode: { enum: ["request_dispatched", "steer_requested", "steer_applied", "steer_fallback", "steer_unknown", "request_cancelled", "reconciled"] } }),
  "attempt.dispatching": object({ requestId: uuid, generation: positiveInteger, contextBoundaryMessageId: uuid, policyRevision: shortText, policyHash: sha256 }),
  "attempt.started": object({ requestId: uuid, generation: positiveInteger }),
  "attempt.waiting_input": object({ requestId: uuid, generation: positiveInteger, waitKind: { enum: ["approval", "input"] } }),
  "attempt.stop_requested": object({ generation: positiveInteger, commandId: uuid }),
  "attempt.completed": object({ generation: positiveInteger, output: { oneOf: [object({ kind: { const: "message" }, assistantMessageId: uuid }), object({ kind: { const: "empty" } })] }, usage }, ["usage"]),
  "attempt.failed": object({ generation: positiveInteger, failureClass: { enum: ["task", "node", "policy", "protocol"] }, errorCode: shortText, safeMessage: { type: "string", minLength: 1, maxLength: 500, "x-utf8MaxBytes": 500 }, retryable: { type: "boolean" }, effectStatus: { enum: ["none", "known", "unknown"] } }),
  "attempt.interrupted": object({ generation: positiveInteger, reason: { enum: ["owner_stop", "provider_interrupt", "process_exit"] }, effectStatus: { enum: ["none", "known", "unknown"] } }),
  "attempt.unknown": object({ generation: positiveInteger, reason: { enum: ["dispatch_uncertain", "cancel_unconfirmed", "adapter_protocol", "provider_state", "unmapped_event"] }, effectStatus: { enum: ["none", "known", "unknown"] } }),
  "assistant.delta": object({ messageId: uuid, deltaIndex: safeInteger, content: safeContent }),
  "assistant.message": object({ messageId: uuid, content: safeContent, finishReason: { enum: ["complete", "length", "cancelled", "error"] } }),
  "tool.started": object({ callId: uuid, toolName: shortText, actionHash: sha256, input: safeContent }),
  "tool.output": object({ callId: uuid, chunkIndex: safeInteger, stream: { enum: ["stdout", "stderr", "result", "diagnostic"] }, output: safeContent }),
  "tool.completed": object({ callId: uuid, status: { enum: ["succeeded", "failed", "unknown"] }, result: safeContent, effectStatus: { enum: ["none", "known", "unknown"] }, effectRef: shortText }, ["effectRef"]),
  "approval.requested": object({ approvalId: uuid, callId: uuid, actionHash: sha256, safePrompt: { type: "string", minLength: 1, maxLength: 2_000, "x-utf8MaxBytes": 8_192 }, approvalVersion: safeInteger }),
  "approval.resolved": object({ approvalId: uuid, decision: { enum: ["allow_once", "deny"] }, actorId: actorIdentity, approvalVersion: safeInteger }),
  "input.requested": object({ inputRequestId: uuid, prompt: safeContent, inputVersion: safeInteger }),
  "input.resolved": object({ inputRequestId: uuid, messageId: uuid, inputVersion: safeInteger }),
  "artifact.available": object({ artifactId: uuid, callId: uuid, name: shortText, mediaType: shortText, sizeBytes: { type: "integer", minimum: 0, maximum: 16 * 1024 * 1024 }, sha256, redaction: { enum: ["none", "applied"] }, truncated: { type: "boolean" } }, ["callId"]),
  "history.gap": object({ expectedSeq: positiveInteger, availableFromSeq: positiveInteger, reason: { enum: ["storage_corruption", "identity_changed", "unmapped_event"] } }),
  "dialog.deleted": object({ dialogId: uuid }),
};

const attemptEventTypes = new Set(Object.keys(eventPayloads).filter((type) => type.startsWith("attempt.") || type.startsWith("assistant.") || type.startsWith("tool.") || type.startsWith("approval.") || type.startsWith("input.") || type === "artifact.available"));
function eventSchema(type) {
  const base = {
    protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
    seq: positiveInteger, epoch: positiveInteger, type: { const: type }, entityId: uuid,
    entityVersion: safeInteger, observedAt: timestamp, sourceAt: timestamp,
    completeness: { const: "complete" }, payload: eventPayloads[type],
  };
  if (attemptEventTypes.has(type)) { base.attemptId = uuid; base.dialogId = uuid; }
  if (type === "dialog.deleted") base.dialogId = uuid;
  return object(base, ["sourceAt"]);
}

const snapshot = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
  epoch: positiveInteger, stateVersion: safeInteger, lastEventSeq: safeInteger, capturedAt: timestamp,
  node: nodeState, pendingQueue: array(pendingRequest), activeAttempt: { anyOf: [attempt, { type: "null" }] },
  completeness: { const: "complete" },
});

const capabilityStatus = { enum: ["unsupported", "declared", "verified"] };
const capabilities = object({ chat: capabilityStatus, events: capabilityStatus, tool_results: capabilityStatus,
  cancel: capabilityStatus, steer_attached: capabilityStatus, session_resume: capabilityStatus, policy_enforcement: capabilityStatus });
const adapterIdentity = { oneOf: [
  object({ kind: { const: "cursor" }, version: { const: "1.0.31" } }),
  object({ kind: { const: "codex" }, version: { const: "0.153.4" } }),
] };
const nodeIdentity = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
  schemaSHA256: sha256, registryVersion: safeInteger, identityEpoch: positiveInteger,
  adapter: adapterIdentity, capabilities,
});
const attemptRead = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
  epoch: positiveInteger, stateVersion: safeInteger, attempt,
});
const commandStatus = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
  commandId: uuid, canonicalPayloadHash: sha256, status: { const: "accepted" }, receipt: { oneOf: Object.keys(receiptReferences).map(receiptSchema) },
});
const healthLive = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, status: { const: "live" }, processStartedAt: timestamp,
});
const healthReady = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, checkedAt: timestamp,
  identity: nodeIdentity, readiness: { enum: ["ready", "blocked", "unknown"] }, blockedReasons: array(blockedReason, 16),
});
const artifactMetadata = object({
  protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid, dialogId: uuid,
  attemptId: uuid, artifactId: uuid, callId: uuid, name: shortText, mediaType: shortText,
  sizeBytes: { type: "integer", minimum: 0, maximum: 16 * 1024 * 1024 }, sha256,
  redaction: { enum: ["none", "applied"] }, truncated: { type: "boolean" }, disposition: { enum: ["inline", "attachment"] },
}, ["callId"]);

function page(itemName, itemSchema, scope = {}) {
  return object({
    protocolVersion: { const: PROTOCOL_VERSION }, schemaId: { const: SCHEMA_ID }, nodeId: uuid,
    epoch: positiveInteger, snapshotStateVersion: safeInteger, lastEventSeq: safeInteger,
    items: array(itemSchema), nextCursor: { anyOf: [{ type: "string", minLength: 1, maxLength: 512, "x-utf8MaxBytes": 512 }, { type: "null" }] },
    pageType: { const: itemName }, ...scope,
  });
}

const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://h1-cloud.local/schemas/harness-wire-v2.json",
  title: "HL-240 Harness wire schema v2 (protocol v1)",
  description: "Shape validation only. Raw wire numeric tokens must use the plain unsigned integer grammar 0|[1-9][0-9]* before safe-range validation. Authorization, ownership, CAS, idempotency and state transitions are authoritative B1/U1 responsibilities.",
  oneOf: [
    { $ref: "#/$defs/command" }, { $ref: "#/$defs/receipt" }, { $ref: "#/$defs/error" },
    { $ref: "#/$defs/event" }, { $ref: "#/$defs/snapshot" }, { $ref: "#/$defs/dialogPage" },
    { $ref: "#/$defs/historyPage" }, { $ref: "#/$defs/requestPage" }, { $ref: "#/$defs/eventPage" },
    { $ref: "#/$defs/attemptRead" }, { $ref: "#/$defs/commandStatus" }, { $ref: "#/$defs/nodeIdentity" },
    { $ref: "#/$defs/healthLive" }, { $ref: "#/$defs/healthReady" },
    { $ref: "#/$defs/attemptPage" }, { $ref: "#/$defs/artifactMetadata" },
  ],
  $defs: {
    command: { oneOf: commandSpecs.map(commandSchema) },
    receipt: { oneOf: Object.keys(receiptReferences).map(receiptSchema) },
    error: errorSchema,
    event: { oneOf: Object.keys(eventPayloads).map(eventSchema) },
    snapshot,
    dialogPage: page("dialogs", dialogSummary), requestPage: page("requests", request),
    historyPage: page("history", historyItem, { dialogId: uuid }),
    attemptPage: page("attempts", attempt, { dialogId: uuid, requestId: uuid }),
    eventPage: page("events", { oneOf: [...attemptEventTypes].map(eventSchema) }, { dialogId: uuid, attemptId: uuid }),
    attemptRead, commandStatus, nodeIdentity, healthLive, healthReady, artifactMetadata,
  },
};
const schemaText = `${JSON.stringify(schema, null, 2)}\n`;
const schemaDigest = createHash("sha256").update(schemaText).digest("hex");

const ids = {
  command: "10000000-0000-4000-8000-000000000001", receipt: "10000000-0000-4000-8000-000000000002",
  node: "20000000-0000-4000-8000-000000000001", dialog: "30000000-0000-4000-8000-000000000001",
  message: "40000000-0000-4000-8000-000000000001", request: "50000000-0000-4000-8000-000000000001",
  attempt: "60000000-0000-4000-8000-000000000001", entity: "70000000-0000-4000-8000-000000000001",
  call: "80000000-0000-4000-8000-000000000001", approval: "90000000-0000-4000-8000-000000000001",
  input: "a0000000-0000-4000-8000-000000000001", artifact: "b0000000-0000-4000-8000-000000000001",
  actor: "1-1",
};
const at = "2026-09-09T00:00:00Z";
const hash = "0".repeat(64);

function payloadExample(kind) {
  const examples = {
    "node.state_changed": { transportAvailability: "online", engineReadiness: "ready", occupancy: "idle", queuePaused: false, queueVersion: 1, pendingCount: 0, blockedReasons: [], activeAttemptId: null },
    "queue.changed": { queueVersion: 2, pendingCount: 1, activeAttemptId: ids.attempt, queuePaused: false },
    "message.accepted": { dialogId: ids.dialog, messageId: ids.message, requestId: ids.request, sequence: 1, disposition: "queued" },
    "message.disposition_changed": { messageId: ids.message, from: "queued", to: "steer_pending", reasonCode: "steer_requested" },
    "attempt.dispatching": { requestId: ids.request, generation: 1, contextBoundaryMessageId: ids.message, policyRevision: "HL-A-23@1", policyHash: hash },
    "attempt.started": { requestId: ids.request, generation: 1 },
    "attempt.waiting_input": { requestId: ids.request, generation: 1, waitKind: "approval" },
    "attempt.stop_requested": { generation: 1, commandId: ids.command },
    "attempt.completed": { generation: 1, output: { kind: "empty" }, usage: { source: "per_attempt", inputTokens: 1, outputTokens: 1, totalTokens: 2 } },
    "attempt.failed": { generation: 1, failureClass: "task", errorCode: "tool_failed", safeMessage: "tool failed", retryable: false, effectStatus: "none" },
    "attempt.interrupted": { generation: 1, reason: "owner_stop", effectStatus: "none" },
    "attempt.unknown": { generation: 1, reason: "cancel_unconfirmed", effectStatus: "unknown" },
    "assistant.delta": { messageId: ids.message, deltaIndex: 0, content: { kind: "inline", content: "delta", redaction: "none", truncated: false } },
    "assistant.message": { messageId: ids.message, content: { kind: "inline", content: "done", redaction: "none", truncated: false }, finishReason: "complete" },
    "tool.started": { callId: ids.call, toolName: "synthetic", actionHash: hash, input: { kind: "inline", content: "marker", redaction: "none", truncated: false } },
    "tool.output": { callId: ids.call, chunkIndex: 0, stream: "result", output: { kind: "inline", content: "output", redaction: "none", truncated: false } },
    "tool.completed": { callId: ids.call, status: "succeeded", result: { kind: "inline", content: "ok", redaction: "applied", truncated: false }, effectStatus: "none" },
    "approval.requested": { approvalId: ids.approval, callId: ids.call, actionHash: hash, safePrompt: "allow?", approvalVersion: 1 },
    "approval.resolved": { approvalId: ids.approval, decision: "allow_once", actorId: ids.actor, approvalVersion: 2 },
    "input.requested": { inputRequestId: ids.input, prompt: { kind: "inline", content: "value?", redaction: "none", truncated: false }, inputVersion: 1 },
    "input.resolved": { inputRequestId: ids.input, messageId: ids.message, inputVersion: 2 },
    "artifact.available": { artifactId: ids.artifact, callId: ids.call, name: "result.txt", mediaType: "text/plain", sizeBytes: 2, sha256: hash, redaction: "applied", truncated: false },
    "history.gap": { expectedSeq: 4, availableFromSeq: 8, reason: "storage_corruption" },
    "dialog.deleted": { dialogId: ids.dialog },
  };
  return examples[kind];
}

function commandExample(spec, index) {
  const [kind, targetIDs, expectedVersions, payload] = spec;
  const targetMap = { nodeId: ids.node, dialogId: ids.dialog, messageId: ids.message, requestId: ids.request, attemptId: ids.attempt, approvalId: ids.approval, inputRequestId: ids.input };
  const value = { protocolVersion: 1, schemaId: SCHEMA_ID, commandId: ids.command, kind,
    target: Object.fromEntries(["nodeId", ...targetIDs].map((key) => [key, targetMap[key]])),
    expected: Object.fromEntries(expectedVersions.map((key) => [key, 1])), payload: {} };
  for (const key of Object.keys(payload)) value.payload[key] = key === "acknowledgeKnownEffects" ? false : key === "decision" ? "allow_once" : key === "actionHash" ? hash : "test";
  return { name: `command.${index + 1}.${kind}`, wireType: "command", shapeValid: true, value };
}

const commandFixtures = commandSpecs.map(commandExample);
const eventFixtures = Object.keys(eventPayloads).map((type, index) => ({
  name: `event.${index + 1}.${type}`, wireType: "event", shapeValid: true,
  value: { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, seq: index + 1, epoch: 1, type,
    entityId: type === "dialog.deleted" ? ids.dialog : ids.entity, entityVersion: 1, ...(attemptEventTypes.has(type) || type === "dialog.deleted" ? { ...(attemptEventTypes.has(type) ? { attemptId: ids.attempt } : {}), dialogId: ids.dialog } : {}),
    observedAt: at, completeness: "complete", payload: payloadExample(type) },
}));
const receiptFixtures = Object.entries(receiptReferences).map(([kind, refs], index) => ({
  name: `receipt.${index + 1}.${kind}`, wireType: "receipt", shapeValid: true,
  value: { protocolVersion: 1, schemaId: SCHEMA_ID, commandId: ids.command, commandKind: kind, receiptId: ids.receipt,
    acceptedAt: at, nodeId: ids.node, eventSeq: index + 1, result: kind === "dialog.delete" ? "deleted" : kind === "queue.resume" ? "applied" : "admitted",
    references: Object.fromEntries(refs.map((ref) => [ref, ({ dialogId: ids.dialog, messageId: ids.message, requestId: ids.request,
      attemptId: ids.attempt, priorAttemptId: "60000000-0000-4000-8000-000000000002", approvalId: ids.approval,
      inputRequestId: ids.input, nodeId: ids.node })[ref]])) },
}));

const baseNode = payloadExample("node.state_changed");
const snapshotValue = { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, epoch: 1, stateVersion: 4,
  lastEventSeq: 23, capturedAt: at, node: { ...baseNode, pendingCount: 1 },
  pendingQueue: [{ requestId: ids.request, dialogId: ids.dialog, inputMessageId: ids.message, queueSequence: 1, version: 1, status: "queued" }],
  activeAttempt: null, completeness: "complete" };
const pageBase = { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, epoch: 1, snapshotStateVersion: 4, lastEventSeq: 23, nextCursor: null };
const readFixtures = [
  { name: "snapshot.atomic", wireType: "snapshot", shapeValid: true, value: snapshotValue },
  { name: "page.dialogs", wireType: "dialogPage", shapeValid: true, value: { ...pageBase, pageType: "dialogs", items: [{ dialogId: ids.dialog, version: 1, title: "test", createdAt: at }] } },
  { name: "page.history.user", wireType: "historyPage", shapeValid: true, value: { ...pageBase, pageType: "history", dialogId: ids.dialog, items: [{ messageId: ids.message, role: "user", dialogId: ids.dialog, sequence: 1, version: 1, createdAt: at, text: "test", disposition: "queued", commandId: ids.command, requestId: ids.request }] } },
  { name: "page.history.assistant", wireType: "historyPage", shapeValid: true, value: { ...pageBase, pageType: "history", dialogId: ids.dialog, items: [{ messageId: "40000000-0000-4000-8000-000000000002", role: "assistant", dialogId: ids.dialog, sequence: 2, version: 1, createdAt: at, attemptId: ids.attempt, content: { kind: "inline", content: "done", redaction: "none", truncated: false }, finishReason: "complete" }] } },
  { name: "page.requests", wireType: "requestPage", shapeValid: true, value: { ...pageBase, pageType: "requests", items: snapshotValue.pendingQueue } },
  { name: "page.attempts", wireType: "attemptPage", shapeValid: true, value: { ...pageBase, pageType: "attempts", dialogId: ids.dialog, requestId: ids.request, items: [{ attemptId: ids.attempt, dialogId: ids.dialog, requestId: ids.request, generation: 1, version: 1, state: "running", effectStatus: "none", startedAt: at }] } },
  { name: "page.events", wireType: "eventPage", shapeValid: true, value: { ...pageBase, pageType: "events", dialogId: ids.dialog, attemptId: ids.attempt, items: [eventFixtures.find((item) => item.value.type === "attempt.started").value] } },
  { name: "error.stale", wireType: "error", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, code: "stale", safeMessage: "version changed", retryable: false, correlationId: ids.command, currentVersion: 2, currentState: "active" } },
  { name: "read.attempt", wireType: "attemptRead", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, epoch: 1, stateVersion: 4, attempt: { attemptId: ids.attempt, dialogId: ids.dialog, requestId: ids.request, generation: 1, version: 1, state: "running", effectStatus: "none", startedAt: at } } },
  { name: "read.command", wireType: "commandStatus", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, commandId: ids.command, canonicalPayloadHash: hash, status: "accepted", receipt: receiptFixtures[1].value } },
  { name: "read.identity", wireType: "nodeIdentity", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, schemaSHA256: schemaDigest, nodeId: ids.node, registryVersion: 1, identityEpoch: 1, adapter: { kind: "cursor", version: "1.0.31" }, capabilities: { chat: "verified", events: "verified", tool_results: "verified", cancel: "verified", steer_attached: "verified", session_resume: "verified", policy_enforcement: "verified" } } },
  { name: "health.live", wireType: "healthLive", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, status: "live", processStartedAt: at } },
  { name: "timestamp.year_zero_leap", wireType: "healthLive", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, status: "live", processStartedAt: "0000-02-29T00:00:00Z" } },
  { name: "health.ready", wireType: "healthReady", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, checkedAt: at, identity: { protocolVersion: 1, schemaId: SCHEMA_ID, schemaSHA256: schemaDigest, nodeId: ids.node, registryVersion: 1, identityEpoch: 1, adapter: { kind: "codex", version: "0.153.4" }, capabilities: { chat: "verified", events: "verified", tool_results: "verified", cancel: "verified", steer_attached: "verified", session_resume: "verified", policy_enforcement: "verified" } }, readiness: "ready", blockedReasons: [] } },
  { name: "event.tool_input_unavailable", wireType: "event", shapeValid: true, value: { ...eventFixtures.find((item) => item.value.type === "tool.started").value, payload: { callId: ids.call, toolName: "synthetic", actionHash: hash, input: { kind: "unavailable", reason: "not_observed", redaction: "unknown", truncated: false } } } },
  { name: "history.assistant_artifact", wireType: "historyPage", shapeValid: true, value: { ...pageBase, pageType: "history", dialogId: ids.dialog, items: [{ messageId: "40000000-0000-4000-8000-000000000003", role: "assistant", dialogId: ids.dialog, sequence: 3, version: 1, createdAt: at, attemptId: ids.attempt, content: { kind: "artifact", artifactId: ids.artifact, sizeBytes: 1024, sha256: hash, redaction: "applied", truncated: false }, finishReason: "complete" }] } },
  { name: "read.artifact", wireType: "artifactMetadata", shapeValid: true, value: { protocolVersion: 1, schemaId: SCHEMA_ID, nodeId: ids.node, dialogId: ids.dialog, attemptId: ids.attempt, artifactId: ids.artifact, callId: ids.call, name: "result.txt", mediaType: "text/plain", sizeBytes: 1024, sha256: hash, redaction: "applied", truncated: false, disposition: "attachment" } },
  { name: "utf8.title_exact_200_bytes", wireType: "command", shapeValid: true, value: { ...commandFixtures[0].value, payload: { title: "я".repeat(100) } } },
];

function invalid(name, wireType, value, errorCode = "invalid") { return { name, wireType, shapeValid: false, errorCode, value }; }
const badActor = structuredClone(commandFixtures[1].value); badActor.actorId = ids.actor;
const badUnknown = structuredClone(commandFixtures[1].value); badUnknown.payload.extra = true;
const badProtocol = structuredClone(commandFixtures[1].value); badProtocol.protocolVersion = 2;
const badSchema = structuredClone(commandFixtures[1].value); badSchema.schemaId = "harness-wire-v1";
const badSafe = structuredClone(commandFixtures[1].value); badSafe.expected.dialogVersion = MAX_SAFE_INTEGER + 1;
const badUTF8 = structuredClone(commandFixtures[1].value); badUTF8.payload.text = "я".repeat(32_769);
const badEvent = structuredClone(eventFixtures[0].value); badEvent.type = "vendor.raw";
const badEventPayload = structuredClone(eventFixtures[5].value); badEventPayload.payload.vendorTurnId = "private";
const missing = structuredClone(commandFixtures[4].value); delete missing.expected.attemptGeneration;
const badTitleUTF8 = structuredClone(commandFixtures[0].value); badTitleUTF8.payload.title = "я".repeat(101);
const badHistoryScope = structuredClone(readFixtures.find((item) => item.name === "page.history.user").value); badHistoryScope.items[0].dialogId = "30000000-0000-4000-8000-000000000002";
const badAttemptScope = structuredClone(readFixtures.find((item) => item.name === "page.attempts").value); badAttemptScope.items[0].requestId = "50000000-0000-4000-8000-000000000002";
const badEventScope = structuredClone(readFixtures.find((item) => item.name === "page.events").value); badEventScope.items[0].attemptId = "60000000-0000-4000-8000-000000000002";
const badEventNodeScope = structuredClone(readFixtures.find((item) => item.name === "page.events").value); badEventNodeScope.items[0].nodeId = "20000000-0000-4000-8000-000000000002";
const badReady = structuredClone(readFixtures.find((item) => item.name === "health.ready").value); badReady.identity.capabilities.cancel = "declared";
const badAdapterVersion = structuredClone(readFixtures.find((item) => item.name === "read.identity").value); badAdapterVersion.adapter.version = "1.0.30";
const badCompiledSchemaHash = structuredClone(readFixtures.find((item) => item.name === "read.identity").value); badCompiledSchemaHash.schemaSHA256 = "f".repeat(64);
const badErrorRetryable = structuredClone(readFixtures.find((item) => item.name === "error.stale").value); badErrorRetryable.retryable = true;
const badSnapshotCount = structuredClone(snapshotValue); badSnapshotCount.node.pendingCount = 2;
const badSnapshotActive = structuredClone(snapshotValue); badSnapshotActive.node.activeAttemptId = ids.attempt;
const badCommandStatusScope = structuredClone(readFixtures.find((item) => item.name === "read.command").value); badCommandStatusScope.receipt.commandId = "10000000-0000-4000-8000-000000000002";
const badSafePromptCodePoints = structuredClone(eventFixtures.find((item) => item.value.type === "approval.requested").value); badSafePromptCodePoints.payload.safePrompt = "я".repeat(2001);
const secondPending = { ...snapshotValue.pendingQueue[0], requestId: "50000000-0000-4000-8000-000000000002", inputMessageId: "40000000-0000-4000-8000-000000000002", queueSequence: 2 };
const badDuplicateRequest = structuredClone(snapshotValue); badDuplicateRequest.pendingQueue.push({ ...secondPending, requestId: ids.request }); badDuplicateRequest.node.pendingCount = 2;
const badDuplicateMessage = structuredClone(snapshotValue); badDuplicateMessage.pendingQueue.push({ ...secondPending, inputMessageId: ids.message }); badDuplicateMessage.node.pendingCount = 2;
const badDuplicateSequence = structuredClone(snapshotValue); badDuplicateSequence.pendingQueue.push({ ...secondPending, queueSequence: 1 }); badDuplicateSequence.node.pendingCount = 2;
const badFIFOOrder = structuredClone(snapshotValue); badFIFOOrder.pendingQueue[0].queueSequence = 2; badFIFOOrder.pendingQueue.push({ ...secondPending, queueSequence: 1 }); badFIFOOrder.node.pendingCount = 2;
const badOffsetHour = structuredClone(readFixtures.find((item) => item.name === "health.live").value); badOffsetHour.processStartedAt = "2026-01-01T12:00:00+24:00";
const badFractionSeparator = structuredClone(readFixtures.find((item) => item.name === "health.live").value); badFractionSeparator.processStartedAt = "2026-01-01T12:00:00,1Z";
const invalidFixtures = [
  invalid("invalid.browser_actor", "command", badActor), invalid("invalid.unknown_payload", "command", badUnknown),
  invalid("invalid.protocol_pin", "command", badProtocol, "protocol_mismatch"), invalid("invalid.schema_pin", "command", badSchema, "schema_mismatch"),
  invalid("invalid.unsafe_integer", "command", badSafe), invalid("invalid.utf8_bytes", "command", badUTF8, "too_large"),
  invalid("invalid.unknown_event", "event", badEvent), invalid("invalid.vendor_ref", "event", badEventPayload),
  invalid("invalid.missing_generation", "command", missing),
  invalid("invalid.utf8_title_bytes", "command", badTitleUTF8, "too_large"),
  { ...invalid("invalid.history_scope_mismatch", "historyPage", badHistoryScope), schemaValid: true },
  { ...invalid("invalid.attempt_scope_mismatch", "attemptPage", badAttemptScope), schemaValid: true },
  { ...invalid("invalid.event_scope_mismatch", "eventPage", badEventScope), schemaValid: true },
  { ...invalid("invalid.event_node_scope_mismatch", "eventPage", badEventNodeScope), schemaValid: true },
  { ...invalid("invalid.ready_unverified_capability", "healthReady", badReady), schemaValid: true },
  invalid("invalid.adapter_version_pin", "nodeIdentity", badAdapterVersion, "protocol_mismatch"),
  { ...invalid("invalid.compiled_schema_hash", "nodeIdentity", badCompiledSchemaHash, "schema_mismatch"), schemaValid: true },
  invalid("invalid.error_retryability", "error", badErrorRetryable),
  { ...invalid("invalid.snapshot_pending_count", "snapshot", badSnapshotCount), schemaValid: true },
  { ...invalid("invalid.snapshot_active_attempt", "snapshot", badSnapshotActive), schemaValid: true },
  { ...invalid("invalid.snapshot_duplicate_request", "snapshot", badDuplicateRequest), schemaValid: true },
  { ...invalid("invalid.snapshot_duplicate_message", "snapshot", badDuplicateMessage), schemaValid: true },
  { ...invalid("invalid.snapshot_duplicate_sequence", "snapshot", badDuplicateSequence), schemaValid: true },
  { ...invalid("invalid.snapshot_fifo_order", "snapshot", badFIFOOrder), schemaValid: true },
  { ...invalid("invalid.command_status_scope", "commandStatus", badCommandStatusScope), schemaValid: true },
  invalid("invalid.safe_prompt_codepoints", "event", badSafePromptCodePoints, "too_large"),
  invalid("invalid.timestamp_offset_hour", "healthLive", badOffsetHour),
  invalid("invalid.timestamp_fraction_separator", "healthLive", badFractionSeparator),
  { name: "invalid.duplicate_key", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":1},"payload":{"text":"one","text":"two"}}` },
  { name: "invalid.escaped_duplicate_key", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":1},"payload":{"text":"one","te\\u0078t":"two"}}` },
  { name: "invalid.fraction_rounding", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":9007199254740991.1},"payload":{"text":"test"}}` },
  { name: "invalid.fraction_to_one", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":1.0000000000000001},"payload":{"text":"test"}}` },
  { name: "invalid.exponent_integer", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":1e3},"payload":{"text":"test"}}` },
  { name: "invalid.exponent_overflow", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":1e999},"payload":{"text":"test"}}` },
  { name: "invalid.negative_zero", wireType: "command", shapeValid: false, errorCode: "invalid", raw: `{"protocolVersion":1,"schemaId":"${SCHEMA_ID}","commandId":"${ids.command}","kind":"message.enqueue","target":{"nodeId":"${ids.node}","dialogId":"${ids.dialog}"},"expected":{"dialogVersion":-0},"payload":{"text":"test"}}` },
];
const authoritativeCases = [
  { name: "state.stale", wireType: "command", shapeValid: true, authoritativeOutcome: "reject", errorCode: "stale", value: commandFixtures[4].value },
  { name: "state.foreign_object", wireType: "command", shapeValid: true, authoritativeOutcome: "reject", errorCode: "not_found", value: commandFixtures[3].value },
  { name: "state.id_conflict", wireType: "command", shapeValid: true, authoritativeOutcome: "reject", errorCode: "id_conflict", value: commandFixtures[1].value },
  { name: "state.duplicate_same_payload", wireType: "command", shapeValid: true, authoritativeOutcome: "return_original_receipt", value: commandFixtures[1].value },
  { name: "state.unknown_blocks", wireType: "event", shapeValid: true, authoritativeOutcome: "block_new_starts", value: eventFixtures.find((item) => item.value.type === "attempt.unknown").value },
  { name: "state.late_generation", wireType: "event", shapeValid: true, authoritativeOutcome: "record_without_mutating_active_slot", value: { ...eventFixtures.find((item) => item.value.type === "attempt.completed").value, payload: { generation: 1, output: { kind: "empty" } } } },
];

const fixtures = {
  protocolVersion: PROTOCOL_VERSION, schemaId: SCHEMA_ID,
  note: "Validators prove wire shape only. authoritativeCases require B1/U1 ownership, CAS, idempotency and state-machine checks.",
  fixtures: [...commandFixtures, ...eventFixtures, ...receiptFixtures, ...readFixtures, ...invalidFixtures, ...authoritativeCases],
};

const fixtureText = `${JSON.stringify(fixtures, null, 2)}\n`;
writeFileSync(join(here, "harness-v1.schema.json"), schemaText);
writeFileSync(join(here, "harness-v1.fixtures.json"), fixtureText);
const manifest = {
  protocolVersion: PROTOCOL_VERSION, schemaId: SCHEMA_ID,
  schemaSHA256: schemaDigest,
  fixturesSHA256: createHash("sha256").update(fixtureText).digest("hex"),
  scenariosSHA256: createHash("sha256").update(readFileSync(join(here, "harness-v1.scenarios.json"))).digest("hex"),
  commandKinds: commandSpecs.length, eventTypes: Object.keys(eventPayloads).length,
};
writeFileSync(join(here, "harness-v1.manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest));
