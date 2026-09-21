# Harness wire protocol v1 / schema v2

Status: C1 contract for HL-250@4. This package defines wire shapes and the
provider-neutral adapter seam. It does not implement Harness admission, state,
storage, execution, Gateway routes, UI, authentication, or provider SDK calls.

The exact wire pins are `protocolVersion: 1` and `schemaId:
"harness-wire-v2"`. The source is `api/generate-harness-v1.mjs`; generated
artifacts and their SHA-256 values are in `api/harness-v1.manifest.json`.
Consumers reject an unknown protocol, schema, field, subtype, enum value, or
duplicate decoded key. Raw JSON keys that are equivalent after escape decoding
are duplicates. Raw numeric tokens use only `0|[1-9][0-9]*`, and every number is
at most `9007199254740991`. This lexical rule prevents JavaScript rounding of a
fraction or exponent before range validation. Timestamps use a four-digit year,
uppercase `T`/`Z`, optional dot fraction of one through nine digits, and either
`Z` or an offset from `00:00` through `23:59`; Gregorian calendar validity still
applies and year `0000` is allowed. Text limits are UTF-8 byte limits.
`approval.requested.safePrompt` additionally permits at most 2,000 Unicode code
points and 8,192 UTF-8 bytes.
Every JSON wire document is limited to 8 MiB before parsing. Binary artifacts
use their separate 16 MiB limit.

## Identity and authority

Harness owns canonical UUIDs for node, dialog, command, receipt, message,
request, attempt, tool call, approval, input request, artifact, and event
entities. Native Cursor agent/run IDs and Codex thread/turn IDs remain inside an
adapter implementation and never enter the wire contract.

The browser command has no `actorId`. Gateway derives the actor from its
authenticated server session, strips any browser-supplied actor header, and sets
`X-Harness-Actor-ID` only on its authenticated mTLS request to Harness.
That identity is a bounded opaque string (`1-1` is valid); it is not a Harness
UUID and no synthetic user mapping is required. A foreign object is returned as
`not_found`, so object existence is not disclosed.

## Commands and durable receipts

All mutations use `POST /v1/nodes/{nodeId}/commands`. URL node ID, command target,
registry identity, and mTLS peer identity must agree. The ten command variants
are closed:

| Kind | Target | Expected CAS | Payload | Receipt references |
|---|---|---|---|---|
| `dialog.create` | node | registry version | optional title | dialog |
| `dialog.delete` | node, dialog | dialog version | empty | dialog |
| `message.enqueue` | node, dialog | dialog version | text | dialog, message, request |
| `message.steer` | node, dialog, attempt, queued message | attempt generation, message version | empty | dialog, message, attempt |
| `request.cancel` | node, queued request | request version | empty | request |
| `attempt.stop` | node, attempt | attempt generation | empty | attempt |
| `queue.resume` | node | queue version | empty | node |
| `attempt.retry` | node, prior attempt | prior generation | acknowledge known effects | prior attempt, request |
| `approval.respond` | node, approval, attempt | approval version, attempt generation | allow-once/deny and action hash | approval, attempt |
| `input.respond` | node, input request, attempt | input version, attempt generation | text | input request, attempt, message |

The Gateway carries the exact node ID, registry version, identity epoch, adapter
kind, and adapter version observed for routing in private expected-identity
headers on the same POST. Harness compares them with durable state while holding
the admission lock; a replacement between the preceding read and POST therefore
returns `409 stale` before any command mutation.

Processing order is authentication, routing-identity fence, object isolation,
lookup of `commandId` and canonical semantic payload hash, CAS/state checks, one
atomic domain+command+event commit, then receipt. An accepted command gets HTTP
202. Repeating the
same command ID and semantic payload returns the original receipt with HTTP 200,
even after versions change. Reusing the ID for a different payload returns
`id_conflict`. A lost response is never replaced by a Gateway-generated receipt.

`canonicalPayloadHash` is lowercase SHA-256 of the UTF-8
[RFC 8785/JCS](https://www.rfc-editor.org/rfc/rfc8785.html) representation of the
complete validated command (`canonicalValue` in the scenarios), including ID,
target, expected versions and payload. Actor is stored separately and is not
part of this hash. The current command domain has ASCII property names and safe
integer numbers: recursively sort object keys, preserve array order, serialize
primitives as ECMAScript JSON, and omit whitespace between tokens. Preserve
Unicode strings without normalization; do not HTML-escape `<`, `>`, `&` or
escape U+2028/U+2029. Go's default `encoding/json` output alone is insufficient.
The generated ASCII scenario hashes are pinned for schema v2. B1 persistence and U1 status
reconciliation must use these same bytes; a matching receipt with a different
canonical hash is not confirmation of the retained command.

`admitted` means durable admission only. It does not mean running or completed.
An admitted retry returns no new attempt ID. The ID is allocated and first
published by a later FIFO `attempt.dispatching` event. When an online Harness can
store work but its engine is blocked, the receipt may contain `blockingReason`.
`applied` is limited to synchronous state changes such as resuming a queue; it
does not assert a provider terminal outcome.

## Reads, cursors, and HTTP status

All reads are owner-scoped through Gateway and validate node/object ownership.
The response shapes are closed definitions in the schema:

| Route | Response and rule |
|---|---|
| `GET /v1/nodes/{nodeId}/snapshot` | one complete atomic node state with `stateVersion` and `lastEventSeq`, active attempt, and pending queue bounded by the 100-request admission limit |
| `GET /v1/nodes/{nodeId}/dialogs?cursor&limit` | `dialogPage` |
| `GET /v1/nodes/{nodeId}/dialogs/{dialogId}/messages?cursor&limit` | `historyPage`, ordered union of user and assistant items; user version supports steer CAS, assistant content may be inline/artifact/unavailable |
| `GET /v1/nodes/{nodeId}/requests?state&cursor&limit` | `requestPage` |
| `GET /v1/nodes/{nodeId}/requests/{requestId}/attempts?cursor&limit` | request/dialog-scoped `attemptPage`, so every retry generation is discoverable |
| `GET /v1/nodes/{nodeId}/attempts/{attemptId}` | `attemptRead`, including dialog and request ownership without scanning pages |
| `GET /v1/nodes/{nodeId}/attempts/{attemptId}/events?after&limit` | attempt/dialog-scoped `eventPage` containing only attempt-owned events |
| `GET /v1/nodes/{nodeId}/commands/{commandId}` | `commandStatus` with canonical hash and original typed receipt |
| `GET /v1/nodes/{nodeId}/identity` | registry version, node identity epoch, exact schema SHA-256 and adapter version, plus seven capabilities as `unsupported/declared/verified` |
| `GET /v1/nodes/{nodeId}/artifacts/{artifactId}/metadata` | typed `artifactMetadata` with ownership, dialog/attempt/call linkage, size, SHA-256, media type, redaction and truncation |
| `GET /v1/nodes/{nodeId}/artifacts/{artifactId}` | ownership-checked binary whose headers and bytes match the metadata |
| `GET /health/live` | process liveness only |
| `GET /health/ready` | node identity plus `ready/blocked/unknown` and exact blocked reasons |

The snapshot pending queue is complete, ordered by strictly increasing
`queueSequence`, and contains unique request IDs, input message IDs, and queue
sequences. Consumers reject a relational mismatch even when every item has a
valid standalone shape.

Page `limit` is 1 through 100. Cursors are opaque, non-empty, at most 512 bytes,
bound to node identity epoch, filter, ordering, and `snapshotStateVersion`.
Malformed cursors return 400; an expired version/epoch returns 409 `stale` and
requires a fresh snapshot. Pages return `lastEventSeq` so a client can join SSE
without a snapshot/page-to-stream gap. IDs from another owner or node return the
same 404 `not_found` as an absent ID.
The server may return fewer items than the requested limit and a non-null
`nextCursor` to stay within the 8 MiB JSON budget.

Every scoped page repeats its scope, and each item must have identical dialog,
request, and attempt IDs as applicable. JSON Schema proves each field shape; the
Go/TypeScript consumers additionally reject cross-scope items. Bootstrap reads
one atomic snapshot, joins SSE after `lastEventSeq`, then loads archive pages.
If a page snapshot becomes stale, the client re-queries it; C1 does not require a
long-lived SQL snapshot or MVCC cursor.

Success reads return 200. The error/status mapping is exact: 400 `invalid`, 401
`no_session`, 403 `forbidden`, 404 `not_found`, 409 `stale`, `id_conflict`,
`protocol_mismatch`, or `schema_mismatch`, 413 `too_large`, 422 `unsupported`,
429 `queue_full`, and 503 `node_unavailable` or `not_durable`. Only
`queue_full`, `node_unavailable`, and `not_durable` have `retryable: true`; all
other codes require a changed input, refreshed state, authentication, or
consumer upgrade. Retry means transport/service retry of the same intent and
command ID; it never authorizes a second attempt. `correlationId` is safe to
log. `currentVersion` and `currentState` are present only when disclosure is
authorized.

Artifact GET supports one byte range within the persisted size and returns 206
with a matching `Content-Range`; unsatisfiable or multiple ranges return 416. It
never returns more than the 16 MiB artifact limit. Metadata/hash mismatch or
unavailable durable bytes returns `not_durable`, never partial success. The
browser receives content only through the authenticated Gateway.

## Event stream and content

`GET /v1/nodes/{nodeId}/events?after=<seq>` is an at-least-once SSE replay.
Consumers deduplicate by node ID and sequence. A gap or node identity epoch
change requires a fresh snapshot; histories from distinct identities are not
joined. Every attempt-owned event also carries `dialogId`, `attemptId`, and the
payload generation where applicable. A late event is persisted against its old
generation and cannot mutate a newer active slot.

The 24 mandatory event variants are `node.state_changed`, `queue.changed`,
`message.accepted`, `message.disposition_changed`,
`attempt.dispatching/started/waiting_input/stop_requested/completed/failed/
interrupted/unknown`, `assistant.delta/message`,
`tool.started/output/completed`, `approval.requested/resolved`,
`input.requested/resolved`, `artifact.available`, `history.gap`, and
`dialog.deleted`. Each has a
closed payload. An unmapped provider lifecycle becomes `attempt.unknown` with
`completeness: complete`; its typed reason records that mapping failed. Every
authoritative lifecycle/state-change event is complete. Text is never
interpreted as a terminal event.

Tool inputs and results use the same explicit safe-content union:

- `inline`: up to 64 KiB UTF-8 with visible redaction and truncation markers;
- `artifact`: UUID, size and SHA-256, at most 16 MiB, with the same markers;
- `unavailable`: explicit reason, redaction status, and truncation status.

`tool.output` also records chunk index and stream (`stdout`, `stderr`, `result`,
or `diagnostic`). Multiple chunks may total at most 64 MiB per attempt; enforcing
that aggregate and emitting `output_limit` is B1. The same union carries
assistant deltas, final assistant messages, input prompts, tool inputs, tool
chunks, and terminal tool results. Observed content that cannot be represented
is `unavailable`, never an empty inline value. Assistant history uses the same
content union, so output above 64 KiB is referenced as an artifact or explicitly
unavailable rather than silently shortened. A confirmed native terminal with no
assistant text uses `attempt.completed.output.kind: empty`; no message ID is
fabricated. Usage is optional. Missing native usage is unknown, never zero;
Codex cumulative process counters retain `source: cumulative_process` and are
reset only with the adapter process accounting boundary.

## State semantics delegated to B1/U1

Schema and Go/TypeScript validators prove shape only. They cannot prove session
authority, ownership, canonical idempotency hash, CAS, FIFO order, capacity,
atomic commit, or provider state. The shared corpus therefore marks stale,
foreign, ID-conflict, duplicate-same-payload, unknown-blocking, and late-
generation cases as shape-valid with an explicit `authoritativeOutcome`. A
consumer must not turn that into authoritative PASS.

`api/harness-v1.scenarios.json` is the shared given/expect corpus for those
authoritative cases. Its exact digest is pinned as `scenariosSHA256` in the
manifest. The smaller `authoritativeCases` fixture entries link wire examples to
expected outcome names and do not replace scenario execution in B1/U1.

Unknown dispatch, stop, steer, provider state, or external effect blocks new
starts. Cancel acknowledgement leaves the attempt `stopping`; only a typed
terminal result permits `completed`, `failed`, or `interrupted`. Manual stop
durably pauses the queue before provider cancellation and restart/health refresh
does not clear it. A confirmed task failure on a ready node may release the FIFO
slot; node/policy/protocol failure blocks readiness. Those transitions, command
hash persistence, and atomic event/domain writes belong to B1. Gateway session,
CSRF, object isolation, cursor issuance, and SSE forwarding belong to U1.

## Adapter contract and compatibility

`internal/harnessadapter.Adapter` has explicit `Start`, `Resume`, `Events`,
`Steer`, `Cancel`, `RespondApproval`, `RespondInput`, and `Reconcile` calls.
Response calls address the Harness attempt generation plus pending entity ID and
version; approval also carries the action hash. Their `applied` result confirms
delivery to that native pending request and is not terminal. Both start and
resume carry the exact policy and tool-manifest bytes alongside their selected
revision and hashes. `ValidatePolicySnapshot` fails closed on missing pins or a
hash mismatch, and native policy is reapplied on every resume. The interface
uses Harness IDs and generation only. Vendor IDs are private adapter state.

The only C1 approval modes are `deny` (all effectful tool requests are denied)
and `explicit_once` (each effect requires the addressed `approval.respond`
decision). `EffectivePolicyHash` is SHA-256 over the domain
`harness-effective-policy-v1`, followed by 64-bit big-endian length-prefixed
UTF-8 values for revision, content SHA-256, tool-manifest SHA-256, and approval
mode. `attempt.dispatching.policyHash` is this effective hash. Policy content and
the manifest must be non-empty, their individual hashes must match exact bytes,
and `PreparePolicySnapshot` clones both byte slices before an asynchronous
native call.

The exact C1 pins are Cursor TypeScript SDK 1.0.31, local attached runs, and Codex
app-server 0.153.4 stable protocol. Before any mutation, consumers compare the
identity `protocolVersion`, `schemaId`, and `schemaSHA256` with their compiled
manifest pins; any mismatch blocks command forwarding. Cursor native steer maps
`complete_delivered` to `applied`, `revert_to_followup` to `fallback_queued`, and
an uncertain result to `unknown`; a definite fallback keeps the original queued
message in FIFO. Codex implementations map the Harness generation to a private
turn and send `expectedTurnId`. Neither adapter blindly retries an unknown send.
Cancel `acknowledged` is separate from terminal reconciliation.

Protocol/schema changes are additive only when existing strict consumers still
accept the same bytes and semantics. Any new command/event variant, required
field, enum meaning, ID ownership rule, or provider pin requires a new schema ID
and compatibility review. Declared capability and verified capability remain
separate; a missing mandatory verified capability makes readiness blocked.

Schema v2 adds `dialog.delete` and `dialog.deleted`; strict v1 consumers do not
accept those variants, so this is intentionally not advertised as rolling-wire
compatible. Harness storage schema version 2 has the same DDL as version 1 but a
different fingerprint and wire pin. On startup the node first opens an existing
volume read-only and accepts migration only when user version, the frozen v1
fingerprint, exact compiled DDL, durable node/owner/registry identity, SQLite
integrity, and foreign keys all match. One transaction then validates every
legacy command, receipt, and event, rewrites only the root schema ID, recomputes
command canonical hashes, validates the resulting v2 documents, and finally
updates the fingerprint and user version. Any malformed or v2-only document in
a claimed v1 volume aborts the transaction. The deployment boundary must drain
the node and coordinate strict consumers; CD must not treat the changed storage
fingerprint or wire schema as state-compatible without this migration-aware
handoff.

Reproduction after frontend dependencies are installed:

```sh
node api/generate-harness-v1.mjs
node api/check-harness-v1-schema.mjs
go test ./internal/harnessprotocol ./internal/harnessadapter ./internal/architecture
```
