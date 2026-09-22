# Operational logging

Harness emits diagnostic events as one JSON object per line on the node process
`stderr`. Every record uses schema `harness.console.v1`, is limited to 4 KiB,
and is queued through a bounded 256-record, non-blocking buffer. When the
writer fails or the queue is full, the logger counts losses and emits a
`log.records_dropped` summary when output becomes available again.

`stdout` is not a diagnostic channel. The node's existing startup and recovery
sentinels remain unchanged. Codex app-server stdout remains its JSON-RPC
transport, and `harness-tool-runner` stdout remains its single JSON response.

Records contain only allowlisted metadata: component, event, level, timestamp,
Harness correlation IDs, mandatory `nodeId`, per-process `bootId`, generation, bounded enum-like status/reason/tool
tokens, and truncation flags. Do not add prompts, messages, assistant output,
file names or contents, tool arguments/results, provider frames, credentials,
device codes, raw exceptions, storage paths, HTTP bodies, or query strings.
Logs are diagnostic evidence only; durable events and SQLite remain the source
of business state.

The emitted lifecycle catalogue is intentionally small:

- service start, stop, and sanitized failure;
- bounded recovery start, completion, and failure;
- runtime open and close;
- provider process ready and exit;
- attempt dispatch, start, terminal, and unknown transitions;
- tool start and completion;
- command accepted, rejected, deduplicated, and sanitized durable failures;
- provider-auth and readiness states observed at API boundaries;
- bounded logger drop and write-failure summaries.

High-frequency deltas, heartbeats, normal reads, prompts and tool output are not
logged. Auth and readiness events describe state observed by mutation/status
API calls; they are not a second authoritative state machine. Container deployments must configure rotation and retention in their
runtime logging driver; Harness does not write or retain log files and does not
introduce a log database or viewer.
