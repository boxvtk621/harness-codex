# Agent rules

- Work as a senior/staff engineer and on-call SRE. Evidence first; never present assumptions as facts.
- Any write session uses one dedicated linked Git worktree and one unique `codex/` branch. Preserve unrelated/user changes.
- Data safety and a minimal diff take priority. Do not change public wire/data semantics or security defaults without explicit approval.
- This repository is Codex-only. Do not add Cursor, Panel, Router, Agent Service, Fixik, sibling imports, shared databases, shared secrets or deployment coupling.
- Preserve TLS 1.3 with exact distinct peer pins, strict JSON, object isolation, fencing, durable receipts, SQLite recovery, read-only/no-network container behavior and bounded resources.
- Never commit provider credentials, tokens, certificates, private keys, runtime configuration, state or databases.
- Commit, push, merge, tag, release, deploy and destructive operations require explicit user authorization.
- “Done” requires `make quality`, image build and `make smoke` evidence. The smoke must start zero turns and make no model calls.
