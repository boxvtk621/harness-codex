# Contributing

Work in a dedicated linked worktree and a unique `codex/` branch. Keep changes minimal and preserve the fail-closed security boundary.

Before a change:

1. Read `AGENTS.md` and the relevant API/runtime code.
2. Confirm the source tree is clean and the worktree is isolated.
3. Treat public JSON contracts, SQLite migrations, native mapping schema, mTLS pins and recovery proofs as compatibility boundaries.

Before handoff run:

```sh
make quality
make image IMAGE=harness-codex:local
make smoke IMAGE=harness-codex:local
git diff --check
```

Do not add provider credentials, certificates, databases, runtime state, sibling module replacements, Panel/Router/Agent Service code, publishing automation or production deployment configuration. Commits, pushes, releases and deployments require explicit authorization.
