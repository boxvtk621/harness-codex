# Harness Codex

Standalone, fail-closed runtime for running OpenAI Codex app-server in an isolated Docker container behind the private Harness HTTP/SSE API.

The repository owns the Codex adapter, durable SQLite supervisor, mTLS API server, isolated tool runner, wire contracts, image and zero-turn smoke. It does not contain Panel, Router, Agent Service, Cursor, Fixik, provider credentials or production deployment state.

## Requirements

- Go 1.26.5 on Linux
- Node.js 24.18 or newer
- Python 3.11 or newer
- Docker with Linux containers and OpenSSL 3

## Verify

```sh
make quality SOURCE_REPO=/absolute/path/to/homelab-telegram-panel
make image IMAGE=harness-codex:local
make smoke IMAGE=harness-codex:local
```

`make smoke` starts no turn and performs no model call. It proves the pinned Codex CLI version, native policy/MCP fence, helper isolation, mTLS identity, empty durable ledger, schema hashes, resource bounds and stable restart identity.

## Local fixture

Generate a fresh local identity and configuration in a new directory:

```sh
python3 scripts/setup.py \
  --directory /absolute/path/to/fixture \
  --owner-id local-owner \
  --codex-executable /opt/codex/node_modules/.bin/codex \
  --codex-home /absolute/path/to/codex-home \
  --codex-model MODEL
```

The script refuses to overwrite an existing directory. Never commit its certificates, keys, state or configuration.

With `--container`, the generated private files intentionally remain owner-only. Before starting the non-root image, copy them into private Docker volumes from a one-shot root initializer and change the volume contents to `10001:10001`; do not relax key permissions on the host.

## Security boundary

The image runs as UID/GID `10001:10001`; production launches must keep a read-only root filesystem, no network, all capabilities dropped, `no-new-privileges`, bounded CPU/memory/PIDs, a bounded `rw,noexec,nosuid` tmpfs at `/tmp`, and separate `/config`, `/state`, `/auth`, `/workspace` mounts. The private API requires TLS 1.3 and exact, distinct gateway/operator certificate SHA-256 pins.

The versioned wire contract is documented in [`docs/harness-v1.md`](docs/harness-v1.md). Source extraction provenance is recorded in `provenance/source-manifest.csv`.
