# Harness provider authentication v1

`harness-provider-auth-v1` is the provider-neutral private API used by the
Adapter and Gateway. Every request carries the exact lowercase UUID `nodeId`;
every mutation also carries an exact lowercase UUID `commandId`.

| Method | Route | Body/query |
| --- | --- | --- |
| `GET` | `/v1/provider-auth` | `?nodeId=...` |
| `POST` | `/v1/provider-auth/check` | `{nodeId,commandId}` |
| `POST` | `/v1/provider-auth/operations` | `{nodeId,commandId,method,secret?}` |
| `GET` | `/v1/provider-auth/operations/{operationId}` | `?nodeId=...` |
| `POST` | `/v1/provider-auth/operations/{operationId}/cancel` | `{nodeId,commandId}` |
| `POST` | `/v1/provider-auth/logout` | `{nodeId,commandId}` |

All successful routes return the envelope defined by
`api/provider-auth-v1.schema.json`. Codex advertises only `device_code`.
`secret` input is rejected and API keys, passwords, cookies, access tokens and
refresh tokens are never accepted by Harness.

The Codex implementation uses the pinned App Server `0.153.4` methods
`account/read`, `account/login/start` with `type=chatgptDeviceCode`,
`account/login/cancel` and `account/logout`. The pinned CLI-generated schema was
checked as part of HL-306, independently of the current
[authentication](https://learn.chatgpt.com/docs/auth) and
[App Server](https://learn.chatgpt.com/docs/app-server) documentation.
Completion is accepted only after `account/login/completed` and a successful
`account/read` readback reporting a managed ChatGPT account.

`commandId` receipts are written before the native request. Repeating the same
command returns its current envelope; reusing it for different input returns
`id_conflict`. Only one device-code operation may be pending. Codex does not
report device-code expiry in this protocol version, so `expiresAt` is `null`
and Harness publishes its persisted 15-minute `timeoutAt`. Cancellation,
timeout and late completion are fenced by the exact provider `loginId`.
Every terminal transition clears `verificationUrl` and `userCode` before the
operation is persisted or returned.

Receipts are retained for the node lifetime and are never evicted or silently
forgotten. The private ledger is bounded at 65,536 commands and 64 MiB; reaching
either operational limit fails closed with `provider_unavailable` and cannot
repeat an older native mutation.

On process restart, a persisted pending operation becomes `failed` with
`interrupted_by_restart`; it never remains pending against a dead App Server.
Provider auth state and command receipts live in the adapter `stateDir` as an
atomic owner-only `provider-auth-v1.json`. While a device login is pending this
private file necessarily contains the one-time user code shown by the API. It
never contains Codex tokens. Tokens remain entirely in the dedicated
`CODEX_HOME`, which should be a private persistent volume such as
`/provider-auth/codex-home`, owned by UID/GID `10001:10001`.

The offline zero-turn smoke keeps `network=none`. A deployment that enables
managed login attaches only the Harness container to a dedicated egress
network restricted to provider HTTPS endpoints; the private API is not
published on that network.

The user tool runner mounts only `/workspace` and fixed system read roots.
Neither `stateDir` nor `CODEX_HOME` is in its namespace. The node stays live
while unauthenticated, but `/health/ready`, admission and executor readiness are
blocked and dispatch does not begin. Starting a replacement login or logging
out while an attempt is active returns `busy`.

Error bodies contain only a fixed code:
`invalid_request`, `not_found`, `pending_operation`, `busy`, `id_conflict`,
`unsupported_method`, `invalid_secret`, or `provider_unavailable`.
