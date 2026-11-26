# Tailscale transport contract

## Exported operations

`TailnetAPI(tailnet:)` accepts one explicit, bounded ASCII tailnet identifier provisioned outside a proposal. It rejects `-`, URLs, percent encoding, whitespace, slashes, query strings, and fragments. There is no origin override, generic URL executor, token accessor, key-mint method, or device mutation method.

- `getPolicy(using:) -> PolicySnapshot`: exact raw HuJSON bytes and a required strong quoted ETag.
- `validate(_:using:)`: sends the exact complete candidate, including its tests; throws unless server validation succeeds.
- `apply(_:ifMatch:using:) -> PolicySnapshot`: one policy POST with the caller's original required strong ETag. The **caller** must verify and durably consume the signed approval before calling this method.
- `devices(using:) -> [TailnetDevice]`: one complete inventory or an error. Fields are `id`, `nodeID`, `nodeKey`, `authorized`, `tags`, `name`, and `hostname`. Do not use `name`/`hostname` for identity binding. Compare the trusted, out-of-band expected `nodeKey`; require authorization and exact tags.
- `OAuthCredential(clientID:secret:)`: opaque, nonserializable credential holder; textual and reflected summaries are redacted. Credentials and OAuth access tokens remain secrets in application memory. Swift Strings do not provide guaranteed zeroization. Never log requests, credentials, responses, or memory dumps.

There is no automatic retry in this module. **Do not add an outer retry around `apply`.** Network failures, server errors, redirects, throttling, malformed success responses or missing success ETags during a write are `.outcomeUnknown`. HTTP 412 is `.stalePolicy`; re-fetch, rebuild the diff and obtain a new approval. Known rejection statuses 400/401/403/404/405/409/422 are `.rejected(status)`. The error values deliberately omit server messages, bodies, URLs, credentials and bearer tokens. After unknown outcomes, reconcile using read-only policy/inventory calls; do not infer that lack of a response means lack of a write.

## HTTPS and credential handling

Every call goes to `https://api.tailscale.com/api/v2/...`, with default macOS TLS certificate and hostname verification and TLS 1.2 minimum. **Origin pinning is not certificate/SPKI pinning:** system-installed trust roots remain trusted. Each call uses a new ephemeral URLSession with no persistent cookie store, credential store or URL cache, an empty proxy dictionary, no redirect following, no HTTP authentication negotiation, a 25-second request timeout and 35-second resource timeout. There are no custom retry loops or fallback hosts. URLSession may manage/re-establish transport connections internally; this code does not claim the service provides idempotency. The response delegate cancels downloads over the cap as data arrives, including responses without a Content-Length. Cancellation of a submitted write is an unknown outcome.

OAuth uses the client-credentials POST endpoint with form-encoded values. No Basic authorization header or secret is sent to a tailnet endpoint. The bearer is local to one operation; no access token is cached or returned. Requests explicitly downscope:

| Operation | Requested OAuth scopes |
| --- | --- |
| Policy GET / validation | `policy_file:read devices:core:read devices:posture_attributes:read` |
| Policy POST | `policy_file devices:core:read devices:posture_attributes` |
| Inventory | `devices:core:read` |

Policy scope dependencies follow the trust-credential documentation. Provision reader and writer clients with exactly their required scopes. A writer scope is broad: these scopes do not enforce the reviewed diff for you. Token success must contain a bounded printable bearer value, `token_type: Bearer`, and an integer `expires_in` from 1 through 3600. If `scope` is returned, additional unrequested scopes cause rejection. Duplicate JSON names, including escaped aliases, are rejected rather than interpreted by last-write-wins parsing.

## Wire shapes and conservative behavior

| Operation | Request | Supported success |
| --- | --- | --- |
| OAuth | `POST /oauth/token`, `application/x-www-form-urlencoded` with `grant_type=client_credentials`, `client_id`, `client_secret`, `scope` | HTTP 200 token JSON, max 16 KiB |
| Read policy | `GET /tailnet/{explicit-id}/acl`, `Accept: application/hujson` | HTTP 200 raw UTF-8 HuJSON/JSON, strong quoted `ETag`, recognized Content-Type |
| Validate candidate | `POST /tailnet/{explicit-id}/acl/validate`, `Content-Type: application/hujson`, unmodified full candidate | HTTP 200 and empty bytes, `{}`, or an envelope with only empty `message` and/or empty `data` array |
| Apply policy | `POST /tailnet/{explicit-id}/acl`, `Content-Type/Accept: application/hujson`, exact candidate, original `If-Match` | HTTP 200 raw policy and strong quoted `ETag`; unknown outcome if success is incomplete |
| Read inventory | `GET /tailnet/{explicit-id}/devices?fields=all`, `Accept: application/json` | HTTP 200 with exactly one top-level `devices` array; at most 10,000 complete records |

Candidate/request policy bytes and policy snapshots are limited to 1 MiB. Inventory and other tailnet replies are bounded to 8 MiB in streaming transport. Unsupported root inventory fields (including pagination indicators), missing identity/auth/tag fields, duplicate records/keys, unknown node-key representations, missing pages or incomplete records fail closed. Official `testdata/devices.json` fixtures omit `tags` on user-owned/untagged nodes, so an absent field maps to an empty array; explicit null and wrong types fail closed. Public documentation currently describes a whole-list device endpoint; a future pagination contract must be implemented and tested before accepting its results. Device key formats supported are 64 lowercase hexadecimal digits, optionally prefixed `nodekey:`. Both spellings normalize to the `nodekey:` prefix before duplicate detection and comparison against trusted pins.

Validation does not modify policy. HTTP 200 is not by itself sufficient: official clients show failures returned as JSON even with status 200. We reject any nonempty diagnostic/data array, unknown key, malformed JSON, or unsupported response shape. No diagnostic body is forwarded to the proposer. This conservative behavior can reject new API formats instead of falsely claiming a validation passed.

## Sources and verification

Reviewed public official sources on 2026-11-26 (no authenticated API endpoint was called):

- [Tailscale v2 client policyfile.go](https://github.com/tailscale/tailscale-client-go-v2/blob/f9e92a86ee85097dbabd255384403cb32b94f7c0/policyfile.go): Raw GET accepts HuJSON; Validate accepts the full ACL, test array, or HuJSON; full candidate string uses `application/hujson`; HTTP 200 with empty body is success; Set sends `If-Match`.
- [Tailscale v2 policyfile tests](https://github.com/tailscale/tailscale-client-go-v2/blob/f9e92a86ee85097dbabd255384403cb32b94f7c0/policyfile_test.go): validation failures can have HTTP 200 and a message/data body.
- [Official GitOps pusher](https://github.com/tailscale/tailscale/blob/f2c476cf173836a9873c7c9d593c9784619ecd80/cmd/gitops-pusher/gitops-pusher.go): posts candidate bytes to `/acl/validate` and requires empty message/data diagnostics. This corroborates the empty-envelope variant.
- [Official ACL client](https://github.com/tailscale/tailscale/blob/f2c476cf173836a9873c7c9d593c9784619ecd80/client/tailscale/acl.go): policy POST content type, strong ETag conditional update and HTTP 412 behavior.
- [Device list/type contract](https://github.com/tailscale/tailscale-client-go-v2/blob/f9e92a86ee85097dbabd255384403cb32b94f7c0/devices.go): `devices` list, `fields=all`, `nodeId`, `nodeKey`, `authorized`, tags; [official untagged device fixtures](https://github.com/tailscale/tailscale-client-go-v2/blob/f9e92a86ee85097dbabd255384403cb32b94f7c0/testdata/devices.json) show `tags` omitted on user-owned nodes.
- [OAuth clients](https://tailscale.com/docs/features/oauth-clients), [scope dependencies](https://tailscale.com/docs/reference/trust-credentials).

Offline scripted-transport tests exercise exact bytes/headers/scopes, token/credential redaction, failure envelopes, stale/unknown write outcomes without retries, complete inventory checks and ephemeral configuration. They do not certify live server behavior, network TLS/proxy behavior, Keychain isolation, hardware authentication or signed approval enforcement. No credential, key or real device is created by these tests.
