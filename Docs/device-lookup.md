# Exact device lookup for a waiting agent

The agent can use a machine name already present in its conversation to **request** the machine's current name, tags and/or overlay IPs. It cannot enumerate your tailnet or get your OAuth credentials. A human first chooses to fetch the result for local review, then separately approves the exact disclosure with Touch ID. The CLI waits for that decision.

```sh
Scripts/tailgate-lookup --name demo-runner --fields name,tags,ips
```

`demo-runner` is fictional. Supported field sets, in canonical order: `name`, `name,tags`, `name,ips`, `name,tags,ips`. Hostnames must be exact lowercase single labels, 1–63 ASCII characters, beginning with a letter and ending in a letter or digit; interior hyphens are allowed. No IP search, fuzzy match, wildcard, hostname list, domain suffix, regex, endpoint URL or list-all command is supported. The name supplied on the CLI is itself visible in the agent session and may be visible in the local process list; never supply credentials or sensitive free-form context there.

## What happens

1. The wrapper reuses the submission adapter's fixed installed-app verification, sanitized environment and single-launch exclusion. It launches only `/Applications/Tailgate.app/Contents/MacOS/TailgateReview --lookup-and-wait`. There is no development/unsigned fallback.
2. A dedicated lookup window receives one bounded frame over stdin. Merely opening this window does not initialize credential access, fetch inventory or prompt Touch ID. Operator setup and policy-write windows are unavailable in this mode.
3. You choose **Fetch for my local review…**. The controller uses its separately provisioned `devices:core:read` credential, selects one exact authorized match from trusted inventory, and constructs a review. Missing, ambiguous, unauthorized or malformed matches return the same generic data-free rejection to the agent.
4. You inspect the requested fields and exact response. The review warns that output goes to the requesting Pi agent, its session history, and its configured model/provider. You can decline; this returns **no device information**, not even a count or found/not-found flag.
5. Choose **Disclose these exact fields with Touch ID…** to sign the immutable disclosure review. The controller rechecks freshness and device identity/data before releasing the saved response. Changing requested fields, moving to another device, expiry, replay, a cancelled prompt or mismatching data cannot authorize a new response.
6. Only a verified success is forwarded to the agent. This is a **read/disclosure**, not a policy change, device approval or enrollment. A later proposal to change access requires a separate write review and approval.

The controller's lookup credential lives in a separate protected Keychain item. Lookup does not need to deserialize a writer credential. Initial provisioning is operator-only in the independently verified app, never through an agent-launched lookup request. See the signed deployment requirements in [signing.md](signing.md). Reader visibility must be verified independently by the operator; a syntactically complete reply cannot prove the credential sees the entire tailnet.

## Wire contract

The wrapper constructs the entire bounded ASCII query; it does not forward caller stdin or accept a filename:

```text
TAILGATE-LOOKUP/1
demo-runner
name,tags,ips
```

The final LF is mandatory; extra lines are rejected. Input must end within five seconds. The UI has a five-minute session limit; each prepared disclosure has its own shorter monotonic approval deadline. The wrapper has an outer six-minute bound and monitors caller survival; the app monitors its waiting parent and output pipe. Closing, disconnecting or timing out never returns device fields. If a response is missing or incomplete, treat the disclosure result as unknown and do not automatically re-prompt the person.

Successful stdout is one bounded JSON object with only the requested fields, for example:

```json
{"version":1,"status":"disclosed","device":{"name":"demo-runner","tags":["tag:demo-client"]}}
```

Non-success has no `device`, `name`, reason, count, raw server message, account ID or other identifying data:

```json
{"version":1,"status":"rejected"}
```

Other non-success statuses are `declined`, `expired` and `unknown`. Exit code is 0 for `disclosed`, 2 for the known no-data outcomes, and 3 for `unknown`. The wrapper discards malformed/duplicate/extra-field output and inconsistent exit codes, returning only `unknown`. Output is capped at 8 KiB. IPs, when selected, are only validated Tailscale overlay IPv4/IPv6 addresses, not public or LAN interface addresses. Never infer that a lookup IP grants permission to use it: current policy compilation still accepts only the supported explicit tag-based policy subset.

## Privacy and verification limits

Approval controls what leaves the trusted app. It cannot retract data already read by the caller or prevent an approved agent from putting it in a model request, session log, terminal capture, or another file. Do not approve those fields unless you accept that exposure. Avoid publishing real lookup output or attaching it to issues.

The wrapper is a convenience, not the authority: it reuses `tailgate-submit` installation checks, while the signed application performs Keychain and biometric enforcement. An untrusted same-user program can interfere with its own request or cause denial of service; it cannot self-approve. The local administrator, release signing process, installed app and Mac remain trusted assumptions.

Automated verification is offline: wrapper schema/query/process tests and controller test doubles. No real inventory, credentials, installed signed app, native rendering, file picker, Secure Enclave signing, Touch ID prompt or API request was used to verify this feature. A build and a passing mock suite do **not** establish a successful signed deployment; use the [operator acceptance checklist](acceptance.md).
