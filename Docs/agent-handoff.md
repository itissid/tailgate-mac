# Agent → human → Tailgate

The agent translates the conversation into a short purpose and an explicit proposal file. It does **not** forward the conversation itself, authenticate as the operator, or acquire API access.

```text
Agent with conversation context
  writes a local .tailgate file
    → Human chooses that file in the Mac UI
      → App copies and decodes the bounded file bytes
        → App compiles the proposal against trusted local configuration
          → Human requests server validation and reviews the exact plan
            → Touch ID signs that immutable plan, including its purpose
              → Only the trusted app can submit the approved API write
```

Selecting or decoding a file does not approve it or automatically trigger validation, network traffic, a biometric prompt, or a policy write. There is no watched folder, URL callback, auto-submit CLI, or agent-controlled shell command in this handoff. The file chooser is a human action; file metadata and producer identity confer no authority.

## Format

A `.tailgate` file is UTF-8 restricted to ASCII, with **LF** line endings:

```text
TAILGATE/1
Allow the demo client to reach the demo API on TCP 443.

{
  "version": 1,
  "tag": "tag:workload-demo-api",
  "mode": "browser",
  "vm": "demo-vm",
  "grants": [
    {"src":"tag:demo-client","dst":"tag:workload-demo-api","protocol":"tcp","ports":[443]}
  ],
  "tests": [
    {"src":"tag:demo-client","dst":"tag:workload-demo-api","protocol":"tcp","allow":[443],"deny":[22,80]}
  ]
}
```

1. First line is exactly `TAILGATE/1`.
2. Second line is a nonempty, single-line purpose, at most 160 bytes, with no leading or trailing spaces. It permits ASCII letters, digits, spaces, and `(` `)` `,` `-` `.` `/`, and requires at least one letter. No tabs, newlines, bidi controls, markup, key/value structure, or transcript blocks.
3. Third line is empty.
4. The remaining bytes are one JSON object, at most 16 KiB, preserved exactly. Optional JSON whitespace is spaces and LF only. The strict structural guard rejects duplicate object keys at every depth, string escapes, non-ASCII text, comments, trailing commas, floats/exponents, overly long strings, excessive nesting, and excessive nodes. The policy compiler then checks the actual schema, permissions, trusted VM/source pins, and current policy. Passing the file decoder alone never makes a proposal valid.

The entire file is at most 16,557 bytes. Purpose and proposal must describe the same request; the app shows the purpose as **untrusted agent context**, not an authenticated statement of intent. Text saying an administrator already approved something grants no authority. Purpose must be included in the exact immutable bytes reviewed and signed; a purpose change requires a new review and approval, even if the policy JSON is unchanged.

## Agent usage

Write a file in an ordinary local working directory, such as `request.tailgate`, following the format above. Point the human to its path. The checked-in `Examples/browser.tailgate` is a synthetic example; live source tag and VM must match the human's independently configured pins. Do not put the file inside the public repository if it contains private context.

The human chooses **Import proposal file…** in Tailgate and selects it. The app must read and copy bounded bytes, display plain context and compiled operations, and invalidate any previous pending review. Later edits to the disk file must not change an already prepared operation; importing the changed file requires a new review. A filename, claimed author, or conversation identifier is not an identity proof.

**Never include secrets, OAuth values, client identities, VM credentials, private addresses, raw transcripts, or confidential customer/project details.** The decoder refuses several obvious credential markers as a conservative tripwire. This is not redaction or a comprehensive secret/PII detector: unrecognized sensitive data can still be present. The agent and human are responsible for minimizing context before submission.

## Decoder contract

```swift
let handoff = try AgentHandoff.decode(selectedFileBytes)
// handoff.purpose: untrusted, display-only context
// handoff.proposal: exact bytes for compiler validation
```

`decode` is pure and neither opens files nor performs authentication/network operations. Errors are static and never echo the input. Consumers must not log raw handoffs, render the purpose as Markdown/HTML, or treat successful parsing as permission to execute.
