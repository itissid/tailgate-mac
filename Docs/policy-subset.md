# Supported live policy subset

`Compiler.compileLive(proposal:base:vm:source:occupiedTags:)` accepts an append-only access proposal against a **restricted existing policy**. It does not replace a live policy with the demo fixture and does not migrate permissive policies into restrictive ones. Unsupported documents are rejected; a human must manage those outside this app.

## Trusted inputs

The app obtains `vm` and `source` from human-controlled local configuration. `vm` is an exact ASCII label, **not proof of VM identity**. The enrollment module must authenticate its independently configured node or receiver pin. `source` must already be a defined tag in the policy; the compiler does not create or change the source tag.

`occupiedTags` is a trusted complete inventory of existing device tags, including tags not present in `tagOwners`. The compiler independently checks policy definitions and inventory for reuse of the proposed tag, but cannot prove the caller supplied a complete or current inventory. The transport must obtain inventory itself; accepting the agent's list would defeat freshness checking. Policy ETag alone does not version inventory, so enrollment must also check freshness at execution and before authorizing the intended device.

## Proposal

The schema is the same as the demo proposal, with an exact human-configured source and VM:

```json
{
  "version": 1,
  "tag": "tag:workload-api-01",
  "mode": "browser",
  "vm": "api-vm-01",
  "grants": [
    {"src":"tag:trusted-client","dst":"tag:workload-api-01","protocol":"tcp","ports":[443]}
  ],
  "tests": [
    {"src":"tag:trusted-client","dst":"tag:workload-api-01","protocol":"tcp","allow":[443],"deny":[22,80]}
  ]
}
```

Only `browser` or separately explicit `key` modes are accepted. Each protocol can have one grant and one test; `allow` must equal the exact grant ports and `deny` must be nonempty and disjoint. The mode is metadata, not part of the policy body: the broker must bind **candidate, tag, mode, VM, ETag, target, operation and expiry** in the approved plan.

The new tag must start `tag:workload-` and have a 1–32-byte suffix with lowercase letters/digits/internal hyphens, starting with a letter and ending with a letter or digit. It must differ from the source and not already be owned or occupied. The compiler does not assign it to an existing device. No request can change tag owners, an existing grant, an existing test, or any other section.

## Existing policy

All five top-level sections must be explicitly present, with **no additional sections**:

- `acls: []` and `ssh: []`. The compiler refuses missing sections, legacy ACL rules, SSH rules and broad/default-allow policies.
- `tagOwners`: 1–32 valid explicit tags, each owned **only** by `["autogroup:admin"]`. User/group/tag owners, delegated/transitive owners and wildcard selectors are rejected. Tags use lowercase ASCII letters/digits/internal hyphens, up to 48 bytes after `tag:`.
- `grants`: up to 32 rows, each containing only `src`, `dst`, and `ip`. Each source/destination is a one-element array referring to a defined tag. They must differ. Each row allows 1–16 unique explicit canonical `tcp:PORT` or `udp:PORT` values for one protocol only. No app capabilities, posture selectors, mixed protocols in a row, ranges, addresses, wildcards or multiple selectors.
- `tests`: exactly one complete test per existing source/destination/protocol grant, containing only `src`, `proto`, `accept`, `deny`. Its explicit tag:port accepts must equal that grant's allowed ports; its nonempty explicit tag:port denies must not overlap. All endpoints in the test refer to the same defined destination. Duplicate tests/edges or multiple grants for one edge are rejected rather than merged. Old test arrays and values are retained; the new tests are appended.

The whole policy is checked before and after compilation. Appending up to two protocol rows requires at most 30 existing rows and fewer than 32 existing tag definitions. Existing arrays and values are preserved exactly as semantic JSON; object key order and whitespace are normalized. This means even a narrow policy with a test-only denial row, a mixed-protocol grant, or no explicit `ssh` section is unsupported. That restriction is intentional, not an automatic invitation to rewrite the tailnet.

## Safe parsing and display

Both proposal and policy use a deliberately strict JSON subset: ASCII only, no escaped strings, duplicate keys, comments, trailing commas, floating-point numbers, or unknown fields. **HuJSON comments are rejected, never stripped or silently lost.** Inputs and the generated candidate must each fit 16 KiB, 12 levels, 1,024 JSON nodes and 128 bytes per string. VM labels are 1–64 lowercase ASCII letters/digits/internal hyphens, starting with a letter.

`Compiler.reviewDiff(base:candidate:)` validates both policies and displays a full normalized line diff with unchanged context and no omitted changed values. Object order/whitespace are normalized; array order and every value remain visible. Diff size is bounded at 128 KiB. Rendering data is restricted to schema-checked ASCII names, tags, protocols and ports; control-sequence or Unicode spoof text cannot enter the review. The app should also show the exact candidate body bytes/hash used for the write.

## What local compilation does not prove

The compiler is not Tailscale's policy engine. It checks only this subset's structure and exact allow/deny relationships. Before approval, submit the exact candidate to Tailscale validation. At execution, submit those same approved bytes with the original `If-Match`; a stale policy requires a new review. Check actual device identity, exact tags and current inventory through independently authenticated observations. A new tag must not be applied to an unintended device, and device-tag changes outside this policy transaction remain a separate race to detect and handle conservatively. These checks do not mint a key, enroll a node, or grant an OAuth issuer authority over a new tag.
