# Tailgate

Tailgate separates an agent’s request from a person’s approval and the credentials that permit a network change. This glossary follows the [trust atlas](Docs/trust-atlas.html), grounded in the live app’s [setup and review](Sources/TailgateLive/LiveController.swift), [Mac trust](Sources/TailgateLive/MacTrust.swift), [API access](Sources/TailgateLive/TailnetAPI.swift), [lookup](Sources/TailgateLive/Lookup.swift), and [enrollment](Sources/TailgateLive/Enrollment.swift) code.

## Language

### Requests and network policy

**Tailgate**:
The Mac app that turns an agent’s proposed network change into an exact, human-reviewed request and sends it only after local approval checks. The agent supplies input, not authority or credentials.

**Tailnet**:
A private network managed by Tailscale, with its own devices and rules for which connections are allowed.

**Proposal**:
An untrusted description of the access an agent wants, including the connections and tests it requests. An accompanying purpose explains the agent’s stated intent but is not an instruction or an approval.
_Avoid_: Approved request.

**Tag**:
A policy label used to select devices for access rules. A rule applies to every device carrying its selected tag, not just the intended machine.

**Candidate policy**:
The complete proposed replacement for the tailnet’s current access rules, including the requested change and its tests. It is the exact content reviewed and sent, not merely a summary of differences.

**Policy validation**:
Tailscale’s check of the candidate policy and its tests before approval. Validation does not install the policy or authorize a write.

### Saved setup and API credentials

**Save in Keychain**:
The setup action that keeps settings and client credentials on this Mac after the app quits. Saving is not sending a policy change, obtaining an access token, or approving a write.
_Avoid_: Submit, apply.

**Setup record**:
The saved `configuration` Keychain item containing the target network, intended machine and its identity pin, allowed connection source, and separate reader and writer client credentials. It is setup for later operations, not a review plan or a record of an approved write.
_Avoid_: Approval record.

**Keychain item**:
One protected record in macOS Keychain, such as the setup record, saved lookup credentials, or a receipt. An item can contain settings or evidence; it is not necessarily a cryptographic key.

**Create-only**:
The rule that an existing setup or lookup-credential record cannot be overwritten by saving again. Replacing those credentials requires a separate review of the replacement; this rule does not make the operator receipt immutable.

**Read-only client**:
The OAuth credential set Tailgate uses to read policy and device inventory and to validate a candidate without changing policy. It is the reader credential used by the same app as the policy writer, not a person, another app, or a separate process.
_Avoid_: Reader, when it could mean a person.

**Policy writer**:
The separate OAuth credential set Tailgate uses for an approved policy write, after checking the signed review and reserving its single-use intent. It belongs to the same app as the read-only client, not to a separate writer person or process.
_Avoid_: Writer, when it could mean a person.

**Lookup client**:
An optional, separate read-only OAuth credential set saved in the `lookup-reader` Keychain item for device lookup. Its saved record contains no policy-writer secret, and fetching with it does not itself approve disclosure to the agent.

**Client credentials**:
An app client ID and secret in Tailscale’s OAuth authorization system, provisioned for Tailgate to exchange for an access token. These are not the operator’s login, a Touch ID result, or the token sent with a policy request.

**Access token**:
A short-lived bearer credential issued by Tailscale for an API operation: whoever possesses it can exercise its permitted access. Tailgate obtains a fresh token for each operation and does not save it or return it to the agent.

**Scope**:
A named permission that limits what an OAuth client or its access token may do at Tailscale, such as reading devices or writing policy. Scope is remote API authority, not proof that a person approved one particular review.

### App identity and local approval

**Local trust check**:
Tailgate’s check that it is running as the expected installed, signed release app with the required protections and private Keychain access group. Passing it permits protected local operations; it does not approve a plan or obtain Tailscale permission.

**Signing identity**:
The release-signing private key and certificate used to sign the app, allowing macOS to check its publisher and integrity. This identity is distinct from the local approval key and from a signature on one review plan.
_Avoid_: Plan signer, when referring to release signing.

**Provisioning profile**:
Apple-issued material carried by the release app that authorizes its app identity and private Keychain access group. It is not a client secret, an access token, or approval of a policy change.

**Keychain access group**:
The protected grouping of Keychain items that only appropriately authorized signed apps may access. Sharing the Mac login, app name, or bundle identifier does not by itself grant membership.

**Data Protection Keychain**:
The macOS protected store Tailgate uses for credentials, identity pins, and write records, kept on this device and accessible while it is unlocked. Access is restricted by app identity and access group, not by a fresh Touch ID prompt for every item read.

**Secure Enclave**:
The Mac’s hardware-protected boundary that holds Tailgate’s approval private key and signs without exporting that key. It is separate from the Keychain records holding settings and receipts.

**Approval key**:
The local private key whose use requires fresh Touch ID authentication and produces a signature over an exact review. It stays in the Secure Enclave and is neither an OAuth credential nor the release-signing key.

**Approval public-key pin**:
The saved public counterpart Tailgate trusts when checking approval signatures. It identifies the local approval key, not the intended machine or a Tailscale API client.

**Review plan**:
The fixed, short-lived description of one proposed policy write, including its target, policy version, purpose, deadline, differences, and exact replacement policy. It is held in memory for review, not saved as the setup record or durable write history.
_Avoid_: Proposal, when referring to the compiled review.

**Review fingerprint**:
A content-derived identifier, called a hash, for the exact review text; it changes if that text changes. It is not a signature, proof of Touch ID, or permission to send the request.

**Approval signature**:
Cryptographic evidence produced by the approval key over the exact review text after Touch ID permits signing. Tailgate verifies it locally; it is not persisted in the write journal or sent to Tailscale, which checks the access token instead.
_Avoid_: Access token, app signature.

### Writing, evidence, and uncertain outcomes

**ETag**:
Tailscale’s version label for a policy snapshot, compared as-is rather than interpreted. It is neither a signature nor a lock on device tags.

**Conditional policy write**:
A request to install the exact reviewed candidate only if the current policy still has the reviewed ETag. A changed version requires a new review rather than reusing the old approval.

**Intent journal**:
The durable local record that reserves a single-use write intent, prevents overlapping writes, and retains its outcome across app restarts. It keeps identifiers, review hashes, and outcomes, not the complete review or its approval signature.

**Write history**:
The immutable per-review records within the intent journal that bind a review identifier and hash to a recorded outcome. Unlike the replaceable operator receipt, this history is used to check that the corresponding write was recorded as applied.
_Avoid_: Receipt, when referring to immutable applied history.

**Unresolved write**:
A reserved write whose outcome is not definitively resolved, including after a crash or an uncertain network result. Its durable block prevents another write; silence or a missing response is not permission to retry.

**Operator receipt**:
The saved local summary of a write attempt, including its review fingerprint, target and machine binding, policy hashes, and any confirmed post-write version and time. It can be updated or replaced, so it is not the immutable write history, the signed review itself, or proof of enrollment.

**CLI receipt**:
The limited result returned through the command-line wrapper to the waiting agent for a policy submission, reporting status, write outcome, and enrollment as not confirmed. It contains no client secret, access token, or approval signature and is distinct from the saved operator receipt.
_Avoid_: Enrollment confirmation.

**Read-only reconciliation**:
An observation comparing current policy with the prior and candidate policy hashes in the operator receipt after an uncertain write. A match does not prove who made the change, clear the unresolved block, or authorize a retry or rollback.

### Lookup and enrollment

**Device lookup**:
A separate read-only operation that privately finds one authorized device by exact hostname for the operator to inspect. Fetching the result does not yet release it to the agent or change policy.

**Disclosure review**:
The fixed, short-lived review of the exact device information proposed for release to the waiting agent. Its separate Touch ID approval covers that disclosure, not a policy write, and Tailgate rechecks the device and selected information before release.

**Browser enrollment**:
The separate human sign-in flow that joins the intended machine to Tailscale. Tailgate does not sign the machine in, send it credentials, retag it, or mint a live enrollment key.

**Enrollment check**:
A read-only observation that checks applied write history, unchanged reviewed policy, and whether the independently pinned machine is authorized with exactly the approved tag and no other device holds that tag. Confirmation describes the observed state, not a new enrollment action or a guarantee of future access.

**VM node public-key pin**:
The expected public identity of the intended virtual machine, obtained independently by the operator and saved for later comparison with device inventory. A hostname or network address is not a substitute, and this pin is distinct from the approval public-key pin.
