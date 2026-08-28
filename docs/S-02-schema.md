# S-02 · Journal and Grant Schema

> Zone 0. Changes by a human only, and only with a version bump.
> This is the contract between signer and verifier. Everything else in the project is replaceable, this document is not.

## 1. Canonicalization

A hash over a JSON object is only stable if the byte representation is unambiguous. Without a fixed rule, two implementations produce different hashes for the same object, and the verifier fails for reasons that have nothing to do with tampering.

**Binding: RFC 8785, JSON Canonicalization Scheme (JCS).**
- Keys sorted by Unicode code point
- No superfluous whitespace
- Numbers serialized per ECMAScript rules
- UTF-8 without BOM

Every hash and signature operation works on JCS bytes. Implementations without a JCS library are not permitted — hand-rolled sort logic is a known source of bugs.

## 2. Hash Definitions

All hashes are SHA-256, represented as `sha256:` followed by lowercase hex.

| Term | Definition |
|---|---|
| `entry_hash` | SHA-256 over the JCS bytes of the entry **without** the `sig` field |
| `prev` | `entry_hash` of the preceding entry — i.e. without its signature |
| `content_digest` | SHA-256 over the raw bytes of the content (issue text, diff, file) |
| `grant_hash` | SHA-256 over the JCS bytes of the grant without its `sig` |

**Why `prev` excludes the signature:** Sigstore bundles are not byte-for-byte reproducible — timestamp and certificate vary. A `prev` over the signed entry would not be stably recomputable. The signature protects the entry; the chain protects the order. Both are separate and checked separately.

## 3. Journal Entry

A file `journal/journal.jsonl`, one entry per line, JSON Lines, append-only.

```json
{
  "v": 1,
  "seq": 42,
  "prev": "sha256:9f2c1a…",
  "ts": "2026-08-22T14:02:11Z",
  "run": { "workflow_run_id": 1847362891, "attempt": 1 },
  "idempotency_key": "17:1847362891",
  "actor": {
    "kind": "agent",
    "id": "coder",
    "identity": "https://github.com/USER/REPO/.github/workflows/govern.yml@refs/heads/main"
  },
  "subject": { "ticket": "17", "grant": "sha256:41ab…" },
  "action": "code.changed",
  "inputs":  ["sha256:c1d0…"],
  "outputs": ["sha256:77be…"],
  "result": "ok",
  "detail": { "paths": ["src/verify/chain.py"], "zone": 1 },
  "sig": {
    "alg": "ed25519",
    "bundle": "…base64…",
    "rekor_index": 218374615
  }
}
```

### Field Rules

| Field | Type | Rule |
|---|---|---|
| `v` | integer | Schema version. Currently `1`. Change only with a version bump. |
| `seq` | integer ≥ 0 | Gapless, strictly ascending. `0` is the genesis entry. |
| `prev` | string | `entry_hash` of the predecessor. `sha256:` followed by 64 zeros for the genesis entry. |
| `ts` | string | RFC 3339, UTC, second precision. **Set by the signing job**, never by the agent. |
| `run` | object | GitHub run context for traceability. |
| `idempotency_key` | string | `<issue-number>:<workflow_run_id>`. Prevents duplicate processing. |
| `actor.kind` | enum | `human`, `agent`, `job` |
| `actor.id` | string | Identifier from S-05, e.g. `gatekeeper`, `coder`, `tester`, `signer` |
| `actor.identity` | string | **Derived from the OIDC token**, never taken from the agent's report. For `kind: human`, the GitHub login of the approver. |
| `subject.ticket` | string | GitHub issue number, as a string. |
| `subject.grant` | string\|null | `grant_hash`. Required when `actor.kind: agent`, otherwise `null` is allowed. |
| `action` | enum | See §5 |
| `inputs` | array | **Exclusively** `sha256:` strings. No free text. |
| `outputs` | array | Same. |
| `result` | enum | `ok`, `rejected`, `failed`, `skipped` |
| `detail` | object | Metadata without content: paths, zone, failure reason. No diffs, no issue text. |
| `sig` | object | Sigstore bundle and Rekor index. |

**Hard rule:** `inputs` and `outputs` allow exclusively hash strings. An entry with free text is invalid against the schema. The repository is public — this rule is the only safeguard against publishing issue content or diffs.

## 4. Genesis Entry

```json
{
  "v": 1,
  "seq": 0,
  "prev": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "ts": "…",
  "run": { "workflow_run_id": 0, "attempt": 0 },
  "idempotency_key": "genesis",
  "actor": { "kind": "human", "id": "bootstrap", "identity": "<github-login>" },
  "subject": { "ticket": null, "grant": null },
  "action": "journal.genesis",
  "inputs": [], "outputs": [], "result": "ok",
  "detail": { "note": "Anchor of trust. Signed by hand." },
  "sig": { … }
}
```

Signed by hand by Cengiz. This is the anchor of trust (S-00 §3).

## 5. Action Vocabulary

Closed list. New actions require a schema change.

| Action | Who writes it | Meaning |
|---|---|---|
| `journal.genesis` | Human | First entry |
| `ticket.received` | Signing job | Issue event arrived, ticket recognized |
| `ticket.triaged` | Signing job on behalf of gatekeeper | Assessment available |
| `grant.issued` | Signing job | Human has approved |
| `grant.rejected` | Signing job | Human has rejected |
| `code.changed` | Signing job on behalf of coder | Application code changed |
| `tests.changed` | Signing job on behalf of tester | Tests changed |
| `branch.pushed` | Signing job | Branch published |
| `pr.opened` | Signing job | Pull request created |
| `run.failed` | Signing job | Run aborted, reason in `detail.reason` |
| `grant.expired` | Signing job | Grant expired without completion |

## 6. Grant

A grant is the cryptographic image of a human approval. No agent may act without a valid grant.

```json
{
  "v": 1,
  "ticket": "17",
  "issued_at": "2026-08-22T13:58:04Z",
  "expires_at": "2026-08-22T17:58:04Z",
  "issued_by": {
    "kind": "human",
    "login": "<github-login>",
    "environment": "approval",
    "approval_run_id": 1847362891
  },
  "requested_by": "<github-login-of-issue-author>",
  "ticket_digest": "sha256:c1d0…",
  "scope": {
    "agents": ["coder", "tester"],
    "paths": ["src/verify/**", "src/journal/**", "src/ticket/**", "tests/**"],
    "zones": [1, 2],
    "max_actions": 20
  },
  "sig": { "alg": "ed25519", "bundle": "…", "rekor_index": 218374701 }
}
```

### The Three Load-Bearing Fields

**`ticket_digest`** binds the grant to the issue text at approval time. Before every agent action, the issue text is re-read and hashed. If it differs, the run aborts with `run.failed` and `detail.reason: ticket_mutated`. This is the countermeasure for T-03 and the reason a later-manipulated issue does not get executed.

**`scope.paths`** limits what the agent may touch at all. Zone 0 paths never appear here. The verifier checks every `detail.paths` entry against this pattern.

**`expires_at`** and **`scope.max_actions`** limit reuse. Defaults: four hours, twenty actions. Both values are set, not derived — see residual risks in S-01 §7.

## 7. What Gets Signed

| Object | Signed bytes |
|---|---|
| Journal entry | JCS bytes of the entry without `sig` |
| Grant | JCS bytes of the grant without `sig` |

Signing happens exclusively in the `sign` job via Sigstore keyless. The identity comes from the OIDC token of the workflow and is carried unchanged into `actor.identity` or `issued_by`. **The signing job never adopts an identity claimed by the agent.**

## 8. Versioning

- `v` changes only for non-backward-compatible changes.
- The verifier must be able to read every version ever published — a journal is never migrated, because any migration would break the chain.
- New optional fields with no bearing on verification do not require a version bump, but must be documented here.
- The JSON Schema files live under `schemas/` and are part of zone 0.
