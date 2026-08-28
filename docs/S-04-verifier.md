# S-04 · Verifier

> Zone 1 for the code (`src/verify/`), zone 2 for this document.
> Every change to the verifier must pass the conformance suite.

## 1. Purpose

The verifier answers one question: **Is this journal complete, unaltered, and is every entry covered by a human approval?**

It uses no model, no network connection except to Rekor, and trusts neither the repository nor the agents. It is the only component whose verdict counts.

## 2. Invocation

```
verify journal/journal.jsonl [--offline] [--since SEQ] [--json]
```

| Option | Effect |
|---|---|
| `--offline` | Skips V-07 (Rekor check). For local runs without network. |
| `--since` | Checks from a sequence number onward. The chain before it is assumed as an anchor. |
| `--json` | Machine-readable report instead of plain text. |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | At least one check failed |
| `2` | Journal not readable or invalid against the schema |
| `3` | Rekor unreachable and `--offline` not set |

A failure always names the sequence number, the check ID, and the expected versus actual value. A report without these three is useless.

## 3. Check List

Every check is an acceptance criterion with a matching fixture in `conformance/`.

| ID | Check | Fixture |
|---|---|---|
| **V-01** | Every line is valid JSON and matches `schemas/journal-entry.schema.json` | `bad-schema.jsonl` |
| **V-02** | `seq` starts at 0, is gapless and strictly ascending | `bad-seq-gap.jsonl` |
| **V-03** | `inputs` and `outputs` contain exclusively `sha256:` strings, no free text | `bad-plaintext-input.jsonl` |
| **V-04** | Every entry's `prev` matches the `entry_hash` of its predecessor | `bad-prev-hash.jsonl` |
| **V-05** | Every signature verifies against the certificate in the bundle over the JCS bytes without `sig` | `bad-signature.jsonl` |
| **V-06** | The identity in the certificate matches `actor.identity` | `bad-identity-claim.jsonl` |
| **V-07** | The Rekor entry under `rekor_index` exists and matches the signature | `bad-rekor-index.jsonl` |
| **V-08** | Every entry with `actor.kind: agent` references an existing, signed grant | `bad-missing-grant.jsonl` |
| **V-09** | The entry's `ts` lies between the grant's `issued_at` and `expires_at` | `bad-expired-grant.jsonl` |
| **V-10** | The number of entries referencing a grant does not exceed `scope.max_actions` | `bad-grant-exhausted.jsonl` |
| **V-11** | `grant.issued_by.login` is not identical to `grant.requested_by` | `bad-self-approval.jsonl` |
| **V-12** | All paths in `detail.paths` lie within `scope.paths` | `bad-path-out-of-scope.jsonl` |
| **V-13** | No entry with `actor.kind: agent` touches a zone 0 path | `bad-zone-zero.jsonl` |
| **V-14** | `idempotency_key` occurs at most once | `bad-duplicate-key.jsonl` |
| **V-15** | The genesis entry has `seq: 0`, `prev` of zeros, and `actor.kind: human` | `bad-genesis.jsonl` |
| **V-16** | `ts` is non-decreasing across the sequence | `bad-time-travel.jsonl` |

## 4. Conformance Suite

`conformance/` contains, for every check, one journal that violates exactly that check, plus `good.jsonl`, which passes every check.

**The test:** `good.jsonl` must return exit code 0, every `bad-*.jsonl` must return exit code 1 **and name the matching check ID**.

The second half is decisive. A verifier that fails for the wrong reason does not pass the test. Otherwise a weakened check could be masked by some other unrelated failure.

`conformance/` lives in zone 0. An agent allowed to change both the verifier and its fixtures could hollow out both at once.

## 5. Where the Verifier Runs

| Location | When | Mode |
|---|---|---|
| CI on every push | always | full |
| CI before every merge | required check | full |
| After every `sign` job | within the governance workflow | `--since` last known anchor |
| Locally | any time | `--offline` allowed |

The verifier is a required check for merging. A red journal blocks every pull request — including one created by hand.

## 6. What the Verifier Explicitly Does Not Check

- **Whether the code change made sense.** Tests and review are responsible for that.
- **Whether the approval was wise.** It checks that it happened, and by whom.
- **Whether the issue text was harmless.** It only sees its hash.
- **Whether a human deliberately re-created the journal from scratch.** A fully new, internally consistent journal passes every check. This is only disproved by Rekor: the old entries still stand there, and their absence from the new journal is visible from the outside. This check lies outside the verifier and requires a human who looks at the public log.

The last point belongs in the README. It is the most honest statement about the limits of the design.
