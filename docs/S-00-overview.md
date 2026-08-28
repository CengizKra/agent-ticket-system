# S-00 · Overview, Zones, and Architecture Decisions

> Entry document. Whoever reads this project for the first time reads this document first.
> Status: binding. Changes require a new ADR, not a silent correction.

## 1. Purpose

An issue triggers a code change. A human approves it. An agent executes it. Every step is logged as a signed, hash-chained entry that the executing agent itself cannot forge.

The value does not lie in the coding agent — that has been a standard product since 2026. The value lies in the provable answer to the question: **Was this change authorized, on what basis, and has the record of it remained unchanged?**

## 2. Non-Purpose

- Not a certified compliance product. A reference architecture for the logging requirements of Article 12 of the EU AI Act, nothing more.
- No statement about the *quality* of the change. The log proves authorization and integrity, not correctness.
- No encryption. Signatures prove authorship and integrity, not confidentiality.

## 3. Self-Governance

The project manages changes to itself: an issue to improve the verifier goes through the same workflow as any other change.

That creates two problems, both solved architecturally:

**Self-weakening.** A manipulated agent could change the verifier so that it no longer checks anything — with a valid signature, because it was properly approved. Solved by the zone model (§4) and the conformance suite (§5).

**Bootstrapping.** The first verifier cannot have verified itself. The anchor of trust is a human act: the genesis entry and the first verifier version are signed by hand by Cengiz. That is not a weakness — every PKI starts this way — but it needs to be stated explicitly.

## 4. Zone Model

The repository splits into three zones with different change rules.

| Zone | Paths | Who may change it |
|---|---|---|
| **0 — locked** | `.github/**`, `src/sign/**`, `conformance/**`, `docs/S-00`, `docs/S-01`, `docs/S-02`, `schemas/**`, `journal/**` | Human only, by hand only |
| **1 — conditional** | `src/verify/**`, `src/journal/**`, `src/ticket/**` | Agent may change, change must pass the conformance suite |
| **2 — free** | `tests/**`, `docs/S-03`, `docs/S-04`, `docs/S-05`, remaining documentation, other application code | Agent may change in the normal flow |

Rationale for zone 0: whoever can change orchestration, signing logic, schema, the conformance fixtures, or the journal itself undermines the entire security claim. These paths are therefore outside what automation is allowed to decide. No agent ever gets a write path onto `journal/**` in the first place (S-05) — its zone 0 membership here exists so the same CI check and review requirement apply to it as to every other load-bearing path.

### Enforcement — four independent layers

1. **Structural.** Workflows started by a native `issues` event always run from the default branch on GitHub. An agent that changes a workflow file on its feature branch does not change the running flow. The orchestration cannot rewrite itself.
2. **Tool-side.** Every agent gets write access, via `--allowedTools` and permission rules, only to the paths in its profile (S-05).
3. **Review-side.** `CODEOWNERS` plus branch protection enforce human review for all zone 0 paths.
4. **Check-side.** A CI check fails as soon as an agent-generated branch touches a zone 0 path. In addition, every zone 1 change must pass the conformance suite.

None of these layers is sufficient alone. The design assumes each one individually can be bypassed.

## 5. Conformance Suite

`conformance/` contains hand-written journals that are deliberately broken — a gap in the sequence, a wrong `prev` hash, a signature from the wrong identity, an expired grant, a self-approval, an issue text altered after the fact.

Every verifier version must **reject** these journals. If someone — human or agent — weakens a check, the matching case turns green and the suite fails.

The fixtures live in zone 0 for that reason. An agent allowed to change both the verifier and its test cases could hollow out both at once.

## 6. Architecture Decisions

### ADR-01 · GitHub Environments Are the State Machine
An Actions job that points at an environment with a required reviewer halts until a human approves.

*Why:* The approval gate was the only reason durable state was needed. GitHub solves exactly that natively, logs the approver, allows a comment, and knows "prevent self-approval." Available on the free plan as long as the repository is public. Wait time does not count as Actions minutes.

### ADR-02 · Signing Happens Outside the Agent
The coding agent reports what it did. A separate job with no model access and no agent logic signs that report and appends it to the journal.

*Why:* The identity comes from GitHub's OIDC issuer and is assigned to the job, not produced by the agent. A compromised agent can neither retroactively change entries nor create them under a false identity. This property — audit independence outside the agent — is exactly what most existing tools lack.

### ADR-03 · Keyless Instead of Key Management
Signing goes through Sigstore: the OIDC token of the Actions job is exchanged at Fulcio for a certificate with a lifetime of minutes, the signature is anchored in Rekor.

*Why:* A KMS costs money and only shifts the problem — who is allowed to make the KMS call? If that runs in the same job as the agent, nothing is gained. Keyless solves it structurally: there is no long-lived private key that could be stolen.

### ADR-04 · Self-Governance With Zones
The repository manages changes to itself, but not to its own control structure (§3, §4).

*Why:* Full self-governance would be circular and worthless. No self-governance at all would be a weak story and would dodge the interesting question.

### ADR-05 · Ticket Source Is an Adapter, GitHub Issues First
All reads and writes to the ticket source go through a `TicketSource` interface (`src/ticket/`) with exactly the operations the workflow needs: read an issue, comment on it, read its current text for the digest check. The first and only implementation is GitHub Issues.

*Why:* The concrete ticket backend should not leak into the orchestration, the gatekeeper, or the schema. A GitHub-native trigger removes an entire class of operational risk (see ADR-06) without locking the design to GitHub Issues forever — if a team later needs Jira or another tracker, it implements the same interface and nothing else changes.

### ADR-06 · Native GitHub Issue Events, No Webhook Relay
The workflow triggers directly on the repository's own `issues` event (opened, then labeled `ready-for-agent`), not on an externally relayed `repository_dispatch`.

*Why:* An earlier version of this design relayed tickets from an external tracker through a webhook into `repository_dispatch`, which required a reconciliation loop to cover lost deliveries and a tracker-side automation-run budget. Because the ticket source and the code repository are now the same platform, that entire relay layer is unnecessary — GitHub's own event delivery to a workflow in the same repository does not have the reliability and quota problems an external relay had. One moving part removed, not just one dependency swapped for another.

## 7. Constraints

- **Claude Pro**: Sonnet only, no Opus, roughly 10–45 prompts per five-hour window. No parallel agent fan-outs.
- **Cost**: nothing beyond the Claude subscription. No KMS, no hosting, no paid services.
- **Repository public** — required for the approval gate on the free plan and for the traceability of Rekor entries.
- **GitHub REST/GraphQL API**: 5,000 authenticated requests per hour — far beyond what an on-demand, single-repository workflow needs.

## 8. Document Map

| Document | Content | Zone |
|---|---|---|
| `S-00` | This document. Zones, ADRs, constraints | 0 |
| `S-01` | Threat model | 0 |
| `S-02` | Journal and grant schema, canonicalization | 0 |
| `S-03` | State machine | 2 |
| `S-04` | Verifier check list as acceptance criteria | 2 |
| `S-05` | Agent profiles and permission model | 2 |
