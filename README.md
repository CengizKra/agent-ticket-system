# Agentic Governance Workflow

An issue-to-pull-request workflow with human approval and an audit journal that the executing agent cannot forge itself.

## The Problem

Agents that autonomously change code are a solved product problem since 2026 — GitHub Copilot for Jira turns a ticket into a pull request out of the box. What remains unsolved is the question next to it: **Was the change authorized, and on what basis?**

A signed commit proves that code came from an identity. It does not prove that a human approved the change, what that approval was based on, or that the record of it has remained unchanged since. This project logs exactly that chain of decisions — tamper-evident and independently verifiable.

## The Principle

Most agent audit tools sign inside the agent process itself. That means the log shares the agent's blast radius: whoever compromises the agent can rewrite the log retroactively and have it still validate.

Here, a separate job with no model access does the signing. Its identity comes from GitHub's OIDC issuer, is exchanged via Sigstore for a certificate with a lifetime of minutes, and is anchored in a public transparency log. The agent cannot produce this identity — it can neither create entries nor alter them after the fact without the verification failing.

There is no long-lived private key that could be lost or stolen.

## Flow

1. An issue is opened on GitHub and labeled `ready-for-agent`, which triggers the workflow natively — no external webhook relay needed
2. The gatekeeper reads and classifies it — it assesses, it changes nothing
3. A GitHub Environment with a required reviewer halts the run until a human approves
4. The approval is recorded as a signed grant: who, for which issue, which paths, until when — and the hash of the issue text at approval time
5. The coding agent works exclusively by reference to this grant
6. The signing job logs every action as a hash-chained, signed entry
7. A verifier checks the chain independently, without a model and without trusting the agent

## Self-Governance With Limits

The repository manages changes to itself — an issue to improve the verifier goes through the same workflow as any other change. But not to its own control structure.

| Zone | Content | Who may change it |
|---|---|---|
| **0** | Orchestration, signing logic, schema, conformance fixtures | Human only, by hand only |
| **1** | Verifier, journal logic, ticket adapter | Agent, as long as the conformance suite stays green |
| **2** | Tests, documentation, remaining code | Agent, in the normal flow |

The conformance suite consists of hand-written, deliberately broken journals. Every verifier version must reject them. If a check is weakened, the matching case turns green and the suite fails.

## What the Verifier Checks

V-01 through V-16, fully documented in `docs/S-04-verifier.md`. In essence: an unbroken sequence, correct hash chaining, valid signatures, a match between certificate identity and claimed actor, existence of the transparency log entry, traceability of every agent action to a valid grant, and approval by a human who was not the one who triggered the run.

## Limits, Explicitly

This is a reference architecture, not a certified compliance product. It addresses the logging requirements of Article 12 of the EU AI Act; compliance beyond that comes from organization, retention, and process, not from code.

Three things are deliberately unsolved:

- **A malicious repository administrator** can do anything. The design protects against compromised automation, not against the owner.
- **The self-approval check is ineffective in single-person operation.** It is implemented and tested against fixtures, but if the creator and the approver are the same person, it does not apply.
- **A journal rewritten from scratch, internally consistent, passes every check.** It is only disproved by the public transparency log, where the old entries still stand — and that requires a human who looks.

The anchor of trust is a human act: the genesis entry and the first verifier version are signed by hand. Every PKI starts that way.

## Documentation

| Document | Content |
|---|---|
| `docs/S-00-overview.md` | Zones, architecture decisions, constraints — **read first** |
| `docs/S-01-threat-model.md` | Threats T-01 through T-14, non-goals, residual risk |
| `docs/S-02-schema.md` | Journal and grant format, canonicalization |
| `docs/S-03-state-machine.md` | States, transitions, idempotency |
| `docs/S-04-verifier.md` | Check list V-01 through V-16 |
| `docs/S-05-agents.md` | Agent profiles and permission model |
| `ProjectOverview/Overview.md` | Plain-language project summary, kept up to date as the project evolves |
