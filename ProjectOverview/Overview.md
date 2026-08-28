# Project Overview — Agentic Governance Workflow

> Living summary, kept up to date as the project evolves. Written for reference outside this repository (e.g. a personal knowledge base) — the technical specs (`docs/S-00` through `S-05`) remain the binding source of truth.

## What This Project Is

A GitHub issue triggers a code change. A human approves it. An AI agent implements it. Every step of that chain is logged as a cryptographically signed, tamper-evident entry that the agent itself cannot forge, alter, or backdate.

## The Problem It Solves

AI agents that turn a ticket into a pull request are common now — that part is not the point. The open question most tools don't answer is: **was this change authorized, on what basis, and can I prove the record of that hasn't been altered since?** A signed git commit proves who wrote code, not that a human approved it or that the approval log is intact.

## Why It's a Strong Portfolio Piece

- Touches a real, named regulatory hook: Article 12 of the EU AI Act (record-keeping for AI systems).
- Goes deeper than "AI writes code" — the actual engineering problem is trust and verifiability of an audit trail that a compromised agent cannot rewrite.
- Forces genuinely current 2026 practices: spec-driven development, least-privilege tool scoping per agent, bounded agentic loops instead of open-ended ones, keyless cryptographic signing.
- Fully demoable on a public GitHub repository at zero cost beyond a Claude Pro subscription — no hosting, no paid third-party services, no ongoing bill.

## How It Works, In Plain Terms

1. Someone opens a GitHub issue describing a change and labels it `ready-for-agent`.
2. A **gatekeeper** agent reads the issue and writes an assessment (zone, risk, recommendation) — it cannot change anything itself, and cannot reach the network beyond commenting on the issue.
3. A human reviews that assessment in a GitHub Environment approval gate. Approving creates a **grant**: a signed record of who approved what, for which paths, until when, and a hash of the issue text at that moment.
4. A **coder** agent implements the change, restricted to the paths in the grant. A **tester** agent adds or updates tests.
5. A separate **signer** job — not an AI agent, no model access at all — turns each step's report into a journal entry, signs it via Sigstore (no private key ever exists), and anchors it in a public transparency log (Rekor).
6. A **verifier** — also not an AI agent — independently checks the entire journal: unbroken sequence, valid hash chain, valid signatures, every agent action traceable to a real human approval.
7. A human merges the resulting pull request. Nothing merges automatically.

## Key Concepts and Tools

| Concept / Tool | Role in this project |
|---|---|
| **Zone model (0/1/2)** | Splits the repository into "locked" (only a human can touch it, e.g. signing logic, schema), "conditional" (agent may touch it if tests stay green), and "free" (agent may touch it normally). Prevents the system from being able to weaken its own controls. |
| **Least-privilege agent design** | Each agent (gatekeeper, coder, tester) gets only the exact tools and write paths its one job needs, enforced at three independent layers (tool allowlist, deny rules, a CI check on the resulting diff). |
| **Sigstore (Fulcio + Rekor)** | Keyless signing. Identity comes from GitHub's own OIDC token, exchanged for a short-lived certificate — there's no long-lived private key that could leak. Rekor is the public, append-only transparency log that anchors every signature outside the repository. |
| **JCS (RFC 8785)** | JSON Canonicalization Scheme — guarantees that hashing the same JSON object always produces the same bytes, which the hash chain depends on. |
| **GitHub Environments** | Used natively as the approval gate (a required reviewer must approve before a job continues) instead of building a custom approval mechanism. |
| **Conformance suite** | A set of deliberately broken example journals that the verifier must always reject. Protects against the verifier itself being quietly weakened over time. |
| **TicketSource adapter** | The workflow talks to an interface, not directly to GitHub Issues. Today's implementation is GitHub Issues; a Jira (or other tracker) implementation could be added later without touching the rest of the design. |
| **Bounded agentic loops** | Each agent has a hard `max-turns` limit rather than running indefinitely — matches the current (2026) best practice of using an open-ended loop only where genuinely needed, with an explicit stopping condition. |

## Explicit Non-Goals

- Not a certified compliance product — a reference architecture addressing part of what Article 12 EU AI Act asks for.
- Does not prove the code change was *correct*, only that it was *authorized* and that the record is intact.
- Does not protect against a malicious repository owner/admin — only against a compromised agent.
- Self-approval detection is implemented and tested, but has no effect when the same person is both the issue author and the approver (true for a solo project).

## Status

- Architecture and full specification complete (`docs/S-00` through `S-05`, JSON schemas for journal and grant).
- No implementation code yet — `src/`, `tests/`, and `.claude/agents/` are currently placeholders.
- Originally designed around Jira as the ticket source; changed to GitHub Issues to remove an external dependency, avoid extra account/rate-limit friction, and keep the whole project self-contained in one GitHub repository.
- A possible phase 2, not yet started: a multi-agent "review swarm" (several specialized reviewer agents plus a consolidating agent) as an additional quality gate before a human merges.

## Where To Look Next

- `docs/S-00-overview.md` for the architecture decisions and their reasoning.
- `docs/S-01-threat-model.md` for what this design protects against — and explicitly does not.
- `CLAUDE.md` at the repository root for the hard rules governing any future work on this project.
