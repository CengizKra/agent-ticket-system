# S-01 · Threat Model

> Zone 0. Changes by a human only.
> This document names what the design protects against — and just as clearly, what it does not.

## 1. System In Scope

From an issue arriving to a pull request being merged, including the journal and the verifier. Not in scope: GitHub itself, the Sigstore infrastructure.

## 2. Assets

| # | Asset | Why it matters |
|---|---|---|
| A-1 | Integrity of the journal | The primary asset. Without it, everything else is worthless. |
| A-2 | Authenticity of grants | A forged grant authorizes arbitrary agent actions. |
| A-3 | Secrets in the repository | `CLAUDE_CODE_OAUTH_TOKEN`, GitHub PAT. |
| A-4 | Integrity of the control structure | Zone 0: orchestration, signing logic, schema, fixtures. |
| A-5 | Integrity of the application code | The code that ultimately gets merged. |

## 3. Actors and Trust Levels

| Actor | Level | Rationale |
|---|---|---|
| Cengiz (repo admin, approver) | trusted | Anchor of trust. The design does not protect against them (§6). |
| Issue author | **untrusted** | Can be anyone who can open an issue in this repository. On a public repository, that is anyone with a GitHub account unless an allowlist restricts it. |
| Gatekeeper agent | partially trusted | Correct in the normal case, assumed compromisable. |
| Coder, tester agent | partially trusted | Same. Have write access to the repository. |
| Signing job | trusted | No model access, no agent logic, deterministic. |
| Verifier | trusted | No model access. Secured by the conformance suite. |
| GitHub OIDC issuer, Fulcio, Rekor | trusted (external) | Third-party anchor of trust. Compromise of these is a non-goal (§6). |

## 4. Trust Boundaries

1. **Between issue content and agent prompt.** The most important boundary. Everything that comes from a GitHub issue is untrusted input.
2. **Between agent jobs and the signing job.** The agent cannot reach the signing identity.
3. **Between feature branch and default branch.** The agent never works on the default branch.
4. **Between zone 1/2 and zone 0.** Automation cannot reach the control structure.

## 5. Threats

### T-01 · Prompt Injection via Issue Text → Secret Exfiltration
**Severity: high.** Documented (AgentFlayer, Zenity Labs): an attacker submits an issue containing hidden instructions. The agent reads them as a command, searches for secrets, and sends them out via a comment or a URL parameter. Built-in safeguards have been bypassed by simple rewording ("apples" instead of "API keys").

**Countermeasures**
- Issue text is passed exclusively as a delimited data block, with an explicit instruction never to treat it as an instruction.
- `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` — environment variables never reach subprocesses.
- Agents get no network tools beyond those named in S-05. No `curl`, no `WebFetch` for coder and tester.
- The gatekeeper may only comment on the GitHub issue, nothing else.
- Only issues from authorized authors are processed (allowlist check in the workflow, based on repository collaborator status or an explicit list).
- The workflow rejects triggers from users without write access; `allowed_non_write_users` stays empty.

**Residual risk:** A sufficiently well-crafted issue text can steer the gatekeeper toward a wrong assessment. That is why the gatekeeper does not decide — a human does (T-07).

### T-02 · Prompt Injection → Unauthorized Code Change
**Severity: high.** The issue text gets the agent to change something other than what was requested — for example, removing a check.

**Countermeasures**
- The grant binds the allowed paths (zone 1 and 2) and the allowed agents.
- Zone 0 is locked tool-side, review-side, and by a CI check.
- Every diff goes through human review as a pull request before merge.
- Zone 1 changes must pass the conformance suite.

### T-03 · Issue Text Changed After Approval
**Severity: high.** The attacker files a harmless-looking issue, waits for approval, then changes the text. The agent works against the changed content.

**Countermeasure**
- The grant contains `ticket_digest` — the hash of the issue text at approval time. Before every agent action, the issue text is re-read and the hash compared. On mismatch, the run aborts and writes `run.failed` with reason `ticket_mutated`.

### T-04 · Compromised Agent Rewrites the Journal
**Severity: high.** An agent with repository write access changes past journal entries.

**Countermeasures**
- The agent has no write path to `journal/` (S-05).
- The hash chain makes any change detectable: an altered entry breaks every subsequent `prev` reference.
- Each entry's signature is bound to a certificate the agent does not hold.
- Rekor anchors the entries outside the repository. Even a fully rewritten journal then contradicts the public log.

### T-05 · Agent Forges an Entry Under a False Identity
**Severity: medium.** The agent claims in the `actor.identity` field to be the signing job.

**Countermeasure**
- `actor.identity` is not taken from the entry but derived from the OIDC token of the signing job. The verifier checks that the certificate identity matches the claimed actor (V-06).

### T-06 · Grant Replay
**Severity: medium.** A grant issued once is used for multiple or later actions.

**Countermeasures**
- `expires_at` on the grant, four hours by default.
- `scope.max_actions` limits the number of entries that can be traced back to one grant.
- The verifier checks both (V-09, V-10).

### T-07 · Self-Approval
**Severity: medium.** The creator of an issue approves their own change.

**Countermeasures**
- The verifier checks that `grant.issued_by` is not identical to the issue author (V-11).
- **Explicit limitation in single-person operation:** Cengiz is both author and approver. The check is implemented and tested, but ineffective in the operation of this repository. It is verified against fixtures in the conformance suite, not against real operation. This is documented honestly, not presented as solved.

### T-08 · An Agent Changes the Control Structure
**Severity: high.** The agent changes the workflow, signing logic, schema, or conformance fixtures.

**Countermeasures** — four layers, see S-00 §4.
The structural one is decisive: workflows triggered by native `issues` events run from the default branch; a feature branch cannot change the running flow.

### T-09 · Feedback Loop — the Agent Triggers Itself
**Severity: medium.** An agent commit creates an event that starts another run.

**Countermeasures**
- `allowed_bots` stays empty; the workflow rejects bot triggers.
- `concurrency` group per issue, `cancel-in-progress: false`.
- `scope.max_actions` per grant as a hard ceiling.

### T-10 · Duplicate Event Delivery
**Severity: medium.** The same issue event is delivered or triggered twice.

**Countermeasure**
- Idempotency key from issue number and workflow run ID. If the key already exists in the journal, the run aborts without further action.

### T-11 · A Secret Ends Up in the Public Journal
**Severity: medium.** Issue content or a diff contains a secret and lands in the repository as plain text.

**Countermeasures**
- The schema allows only hash strings in `inputs` and `outputs`. An entry with free text is invalid and gets rejected (V-03).
- Secret scanning enabled on the repository.

### T-12 · Denial of Wallet
**Severity: medium.** Many issues in a short time exhaust the Claude quota or GitHub minutes.

**Countermeasures**
- No agent that consumes model tokens runs without approval — except the gatekeeper.
- The gatekeeper runs with a tight `--max-turns`.
- Workflow timeout and concurrency limit.
- Spend limit in the Claude Console.

### T-13 · Unintended API Billing
**Severity: high (financial).** Documented failure mode: headless runs bill through the API despite OAuth sign-in. A reported single case exceeded $1,800 in two days.

**Countermeasures**
- Set a spend limit before the first unattended run.
- Check platform.claude.com after the first runs for unexpected usage.
- Use `CLAUDE_CODE_OAUTH_TOKEN`, do not set `ANTHROPIC_API_KEY`.

### T-14 · A Fork Pull Request Triggers the Agent
**Severity: medium.** A fork PR brings malicious content into the working directory.

**Countermeasures**
- Only native `issues` events trigger the workflow, never `pull_request` events from forks.
- If PR content is ever read: base ref into the root directory, PR head into an isolated directory, brought in via `--add-dir`.
- GitHub withholds secrets from fork PRs on public repositories regardless.

## 6. Non-Goals

Explicitly out of scope:

- **A malicious repository administrator.** Whoever can change zone 0, disable branch protection, and reconfigure environments can do anything. The design protects against compromised automation, not against the owner.
- **Compromise of GitHub, Fulcio, or Rekor.** These are anchors of trust. If one of them falls, the claim falls with it.
- **Correctness of the code change.** The log proves authorization, not quality. Tests and review are responsible for that.
- **Confidentiality.** Nothing is encrypted. The repository is public, so is the journal.
- **Availability.** No protection against an outage of GitHub or Sigstore.
- **Later deletion.** Rekor is a public append-only log. What is written there stays.

## 7. Residual Risks

| Risk | Why it remains |
|---|---|
| Self-approval in single-person operation | Structurally unsolvable with one person. The check exists, does not apply here (T-07). |
| Gatekeeper misjudges a well-crafted issue text | Mitigated, not eliminated. Human approval is the actual control. |
| A public journal allows inference about activity | Timestamps and frequency are visible. Accepted deliberately. |
| Four-hour grants are a convention, not a derivation | The value is set, not derived. Adjust based on operating experience. |
