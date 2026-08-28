# S-05 · Agent Profiles and Permission Model

> Zone 2. The rights granted here are nonetheless binding — an extension requires justification in the pull request.

## 1. Principles

1. **One agent, one task.** A specialized agent beats a generalist.
2. **Least privilege.** Only the tools and paths the one step needs.
3. **No agent signs anything.** Signing is a job with no model access.
4. **No agent writes to the journal.** Not even indirectly.
5. **No agent reaches zone 0.**
6. **Untrusted input is never an instruction.** Issue text is passed as a data block.

## 2. Roster

| Identifier | Type | Model | Writes |
|---|---|---|---|
| `gatekeeper` | AI agent | Sonnet | nothing in the repository |
| `coder` | AI agent | Sonnet | `src/**` (zone 1 and 2) |
| `tester` | AI agent | Sonnet | `tests/**` |
| `signer` | **Job, no model** | — | `journal/**` |
| `verifier` | **Job, no model** | — | nothing |

That `signer` and `verifier` are not AI agents is not a simplification, it is the load-bearing security decision (ADR-02). If the signer were a model, the entire claim of the project would collapse.

---

## 3. `gatekeeper`

**Task** — read the issue, summarize the intent, estimate the zone and affected paths, assess risk, give a recommendation. **It decides nothing.**

**Input** — issue number and issue text as a delimited data block.
**Output** — structured report: summary, estimated zone, estimated paths, risk assessment, recommendation `accept` or `reject` with reasoning.

| | |
|---|---|
| **Allowed tools** | `Bash(gh issue view:*)`, `Bash(gh issue comment:*)`, `Read`, `Grep`, `Glob` |
| **Forbidden tools** | `Write`, `Edit`, all other `Bash`, `WebFetch`, `WebSearch`, all git write operations |
| **Write paths** | none in the repository |
| **Abort** | issue not readable; author not on the allowlist; `max-turns` reached |
| **max-turns** | 8 |

**Why no general `Bash` and no `WebFetch`:** The gatekeeper is the first component to see untrusted input. An agent that reads issue text while also having network access is the exfiltration path from T-01. It may read and comment on the issue, nothing else.

---

## 4. `coder`

**Task** — implement the code change described in the grant. Nothing beyond that.

**Input** — grant, issue text as a data block, gatekeeper report.
**Output** — changed files in the working tree, a report with a path list and a short description.

| | |
|---|---|
| **Allowed tools** | `Read`, `Grep`, `Glob`, `Edit`, `Write` (only on `scope.paths`), `Bash` only for `pytest`, `npm test`, `git diff`, `git status` |
| **Forbidden tools** | `WebFetch`, `WebSearch`, any MCP tools, `git push`, `git commit --amend`, `gh` |
| **Write paths** | exclusively `scope.paths` from the grant |
| **Abort** | path outside scope; zone 0 path touched; `ticket_digest` mismatch; `max-turns` reached |
| **max-turns** | 25 |

**Why no GitHub issue access:** The coder has repository write access. An agent with both repository write access *and* issue write access could carry results out. The separation is deliberate: the gatekeeper talks to the issue tracker, the coder talks to the repository, neither talks to both.

**Before every action**, the issue text is re-read and checked against `ticket_digest`. On mismatch: immediate abort with `ticket_mutated`.

---

## 5. `tester`

**Task** — add or adjust tests for the coder's change. For zone 1 changes, additionally ensure the conformance suite stays green.

**Input** — grant, coder's diff, gatekeeper report.
**Output** — changed test files, test result.

| | |
|---|---|
| **Allowed tools** | `Read`, `Grep`, `Glob`, `Edit`, `Write` (only `tests/**`), `Bash` only for test runs |
| **Forbidden tools** | write access outside `tests/**`, in particular `conformance/**`; `WebFetch`; MCP tools; git write operations |
| **Write paths** | `tests/**` |
| **Abort** | attempt to change `conformance/**` or `src/**`; `max-turns` reached |
| **max-turns** | 15 |

**Why `conformance/` is forbidden:** Otherwise, on a zone 1 change, the tester could adjust the fixtures instead of fixing the change. That is exactly the self-weakening the zone model is meant to prevent.

---

## 6. `signer` — Job, Not an Agent

**Task** — turn reports from the preceding steps into journal entries, sign them, append them.

**Input** — an action report as a structured object.
**Output** — a journal entry.

| | |
|---|---|
| **Model access** | none |
| **Write paths** | `journal/**` |
| **Identity** | from the job's OIDC token, never from the report |
| **Timestamp** | set by the job, never from the report |

**Two hard rules.** The signer adopts neither `actor.identity` nor `ts` from what an agent reported. It sets both itself. Without this separation, an agent could create entries under a false name or backdated (T-05).

The signer checks before appending: Is the grant valid? Do the reported paths lie within scope? Is `max_actions` not yet exhausted? It refuses the entry rather than writing it and having it discarded later.

---

## 7. `verifier` — Job, Not an Agent

See S-04. No model access, no write access, no network connection except to Rekor.

---

## 8. The Permission Model In Practice

Rights are enforced in three places at once — each alone would be bypassable.

**1 · `claude_args` per job**

```yaml
claude_args: >
  --max-turns 25
  --allowedTools "Read,Grep,Glob,Edit,Write,Bash(pytest:*),Bash(git diff:*)"
```

**2 · `settings.json` with deny rules**

```json
{
  "permissions": {
    "deny": [
      "Write(.github/**)", "Edit(.github/**)",
      "Write(src/sign/**)", "Edit(src/sign/**)",
      "Write(conformance/**)", "Edit(conformance/**)",
      "Write(schemas/**)", "Edit(schemas/**)",
      "Write(journal/**)", "Edit(journal/**)",
      "Bash(curl:*)", "Bash(wget:*)", "Bash(git push:*)"
    ]
  }
}
```

**3 · A CI check after the run**

A step compares the generated diff against `scope.paths` and the zone 0 list. If it hits a disallowed path, the run aborts with `zone_zero_touched` or `path_out_of_scope` and writes `run.failed`.

The third layer is the most important: it checks the result, not the intent. The first two rely on the agent using the tool it was given.

**Environment**

`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` in every job that calls a model. Without this variable, secrets from the job environment reach every subprocess the agent starts.

## 9. Template for New Agents

A new agent is admitted only once every field is answered:

```
Identifier:
Type:                 AI agent | Job
Task:                 one sentence
Input:
Output:
Allowed tools:
Forbidden tools:      especially: network, MCP, git write operations
Write paths:
Abort conditions:
max-turns:
Justification of rights: why exactly these and not fewer
```

The last line is mandatory. A right without justification is not granted.
