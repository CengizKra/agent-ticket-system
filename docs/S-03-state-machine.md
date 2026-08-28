# S-03 · State Machine

> Zone 2. Changes by agents allowed, review as usual.

## 1. Principle

State does not live in a database, but in two places:
- **In flight:** in GitHub's run history. A job pointing at the `approval` environment halts and waits.
- **Durable:** in the journal. Every state transition produces exactly one entry.

From this follows a rule: **A transition without a journal entry did not happen.** If writing the entry fails, the transition counts as failed.

## 2. States

| State | Meaning | Terminal |
|---|---|---|
| `received` | Issue event arrived, ticket identified | no |
| `triaged` | Gatekeeper has analyzed it, a recommendation exists | no |
| `rejected` | Human has rejected it | **yes** |
| `granted` | Human has approved, grant signed | no |
| `implementing` | Coder is working | no |
| `tested` | Tester has added tests | no |
| `proposed` | Branch published, pull request open | no |
| `merged` | Human has merged | **yes** |
| `expired` | Grant expired without completion | **yes** |
| `failed` | Aborted with a reason | **yes** |

## 3. Transitions

| From | To | Trigger | Who | Condition | Journal action |
|---|---|---|---|---|---|
| — | `received` | GitHub `issues` event, labeled `ready-for-agent` | GitHub | Idempotency key unknown | `ticket.received` |
| `received` | `triaged` | Workflow | Gatekeeper | Issue readable, author on allowlist | `ticket.triaged` |
| `received` | `failed` | Workflow | Job | Issue not readable or author not permitted | `run.failed` |
| `triaged` | `granted` | Approval in environment | **Human** | Reviewer ≠ issue author | `grant.issued` |
| `triaged` | `rejected` | Rejection in environment | **Human** | — | `grant.rejected` |
| `granted` | `implementing` | Workflow | Coder | `ticket_digest` matches, grant valid | — |
| `implementing` | `tested` | Workflow | Tester | Change present, paths in scope | `code.changed` |
| `tested` | `proposed` | Workflow | Job | Tests pass, conformance suite green | `tests.changed`, `branch.pushed`, `pr.opened` |
| `proposed` | `merged` | Merge | **Human** | Review done, CI green | — |
| any | `expired` | Time check | Job | `now > grant.expires_at` | `grant.expired` |
| any | `failed` | Error | Job | see §4 | `run.failed` |

**Only humans** trigger `granted`, `rejected`, and `merged`. No agent can move into these states.

## 4. Failure Reasons

`detail.reason` on `run.failed`:

| Reason | Trigger |
|---|---|
| `ticket_unreadable` | The GitHub API does not return the issue |
| `requester_not_allowed` | Issue author not on the allowlist |
| `ticket_mutated` | `ticket_digest` differs — issue changed after approval (T-03) |
| `grant_expired` | Grant expired |
| `grant_exhausted` | `max_actions` reached |
| `path_out_of_scope` | Agent tried to write outside `scope.paths` |
| `zone_zero_touched` | Diff touches zone 0 |
| `conformance_failed` | Conformance suite red after a zone 1 change |
| `duplicate_event` | Idempotency key already in the journal |
| `budget_exceeded` | `max-turns` or workflow timeout reached |

## 5. Flow

```
                    ┌──────────┐
   issue event ────▶│ received │
                    └────┬─────┘
                         │ Gatekeeper
                    ┌────▼─────┐
                    │ triaged  │
                    └────┬─────┘
              Human      │      Human
        ┌────────────────┴────────────────┐
   ┌────▼─────┐                      ┌────▼─────┐
   │ rejected │◀── terminal          │ granted  │
   └──────────┘                      └────┬─────┘
                                          │ Coder
                                    ┌─────▼────────┐
                                    │ implementing │
                                    └─────┬────────┘
                                          │ Tester
                                     ┌────▼─────┐
                                     │  tested  │
                                     └────┬─────┘
                                          │
                                     ┌────▼─────┐
                                     │ proposed │
                                     └────┬─────┘
                                          │ Human
                                     ┌────▼─────┐
                                     │  merged  │
                                     └──────────┘

   Reachable from any state: expired, failed
```

## 6. Idempotency

The key is `<issue-number>:<workflow_run_id>`. Both are available directly from the GitHub Actions `github` context — no external delivery ID is needed, because the trigger is native to this repository.

Before any processing, the workflow searches the journal for this key. If it is present, the run ends with `run.failed` and `duplicate_event`, without starting an agent.

## 7. Reconciliation

A scheduled run periodically checks, via the GitHub API, for issues labeled `ready-for-agent` that do not yet have a `ticket.received` entry. Any it finds are treated like a fresh event.

This is a defense-in-depth safety net rather than a load-bearing requirement: with a native `issues` trigger in the same repository, lost events are far less likely than they were with an externally relayed webhook. The GitHub REST API's rate limit of 5,000 requests per hour carries a check every few minutes without effort, so the cadence is a matter of preference, not of a quota to protect.

## 8. Concurrency

`concurrency: govern-${{ issue-number }}` with `cancel-in-progress: false`. At most one workflow runs per issue. A second one waits instead of cancelling the first — a cancelled run would leave a state without a closing journal entry.

## 9. Re-entry

A waiting run does not stay open indefinitely. If it times out before anyone approves, the ticket ends in `expired`.

Re-entry happens through a new event with a new run ID. The previous history stays in the journal; the new run starts at `received`. There is deliberately no resumption of an expired run — a grant whose approval lies hours in the past is not silently extended.
