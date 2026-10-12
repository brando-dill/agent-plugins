# MCP tool usage for DaVinci flows

Two rules that keep DaVinci MCP calls precise.

## 1. Request the aggregations view for execution events

`getDavinciFlowExecution` supports an optional `attributes` query parameter. Pass `attributes: "aggregations"` as a **second, supplemental** call after the raw fetch to get the per-node execution/outcome rollup (nodeId, outcome counts, durations) instead of the raw event list.

```
getDavinciFlowExecution(environmentId, flowId, interactionId)                              # raw events — analysis source
getDavinciFlowExecution(environmentId, flowId, interactionId, attributes: "aggregations")  # supplemental rollup
```

- Requesting `attributes` **omits the raw event list** — never use it as the only fetch. Timeline construction, failure detection, and subflow traversal all run on raw events.
- Use the rollup to verify event completeness (raw per-node counts vs the aggregation) and to characterize repeated nodes without manual tallying.
- If only "Start Interaction" is found in the events log, the log level can be `error` and explicitly check for aggregations.

## 2. Always filter flow-interaction lists with SCIM filter parity

`listDavinciFlowExecutions` narrows results through a single SCIM `filter` string — there are no `filterByUsername` / `filterByTransactionId` / `daysBack`-style convenience parameters. Inventing them, or omitting the filter when an identifier is known, produces a unfiltered call: slow, cost-heavy, and it can silently miss the target execution in paginated output.

The flow interactions endpoint's SCIM filter parity supports these fields:

| Field | Operators | Use |
|---|---|---|
| `userId` | `eq` | PingOne user ID when known |
| `username` | `eq` | The username used during execution (primary actor filter) |
| `correlationId` | `eq` | Correlation ID (e.g. recovered from PingOne audit events) |
| `transactionId` | `eq` | Transaction ID — the required key for subflow correlation |
| `timestamp` | `ge`, `le` | Bound the search window (ISO 8601, UTC) |

Rules:

- Whenever an identifier is known, ALWAYS pass it via `filter` — never issue an unfiltered call and scan results client-side.
- Bound every actor-based search with a `timestamp ge` predicate; never scan unbounded history.
- Combine conditions with `and`. `flowId` and `environmentId` are always required arguments; a transactionId-only or correlationId-only search iterates over the flow list, one filtered call per flow.

```
listDavinciFlowExecutions(environmentId, flowId,
  filter: 'username eq "jsmith" and timestamp ge "2026-09-14T00:00:00Z" and timestamp le "2026-09-15T00:00:00Z"')
listDavinciFlowExecutions(environmentId, flowId, filter: 'transactionId eq "66b86dfa-1a06-42e7-b536-040905d1d895"')
```
