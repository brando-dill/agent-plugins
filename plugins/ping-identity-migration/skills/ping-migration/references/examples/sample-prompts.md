# Sample prompts

Use these prompts to evaluate routing and playbook behavior. Environments, identifiers, and credentials in the examples are synthetic; substitute authorized values for a real run. A headless run resolves what it can from context and states its assumptions in the output — it does not pause to ask.

| ID | Prompt | Primary behavior |
|---|---|---|
| T-01 | Assess migration readiness for our PingFederate estate. We have a bulk export at ./pf-exports/bulk-063026.json. Classify everything and tell me what can go in wave 1. | File-mode dry-run, classification synthesis into waves |
| T-02 | Preview what a migration of all PingFederate OAuth clients to our PingOne sandbox environment would create, without changing anything. | Dry-run preview, no-apply guarantee |
| T-03 | We recovered client secrets for 40 migrated apps in a CSV. Assign them at the destination and keep the old secrets valid during transition. | CSV batch secret handling, `--previous-expires-at` |
| T-04 | Roll back the wave 1 migration. The migration report is at ./migration-reports/. Preview the delete list first. | Report-driven rollback with `--dry-run` |
| T-05 | Why was the AcmePortal app classified redesign? What exactly has to change in the client code, and what would make it direct? | Rule lookup, grant-type mapping |
| T-06 | Build a cutover design for migrating the customer-facing SAML apps. Authentication failure rate above 5% post-cutover must trigger rollback. | Cutover design, rollback trigger threshold |
| T-07 | Which PingFederate entities will a run create in PingOne, and which need manual work? Include auth policy topology implications. | Entity inventory, topology analysis |
| T-08 | A P14E-sourced app came back with empty post-logout URIs. Why, and does it affect classification? | P14E field-mapping lookup, always-empty list |
| T-09 | Extend the orchestrator with a new source adapter. Where does the new code go and what must it implement? | Architecture, canonical model, adapter seam |
| T-10 | Which grant types will be dropped in a PF → PingOne migration and who must sign off? | Dropped-grant governance lookup |

Minimum expectations for every run: dry-run before apply; no apply without a confirmed destination profile; classification synthesis, not raw report dumps; explicit state of derived values and evidence gaps; no fabricated counts or outcomes.
