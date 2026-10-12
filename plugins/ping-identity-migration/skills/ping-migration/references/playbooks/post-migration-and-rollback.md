# Post-Migration Follow-Up, Secret Handling, and Rollback

What a migration run does not automate, how to handle client secrets that cannot be exported, and how to reverse a completed run.

## Scope

Covers:
- The manual follow-up list every migration leaves behind, and why each item is manual
- Client secret rotation and assigning recovered secret values, including batch mode
- Rollback via `scripts/rollback.js` and its dependence on the migration report

Does NOT cover:
- Flag reference for the orchestrator itself — see `./run-migration.md`
- Cutover triggers and dual-run design — see `./assessment-and-wave-planning.md`
- Building destination sign-on policies or journeys — the destination platform's flow-design documentation

---

## Manual follow-up list

| Item | Why it is manual | Action |
|---|---|---|
| Client secret rotation | PingFederate stores secrets as `OBF:JWE` and cannot export the plaintext | Rotate with `pingcli pingone applications application-secrets rotate`, or assign a recovered value with `scripts/pingone-client-secret.js` |
| `IMPLICIT`-only apps | Require client code changes to adopt PKCE before they can migrate | Redesign to `AUTHORIZATION_CODE` with PKCE, then re-run the migration |
| Sign-on policy assignments | Policies must exist at the destination first | Assign with `pingcli pingone applications sop-assignments create` once the policies exist |
| Data stores to populations | LDAP, database, and AD directory topology has no automatic destination mapping | Map each source directory to a destination population or directory connection in the PingOne admin console |
| SAML post-migration validation | Requires confirmation from the SP vendor, not just a destination read-back | Verify ACS URLs, entity IDs, signing certificates, NameID format, and both SP-initiated and IdP-initiated flows per connection |
| ATM custom scopes | Attribute-contract scopes are not created as part of the resource | Re-create as PingOne resource scopes |
| Signing keys | Private key material cannot be exported, so new keys are provisioned at the destination | Update every relying party's trust store with the new destination signing certificate |

The signing key and SAML validation items are the two most common causes of a wave passing mechanical validation but failing in production — both depend on a third party updating trust.

## Client secrets

`scripts/pingone-client-secret.js` handles PingOne applications and custom resources for three actions: `import` (create with a custom `clientId`), `set-secret` (assign a specific secret value), and `rollback` (delete a created record).

Supply the secret value through the `PINGONE_CLIENT_SECRET` environment variable rather than `--secret`. Command-line arguments are visible to other local users through `ps` and are written to shell history. `PINGONE_CLIENT_SECRET` takes precedence when both are set, and using `--secret` prints a warning.

```bash
# Assign a recovered secret to an already-migrated application
PINGONE_CLIENT_SECRET=<value> node scripts/pingone-client-secret.js \
  --action   set-secret \
  --type     application \
  --id       <applicationId> \
  --env-id   <pingone-environment-uuid> \
  [--previous-expires-at 2026-08-07T00:00:00Z] \
  [--profile <pingcli-profile>] \
  [--dry-run]
```

| Flag | Purpose |
|---|---|
| `--action` | `import`, `set-secret`, or `rollback` |
| `--type` | `application` or `resource`; in CSV mode this filters which rows are processed |
| `--id` | The destination `applicationId` or `resourceId` |
| `--env-id` | Destination environment UUID |
| `--csv` | Batch mode — apply the action to every row; ids are resolved by `clientId` |
| `--previous-expires-at` | ISO 8601 timestamp keeping the previous secret valid during a transition window |
| `--profile` | `pingcli` profile; the default profile is used when omitted |
| `--dry-run` | Preview without changing anything |

Batch CSV columns: `recordType` (`application` or `resource`), `name`, `type`, `clientId`, `clientSecret`. Treat the CSV as a credential file — it holds plaintext secrets.

`--previous-expires-at` is what makes secret rotation non-breaking: it lets clients that still hold the old secret keep authenticating until they redeploy.

## Rollback

`scripts/rollback.js` deletes every resource recorded in a migration report:

```bash
node scripts/rollback.js \
  --report  ./migration-reports/<env-slug>-migration-report-YYYY-MM-DD.md \
  --profile migration-run \
  [--dry-run]
```

Rollback is report-driven and has no dependency on the source system. That has two consequences:

- The migration report is the only record of what was created. If it is lost, rollback cannot reconstruct the run.
- A report from a `--dry-run` cannot be used — dry runs create nothing and write only an assessment report.

Run rollback with `--dry-run` first to confirm the delete list matches expectations.

## Prerequisites

- The migration report from the run being reversed
- A `pingcli` profile with delete permission in the destination environment
- For secret operations: the destination `applicationId` or `resourceId`, or a CSV with `clientId` values to resolve against

## Common variants

| Situation | Approach |
|---|---|
| Reverse only part of a run | Copy the migration report, remove the rows to keep, and run rollback against the copy |
| Secrets recovered from source documentation rather than export | `--action set-secret` per app, or CSV batch mode for an estate |
| Rotating without a recovered value | `pingcli pingone applications application-secrets rotate` — PingOne generates the new secret |
| Rehearsing rollback | Run a full migration into a scratch environment, then roll it back before touching production |

## Related references

- `./run-migration.md`
- `./assessment-and-wave-planning.md`
- `../catalogs/classification-rules.md`

## Source

- [Rotating the client secret for an application](https://docs.pingidentity.com/pingone/applications/p1_rotate_client_secret.md)
- Bundled scripts: `scripts/rollback.js`, `scripts/pingone-client-secret.js`
