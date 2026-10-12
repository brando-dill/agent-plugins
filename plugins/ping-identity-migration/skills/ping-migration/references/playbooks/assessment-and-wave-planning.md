# Migration Assessment, Wave Planning, and Cutover Design

Turn classification output into a wave plan, risk register, governance decision log, validation gates, and cutover design.

## Scope

Covers:
- How to produce an assessment from real classification data rather than estimates
- Wave sequencing by risk and business criticality
- Risk register starting rows and where per-item concerns come from
- Governance decisions that require sign-off before execution
- Per-wave validation gates and cutover and rollback triggers

Does NOT cover:
- The classification rules that produce the input data — see `../catalogs/classification-rules.md`
- PingFederate entity-by-entity scoping — see `../blueprints/pingfederate-migration-inventory.md`
- Rollback execution — see `./post-migration-and-rollback.md`

---

## Method

Run the orchestrator with `--dry-run` to get real classification data from the source, then synthesise the artefacts below on top of the assessment report. Hand back the synthesis, not the raw report — the report is input, not the deliverable.

Use this method whenever the request is to assess readiness, plan waves, decide what to migrate first, design rollback or cutover, define validation and success criteria, identify risks and dependencies, or preview what would be classified without making changes.

## 1. Wave plan

Sequence by risk and business criticality. Populate waves 1 and 2 from the `direct` classification output; wave 3 comes from `redesign`.

| Wave | Scope | Owner | Target date | Acceptance criteria |
|---|---|---|---|---|
| 1 | Internal worker apps (`CLIENT_CREDENTIALS`) | | | All apps enabled, grants present, validation PASS |
| 2 | Authorization-code apps with redirect URIs | | | PKCE S256 enforced, token flows verified |
| 3 | Redesign apps (`IMPLICIT`-only) | | | Client code updated to PKCE, migration re-run |

Wave 1 leads because client-credentials apps have no user-facing redirect surface, so a failure is contained to a back-end integration rather than a login page.

## 2. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Source client secrets not exportable (PingFederate `OBF:JWE`) | High | Medium | Rotate secrets after migration with `pingcli pingone applications application-secrets rotate`, or assign a recovered secret with `scripts/pingone-client-secret.js --action set-secret` |
| `IMPLICIT`-only apps break without code changes | High | High | Exclude from waves 1–2; redesign before wave 3 |
| Worker app lacks organisation-admin scope for environment creation | Medium | Low | Use `--skip-env-create` against an existing environment |
| SAML SP certificate mismatch after migration | Medium | High | Verify the destination signing certificate and update SP trust before cutover |
| Redirect URI uses HTTP on a non-localhost host | Low | Medium | Update to HTTPS before go-live |

Extend the register with per-item concerns from the `meta-oidc-*.json` and `meta-saml-*.json` sidecar files in the work directory — those carry source-specific findings the generic rows above cannot anticipate.

## 3. Governance decisions

Document and get sign-off on these before execution:

- `IMPLICIT` grant dropped across all apps (deprecated per RFC 6749) — confirm with app owners
- `ACCESS_TOKEN_VALIDATION` excluded, no PingOne equivalent — confirm with token consumers
- `AUTHORIZATION_CODE` with PKCE S256 enforced on all migrated authorization-code flows — confirm clients send `code_challenge`
- Disabled source apps excluded from scope — confirm the exclusion is intentional rather than a stale enablement flag
- Signing keys provisioned new at the destination — confirm every relying party can update its trust store within the cutover window

## 4. Validation gates

Per-wave pass and fail criteria, evaluated before proceeding to the next wave:

- All apps enabled at the destination
- `AUTHORIZATION_CODE` apps report `pkceEnforcement=S256_REQUIRED`
- Every app has at least one resource grant, `openid` scope minimum
- No `IMPLICIT` grant present on any migrated app
- Token issuance confirmed for at least one app per wave
- SAML: ACS URLs, entity IDs, NameID format, and signing certificate verified with the SP vendor

The orchestrator's own `validate()` step covers the mechanical invariants. Token issuance and SP vendor confirmation are manual and must not be assumed from a PASS exit code.

## 5. Cutover design

1. Run `--dry-run` per wave to preview payloads before applying
2. Apply the wave, validate, and proceed only on PASS
3. Keep the source system running in parallel during the pilot (dual-run)
4. Rollback trigger: authentication failure rate above 5% in the first 30 minutes after cutover
5. Rollback action: redirect traffic back to the source system, investigate, then re-run

Dual-run is what makes the rollback trigger meaningful — without a live source to fall back to, step 5 becomes a restore rather than a redirect.

## Prerequisites

- A completed `--dry-run` against the real source, not a sample export — wave sizing depends on real counts
- Access to app owners for the governance decisions; the `IMPLICIT` and `ACCESS_TOKEN_VALIDATION` items cannot be decided by the migration team alone

## Common variants

| Situation | Adjustment |
|---|---|
| Small estate, single wave | Keep the risk register and validation gates; collapse the wave table to one row |
| No dual-run possible | Replace the rollback trigger with a maintenance window and rehearse `scripts/rollback.js` against a test environment first |
| Multiple source systems | Assess each source separately — classification is per source and per destination |

## Related references

- `../catalogs/classification-rules.md`
- `./run-migration.md`
- `./post-migration-and-rollback.md`
- `../blueprints/pingfederate-migration-inventory.md`

## Source

- [PingOne Cloud Acceleration Toolset](https://docs.pingidentity.com/pingone/migration-tools/p1_cloud_acceleration_toolset.md)
- [AIC planning and migration](https://docs.pingidentity.com/pingoneaic/planning/plan-identity-cloud.md)
