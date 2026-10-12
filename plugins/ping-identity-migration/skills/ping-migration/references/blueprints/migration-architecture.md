# Migration Orchestrator Architecture and Canonical Item Model

How the bundled migration orchestrator separates source knowledge from destination knowledge, and the canonical item shape that crosses the seam between them.

## Scope

Covers:
- The pipeline stages and which module owns each
- The canonical item model that every source adapter must emit
- The adapter interfaces a source and a destination must implement
- Why the classifier is the single seam, and what that guarantees when adding an adapter

Does NOT cover:
- Flag reference and invocation syntax — see `../playbooks/run-migration.md`
- The classification decision rules themselves — see `../catalogs/classification-rules.md`
- P14E field-level mapping — see `../catalogs/p14e-admin-api-mapping.md`

---

## Pipeline

```
SOURCE                    src.extract(args, workDir)
  PingFederate            live mode: the source's own admin API
  P14E
        │
        │  canonical items[]  { id, type: oidc|saml|atm|key|idp }
        ▼
CLASSIFICATION            classifier.rationalize(items, dest.caps())
        │                 each item judged against THIS destination's caps:
        │                   DIRECT         migrated this run
        │                   REDESIGN       needs manual rework first
        │                   OUT-OF-SCOPE   not migrated, logged with reason
        │
        ├── direct only ──────────────► MIGRATION
        │                                 dest.transform(item)   → API payload
        │                                 dest.apply(payload)    → creates resource
        │                                 dest.validate(id, item) → reads back, checks
        │                                          │
        └── all three ────────────────► REPORTS ◄──┘
                                          assessment-report.md   always, even --dry-run
                                          migration-report.md    full runs only
                                                   │
                                                   ▼
                                        ROLLBACK  rollback.js
                                          parses migration-report.md
                                          → DELETE each resource by type
```

Everything above the classifier is source-aware only; everything below is destination-aware only.

## Module ownership

| Concern | Module | Rule |
|---|---|---|
| Source extraction | One file per source under `scripts/adapters/sources/` | Knows one source's API and native file format. Knows nothing about any destination. |
| Classification | `scripts/classifier.js` | The only place classification logic lives. Reads declared `caps()`, never calls an API. |
| Destination payloads and writes | One file per destination under `scripts/adapters/destinations/` | Knows one destination's API. Knows nothing about any source. |
| Reports | `scripts/reports.js` | Writes both reports. The migration report is rollback's only input. |
| Rollback | `scripts/rollback.js` | Report-driven — no dependency on the source system at all. |
| Orchestration | `scripts/ping-migration.js` | Loads adapters by name, calls a fixed interface, sequences the run. |

## Canonical item model

Every source adapter emits items in this shape. It is the contract that makes sources and destinations independently swappable.

```js
{
  id,                  // stable source identifier
  name,                // human-readable
  type,                // 'oidc' | 'saml' | 'atm' | 'key' | 'idp'
  enabled,             // boolean — source-side enablement
  classification,      // set by the classifier, not the source adapter
  skipReason,          // set by the classifier when out-of-scope
  concerns,            // array of advisory notes surfaced into reports
  capabilities: { },   // type-specific — see table below
  source               // raw source record, opaque to everything downstream
}
```

### Type-specific `capabilities`

| `type` | Key fields |
|---|---|
| `oidc` | `grantTypes` (uppercase), `redirectUris`, `postLogoutUris`, `scopes`, `pkce`, `tokenEndpointAuthMethod` |
| `saml` | `acsUrls`, `entityId`, `nameIdFormat`, `signAssertions`, `signResponse`, `protocol` |
| `atm` | token lifetime, attribute contract |
| `key` | key algorithm and metadata — private key material is never exportable |
| `idp` | SSO endpoints, protocol, binding |

Grant types are normalised to uppercase by every source adapter because `classifier.js`'s `GRANT_MAP` keys are uppercase. A source whose API returns lowercase values (P14E does) must uppercase them during normalisation.

## Adapter interfaces

A source adapter exports:

| Method | Returns |
|---|---|
| `extract(args, workDir)` | Array of canonical items. Handles both live and `--import-file` paths. |

A destination adapter exports:

| Method | Returns |
|---|---|
| `caps()` | Declared destination capabilities the classifier judges items against |
| `transform(item)` | Destination API payload for one canonical item |
| `apply(payload, ctx)` | Creates or updates the resource; records `{ id, status }` |
| `validate(id, item, ctx)` | Reads the resource back and checks invariants |

Adapters that throw `Error('not yet implemented')` have the correct interface but no behaviour — they exist so the architecture is complete and each can be filled in independently.

## Adding an adapter

Adding a source requires implementing `extract()` and emitting canonical items. Adding a destination requires implementing `caps()`, `transform()`, `apply()`, and `validate()`. Neither requires touching the other side, the classifier, or the report and rollback logic — that isolation is the reason the canonical model exists.

Register the new adapter in the `SOURCES` or `DESTINATIONS` map at the top of `scripts/ping-migration.js`.

## Prerequisites

- Node.js 18+
- `pingcli` on `$PATH` and authenticated at least once, when the source or destination is PingOne or PingFederate

## Common variants

| Variant | Effect |
|---|---|
| `--import-file` (file mode) | Source adapter reads a native export instead of calling the source API; no source credentials needed |
| `--dry-run` | Pipeline stops after classification and the assessment report; destinations are never called |
| `--import-file` + `--dry-run` | Neither source nor destination credentials are required |

## Related references

- `../playbooks/run-migration.md`
- `../catalogs/classification-rules.md`
- `../catalogs/p14e-admin-api-mapping.md`

## Source

- [PingOne Cloud Acceleration Toolset](https://docs.pingidentity.com/pingone/migration-tools/p1_cloud_acceleration_toolset.md)
- Bundled orchestrator: `scripts/ping-migration.js`
