# Run a Migration

Every flag, supported source and destination, run sequence, output file, and exit code for the bundled orchestrator `scripts/ping-migration.js` — the step-by-step guide for executing a migration run.

## Scope

Covers:
- Complete flag reference with defaults and conditional requirements
- Supported sources and destinations with extraction and apply mechanisms
- The run sequence step by step
- Output payload files and auto-generated report paths
- Exit codes

Does NOT cover:
- Classification decision rules — see `../catalogs/classification-rules.md`
- Rollback and secret rotation — see `./post-migration-and-rollback.md`
- Adapter internals and the canonical model — see `../blueprints/migration-architecture.md`

---

## Invocation

Offline — classify a pre-exported source file with no live source connection:

```bash
node scripts/ping-migration.js \
  --source          pingfederate \
  --destination     pingone \
  --import-file     ./pf-exports/bulk-063026.json \
  --dest-env-id     <pingone-environment-uuid> \
  --dest-client-id  <worker-app-client-id> \
  --dest-client-secret <worker-app-client-secret> \
  [--dry-run]
```

## Unattended execution

This playbook is written for an agent running without a user present. The rules that keep a run headless:

- **Always pass `--dest-env-name` on a live PingFederate run.** Without it, environment creation prompts on stdin for a name and an unattended run hangs. (File-mode and `--skip-env-create` runs never prompt.)
- Prefer file mode (`--import-file`) for assessment: it needs no source credentials and, with `--dry-run`, no destination credentials either.
- `--use-profile` skips the profile configure and auth steps entirely — the non-interactive choice when an authenticated profile already exists.
- Nothing else in the orchestrator, rollback, or secret scripts reads stdin; secrets arrive via `PINGONE_CLIENT_SECRET`, never a flag.

Live — connect to PingFederate and migrate to PingOne:

```bash
node scripts/ping-migration.js \
  --source          pingfederate \
  --destination     pingone \
  --pf-host         https://pf-admin.example.com:9999 \
  --pf-user         <admin-username> \
  --pf-pass         <admin-password> \
  --dest-env-id     <pingone-environment-uuid> \
  --dest-client-id  <worker-app-client-id> \
  --dest-client-secret <worker-app-client-secret> \
  [--dest-region    pingone.com] \
  [--use-profile    migration-run] \
  [--dest-env-name  "Migration wave 1"] \
  [--skip-env-create] \
  [--work-dir       ./migration-output] \
  [--insecure-pf] \
  [--dry-run]
```

Always run `--dry-run` first.

## Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--source` | Yes | — | Source system name |
| `--destination` | Yes | — | Destination system name |
| `--import-file` | No | — | Path to a pre-exported source-native file. Skips live source steps. With `--dry-run`, no destination credentials are required. |
| `--dest-env-id` | Conditional | — | Destination environment ID. Not required with `--import-file --dry-run` for PingOne. |
| `--dest-client-id` | Conditional | — | Destination worker app client ID. Not required with `--import-file --dry-run`. |
| `--dest-client-secret` | Conditional | — | Destination worker app client secret. Not required with `--import-file --dry-run`. |
| `--dest-region` | No | `pingone.com` | PingOne region root domain (`pingone.eu`, `pingone.ca`, `pingone.asia`) |
| `--dest-auth-env-id` | No | — | Environment where the worker app lives, when different from `--dest-env-id` |
| `--dest-env-name` | No | prompted | Name for a newly created destination environment |
| `--use-profile` | No | — | Use an existing configured `pingcli` profile as-is; skips configure and auth steps |
| `--skip-env-create` | No | `false` | Migrate into the existing `--dest-env-id` instead of creating an environment |
| `--work-dir` | No | `./migration-output` | Directory for exported and generated payload files |
| `--enable-apps` | No | `false` | Create applications as enabled |
| `--insecure-pf` | No | `false` | Skip TLS verification against PingFederate (development and self-signed certificates) |
| `--pf-host` | Conditional | — | PingFederate admin HTTPS host. Required when `--source pingfederate` and no `--import-file`. |
| `--pf-user` | Conditional | — | PingFederate admin username |
| `--pf-pass` | Conditional | — | PingFederate admin password |
| `--p14e-url` | No | `https://admin-api.pingone.com/v3` | P14E admin API base URL, used as-is |
| `--p14e-username` | Conditional | — | P14E admin username. Required when `--source p14e` and no `--import-file`. |
| `--p14e-password` | Conditional | — | P14E admin password |
| `--p14e-cloud-migration-key` | No | — | Key to decrypt exported certificate PKCS12 bundles. Without it, certificates export with metadata only. |
| `--dry-run` | No | `false` | Extract and classify only — nothing is applied to the destination |

## Sources

| `--source` | System | Live extraction | File mode format |
|---|---|---|---|
| `pingfederate` | PingFederate 10–13 | Bulk export API (`/bulk/export`) | PF bulk export JSON |
| `p14e` | PingOne for Enterprise | Admin API (`/applications/instances/idp/{accountId}`) | P14E export JSON (`applications` / `metadata` / `accountCertificates`) |

## Destinations

| `--destination` | System | Apply mechanism |
|---|---|---|
| `pingone` | PingOne, all regions | `pingcli pingone applications apply` |

## Run sequence

| Step | Action |
|---|---|
| 1 | Load the source adapter for `--source` and the destination adapter for `--destination` |
| 2 | `src.extract(args, workDir)` → canonical item array, live or from `--import-file` |
| 2a | PingFederate source only: configure the `pingcli` profile, authenticate, create the environment or skip, export or load the bulk file |
| 3 | `classifier.rationalize(items, dest.caps())` → each item classified direct, redesign, or out-of-scope |
| 4 | Write the assessment report — always, including `--dry-run` |
| 5 | If `--dry-run`: exit here |
| 6 | For each `direct` item: `dest.transform(item)` → API payload |
| 7 | `dest.apply(payload, ctx)` → create or update the resource, record `{ id, status }` |
| 8 | `dest.validate(id, item, ctx)` → read back and check invariants |
| 9 | Write the migration report |
| 10 | Exit 0 if all validations passed, 1 if any failed |

## Output payload files

Written to `--work-dir`.

| File pattern | Contents |
|---|---|
| `pf-bulk-export.json` | Full PingFederate bulk export, all resource types |
| `po-app-<clientId>.json` | PingOne OIDC application payload |
| `grant-<clientId>.json` | PingOne resource grant payload |
| `po-saml-<spId>.json` | PingOne SAML application payload |
| `po-atm-<id>.json` | PingOne resource payload for a token manager (ATM) |
| `po-key-<slug>.json` | PingOne signing key payload |
| `po-idpconn-<slug>.json` | PingOne identity provider payload |
| `meta-oidc-<clientId>.json` | OIDC migration metadata sidecar |
| `meta-saml-<name>.json` | SAML migration metadata sidecar |
| `meta-atm-<slug>.json` | ATM migration metadata sidecar |

Sidecar `meta-*.json` files carry per-item concerns worth folding into a risk register.

## Reports

| Report | Path | Written when |
|---|---|---|
| Assessment | `./migration-reports/<env-slug>-assessment-report-YYYY-MM-DD.md` | After classification — always, including `--dry-run` |
| Migration | `./migration-reports/<env-slug>-migration-report-YYYY-MM-DD.md` | After validation — full runs only |

If a report for today already exists, a sequence suffix is appended (`-2`, `-3`, …). The migration report is rollback's only input — preserve it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All items applied and validated, or `--dry-run` completed |
| `1` | One or more items failed validation |

## Prerequisites

- Node.js 18+
- `pingcli` on `$PATH` and authenticated at least once so `~/.pingcli/config.yaml` exists — required only when the source or destination is PingOne or PingFederate
- A destination worker application with sufficient roles. Environment creation requires organisation-admin scope; without it, use `--skip-env-create` against an existing environment.

## Common variants

| Goal | Flags |
|---|---|
| Classify with no credentials at all | `--import-file` + `--dry-run` |
| Migrate into an existing environment | `--skip-env-create --dest-env-id <uuid>` |
| Reuse an already-authenticated CLI profile | `--use-profile <name>` |
| Worker app lives in a different environment | `--dest-auth-env-id <uuid>` |
| Non-US region | `--dest-region pingone.eu` |
| Development PingFederate with a self-signed certificate | `--insecure-pf` |

## Related references

- `../catalogs/classification-rules.md`
- `./assessment-and-wave-planning.md`
- `./post-migration-and-rollback.md`

## Source

- [PingOne Cloud Acceleration Toolset](https://docs.pingidentity.com/pingone/migration-tools/p1_cloud_acceleration_toolset.md)
- Bundled orchestrator: `scripts/ping-migration.js`
