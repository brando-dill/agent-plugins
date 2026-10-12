# PingFederate Migration Inventory and Auth Policy Topology

Which PingFederate entities an automated migration run covers, which need redesign, and how PingFederate's authentication policy and OIDC policy topology translates to PingOne.

## Scope

Covers:
- Entity-by-entity migration path, complexity, and PingOne target for a PingFederate source
- The authentication infrastructure analysis the assessment report derives from a bulk export
- Why PingFederate OIDC policies have no direct PingOne equivalent and what to do instead

Does NOT cover:
- The classifier's per-item decision rules — see `../catalogs/classification-rules.md`
- Wave sequencing and governance — see `../playbooks/assessment-and-wave-planning.md`
- Building the replacement policies in PingOne — the PingOne admin console and the Cloud Acceleration Toolset documentation

---

## Entity inventory

Automated runs cover the `Direct` rows only. Everything else is planning input, not execution scope.

| PingFederate entity | Migration path | Complexity | PingOne target |
|---|---|---|---|
| OAuth clients | Direct | Low | Applications (OIDC) |
| SAML SP connections | Direct | Low | Applications (SAML) |
| OAuth resources and scopes | Direct | Low | Resources and resource scopes |
| Authentication policies and rules | Direct | Medium | Sign-on policies and authentication policies |
| User directories (LDAP, database, AD) | Direct | Medium | Populations and directory connections |
| Signing and encryption certificates | Direct | Medium | Application signing and encryption certificates |
| Attribute contracts and mappings | Direct | Medium | Claim and attribute mappings |
| Password policies | Redesign | Medium | Password policy — semantics differ |
| Consent management | Redesign | High | Consent configuration or bypass settings |
| Session policies | Redesign | Medium | Session policies |
| MFA and step-up authentication | Redesign | High | MFA policies and MFA devices |
| Custom adapters and plugins | Out-of-scope | High | Custom integration or DaVinci flows |
| Notification adapters | Out-of-scope | High | Webhooks or notification services |

`Direct` in this table means "has a clean PingOne target," which is broader than what the bundled orchestrator applies today. The orchestrator covers OAuth clients, SAML SP connections, token managers (ATM), signing keys, and IdP connections; the remaining `Direct` rows are straightforward but manual.

## Authentication infrastructure analysis

With `--source pingfederate`, the assessment report derives these sections automatically from the bulk export:

| Section | Contents |
|---|---|
| IDP adapters | All adapters with plugin type |
| Authentication Policy Contracts | All APCs with extended attribute lists |
| Authentication policy fragments | Fragment to root adapter or reference, and output APC |
| Default policy trees | Each selection tree: selector, branch context values, and fragment targets |
| OIDC policies | ID token lifetime, ATM binding, extended attributes, and which clients consume each policy |
| Data stores | Type, role, password credential validator, and Local Identity Profile dependencies |
| Migration implications | Notes derived from the authentication policy topology |

This analysis is what makes the policy layer plannable — the entity counts alone do not reveal which clients depend on which adapter chain.

## OIDC policies have no PingOne equivalent

PingFederate's `oauth/openIdConnect/policies` which define the ID token contract for OIDC flows.

PingOne has no shared OIDC policy object. The attribute contract and ATM binding must be re-created as per-application claim mappings on each OIDC application. Two consequences for planning:

- Identify which clients use a non-default policy — those need their attribute mappings and issuance criteria replicated individually
- Clients on the server default can share one mapping pattern, so they batch well into a single wave

## Data store dependencies

Data stores carry a role (identity store, password credential validator backing, attribute source) and may be referenced by Local Identity Profiles. Map each to a PingOne population or directory connection before migrating apps that depend on attribute lookups — an app that migrates cleanly can still fail at runtime if its attribute source does not exist at the destination.

## Prerequisites

- A PingFederate bulk export, either live via the bulk export API or a saved `--import-file`
- PingFederate 10–13; the bulk export shape is what the adapter reads

## Common variants

| Situation | Approach |
|---|---|
| Bulk export unavailable | Request a saved export and run in file mode with `--import-file` |
| Development PingFederate with a self-signed certificate | Add `--insecure-pf` for live extraction |
| Estate spans multiple PingFederate instances | Assess and migrate each instance separately; entity ids are not unique across instances |

## Related references

- `../catalogs/classification-rules.md`
- `../playbooks/assessment-and-wave-planning.md`
- `../playbooks/run-migration.md`

## Source

- [PingOne Cloud Acceleration Toolset](https://docs.pingidentity.com/pingone/migration-tools/p1_cloud_acceleration_toolset.md)
- Bundled adapter: `scripts/adapters/sources/pf-adapter.js`
