# PingOne for Enterprise Admin API and Canonical Field Mapping

The PingOne for Enterprise (P14E) admin API as consumed by `scripts/adapters/sources/p14e-adapter.js`: authentication flow, the endpoints the adapter reads, and how each field maps into the canonical migration model.

## Scope

Covers:
- The four-step P14E authentication flow and its cleanup step
- Every endpoint the adapter calls, with confirmed query parameters and response envelope
- Field-by-field mapping into the canonical model, marked verified or unverified
- Which canonical fields are always empty for a P14E source, and why

Does NOT cover:
- The canonical model definition itself — see `../blueprints/migration-architecture.md`
- Classification behaviour — see `./classification-rules.md`
- PingOne as a destination; this file describes P14E as a source only

---

## Contents

- Ground truth and verification method
- Authentication flow
- Endpoints
- Canonical field mapping — OIDC, SAML, certificates
- Always-empty canonical fields
- Endpoints reachable but not used

## Ground truth

Three sources back every statement below:

| Source | What it establishes |
|---|---|
| `https://admin-api.pingone.com/v3-beta/admin/swagger.json` | Current wire shape — Swagger 2.0, 255 paths. The spec JSON is fetchable without auth. |
| A live export from a production tenant | Confirms field names and value casing against real data |
| `p14e-adapter.js` | The adapter this file documents |

Rows marked **Verified** match both the spec and live data. Rows marked **Unverified** describe adapter code paths that no spec field or live response confirms.

P14E is an app-catalog and SSO-portal product. It has no user-creation or user-management write API — read-only service users and directory-synced groups are the closest available resources.

## Authentication flow

P14E accounts do not ship with a persistent API client capable of calling the admin API. Basic auth against an admin's credentials can only bootstrap a temporary one, so the adapter mints a short-lived scoped credential, uses it once, and discards it.

| Step | Request | Purpose |
|---|---|---|
| 1 | `GET /accounts/whoami` with Basic auth | Returns `IamDto`; `accountId` is threaded through every later call. Non-200 means invalid credentials. |
| 2 | `POST /clients/{accountId}/jwt` with Basic auth, form-encoded | Creates a temporary JWT client. Response carries `id` and `jwtPrivateKey` (a JWK). |
| 3 | `POST /as/token.oauth2/jwt` with Basic auth | Signs a JWT grant. `grantLifespanSeconds` and `tokenLifespanSeconds` both cap at 3600; the adapter uses the maximum. Returns `jwtGrant`. |
| 4 | `POST /as/token.oauth2` with `grant_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` | Exchanges the grant for `access_token`, used as `Authorization: Bearer` for the rest of the session |
| Cleanup | `DELETE` on `/clients/refs/{clientId}/jwt` with Bearer auth | Always called in a `finally` block so the temporary client is not left behind. Cleanup failure and export failure are reported independently. |

The private key in step 2 is returned only at creation time, which is why the adapter captures it immediately rather than re-reading the client.

Scopes requested (`JWT_CLIENT_SCOPES`): `ADD_CONNECTIONS_TO_SERVICE_PROVIDERS`, `CERTIFICATE_MANAGEMENT`, `IDENTITY_BRIDGE`, `IDENTITY_PROVIDER`, `READ_CUSTOMER`, `GROUP_MANAGEMENT`, `MANAGE_ADMIN_API_CLIENT`, `PINGID_CONFIGURATION_READ_ONLY`. All eight appear in the `v3-beta` spec's per-endpoint `security` blocks.

Step 2 posts a `name` form field; the spec documents `client_name`. Live testing returns 201 with a usable client either way. Re-test against live P14E before changing this.

## Endpoints

The adapter's `getResults(baseUrl, accessToken, apiPath)` helper implements one paging pattern for all data fetches, expecting `{ results, nextPageRef, start, limit, count }` with items either inline or as `{ ref }` stubs requiring a follow-up fetch. Any non-200 response ends paging and yields no results.

| Endpoint | Status | Notes |
|---|---|---|
| `GET /applications/instances/idp/{accountId}` | Verified | `operationId: getIdpAccountConnectionInstances`. Query params: `filter`, `type` (`OIDC_SSO`, `SAML20_SSO`, and six others), `start`, `limit` (max 100), `order`. The adapter passes no filters and classifies OIDC vs SAML from the `templateRef` suffix. Passing `type` explicitly would reduce the fetch volume. |
| `GET /accounts/{accountId}/certificates` | Verified | `operationId: getAllCertificatesForAccount`, scope `CERTIFICATE_MANAGEMENT`. Query params: `filter` by usage (`SIGNING`, `VERIFICATION`, `ENCRYPTION`, `DEFAULTSIGNING`), `start`, `limit` (max 2000), `sortKey`, `order`. Items match `CertificateDetailsDto`. |
| `GET /metadata/{accountId}` | Unverified | The spec's metadata path is `/metadata/{instanceId}` — SAML 2.0 IdP metadata XML for one connection instance, not an account-wide list. A live run returned zero metadata records for a tenant with active SAML apps, consistent with an account ID being passed where an instance ID is expected. Reading per-instance metadata would mean calling this once per SAML connection instance using each item's own `id`. |
| `POST /accounts/{accountId}/certificates/{certId}` (PKCS12) | Unverified | Used when `--p14e-cloud-migration-key` is supplied. The documented certificate download endpoint is `GET /accounts/{accountId}/certificates/{certId}/pem`. This path was not exercised in the live run that produced the reference export. |

`raw.metadata` is written to the export file but `normalizeToCanonical()` reads only `raw.applications` and `raw.accountCertificates`, so metadata does not currently reach the canonical model.

Note that `CertificateDetailsDto` (with `subjectDN`, `issuerDN`, and top-level `keyAlgorithm`) is the shape live data returns. A similarly named `CertificateOutputDto` exists with `subjectDn`, `issuerDn`, and a nested `key.algorithm` — that shape does not match this endpoint's live responses.

## Protocol detection

```js
const suffix = (templateRef || '').split('/').pop();
if (suffix === 'oidc')   return 'oidc';
if (suffix === 'saml20') return 'saml';
```

**Verified.** `templateRef` is a documented field on every `*ConnectionInstanceOutputDto`. SAML 1.1 connections exist in P14E (`Saml11*` DTOs) but `saml11` is not recognised here, so those items fall through to the unknown-protocol branch, are logged, and are dropped.

## OIDC mapping — `normalizeOidc()`

Source schema: `OidcConnectionInstanceOutputDto`.

| Canonical field | P14E field | Status |
|---|---|---|
| `id` | `app.id`, falling back to `app.name` | Verified |
| `name` | `app.name` | Verified |
| `enabled` | `app.state === 'ENABLED'` | Verified — `state` is an enum of exactly `ENABLED` and `DISABLED`; the `app.enabled` fallback is unreachable for this source |
| `capabilities.grantTypes` | `app.grantTypes` uppercased | Verified — live values are lowercase snake_case (`authorization_code`, `client_credentials`, `refresh_token`, `implicit`). Uppercasing is required because `classifier.js`'s `GRANT_MAP` keys are uppercase. |
| `capabilities.redirectUris` | `app.redirectUris` | Verified — required array |
| `capabilities.scopes` | `app.scopes ?? []` | Verified |
| `capabilities.postLogoutUris` | `app.postLogoutRedirectUris ?? []` | Unverified — the real field is `logoutUrl`, a single nullable string |
| `capabilities.pkce` | `Boolean(app.pkceEnforced)` | Unverified — no PKCE field exists in the P14E admin API |
| `capabilities.tokenEndpointAuthMethod` | `app.clientAuth?.type ?? null` | Unverified — no `clientAuth` object; the closest real field is `clientSecrets: string[]` |

## SAML mapping — `normalizeSaml()`

Source schema: `Saml20ConnectionInstanceOutputDto`.

| Canonical field | P14E field | Status |
|---|---|---|
| `id` | `app.id`, falling back to `app.name` | Verified |
| `name` | `app.name` | Verified |
| `enabled` | `app.state === 'ENABLED'` | Verified |
| `capabilities.acsUrls` | `[app.acsUrl].filter(Boolean)` | Verified — `acsUrl` is a single required string and the only ACS field that exists. This resolves the candidate-key uncertainty noted in the adapter's own header comment. |
| `capabilities.entityId` | `app.spEntityId ?? app.entityId` | Verified — `spEntityId` is the real field; the `entityId` fallback is unreachable |
| `capabilities.protocol` | Hardcoded `'SAML2.0'` | Verified — matches the `saml20` template suffix |
| `capabilities.signResponse` | `app.signResponse`, falling back to `Boolean(app.signingCertId)` | Partially verified — `signResponse` does not exist, so the fallback always decides. `signingCertId` is real and required; inferring a signed response from a configured signing certificate is a heuristic, not a read field. |
| `capabilities.nameIdFormat` | `app.nameIdFormat ?? null` | Unverified — no NameID field in the SAML DTO |
| `capabilities.signAssertions` | `Boolean(app.signAssertions)` | Unverified — no such field |

## Certificate mapping — `normalizeKey()`

Source: `accountCertificates[]`, schema `CertificateDetailsDto`. `subjectDN`, `issuerDN`, `validFrom`, `expires`, `keyAlgorithm`, `keySize`, `signatureAlgorithm`, and the `status` enum are all verified field-for-field against live data.

Without `--p14e-cloud-migration-key`, certificates export with metadata only and no private key material.

## Always-empty canonical fields

For a P14E source, these canonical fields always carry their default value because the field being read does not exist: `postLogoutUris` (`[]`), `pkce` (`false`), `tokenEndpointAuthMethod` (`null`), `nameIdFormat` (`null`), `signAssertions` (`false`).

None affect classification today — the OIDC rules inspect only `grantTypes` and `enabled`, and the SAML rules inspect ACS URL, protocol, and `enabled`. If the classifier is ever extended to gate on PKCE enforcement or post-logout URIs, every P14E-sourced item will fail that gate. Check this list first when a P14E-sourced field comes back empty.

## Endpoints reachable but not used

| Endpoint | Returns | Why not used |
|---|---|---|
| `GET /groups/{accountId}` | Directory-synced groups with `provisioningId` | Adapter comment cites timeouts on tenants with more than 4,000 groups |
| `GET /groups/refs/{id}` | Single group detail | Same |
| `GET /categories/{accountId}` | Application categories | Not part of the canonical model; apps carry `category` inline |
| `GET /identitybridges/{accountId}/types` | Available identity-bridge types | Bridge configuration is out of scope for a one-way export |

## Prerequisites

- `--p14e-username` and `--p14e-password` for live extraction, or `--import-file` with a P14E export
- `--p14e-url` when the tenant is not on the default `https://admin-api.pingone.com/v3`
- `--p14e-cloud-migration-key` when certificate private key material is needed

## Common variants

| Situation | Approach |
|---|---|
| Field came back empty after a P14E migration | Check the always-empty list above before investigating the adapter |
| Extending the adapter to read more P14E data | Confirm the endpoint exists in the `v3-beta` spec, then verify the response shape against a live tenant |
| SAML 1.1 apps in the estate | They are dropped as unknown protocol; migrate manually or extend `protocolFromTemplateRef()` |
| Native export shape | `{ applications: [], metadata: [], accountCertificates: [] }` |

## Related references

- `../blueprints/migration-architecture.md`
- `./classification-rules.md`
- `../playbooks/run-migration.md`

## Source

- [P14E admin API reference](https://admin-api.pingone.com/v3-beta/api-docs/)
- Bundled adapter: `scripts/adapters/sources/p14e-adapter.js`
