# Migration Classification Rules and Grant Type Mapping

The rules `classifier.js` applies to decide whether each extracted item migrates directly, needs redesign first, or is out of scope — and how PingFederate grant types map to PingOne.

## Scope

Covers:
- Per-type classification rules for OIDC clients, SAML SP connections, ATMs, signing keys, and IdP connections
- The three classification outcomes and what each means for the run
- PingFederate → PingOne grant type mapping, including dropped grants

Does NOT cover:
- Why a specific PingFederate entity type is in or out of automated scope — see `../blueprints/pingfederate-migration-inventory.md`
- Wave sequencing and governance sign-off on dropped grants — see `../playbooks/assessment-and-wave-planning.md`
- P14E-specific field availability that affects classification inputs — see `./p14e-admin-api-mapping.md`

---

## The three outcomes

| Outcome | Meaning | Applied this run |
|---|---|---|
| `direct` | Maps cleanly onto the destination's declared capabilities | Yes |
| `redesign` | Requires manual rework — usually client code changes — before it can migrate | No; listed in reports |
| `out-of-scope` | No destination equivalent, or disabled at the source | No; listed with `skipReason` |

`redesign` and `out-of-scope` items are never applied. They appear in the assessment report so they can be planned, not silently dropped.

## OIDC clients

| Category | Condition |
|---|---|
| Direct migrate | Enabled, and has at least one mappable grant type after removing `IMPLICIT` and `ACCESS_TOKEN_VALIDATION` |
| Redesign | Grant list is exclusively `IMPLICIT` — requires client code changes to adopt PKCE |
| Out-of-scope | Disabled, or only `ACCESS_TOKEN_VALIDATION` (no destination equivalent), or no mappable grants |

An enabled client with `AUTHORIZATION_CODE` plus `IMPLICIT` migrates directly — `IMPLICIT` is dropped and the remaining grant carries it. Only an `IMPLICIT`-only client is a redesign case.

## SAML SP connections

| Category | Condition |
|---|---|
| Direct migrate | Active, SAML20 protocol, and at least one absolute ACS URL |
| Out-of-scope | Disabled, non-SAML protocol, or ACS URL missing or relative |

A relative ACS URL is out of scope because the destination requires an absolute URL and the correct host cannot be inferred.

## Token managers (ATM)

| Category | Condition |
|---|---|
| Direct migrate | All ATMs — each maps to a PingOne resource with an equivalent token lifetime |

Custom attribute-contract scopes on an ATM are not created automatically; see the manual follow-up list in `../playbooks/post-migration-and-rollback.md`.

## Signing key pairs

| Category | Condition |
|---|---|
| Direct migrate | All signing key pairs |

New keys are provisioned at the destination because PingFederate private keys cannot be exported. Every relying party's trust store must be updated with the new destination certificate — this is the highest-impact manual follow-up in a migration.

## External IdP connections (`sp/idpConnections`)

| Category | Condition |
|---|---|
| Direct migrate | Active, SAML protocol, and at least one SSO endpoint |
| Out-of-scope | Disabled, WS-Trust, or non-SAML protocol |

## Grant type mapping — PingFederate to PingOne

| PingFederate | PingOne | Note |
|---|---|---|
| `AUTHORIZATION_CODE` | `AUTHORIZATION_CODE` | PKCE S256 enforced automatically at the destination |
| `CLIENT_CREDENTIALS` | `CLIENT_CREDENTIALS` | |
| `REFRESH_TOKEN` | `REFRESH_TOKEN` | |
| `CIBA` | `CIBA` | |
| `DEVICE_CODE` | `DEVICE_CODE` | |
| `IMPLICIT` | dropped | Deprecated per RFC 6749 |
| `ACCESS_TOKEN_VALIDATION` | dropped | No PingOne equivalent |

Both dropped grants are governance decisions, not silent behaviour: confirm with app owners before executing a wave. Clients relying on `AUTHORIZATION_CODE` must send `code_challenge` after migration because S256 is enforced.

## Prerequisites

- A completed extraction — run with `--dry-run` to classify without applying
- The destination adapter's `caps()` determine the judgement, so classification is destination-specific; the same source items can classify differently against a different destination

## Common variants

| Variant | Effect on classification |
|---|---|
| Different `--destination` | Items are re-judged against that destination's `caps()`; outcomes can change |
| Source app disabled | Always `out-of-scope`, regardless of grant configuration |
| `--enable-apps` | Affects how applications are created at the destination, not classification |

## Related references

- `../blueprints/migration-architecture.md`
- `../playbooks/assessment-and-wave-planning.md`
- `../blueprints/pingfederate-migration-inventory.md`

## Source

- [OAuth 2.0 grant types in PingOne](https://docs.pingidentity.com/pingone/applications/p1_grant_types.md)
- Bundled classifier: `scripts/classifier.js`
