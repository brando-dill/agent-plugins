'use strict';

/**
 * pingone-adapter.js
 *
 * PingOne destination adapter for the hub-and-spoke ping-migration skill.
 *
 * Exposes:
 *   caps()              – declares what PingOne natively supports
 *   transform(item)     – converts a canonical item to a PingOne API payload object
 *   apply(payload, ctx) – calls pingcli to create the resource; returns { id, status }
 *   validate(id, item, ctx) – reads the resource back and checks it; returns { pass, details }
 *
 * Also exports lower-level helpers that ping-migration.js calls directly for the
 * full pipeline (metadata write, grants, summary output, etc.):
 *   buildOidcPayload()        – OIDC payload builder
 *   buildSamlPayload()        – SAML payload builder
 *   buildAtmPayload()         – ATM payload builder
 *   buildSigningKeyPayload()  – signing key payload builder
 *   buildIdpConnPayload()     – external IdP connection payload builder
 *   applyApps()               – batch OIDC apply
 *   applySamlApps()           – batch SAML apply
 *   applyAtms()               – batch ATM apply
 *   applySigningKeys()        – batch signing key apply
 *   applyIdpConnections()     – batch IdP connection apply
 *   writeAppMetadata()        – Step 7f metadata write
 *   createGrants()            – Step 8 resource grant creation
 *   validate() (exported)     – Step 9 validation
 *   printSummary()            – final console summary
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STANDARD_OIDC_SCOPES = new Set(['openid', 'profile', 'email', 'phone', 'address', 'offline_access']);

const SAML_NAMEID_MAP = {
  STANDARD:           'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  EMAIL:              'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  TRANSIENT:          'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  PERSISTENT:         'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  X509_SUBJECT_NAME:  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
};

const GRANT_MAP = {
  AUTHORIZATION_CODE:     'AUTHORIZATION_CODE',
  CLIENT_CREDENTIALS:     'CLIENT_CREDENTIALS',
  IMPLICIT:               null,
  REFRESH_TOKEN:          'REFRESH_TOKEN',
  CIBA:                   'CIBA',
  ACCESS_TOKEN_VALIDATION: null,
  DEVICE_CODE:            'DEVICE_CODE',
};

const CERT_DEFAULTS = {
  algorithm: 'RSA',
  keyLength: 3072,
  signatureAlgorithm: 'SHA256withRSA',
  validityPeriod: 365,
};

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------

const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const BLUE   = '\x1b[34m';
const BOLD   = '\x1b[1m';
const RESET  = '\x1b[0m';

const ok      = (msg) => console.log(`  ${GREEN}✔${RESET}  ${msg}`);
const fail    = (msg) => console.log(`  ${RED}✖${RESET}  ${msg}`);
const info    = (msg) => console.log(`  ${BLUE}→${RESET}  ${msg}`);
const section = (msg) => console.log(`\n${BOLD}${msg}${RESET}`);

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

function run(args, { check = true } = {}) {
  try {
    const stdout = execFileSync(args[0], args.slice(1), { encoding: 'utf8' });
    try {
      return JSON.parse(stdout);
    } catch {
      return { raw: stdout };
    }
  } catch (err) {
    const stderr = err.stderr?.toString() ?? '';
    let data;
    try { data = JSON.parse(err.stdout?.toString() ?? ''); } catch { data = {}; }
    if (check) {
      const errors = data.errors ?? [];
      const msg = errors[0]?.message ?? stderr ?? err.message;
      throw new Error(`Command failed: ${args.join(' ')}\n${msg}`);
    }
    return data;
  }
}

function pingcli(args, { profile, outputFormat = 'json' } = {}) {
  const cmd = ['pingcli'];
  if (profile) cmd.push('--profile', profile);
  cmd.push('--output-format', outputFormat);
  return run([...cmd, ...args]);
}

// ---------------------------------------------------------------------------
// Sanitizers
// ---------------------------------------------------------------------------

function sanitizeDescription(text) {
  return (text ?? '').replace(/[`$+<=>^|~]/g, '');
}

function sanitizeName(text) {
  return (text ?? '').replace(/[^\p{L}\p{M}\p{N} /.'_-]/gu, ' ').replace(/\s+/g, ' ').trim();
}

function slugify(name) {
  return (name ?? 'unknown')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// ---------------------------------------------------------------------------
// caps() — what PingOne supports
// ---------------------------------------------------------------------------

function caps() {
  return {
    grantTypes: ['AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS', 'REFRESH_TOKEN', 'CIBA', 'DEVICE_CODE'],
    pkceEnforced: true,
    saml: true,
    atm: true,
    signingKeys: true,
  };
}

// ---------------------------------------------------------------------------
// buildOidcPayload — OIDC
// ---------------------------------------------------------------------------

function buildOidcPayload(c, poGrants, enableApps, canonicalName) {
  const cid = c.clientId ?? c.id ?? c.name;
  const hasAuthCode = poGrants.includes('AUTHORIZATION_CODE');
  const rawRedirectUris = c.redirectUris ?? [];
  const redirectUris = rawRedirectUris.filter(u => {
    if (u.includes('*')) return false;
    if (u.startsWith('http://') && !/localhost|127\.0\.0\.1|\[::1\]/.test(u)) return false;
    return true;
  });

  const appType = hasAuthCode ? 'WEB_APP'
    : poGrants.includes('CLIENT_CREDENTIALS') ? 'WORKER'
    : 'WEB_APP';

  const oidc = {
    // The canonical item's `name` (source adapter-supplied display name)
    // takes priority — `clientId` is often an opaque ID (e.g. P14E's UUIDs)
    // rather than a human-readable name.
    name: sanitizeName(canonicalName || cid),
    description: sanitizeDescription(c.description || `Migrated from PingFederate: ${cid}`),
    enabled: enableApps,
    protocol: 'OPENID_CONNECT',
    type: appType,
    grantTypes: poGrants,
    tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
    ...(poGrants.includes('REFRESH_TOKEN') ? { refreshTokenType: 'OPAQUE_TOKEN' } : {}),
  };

  if (redirectUris.length) oidc.redirectUris = redirectUris;
  if (hasAuthCode) {
    oidc.pkceEnforcement = 'S256_REQUIRED';
    oidc.responseTypes = ['CODE'];
  }

  return { oidc };
}

// ---------------------------------------------------------------------------
// buildSamlPayload — SAML
// ---------------------------------------------------------------------------

function buildSamlPayload(sp, enableApps, capabilities) {
  // Prefer the canonical capabilities computed by the source adapter — raw
  // `sp` field names are source-specific (PingFederate vs. P14E vs. ...) and
  // must not be read directly here (see HUB-SPOKE.md: "source record is
  // preserved opaquely"). Only SLO, which isn't part of the canonical
  // capabilities schema, still reads the raw PF-shaped fields; sources that
  // don't expose SLO in that shape simply omit it from the payload.
  const caps = capabilities ?? {};
  const sso = sp.spBrowserSso ?? {};
  const acsUrls = caps.acsUrls?.length ? caps.acsUrls : (sso.ssoServiceEndpoints ?? []).map(e => e.url).filter(Boolean);
  const nameIdFormat = caps.nameIdFormat ??
    SAML_NAMEID_MAP[sso.spSamlIdentityMapping] ??
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
  const assertionSigned = caps.signAssertions ?? sso.signAssertions ?? false;
  const responseSigned = caps.signResponse ?? sso.signResponseAsRequired ?? true;
  const assertionDuration = ((sso.assertionLifetime?.minutesBefore ?? 5) +
    (sso.assertionLifetime?.minutesAfter ?? 5)) * 60;

  const sloEndpoints = sso.sloServiceEndpoints ?? [];
  const sloEndpoint = sloEndpoints[0]?.url ?? '';
  const sloBinding = sloEndpoints[0]?.binding === 'REDIRECT'
    ? 'HTTP_REDIRECT' : 'HTTP_POST';

  return {
    saml: {
      name: sanitizeName(sp.name),
      description: sanitizeDescription(sp.name),
      enabled: enableApps,
      protocol: 'SAML',
      type: 'WEB_APP',
      spEntityId: caps.entityId ?? sp.entityId,
      acsUrls: acsUrls.length ? acsUrls : ['https://example.com/saml/acs'],
      assertionDuration,
      assertionSigned,
      responseSigned,
      nameIdFormat,
      ...(sloEndpoint ? { sloEndpoint, sloBinding } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// buildAtmPayload — ATM → pingone resource
// ---------------------------------------------------------------------------

function buildAtmPayload(atm) {
  const fields = atm.configuration?.fields ?? [];
  const lifetimeField = fields.find(f => f.name === 'Token Lifetime');
  const tokenLifetimeMins = parseInt(lifetimeField?.value ?? '60', 10);
  const name = sanitizeName(atm.name ?? atm.id);
  const rawSecs = tokenLifetimeMins * 60;
  const accessTokenValiditySeconds = Math.min(2592000, Math.max(300, rawSecs));

  return {
    payload: {
      name,
      description: sanitizeDescription(`${name} (migrated from PingFederate ATM)`),
      accessTokenValiditySeconds,
      introspectEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
    },
    tokenLifetimeSecs: accessTokenValiditySeconds,
    originalTokenSecs: rawSecs,
  };
}

// ---------------------------------------------------------------------------
// buildSigningKeyPayload — signing key
// ---------------------------------------------------------------------------

function buildSigningKeyPayload(enrichedItem) {
  const { kp, algorithm, keyLength, signatureAlgorithm, deficient } = enrichedItem;
  const cnMatch = /cn=([^,]+)/i.exec(kp.subjectDN ?? '');
  const cn = cnMatch ? cnMatch[1].trim() : (kp.id ?? 'migrated-key');
  const name = sanitizeName(`GEN-${cn}`);

  const subjectDN = kp.subjectDN ?? `CN=${cn}`;
  const issuerDN  = kp.issuerDN  ?? subjectDN;

  return {
    payload: {
      name,
      subjectDN,
      issuerDN,
      algorithm,
      keyLength,
      signatureAlgorithm,
      usageType: 'SIGNING',
      validityPeriod: CERT_DEFAULTS.validityPeriod,
    },
    name,
    subjectDN,
    algorithm,
    keyLength,
    signatureAlgorithm,
    deficient,
  };
}

// ---------------------------------------------------------------------------
// buildIdpConnPayload — external IdP connection
// ---------------------------------------------------------------------------

function buildIdpConnPayload(conn, enableApps) {
  const sso = conn.idpBrowserSso ?? {};
  const certs = conn.credentials?.certs ?? [];
  const primaryCert = certs.find(c => c.primaryVerificationCert) ?? certs[0];
  const certValue = primaryCert?.x509File?.formattedContent ?? primaryCert?.x509File?.id ?? null;

  const ssoEndpoints = sso.ssoServiceEndpoints ?? [];
  const postEndpoint = ssoEndpoints.find(e => e.binding === 'POST') ?? ssoEndpoints[0];
  const redirectEndpoint = ssoEndpoints.find(e => e.binding === 'REDIRECT') ?? null;

  return {
    payload: {
      name: sanitizeName(conn.name),
      description: sanitizeDescription(`Migrated from PingFederate: ${conn.name}`),
      enabled: enableApps,
      type: 'SAML',
      idpEntityId: conn.entityId,
      spEntityId: conn.defaultVirtualEntityId ?? conn.virtualEntityIds?.[0] ?? conn.entityId,
      idpSsoEndpoints: [
        ...(postEndpoint ? [{ binding: 'HTTP_POST', url: postEndpoint.url }] : []),
        ...(redirectEndpoint ? [{ binding: 'HTTP_REDIRECT', url: redirectEndpoint.url }] : []),
      ],
      ...(certValue ? { signingCertificate: certValue } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// transform — canonical item → PingOne payload object
// ---------------------------------------------------------------------------

function transform(item) {
  const src = item.source ?? item;
  const enableApps = item._enableApps ?? false;
  const poGrants = item.poGrants ?? item.capabilities?.grantTypes ?? [];

  switch (item.type) {
    case 'oidc':
      return buildOidcPayload(src, poGrants, enableApps, item.name);
    case 'saml':
      return buildSamlPayload(src, enableApps, item.capabilities);
    case 'atm':
      return buildAtmPayload(src).payload;
    case 'key': {
      const enriched = item._enriched ?? {
        kp: src,
        algorithm: item.capabilities?.algorithm ?? 'RSA',
        keyLength:  item.capabilities?.keySize ?? 3072,
        signatureAlgorithm: item.capabilities?.signatureAlgorithm ?? 'SHA256withRSA',
        deficient: false,
      };
      return buildSigningKeyPayload(enriched).payload;
    }
    case 'idp':
      return buildIdpConnPayload(src, enableApps).payload;
    default:
      throw new Error(`pingone-adapter.transform: unknown item type '${item.type}'`);
  }
}

// ---------------------------------------------------------------------------
// apply — canonical item → call pingcli → { id, status }
// ---------------------------------------------------------------------------

async function apply(payload, ctx) {
  const { item, args, workDir } = ctx;
  const profile = args.profile;
  const poEnvId = args.destEnvId ?? args.poEnvId;

  switch (item.type) {
    case 'oidc': {
      const cid = item.id;
      const fname = path.join(workDir, `po-app-${cid}.json`);
      fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
      const r = pingcli(
        ['pingone', 'applications', 'apply', '--environment-id', poEnvId, '--from-file', fname],
        { profile }
      );
      return { id: r?.data?.id, status: r?.message ?? 'applied' };
    }
    case 'saml': {
      const fname = path.join(workDir, `po-saml-${item.id}.json`);
      fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
      const r = pingcli(
        ['pingone', 'applications', 'apply', '--environment-id', poEnvId, '--from-file', fname],
        { profile }
      );
      return { id: r?.data?.id, status: r?.message ?? 'applied' };
    }
    case 'atm': {
      const fname = path.join(workDir, `po-atm-${slugify(item.id)}.json`);
      fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
      const r = pingcli(
        ['pingone', 'resources', 'apply', '--environment-id', poEnvId, '--from-file', fname],
        { profile }
      );
      return { id: r?.data?.id, status: r?.message ?? 'applied' };
    }
    case 'key': {
      const fname = path.join(workDir, `po-key-${slugify(item.id)}.json`);
      fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
      const r = run(
        ['pingcli', '--profile', profile, '--output-format', 'json',
         'pingone', 'api', '--http-method', 'POST',
         '--fail',
         '--header', 'Content-Type: application/json',
         '--data', fname,
         `environments/${poEnvId}/keys`]
      );
      return { id: r?.data?.id ?? r?.id, status: 'created' };
    }
    case 'idp': {
      const fname = path.join(workDir, `po-idpconn-${slugify(item.id)}.json`);
      fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
      const r = run(
        ['pingcli', '--profile', profile, '--output-format', 'json',
         'pingone', 'api', '--http-method', 'POST',
         '--fail',
         '--header', 'Content-Type: application/vnd.pingidentity.identityProvider.saml+json',
         '--data', fname,
         `environments/${poEnvId}/identityProviders`]
      );
      return { id: r?.data?.id ?? r?.id, status: 'created' };
    }
    default:
      throw new Error(`pingone-adapter.apply: unknown item type '${item.type}'`);
  }
}

// ---------------------------------------------------------------------------
// validate — reads back and checks invariants
// ---------------------------------------------------------------------------

async function validate(id, item, ctx) {
  const { args } = ctx;
  const profile = args.profile;
  const poEnvId = args.destEnvId ?? args.poEnvId;

  if (item.type !== 'oidc') {
    // Non-OIDC items: just confirm the resource exists
    return { pass: !!id, details: { id } };
  }

  const cid = item.id;

  if (!id) {
    return { pass: false, details: { clientId: cid, enabled: false, grants: [], pkce: '?', resourceGrants: 0, issues: ['apply failed'] } };
  }

  try {
    const r = pingcli(
      ['pingone', 'applications', 'get', '--environment-id', poEnvId, '--application-id', id],
      { profile }
    );
    const ad = r?.data ?? {};
    const enabled = ad.enabled === true;
    const grantsInPo = ad.grantTypes ?? [];
    const pkce = ad.pkceEnforcement ?? '?';

    const g = pingcli(
      ['pingone', 'applications', 'application-grants', 'list',
       '--environment-id', poEnvId, '--application-id', id],
      { profile }
    );
    const grantCount = (g?.data ?? []).length;

    const implicitPresent = grantsInPo.includes('IMPLICIT');
    const hasGrant = grantCount > 0;
    const needsPkce = grantsInPo.includes('AUTHORIZATION_CODE');
    const pkceOk = !needsPkce || pkce === 'S256_REQUIRED';

    const issues = [];
    if (args.enableApps && !enabled) issues.push('not enabled');
    if (!hasGrant)       issues.push('no resource grant');
    if (implicitPresent) issues.push('IMPLICIT still present');
    if (!pkceOk)         issues.push(`pkce=${pkce} (expected S256_REQUIRED)`);

    return {
      pass: issues.length === 0,
      details: { clientId: cid, enabled, grants: grantsInPo, pkce, resourceGrants: grantCount, issues },
    };
  } catch (err) {
    return { pass: false, details: { clientId: cid, enabled: false, grants: [], pkce: '?', resourceGrants: 0, issues: [err.message] } };
  }
}

// ---------------------------------------------------------------------------
// Batch helpers (called by ping-migration.js directly)
// ---------------------------------------------------------------------------

function applyApps(payloads, args) {
  section('Step 7 — Apply applications to PingOne');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const results = [];

  for (const item of payloads) {
    const { clientId: cid } = item;
    try {
      const r = pingcli(
        ['pingone', 'applications', 'apply', '--environment-id', poEnvId, '--from-file', item.file],
        { profile }
      );
      const appId = r?.data?.id;
      const action = r?.message ?? '?';
      ok(`${cid} | ${action} | id=${appId}`);
      results.push({ ...item, appId, success: true });
    } catch (err) {
      fail(`${cid} | ${err.message}`);
      results.push({ ...item, appId: null, success: false });
    }
  }

  const applied = results.filter(r => r.success);
  info(`${applied.length}/${payloads.length} apps applied successfully`);
  return results;
}

function applySamlApps(samlPayloads, args) {
  section('Step 7b — Apply SAML applications to PingOne');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const results = [];

  for (const item of samlPayloads) {
    const { name } = item;
    try {
      const r = pingcli(
        ['pingone', 'applications', 'apply', '--environment-id', poEnvId, '--from-file', item.file],
        { profile }
      );
      const appId = r?.data?.id;
      const action = r?.message ?? '?';
      ok(`${name} | ${action} | id=${appId}`);
      results.push({ ...item, appId, success: true });
    } catch (err) {
      fail(`${name} | ${err.message}`);
      results.push({ ...item, appId: null, success: false });
    }
  }

  const applied = results.filter(r => r.success);
  info(`${applied.length}/${samlPayloads.length} SAML apps applied successfully`);
  return results;
}

function applyAtms(atmPayloads, args) {
  section('Step 7c — Apply ATMs to PingOne');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const results = [];

  for (const item of atmPayloads) {
    const { name } = item;
    try {
      const r = pingcli(
        ['pingone', 'resources', 'apply', '--environment-id', poEnvId, '--from-file', item.file],
        { profile }
      );
      const resourceId = r?.data?.id;
      const action = r?.message ?? '?';
      ok(`${name} | ${action} | id=${resourceId}`);
      results.push({ ...item, resourceId, success: true });
    } catch (err) {
      fail(`${name} | ${err.message}`);
      results.push({ ...item, resourceId: null, success: false });
    }
  }

  const applied = results.filter(r => r.success);
  info(`${applied.length}/${atmPayloads.length} ATMs applied successfully`);
  return results;
}

function applySigningKeys(signingPayloads, args) {
  section('Step 7d — Apply signing keys to PingOne');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const results = [];

  for (const item of signingPayloads) {
    const { name } = item;
    try {
      const r = run(
        ['pingcli', '--profile', profile, '--output-format', 'json',
         'pingone', 'api', '--http-method', 'POST',
         '--fail',
         '--header', 'Content-Type: application/json',
         '--data', item.file,
         `environments/${poEnvId}/keys`]
      );
      const keyId = r?.data?.id ?? r?.id;
      ok(`${name} | created | id=${keyId}${item.deficient ? ' (upgraded)' : ''}`);
      results.push({ ...item, keyId, success: true });
    } catch (err) {
      fail(`${name} | ${err.message}`);
      results.push({ ...item, keyId: null, success: false });
    }
  }

  const applied = results.filter(r => r.success);
  info(`${applied.length}/${signingPayloads.length} signing keys applied successfully`);
  return results;
}

function applyIdpConnections(idpConnPayloads, args) {
  section('Step 7e — Apply external IdP connections to PingOne');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const results = [];

  for (const item of idpConnPayloads) {
    const { name } = item;
    try {
      const r = run(
        ['pingcli', '--profile', profile, '--output-format', 'json',
         'pingone', 'api', '--http-method', 'POST',
         '--fail',
         '--header', 'Content-Type: application/vnd.pingidentity.identityProvider.saml+json',
         '--data', item.file,
         `environments/${poEnvId}/identityProviders`]
      );
      const idpId = r?.data?.id ?? r?.id;
      ok(`${name} | created | id=${idpId}`);
      results.push({ ...item, idpId, success: true });
    } catch (err) {
      fail(`${name} | ${err.message}`);
      results.push({ ...item, idpId: null, success: false });
    }
  }

  const applied = results.filter(r => r.success);
  info(`${applied.length}/${idpConnPayloads.length} external IdP connections applied successfully`);
  return results;
}

// ---------------------------------------------------------------------------
// buildOidcPayloads — prepare payload files for batch apply
// ---------------------------------------------------------------------------

function buildOidcPayloads(direct, work, enableApps) {
  section('Step 6 — Build PingOne payloads');
  const payloads = [];

  for (const { c, poGrants, item } of direct) {
    const payload = buildOidcPayload(c, poGrants, enableApps, item?.name);
    const cid = c.clientId ?? c.id ?? c.name;
    const fname = path.join(work, `po-app-${cid}.json`);
    fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
    payloads.push({ clientId: cid, name: item?.name, pf: c, poGrants, file: fname });
  }

  ok(`${payloads.length} payload files written to ${work}/`);
  return payloads;
}

function buildSamlPayloads(samlDirect, work, enableApps) {
  section('Step 6b — Build SAML payloads');
  const payloads = [];

  for (const { sp, item } of samlDirect) {
    const payload = buildSamlPayload(sp, enableApps, item?.capabilities);
    const fname = path.join(work, `po-saml-${sp.id}.json`);
    fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
    payloads.push({ spId: sp.id, name: sp.name, pf: sp, file: fname });
  }

  ok(`${payloads.length} SAML payload files written to ${work}/`);
  return payloads;
}

function buildAtmPayloads(atmDirect, work) {
  section('Step 6c — Build ATM payloads');
  const payloads = [];

  for (const { atm } of atmDirect) {
    const { payload, tokenLifetimeSecs, originalTokenSecs } = buildAtmPayload(atm);
    const name = payload.name;
    const fname = path.join(work, `po-atm-${slugify(atm.id ?? name)}.json`);
    fs.writeFileSync(fname, JSON.stringify(payload, null, 2));
    payloads.push({ atmId: atm.id, name, pf: atm, file: fname, tokenLifetimeSecs, originalTokenSecs });
  }

  ok(`${payloads.length} ATM payload files written to ${work}/`);
  return payloads;
}

function buildSigningKeyPayloads(enrichedKeys, work) {
  section('Step 6d — Build signing key payloads');
  const payloads = [];

  for (const item of enrichedKeys) {
    const built = buildSigningKeyPayload(item);
    const { kp } = item;
    const slug = slugify(kp.id ?? built.name);
    const fname = path.join(work, `po-key-${slug}.json`);
    fs.writeFileSync(fname, JSON.stringify(built.payload, null, 2));
    payloads.push({ pfId: kp.id, name: built.name, subjectDN: built.subjectDN, algorithm: built.algorithm, keyLength: built.keyLength, signatureAlgorithm: built.signatureAlgorithm, deficient: built.deficient, file: fname });

    if (built.deficient) {
      info(`${kp.id} | deficient spec (${item.rawKeySize ?? '?'}-bit ${kp.keyAlgorithm ?? 'RSA'}) → upgraded to ${built.keyLength}-bit ${built.signatureAlgorithm}`);
    }
  }

  ok(`${payloads.length} signing key payload files written to ${work}/`);
  return payloads;
}

function buildIdpConnPayloads(idpConnDirect, work, enableApps) {
  section('Step 6e — Build external IdP connection payloads');
  const payloads = [];

  for (const { conn } of idpConnDirect) {
    const built = buildIdpConnPayload(conn, enableApps);
    const fname = path.join(work, `po-idpconn-${slugify(conn.id)}.json`);
    fs.writeFileSync(fname, JSON.stringify(built.payload, null, 2));
    payloads.push({ connId: conn.id, name: conn.name, pf: conn, file: fname });
  }

  ok(`${payloads.length} external IdP connection payload files written to ${work}/`);
  return payloads;
}

// ---------------------------------------------------------------------------
// Metadata builders (kept separate for reuse in writeAppMetadata)
// ---------------------------------------------------------------------------

function buildOidcMetadata(pfClient, poGrants, updatedAt) {
  const concerns = [];
  const recommendations = [];

  concerns.push('Client secret was not migrated — PingFederate uses OBF:JWE which cannot be exported');
  recommendations.push('Rotate client secret: pingcli pingone applications application-secrets rotate');

  const droppedGrants = (pfClient.grantTypes ?? []).filter(g => !GRANT_MAP[g] || GRANT_MAP[g] === null);
  if (droppedGrants.includes('IMPLICIT')) {
    concerns.push('IMPLICIT grant was present in PingFederate and has been dropped (deprecated per RFC 6749)');
    recommendations.push('Update any clients using implicit flow to authorization_code + PKCE');
  }
  if (droppedGrants.includes('ACCESS_TOKEN_VALIDATION')) {
    concerns.push('ACCESS_TOKEN_VALIDATION grant was dropped — no PingOne equivalent');
  }

  if (poGrants.includes('AUTHORIZATION_CODE')) {
    recommendations.push('PKCE S256 is enforced — confirm all redirect clients send code_challenge');
  }

  const redirectUris = pfClient.redirectUris ?? [];
  const droppedUris = redirectUris.filter(u => {
    if (u.includes('*')) return true;
    if (u.startsWith('http://') && !/localhost|127\.0\.0\.1|\[::1\]/.test(u)) return true;
    return false;
  });
  if (droppedUris.length) {
    concerns.push(`${droppedUris.length} redirect URI(s) dropped — PingOne does not allow wildcards or non-loopback HTTP URIs: ${droppedUris.join(', ')}`);
    recommendations.push('Replace wildcard redirect URIs with explicit URIs, and update HTTP URIs to HTTPS before go-live');
  } else if (redirectUris.some(u => u.startsWith('http://') && !u.includes('localhost'))) {
    concerns.push('One or more redirect URIs use HTTP (non-localhost) — insecure in production');
    recommendations.push('Update redirect URIs to use HTTPS before go-live');
  }

  recommendations.push('Assign a sign-on policy once policies are configured in PingOne');
  recommendations.push('Update client application to point to PingOne authorize/token endpoints');

  return {
    'cmt-updatedat': updatedAt,
    migrationSource: 'PingFederate',
    pfClientId: pfClient.clientId,
    originalGrantTypes: pfClient.grantTypes ?? [],
    droppedGrantTypes: droppedGrants,
    concerns,
    recommendations,
  };
}

function buildSamlMetadata(pfSp, updatedAt) {
  const concerns = [];
  const recommendations = [];

  const sso = pfSp.spBrowserSso ?? {};
  const acsUrls = (sso.ssoServiceEndpoints ?? []).map(e => e.url).filter(Boolean);
  const sloEndpoints = sso.sloServiceEndpoints ?? [];

  recommendations.push('Validate SP-initiated SSO flow end-to-end after migration');
  recommendations.push('Validate IdP-initiated SSO flow if used by this SP');

  if (!sso.signAssertions) {
    concerns.push('PingFederate was not signing assertions — confirm the SP does not require signed assertions');
  }
  if (!sso.signResponseAsRequired) {
    concerns.push('PingFederate was not signing responses — confirm the SP does not require signed responses');
  }

  if (acsUrls.some(u => u.startsWith('http://') && !u.includes('localhost'))) {
    concerns.push('One or more ACS URLs use HTTP (non-localhost) — insecure in production');
    recommendations.push('Update ACS URLs to HTTPS before go-live');
  }

  if (sloEndpoints.length === 0) {
    concerns.push('No SLO endpoint configured in PingFederate — single logout will not work unless configured in PingOne');
    recommendations.push('Configure SLO endpoint in PingOne if single logout is required');
  } else {
    recommendations.push('Verify SLO flow: confirm single logout works from both SP and IdP');
  }

  const nameIdMapping = sso.spSamlIdentityMapping;
  if (!nameIdMapping || nameIdMapping === 'STANDARD') {
    recommendations.push('Confirm NameID format (unspecified) is acceptable to the SP — update if SP requires a specific format');
  }

  recommendations.push('Verify signing certificate: PingOne will use its own signing key — update SP trust if needed');
  recommendations.push('Confirm attribute contract: map required attributes in PingOne attribute mappings');
  recommendations.push('Test with the SP vendor to confirm entity ID and ACS URL are correct in their configuration');

  const encryptionPolicy = pfSp.encryptionPolicy ?? {};
  if (encryptionPolicy.encryptAssertion || encryptionPolicy.encryptSloSubjectNameId) {
    concerns.push('PingFederate had assertion/SLO encryption configured — verify encryption certificate is loaded in PingOne');
    recommendations.push('Upload SP encryption certificate to PingOne application settings');
  }

  return {
    'cmt-updatedat': updatedAt,
    migrationSource: 'PingFederate',
    pfConnectionId: pfSp.id,
    pfEntityId: pfSp.entityId,
    acsUrls,
    nameIdFormat: SAML_NAMEID_MAP[nameIdMapping] ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    concerns,
    recommendations,
  };
}

function buildAtmMetadata(pfAtm, updatedAt, originalTokenSecs, appliedTokenSecs) {
  const fields = pfAtm.configuration?.fields ?? [];
  const lifetime = fields.find(f => f.name === 'Token Lifetime')?.value ?? '60';
  const ac = pfAtm.accessControlSettings ?? {};
  const allowedClients = ac.restrictClients
    ? (ac.allowedClients ?? []).map(c => c.id)
    : [];
  const extendedAttrs = (pfAtm.attributeContract?.extendedAttributes ?? []).map(a => a.name);
  const clamped = originalTokenSecs != null && originalTokenSecs !== appliedTokenSecs;

  const recommendations = [
    'Assign this PingOne resource to applications that previously used this ATM',
    'Verify token lifetime matches application expectations',
    'Custom scopes from the ATM attribute contract must be re-created as resource scopes in PingOne',
  ];
  if (clamped) {
    recommendations.unshift(`Token lifetime clamped: PF value was ${originalTokenSecs}s (${Math.round(originalTokenSecs/60)}min) — below PingOne minimum 300s; applied ${appliedTokenSecs}s`);
  }

  return {
    'cmt-updatedat': updatedAt,
    migrationSource: 'PingFederate',
    pfAtmId: pfAtm.id,
    pfAtmName: pfAtm.name,
    tokenLifetimeMinutes: parseInt(lifetime, 10),
    ...(clamped ? { tokenLifetimeClampedSecs: appliedTokenSecs, originalTokenSecs } : {}),
    allowedClients: allowedClients.length ? allowedClients : ['(all clients)'],
    extendedAttributes: extendedAttrs,
    recommendations,
  };
}

// ---------------------------------------------------------------------------
// writeMetadata (Step 7f)
// ---------------------------------------------------------------------------

function writeAppMetadata(appResults, samlResults, atmResults, signingResults, args, work) {
  section('Step 7f — Write migration metadata');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const updatedAt = new Date().toISOString();
  let written = 0, errored = 0;

  const allItems = [
    ...appResults.filter(r => r.success && r.appId).map(item => ({
      label: item.clientId,
      appId: item.appId,
      metadata: buildOidcMetadata(item.pf, item.poGrants, updatedAt),
      sidecar: path.join(work, `meta-oidc-${item.clientId}.json`),
      metadataPath: `environments/${poEnvId}/applications/${item.appId}/metadata`,
    })),
    ...samlResults.filter(r => r.success && r.appId).map(item => ({
      label: item.name,
      appId: item.appId,
      metadata: buildSamlMetadata(item.pf, updatedAt),
      sidecar: path.join(work, `meta-saml-${item.name}.json`),
      metadataPath: `environments/${poEnvId}/applications/${item.appId}/metadata`,
    })),
    ...atmResults.filter(r => r.success && r.resourceId).map(item => ({
      label: item.name,
      appId: item.resourceId,
      metadata: buildAtmMetadata(item.pf, updatedAt, item.originalTokenSecs, item.tokenLifetimeSecs),
      sidecar: path.join(work, `meta-atm-${slugify(item.atmId ?? item.name)}.json`),
      metadataPath: null, // PingOne resources/{id}/metadata endpoint does not support writes
    })),
  ];

  for (const { label, appId, metadata, sidecar, metadataPath } of allItems) {
    fs.writeFileSync(sidecar, JSON.stringify(metadata, null, 2));
    if (!metadataPath) {
      ok(`${label} | metadata saved locally → ${path.basename(sidecar)} (API write not supported for this resource type)`);
      written++;
      continue;
    }
    const tmp = path.join(os.tmpdir(), `meta-${appId}.json`);
    fs.writeFileSync(tmp, JSON.stringify({ metadata }));
    try {
      run(['pingcli', '--profile', profile, '--output-format', 'json',
        'pingone', 'api', '--http-method', 'PUT',
        '--fail',
        '--header', 'Content-Type: application/json',
        '--data', tmp,
        metadataPath]);
      const verify = run(['pingcli', '--profile', profile, '--output-format', 'json',
        'pingone', 'api', '--fail',
        metadataPath]);
      const keys = Object.keys(verify?.data?.metadata ?? verify?.data ?? {});
      ok(`${label} | metadata written & verified (${keys.length} keys) → ${path.basename(sidecar)}`);
      written++;
    } catch (err) {
      fail(`${label} | metadata error: ${err.message}`);
      errored++;
    } finally {
      fs.unlinkSync(tmp);
    }
  }

  info(`${written} metadata records written${errored ? `  Errors: ${errored}` : ''}`);
}

// ---------------------------------------------------------------------------
// createGrants (Step 8)
// ---------------------------------------------------------------------------

function createGrants(appResults, args, work) {
  section('Step 8 — Create resource grants');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  const grantDetails = {};

  const resources = pingcli(
    ['pingone', 'resources', 'list', '--environment-id', poEnvId],
    { profile }
  );
  const openidResource = (resources?.data ?? []).find(r => r.type === 'OPENID_CONNECT');
  if (!openidResource) {
    fail('Could not find openid resource in PingOne environment');
    return {};
  }

  const openidResourceId = openidResource.id;

  const scopesR = pingcli(
    ['pingone', 'resources', 'resource-scopes', 'list',
     '--environment-id', poEnvId, '--resource-id', openidResourceId],
    { profile }
  );
  const scopeMap = Object.fromEntries((scopesR?.data ?? []).map(s => [s.name, s.id]));

  for (const item of appResults) {
    if (!item.success || !item.appId) continue;

    const { clientId: cid, appId, pf } = item;
    const pfScopes = pf.restrictedScopes ?? [];

    const scopeIds = pfScopes
      .filter(s => scopeMap[s] && STANDARD_OIDC_SCOPES.has(s))
      .map(s => ({ id: scopeMap[s] }));

    const finalScopeIds = scopeIds.length > 0
      ? scopeIds
      : scopeMap['openid'] ? [{ id: scopeMap['openid'] }] : [];

    const grant = { resource: { id: openidResourceId }, scopes: finalScopeIds };
    const grantFile = path.join(work, `grant-${cid}.json`);
    fs.writeFileSync(grantFile, JSON.stringify(grant, null, 2));

    try {
      const existing = pingcli(
        ['pingone', 'applications', 'application-grants', 'list',
         '--environment-id', poEnvId, '--application-id', appId],
        { profile }
      );
      const already = (existing?.data ?? []).some(g => g.resource?.id === openidResourceId);

      if (already) {
        info(`${cid} | grant already exists — skipped`);
        grantDetails[cid] = ['(existing)'];
      } else {
        pingcli(
          ['pingone', 'applications', 'application-grants', 'create',
           '--environment-id', poEnvId, '--application-id', appId, '--from-file', grantFile],
          { profile }
        );
        const scopeNames = pfScopes.filter(s => STANDARD_OIDC_SCOPES.has(s));
        const finalNames = scopeNames.length ? scopeNames : ['openid'];
        ok(`${cid} | created | scopes=${JSON.stringify(finalNames)}`);
        grantDetails[cid] = finalNames;
      }
    } catch (err) {
      fail(`${cid} | ${err.message}`);
      grantDetails[cid] = ['ERROR'];
    }
  }
  return grantDetails;
}

// ---------------------------------------------------------------------------
// validateBatch (Step 9)
// ---------------------------------------------------------------------------

function validateBatch(appResults, args) {
  section('Step 9 — Validate');
  const { profile } = args;
  const poEnvId = args.destEnvId ?? args.poEnvId;
  let passed = 0, failed = 0;
  const details = [];

  for (const item of appResults) {
    const { clientId: cid, name, appId } = item;

    if (!item.success || !appId) {
      fail(`${cid} | skipped (apply failed)`);
      failed++;
      details.push({ clientId: cid, name, enabled: false, grants: [], pkce: '?', resourceGrants: 0, pass: false, issues: ['apply failed'] });
      continue;
    }

    try {
      const r = pingcli(
        ['pingone', 'applications', 'get', '--environment-id', poEnvId, '--application-id', appId],
        { profile }
      );
      const ad = r?.data ?? {};
      const enabled = ad.enabled === true;
      const grantsInPo = ad.grantTypes ?? [];
      const pkce = ad.pkceEnforcement ?? '?';

      const g = pingcli(
        ['pingone', 'applications', 'application-grants', 'list',
         '--environment-id', poEnvId, '--application-id', appId],
        { profile }
      );
      const grantCount = (g?.data ?? []).length;

      const implicitPresent = grantsInPo.includes('IMPLICIT');
      const hasGrant = grantCount > 0;
      const needsPkce = grantsInPo.includes('AUTHORIZATION_CODE');
      const pkceOk = !needsPkce || pkce === 'S256_REQUIRED';

      const issues = [];
      if (args.enableApps && !enabled) issues.push('not enabled');
      if (!hasGrant)       issues.push('no resource grant');
      if (implicitPresent) issues.push('IMPLICIT still present');
      if (!pkceOk)         issues.push(`pkce=${pkce} (expected S256_REQUIRED)`);

      if (issues.length === 0) {
        ok(`${cid} | enabled=${enabled} grants=${JSON.stringify(grantsInPo)} pkce=${pkce} resource_grants=${grantCount}`);
        passed++;
      } else {
        fail(`${cid} | ${issues.join(', ')}`);
        failed++;
      }
      details.push({ clientId: cid, name, enabled, grants: grantsInPo, pkce, resourceGrants: grantCount, pass: issues.length === 0, issues });
    } catch (err) {
      fail(`${cid} | ${err.message}`);
      failed++;
      details.push({ clientId: cid, name, enabled: false, grants: [], pkce: '?', resourceGrants: 0, pass: false, issues: [err.message] });
    }
  }

  console.log(`\n  Result: ${passed} passed, ${failed} failed`);
  return { success: failed === 0, details };
}

// ---------------------------------------------------------------------------
// printSummary
// ---------------------------------------------------------------------------

function printSummary(appResults, samlResults, atmResults, signingResults, idpConnResults, args) {
  section('Summary');
  const applied = appResults.filter(r => r.success);
  const failed = appResults.filter(r => !r.success);
  const samlApplied = samlResults.filter(r => r.success);
  const samlFailed = samlResults.filter(r => !r.success);
  const atmApplied = atmResults.filter(r => r.success);
  const atmFailed = atmResults.filter(r => !r.success);
  const keyApplied = signingResults.filter(r => r.success);
  const keyFailed = signingResults.filter(r => !r.success);
  const keyUpgraded = signingResults.filter(r => r.deficient);
  const idpApplied = idpConnResults.filter(r => r.success);
  const idpFailed = idpConnResults.filter(r => !r.success);

  const poEnvId = args.destEnvId ?? args.poEnvId;
  console.log(`  Environment  : ${poEnvId}`);
  console.log(`  OIDC applied : ${applied.length}${failed.length ? `  Failed: ${failed.length}` : ''}`);
  console.log(`  SAML applied : ${samlApplied.length}${samlFailed.length ? `  Failed: ${samlFailed.length}` : ''}`);
  console.log(`  ATMs applied : ${atmApplied.length}${atmFailed.length ? `  Failed: ${atmFailed.length}` : ''}`);
  console.log(`  Keys applied : ${keyApplied.length}${keyFailed.length ? `  Failed: ${keyFailed.length}` : ''}${keyUpgraded.length ? `  Upgraded: ${keyUpgraded.length}` : ''}`);
  console.log(`  Ext IdPs     : ${idpApplied.length}${idpFailed.length ? `  Failed: ${idpFailed.length}` : ''}`);
  if (failed.length) for (const r of failed) console.log(`    – ${r.clientId ?? r.name}`);
  if (samlFailed.length) for (const r of samlFailed) console.log(`    – ${r.name}`);
  if (atmFailed.length) for (const r of atmFailed) console.log(`    – ${r.name}`);
  if (keyFailed.length) for (const r of keyFailed) console.log(`    – ${r.name}`);
  if (idpFailed.length) for (const r of idpFailed) console.log(`    – ${r.name}`);
  if (keyUpgraded.length) {
    console.log('  Upgraded keys (deficient spec → best-practice defaults):');
    for (const r of keyUpgraded) console.log(`    ↑ ${r.pfId} → ${r.keyLength}-bit ${r.signatureAlgorithm}`);
  }
  console.log();
  console.log('  Next steps:');
  console.log('    1. Rotate client secrets — PF secrets are not migrated');
  console.log('    2. Assign sign-on policies (sop-assignments) once policies are configured');
  console.log('    3. Migrate data stores → PingOne populations');
  console.log('    4. Redesign IMPLICIT-only apps and re-run with --dry-run to preview');
  console.log('    5. Update client applications to point to PingOne token/authorize endpoints');
  console.log('    6. Validate SAML apps — confirm ACS URLs, entity IDs, signing certs, and SP/IdP-initiated flows');
  console.log('    7. Re-create ATM attribute contract scopes as PingOne resource scopes');
  console.log('    8. Review ATM allowed-client restrictions and configure PingOne access policies');
  console.log('    9. Update SP trust — distribute new PingOne signing certificates to all relying parties');
  console.log('   10. Review upgraded keys — confirm new algorithm/size is acceptable and document the change');
  console.log('   11. External IdP connections — verify attribute mappings and APC re-creation in PingOne for each migrated SAML IdP');
  console.log();
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

module.exports = {
  name: 'pingone',
  caps,
  transform,
  apply,
  validate,
  // Batch helpers (called by ping-migration.js)
  buildOidcPayloads,
  buildSamlPayloads,
  buildAtmPayloads,
  buildSigningKeyPayloads,
  buildIdpConnPayloads,
  applyApps,
  applySamlApps,
  applyAtms,
  applySigningKeys,
  applyIdpConnections,
  writeAppMetadata,
  createGrants,
  validateBatch,
  printSummary,
  // Payload builders (exported for testing / reuse)
  buildOidcPayload,
  buildSamlPayload,
  buildAtmPayload,
  buildSigningKeyPayload,
  buildIdpConnPayload,
};
