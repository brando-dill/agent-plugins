'use strict';

/**
 * p14e-adapter.js
 *
 * Source adapter for PingOne for Enterprise (P14E).
 *
 * Native export format: a JSON object with top-level arrays `applications`,
 * `metadata`, and `accountCertificates` — the same shape produced by
 * pingmigrate's `P14E.js#exportConfig()` (api/src/js/P14E.js in the pingmigrate
 * repo), which this adapter's live-mode auth/export logic is ported from.
 *
 * In FILE mode (--import-file):
 *   Reads a native P14E export JSON from disk and normalizes it to the
 *   canonical model.
 *
 * In LIVE mode:
 *   Authenticates to the PingOne for Enterprise admin API (via admin basic auth),
 *   fetches `applications`, `metadata`, and `accountCertificates`, then
 *   deletes the temporary JWT client and normalizes the result.
 *
 * Other P14E endpoints (categories, groups, dataStores, pingid, ...) are
 * intentionally not fetched — pingmigrate's P14E.js disabled them after
 * tenants with >4,000 groups caused API timeouts. Same tradeoff here.
 *
 * Field names for `applications`/`accountCertificates` are ported from
 * pingmigrate's OIDCApp.js/SAMLApp.js/SigningKeyPair.js resource classes.
 * The SAML SSO-endpoint property name in particular could not be confirmed
 * against a live P14E export; extractSaml() below tries several candidate
 * keys — narrow this to the confirmed field once a real export is available.
 */

const fs = require('fs');
const path = require('path');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const BLUE = '\x1b[34m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

const ok = (msg) => console.log(`  ${GREEN}✔${RESET}  ${msg}`);
const fail = (msg) => console.log(`  ${RED}✖${RESET}  ${msg}`);
const info = (msg) => console.log(`  ${BLUE}→${RESET}  ${msg}`);
const section = (msg) => console.log(`\n${BOLD}${msg}${RESET}`);

const DEFAULT_BASE_URL = 'https://admin-api.pingone.com/v3';

const JWT_CLIENT_SCOPES = [
  'ADD_CONNECTIONS_TO_SERVICE_PROVIDERS',
  'CERTIFICATE_MANAGEMENT',
  'IDENTITY_BRIDGE',
  'IDENTITY_PROVIDER',
  'READ_CUSTOMER',
  'GROUP_MANAGEMENT',
  'MANAGE_ADMIN_API_CLIENT',
  'PINGID_CONFIGURATION_READ_ONLY',
];

// ---------------------------------------------------------------------------
// Live-mode auth + export (ported from pingmigrate/api/src/js/P14E.js)
// ---------------------------------------------------------------------------

async function login(baseUrl, username, password) {
  const basicAuth = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

  // Step 1 — identify the account
  let res = await fetch(`${baseUrl}/accounts/whoami`, { headers: { Authorization: basicAuth } });
  if (res.status !== 200) throw new Error('invalid username/password');
  const { accountId } = await res.json();

  // Step 2 — create a short-lived admin JWT client
  const jwtClientBody = new URLSearchParams({
    scope: JWT_CLIENT_SCOPES.join(' '),
    name: `CMT Client - ${new Date().toISOString()}`,
    description: 'Client created by the ping-migration skill. Deleted immediately after use.',
  });
  res = await fetch(`${baseUrl}/clients/${accountId}/jwt`, {
    method: 'POST',
    headers: { Authorization: basicAuth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: jwtClientBody,
  });
  if (res.status !== 201) throw new Error('unable to create JWT client');
  const { id: clientId, jwtPrivateKey } = await res.json();

  // Step 3 — generate a JWT grant (assertion)
  const grantBody = new URLSearchParams({
    clientId,
    jwtPrivateKey: JSON.stringify(jwtPrivateKey),
    grantLifespanSeconds: 3600,
    tokenLifespanSeconds: 3600,
  });
  res = await fetch(`${baseUrl}/as/token.oauth2/jwt`, {
    method: 'POST',
    headers: { Authorization: basicAuth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: grantBody,
  });
  if (res.status !== 200) throw new Error('unable to create JWT grant');
  const { jwtGrant } = await res.json();

  // Step 4 — exchange the JWT grant for an OAuth bearer token
  const tokenBody = new URLSearchParams({
    client_id: clientId,
    grant_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    assertion: jwtGrant,
  });
  res = await fetch(`${baseUrl}/as/token.oauth2`, {
    method: 'POST',
    headers: { Authorization: basicAuth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenBody,
  });
  if (res.status !== 200) throw new Error('unable to create bearer token');
  const { access_token: accessToken } = await res.json();

  return { accountId, clientId, accessToken };
}

async function deleteClient(baseUrl, accessToken, clientId) {
  if (!clientId) return;
  const res = await fetch(`${baseUrl}/clients/refs/${clientId}/jwt`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (res.status !== 204) throw new Error('unable to delete JWT client');
}

async function getResults(baseUrl, accessToken, apiPath) {
  const results = [];
  let url = `${baseUrl}${apiPath}`;
  while (url) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (res.status !== 200) break;
    const data = await res.json();
    if (!data.results) break;
    for (const r of data.results) {
      if (r.ref) {
        const refRes = await fetch(`${baseUrl}${r.ref}`, { headers: { Authorization: `Bearer ${accessToken}` } });
        results.push(await refRes.json());
      } else {
        results.push(r);
      }
    }
    url = data.nextPageRef ? `${baseUrl}${data.nextPageRef}` : undefined;
  }
  return results;
}

async function exportConfig(baseUrl, accountId, accessToken, cloudMigrationKey) {
  const apis = [
    { id: 'applications', path: `/applications/instances/idp/${accountId}` },
    { id: 'metadata', path: `/metadata/${accountId}` },
    { id: 'accountCertificates', path: `/accounts/${accountId}/certificates` },
  ];

  const items = {};
  for (const api of apis) {
    const start = Date.now();
    items[api.id] = await getResults(baseUrl, accessToken, api.path);
    info(`Fetched ${api.id} (${items[api.id].length} records, ${Date.now() - start}ms)`);
  }

  // Fetch + base64-encode each certificate's PKCS12 bundle (requires the
  // cloud migration key to decrypt; skip silently if none was supplied).
  for (const cert of items.accountCertificates ?? []) {
    if (!cloudMigrationKey) continue;
    const res = await fetch(`${baseUrl}/accounts/${accountId}/certificates/${cert.id}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/x-pkcs12',
      },
      body: `password=${encodeURIComponent(cloudMigrationKey)}`,
    });
    if (res.status === 200) {
      cert.pkcs12 = Buffer.from(await res.arrayBuffer()).toString('base64');
    }
  }

  return items;
}

async function exportP14e(args, workDir) {
  const baseUrl = args.p14eUrl || DEFAULT_BASE_URL;
  if (!args.p14eUsername || !args.p14ePassword) {
    throw new Error('Live mode requires --p14e-username and --p14e-password.');
  }

  section('Step 1 — Authenticate to PingOne for Enterprise');
  const { accountId, clientId, accessToken } = await login(baseUrl, args.p14eUsername, args.p14ePassword);
  ok(`Authenticated (account ${accountId}, ${baseUrl})`);

  let items;
  try {
    section('Step 2 — Export configuration');
    items = await exportConfig(baseUrl, accountId, accessToken, args.p14eCloudMigrationKey);
  } finally {
    try {
      await deleteClient(baseUrl, accessToken, clientId);
    } catch (err) {
      fail(`Cleanup of temporary JWT client failed: ${err.message}`);
    }
  }

  const outfile = path.join(workDir, 'p14e-export.json');
  fs.writeFileSync(outfile, JSON.stringify(items, null, 2));
  ok(`Export written → ${outfile}`);

  return outfile;
}

// ---------------------------------------------------------------------------
// File-mode loader
// ---------------------------------------------------------------------------

function loadExportFile(importFile) {
  JSON.parse(fs.readFileSync(importFile, 'utf8')); // fail fast on malformed JSON
  return importFile;
}

// ---------------------------------------------------------------------------
// Canonical model normalization
// ---------------------------------------------------------------------------

function protocolFromTemplateRef(templateRef) {
  const suffix = (templateRef || '').split('/').pop();
  if (suffix === 'oidc') return 'oidc';
  if (suffix === 'saml20') return 'saml';
  return null;
}

function normalizeOidc(app) {
  return {
    id: app.id ?? app.name,
    name: app.name,
    type: 'oidc',
    enabled: app.state ? app.state === 'ENABLED' : app.enabled !== false,
    classification: null,
    skipReason: null,
    concerns: [],
    capabilities: {
      // P14E returns grant types lowercase (e.g. "authorization_code");
      // the classifier's GRANT_MAP keys are uppercase.
      grantTypes: (app.grantTypes ?? []).map((g) => g.toUpperCase()),
      redirectUris: app.redirectUris ?? [],
      postLogoutUris: app.postLogoutRedirectUris ?? [],
      scopes: app.scopes ?? [],
      pkce: Boolean(app.pkceEnforced),
      tokenEndpointAuthMethod: app.clientAuth?.type ?? null,
    },
    source: app,
  };
}

function normalizeSaml(app) {
  // P14E returns a single `acsUrl` string, not an array of SSO endpoints.
  const acsUrls = [app.acsUrl].filter(Boolean);
  return {
    id: app.id ?? app.name,
    name: app.name,
    type: 'saml',
    enabled: app.state ? app.state === 'ENABLED' : app.enabled !== false,
    classification: null,
    skipReason: null,
    concerns: [],
    capabilities: {
      acsUrls,
      entityId: app.spEntityId ?? app.entityId,
      nameIdFormat: app.nameIdFormat ?? null,
      // P14E has no explicit sign-assertions/sign-response toggle — a
      // configured signingCertId means the response is always signed.
      signAssertions: Boolean(app.signAssertions),
      signResponse: app.signResponse != null ? Boolean(app.signResponse) : Boolean(app.signingCertId),
      protocol: 'SAML2.0',
    },
    source: app,
  };
}

function normalizeKey(cert) {
  return {
    id: cert.id,
    name: cert.subjectDN ?? cert.id,
    type: 'key',
    enabled: cert.status === 'VALID',
    classification: null,
    skipReason: null,
    concerns: [],
    capabilities: {
      algorithm: cert.keyAlgorithm ?? null,
      keySize: cert.keySize ?? null,
      validityDays: cert.expires ? Math.round((new Date(cert.expires) - Date.now()) / 86400000) : null,
    },
    source: cert,
  };
}

function normalizeToCanonical(exportFilePath) {
  const raw = JSON.parse(fs.readFileSync(exportFilePath, 'utf8'));
  const items = [];

  for (const app of raw.applications ?? []) {
    const protocol = protocolFromTemplateRef(app.templateRef);
    if (protocol === 'oidc') items.push(normalizeOidc(app));
    else if (protocol === 'saml') items.push(normalizeSaml(app));
    else info(`Skipping application '${app.name}' — unknown protocol (templateRef: ${app.templateRef})`);
  }

  for (const cert of raw.accountCertificates ?? []) {
    items.push(normalizeKey(cert));
  }

  return items;
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

module.exports = {
  name: 'p14e',
  displayName: 'PingOne for Enterprise',

  /** CLI params needed in live mode */
  params() {
    return ['p14e-url', 'p14e-username', 'p14e-password', 'p14e-cloud-migration-key'];
  },

  /**
   * extract(args, workDir)
   * If args.importFile is set, reads a native P14E export JSON from disk.
   * Otherwise authenticates live to PingOne for Enterprise (default base URL:
   * https://admin-api.pingone.com/v3, override with --p14e-url) and exports
   * applications, metadata, and account certificates.
   * Returns array of canonical items.
   */
  async extract(args, workDir) {
    const exportFilePath = args.importFile
      ? loadExportFile(args.importFile)
      : await exportP14e(args, workDir);

    return normalizeToCanonical(exportFilePath);
  },
};
