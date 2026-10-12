'use strict';

/**
 * pf-adapter.js
 *
 * PingFederate source adapter for the hub-and-spoke ping-migration skill.
 *
 * In LIVE mode (no --import-file):
 *   1. Configures a pingcli profile with PF + PingOne credentials.
 *   2. Authenticates to PingFederate (basicAuth) and PingOne (client_credentials).
 *   3. Creates (or reuses) the target PingOne environment.
 *   4. Calls PF bulk/export?includeExternalResources=true → writes pf-bulk-export.json.
 *   5. Enriches signing keys from the live PF key API.
 *   6. Normalizes all items into the canonical model.
 *
 * In FILE mode (--import-file):
 *   Reads the native PF bulk export JSON from disk and normalizes it.
 *   Signing key enrichment is attempted if a PF profile is available; silently skipped if not.
 *
 * Native export format: PingFederate bulk export JSON, either as:
 *   - The raw bulk body:    { operations: [...] }
 *   - The pingcli envelope: { status: 'success', data: { operations: [...] } }
 *
 * Returns: array of canonical items matching the shape described in HUB-SPOKE.md.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const YAML = (() => { try { return require('js-yaml'); } catch { return null; } })();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GRANT_MAP = {
  AUTHORIZATION_CODE: 'AUTHORIZATION_CODE',
  CLIENT_CREDENTIALS: 'CLIENT_CREDENTIALS',
  IMPLICIT: 'IMPLICIT',          // kept as-is; classifier will handle
  REFRESH_TOKEN: 'REFRESH_TOKEN',
  CIBA: 'CIBA',
  ACCESS_TOKEN_VALIDATION: 'ACCESS_TOKEN_VALIDATION', // kept; classifier will handle
  DEVICE_CODE: 'DEVICE_CODE',
};

const SAML_NAMEID_MAP = {
  STANDARD: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  EMAIL: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  TRANSIENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  PERSISTENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  X509_SUBJECT_NAME: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
};

const KEY_SIZE_MINIMUMS = { RSA: 2048, EC: 256 };
const CERT_DEFAULTS = {
  algorithm: 'RSA',
  keyLength: 3072,
  signatureAlgorithm: 'SHA256withRSA',
  validityPeriod: 365,
};

// ---------------------------------------------------------------------------
// ANSI helpers (same style as legacy script)
// ---------------------------------------------------------------------------

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const BLUE = '\x1b[34m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

const ok = (msg) => console.log(`  ${GREEN}✔${RESET}  ${msg}`);
const fail = (msg) => console.log(`  ${RED}✖${RESET}  ${msg}`);
const info = (msg) => console.log(`  ${BLUE}→${RESET}  ${msg}`);
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

// ---------------------------------------------------------------------------
// Normalizers
// ---------------------------------------------------------------------------

function normalizeCertSpec(pfCert) {
  const algorithm = (pfCert.keyAlgorithm === 'EC' ? 'EC' : 'RSA');
  const minKeySize = KEY_SIZE_MINIMUMS[algorithm];
  const rawKeySize = typeof pfCert.keySize === 'number' ? pfCert.keySize : null;
  const deficient = !rawKeySize || rawKeySize < minKeySize;
  const keyLength = deficient
    ? (algorithm === 'EC' ? 256 : 3072)
    : rawKeySize;
  let signatureAlgorithm = pfCert.signatureAlgorithm;
  if (!signatureAlgorithm || /SHA1|MD5/i.test(signatureAlgorithm)) {
    signatureAlgorithm = algorithm === 'EC' ? 'SHA256withECDSA' : 'SHA256withRSA';
  }
  return { algorithm, keyLength, signatureAlgorithm, deficient, rawKeySize };
}

function slugify(name) {
  return (name ?? 'unknown')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// ---------------------------------------------------------------------------
// Step 1: Configure pingcli profile
// ---------------------------------------------------------------------------

function ensureProfileExists(profile) {
  const configPath = path.join(os.homedir(), '.pingcli', 'config.yaml');
  if (!fs.existsSync(configPath)) {
    throw new Error(`pingcli config not found at ${configPath}. Run 'pingcli' once to initialise it.`);
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  if (new RegExp(`^${profile}:`, 'm').test(raw)) return false;

  if (!YAML) {
    throw new Error('js-yaml is required to create new profiles. Install it with: npm install js-yaml');
  }

  const config = YAML.load(raw) ?? {};
  if (config[profile]) return false;

  config[profile] = JSON.parse(JSON.stringify(config.default ?? {}));
  config[profile].description = 'Auto-created by ping-migration.js';

  fs.writeFileSync(configPath, YAML.dump(config, { allowUnicode: true }));
  return true;
}

function configureProfile(args) {
  section('Step 1 — Configure pingcli profile');
  const { profile } = args;

  const created = ensureProfileExists(profile);
  info(created ? `Created new profile '${profile}'` : `Using existing profile '${profile}'`);

  // Use the worker app's home environment for the token endpoint during auth.
  const authEnvId = args.destAuthEnvId || args.destEnvId;

  const keys = [
    `service.pingFederate.httpsHost=${args.pfHost}`,
    `service.pingFederate.authentication.basicAuth.username=${args.pfUser}`,
    `service.pingFederate.authentication.basicAuth.password=${args.pfPass}`,
    'service.pingFederate.authentication.type=basicAuth',
    'service.pingFederate.enabled=true',
    `service.pingOne.authentication.clientCredentials.clientID=${args.destClientId}`,
    `service.pingOne.authentication.clientCredentials.clientSecret=${args.destClientSecret}`,
    `service.pingOne.endpoint.environmentID=${authEnvId}`,
    `service.pingOne.endpoint.rootDomain=${args.destRegion}`,
    'service.pingOne.authentication.grantType=client_credentials',
    'service.pingOne.enabled=true',
  ];

  if (args.insecurePf) {
    keys.push('service.pingFederate.insecureTrustAllTLS=true');
    keys.push('service.pingFederate.xBypassExternalValidationHeader=true');
  }

  for (const kv of keys) {
    run(['pingcli', 'config', 'set', '--profile', profile, kv]);
  }

  ok(`Profile '${profile}' configured`);
}

// ---------------------------------------------------------------------------
// Step 2: Authenticate
// ---------------------------------------------------------------------------

function authenticate(args) {
  section('Step 2 — Authenticate');
  const { profile } = args;

  run(['pingcli', '--profile', profile, 'pingfederate', 'auth', 'login']);
  ok('Authenticated to PingFederate');

  run(['pingcli', '--profile', profile, 'pingone', 'auth', 'login', '--client-credentials']);
  ok('Authenticated to PingOne');

  // If the worker app lives in a different env than the migration target, switch now.
  if (args.destAuthEnvId && args.destAuthEnvId !== args.destEnvId) {
    run(['pingcli', 'config', 'set', '--profile', profile,
      `service.pingOne.endpoint.environmentID=${args.destEnvId}`]);
    info(`Switched target environment to ${args.destEnvId}`);
  }
}

// ---------------------------------------------------------------------------
// Step 3: Create target PingOne environment
// ---------------------------------------------------------------------------

function resolveEnvName(args) {
  if (args.resolvedEnvName) return;
  try {
    const r = run(
      ['pingcli', '--profile', args.profile, '--output-format', 'json',
        'pingone', 'environments', 'get', '--environment-id', args.destEnvId]
    );
    args.resolvedEnvName = r?.data?.name ?? args.destEnvId;
  } catch {
    args.resolvedEnvName = args.destEnvId;
  }
}

function createTargetEnvironment(args) {
  section('Step 3 — Create target PingOne environment');
  const { profile } = args;

  const ref = run(
    ['pingcli', '--profile', profile, '--output-format', 'json',
      'pingone', 'environments', 'get', '--environment-id', args.destEnvId]
  );
  const refData = ref?.data ?? {};
  const licenseId = refData.license?.id;
  const region = refData.region ?? 'NA';
  const envType = refData.type ?? 'SANDBOX';

  if (!licenseId) throw new Error('Could not determine license ID from reference environment');

  const today = new Date().toISOString().slice(0, 10);
  const defaultName = `Migration ${today}`;

  let envName;
  if (args.destEnvName) {
    envName = args.destEnvName;
  } else {
    process.stdout.write(`  New environment name [${defaultName}]: `);
    const buf = execFileSync('bash', ['-c', 'read line && echo "$line"'],
      { stdio: ['inherit', 'pipe', 'inherit'], encoding: 'utf8' });
    const entered = buf.trim();
    envName = entered || defaultName;
  }

  const payload = {
    name: envName,
    description: `Migrated from PingFederate on ${today}`,
    type: envType,
    region,
    license: { id: licenseId },
  };

  const tmpFile = path.join(os.tmpdir(), `po-env-${process.pid}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify(payload));
  let result;
  try {
    result = run(
      ['pingcli', '--profile', profile, '--output-format', 'json',
        'pingone', 'environments', 'create', '--from-file', tmpFile]
    );
  } catch (err) {
    fs.unlinkSync(tmpFile);
    const msg = err.message ?? '';
    if (/permission|access|forbidden|not.*allowed/i.test(msg)) {
      throw new Error(
        `Environment creation failed — the worker app does not have org-admin permissions.\n` +
        `  Either grant the Environment Admin or Org Admin role to the worker app,\n` +
        `  or re-run with --skip-env-create to migrate into the existing --dest-env-id environment.\n` +
        `  Original error: ${msg}`
      );
    }
    throw err;
  }
  fs.unlinkSync(tmpFile);
  const newEnvId = result?.data?.id;
  if (!newEnvId) throw new Error(`Environment creation returned no ID: ${JSON.stringify(result)}`);
  ok(`Created environment '${envName}' → id=${newEnvId}`);
  args.destEnvId = newEnvId;
  args.resolvedEnvName = envName;
}

// ---------------------------------------------------------------------------
// Step 4 (offline): Load bulk export from file
// ---------------------------------------------------------------------------

function loadBulkFile(args, workDir) {
  section('Step 4 — Load bulk export from file (offline mode)');
  fs.mkdirSync(workDir, { recursive: true });

  const src = path.resolve(args.importFile);
  if (!fs.existsSync(src)) {
    throw new Error(`--import-file not found: ${src}`);
  }

  const raw = JSON.parse(fs.readFileSync(src, 'utf8'));

  // Normalise: may be the raw bulk body or the pingcli JSON envelope
  let normalised;
  if (raw?.data?.operations) {
    normalised = raw; // already the pingcli envelope
  } else if (Array.isArray(raw?.operations)) {
    normalised = { status: 'success', data: raw }; // bare bulk body
  } else {
    throw new Error(`--import-file does not appear to be a PingFederate bulk export: ${src}`);
  }

  const outfile = path.join(workDir, 'pf-bulk-export.json');
  fs.writeFileSync(outfile, JSON.stringify(normalised, null, 2));
  ok(`Loaded bulk export from ${src} → pf-bulk-export.json`);

  return outfile;
}

// ---------------------------------------------------------------------------
// Step 4 (live): Export from PingFederate
// ---------------------------------------------------------------------------

function exportPf(args, workDir) {
  section('Step 4 — Export from PingFederate');
  const { profile } = args;
  fs.mkdirSync(workDir, { recursive: true });

  const outfile = path.join(workDir, 'pf-bulk-export.json');
  const result = run(
    ['pingcli', '--profile', profile, '--output-format', 'json',
      'pingfederate', 'api', '--http-method', 'GET', 'bulk/export?includeExternalResources=true'],
    { check: false }
  );
  fs.writeFileSync(outfile, JSON.stringify(result, null, 2));
  const status = result?.status ?? '?';
  if (status === 'success') {
    ok(`Bulk export → pf-bulk-export.json`);
  } else {
    info(`Bulk export returned non-success (may be empty): pf-bulk-export.json`);
  }

  return outfile;
}

// ---------------------------------------------------------------------------
// Step 5b: Enrich signing keys from live PF API
// ---------------------------------------------------------------------------

function enrichSigningKeys(signingItems, args) {
  let liveCerts = [];
  try {
    const r = run(
      ['pingcli', '--profile', args.profile, '--output-format', 'json',
        'pingfederate', 'api', 'keyPairs/signing'],
      { check: false }
    );
    liveCerts = r?.data?.items ?? r?.items ?? [];
  } catch {
    // PF unreachable in offline mode — proceed without enrichment
  }

  const liveMap = Object.fromEntries(liveCerts.map(c => [c.id, c]));

  return signingItems.map(kp => {
    const live = liveMap[kp.id] ?? {};
    const merged = { ...kp, ...live };
    const { algorithm, keyLength, signatureAlgorithm, deficient, rawKeySize } = normalizeCertSpec({
      keyAlgorithm: merged.keyAlgorithm,
      keySize: merged.keySize,
      signatureAlgorithm: merged.signatureAlgorithm,
    });
    return { kp: merged, algorithm, keyLength, signatureAlgorithm, deficient, rawKeySize, enriched: Object.keys(live).length > 0 };
  });
}

// ---------------------------------------------------------------------------
// Authentication infrastructure analysis (for assessment report)
// ---------------------------------------------------------------------------

function analyzeAuthPolicies(bulkFilePath) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(bulkFilePath, 'utf8'));
  } catch {
    return null;
  }
  const operations = raw?.data?.operations ?? [];
  const find = (type) => (operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === type)?.items ?? []);

  const adapters = find('idp/adapters');
  const adapterMap = {};
  for (const a of adapters) adapterMap[a.id] = a;

  const PLUGIN_SHORT = {
    'com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter': 'HtmlFormIdp',
    'com.pingidentity.adapters.identifierfirst.idp.IdentifierFirstAdapter': 'IdentifierFirst',
    'com.pingidentity.adapters.passthrough.idp.PassthroughIdpAdapter': 'Passthrough',
    'com.pingidentity.adapters.pingone.davinci.PingOneDaVinciAdapter': 'PingOneDaVinci',
    'com.pingidentity.adapters.pingone.protect.PingOneProtectIdpAdapter': 'PingOneProtect',
    'com.pingidentity.adapters.pingone.verify.PingOneVerifyAdapter': 'PingOneVerify',
    'com.pingidentity.adapters.pingone.mfa.PingOneMfaIdpAdapter': 'PingOneMfa',
    'com.pingidentity.adapters.pingone.credentials.PingOneCredentialsAdapter': 'PingOneCredentials',
    'com.pingidentity.adapters.idp.facebook.FacebookAuthenticationAdapter': 'Facebook',
    'com.pingidentity.adapter.idp.google.GoogleAuthenticationAdapter': 'Google',
    'com.pingidentity.pf.adapters.referenceid.IdpBackchannelReferenceAuthnAdapter': 'BackchannelReference',
  };

  const fragments = find('authenticationPolicies/fragments');
  const fragMap = {};
  for (const f of fragments) fragMap[f.id] = f;

  function collectFragmentRefs(node) {
    if (!node) return { adapters: [], fragments: [] };
    const a = node.action ?? {};
    const refs = { adapters: [], fragments: [] };
    if (a.type === 'AUTHN_SOURCE') {
      const src = a.authenticationSource ?? {};
      if (src.type === 'IDP_ADAPTER' && src.sourceRef?.id) refs.adapters.push(src.sourceRef.id);
    }
    if (a.type === 'FRAGMENT' && a.fragment?.id) refs.fragments.push(a.fragment.id);
    for (const child of (node.children ?? [])) {
      const sub = collectFragmentRefs(child);
      refs.adapters.push(...sub.adapters);
      refs.fragments.push(...sub.fragments);
    }
    return refs;
  }

  const apcs = find('authenticationPolicyContracts');
  const apcMap = {};
  for (const a of apcs) apcMap[a.id] = a;

  const oidcPolicies = find('oauth/openIdConnect/policies');
  const dataStores = find('dataStores');
  const pcvs = find('passwordCredentialValidators');
  const lips = find('localIdentity/identityProfiles');

  const polOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'authenticationPolicies/default');
  const trees = polOp?.items?.[0]?.authnSelectionTrees ?? [];

  function walkTreeBranches(node) {
    const branches = [];
    for (const child of (node?.children ?? [])) {
      const ca = child.action ?? {};
      let target = null;
      let type = ca.type;
      if (ca.type === 'FRAGMENT') target = ca.fragment?.id;
      else if (ca.type === 'AUTHN_SELECTOR') target = ca.authenticationSelectorRef?.id;
      else if (ca.type === 'AUTHN_SOURCE') {
        const src = ca.authenticationSource ?? {};
        if (src.type === 'IDP_ADAPTER') { type = 'ADAPTER'; target = src.sourceRef?.id; }
      }
      const ctx = ca.context ?? null;
      if (target || type === 'DONE') branches.push({ context: ctx, type, target });
      if (child.children?.length) {
        const sub = walkTreeBranches(child);
        branches.push(...sub);
      }
    }
    return branches;
  }

  const clients = find('oauth/clients');
  const clientOidcPolicyMap = {};
  for (const c of clients) {
    const policyGroupId = c.oidcPolicy?.policyGroup?.id;
    if (policyGroupId) clientOidcPolicyMap[c.clientId] = policyGroupId;
  }

  const idpConns = find('sp/idpConnections');

  return {
    adapters, adapterMap, pluginShort: PLUGIN_SHORT,
    fragments, fragMap, apcs, apcMap, oidcPolicies,
    dataStores, pcvs, lips, trees, clients, clientOidcPolicyMap,
    idpConns, walkTreeBranches, collectFragmentRefs,
  };
}

// ---------------------------------------------------------------------------
// Normalize bulk export → canonical items
// ---------------------------------------------------------------------------

function normalizeToCanonical(bulkFilePath) {
  const raw = JSON.parse(fs.readFileSync(bulkFilePath, 'utf8'));
  const operations = raw?.data?.operations ?? [];

  const items = [];

  // Inventory across all resource types
  const inventory = {};
  for (const op of operations) {
    const type = (op.resourceType ?? '').replace(/^\//, '') || 'unknown';
    inventory[type] = (inventory[type] ?? 0) + (op.items?.length ?? 0);
  }

  // --- OIDC clients ---
  const clientsOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'oauth/clients');
  const clients = clientsOp?.items ?? [];
  for (const c of clients) {
    const rawGrants = c.grantTypes ?? [];
    items.push({
      id: c.clientId,
      name: c.clientId,
      type: 'oidc',
      enabled: c.enabled !== false,
      capabilities: {
        grantTypes: rawGrants,
        redirectUris: c.redirectUris ?? [],
        postLogoutUris: c.postLogoutRedirectUris ?? [],
        scopes: c.restrictedScopes ?? [],
        pkce: !!(c.requirePushedAuthorizationRequests || rawGrants.includes('AUTHORIZATION_CODE')),
        tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
      },
      concerns: [],
      classification: null,
      skipReason: null,
      source: c,
    });
  }

  // --- SAML SP connections ---
  const spOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'idp/spConnections');
  const spConnections = spOp?.items ?? [];
  for (const sp of spConnections) {
    const sso = sp.spBrowserSso ?? {};
    const acsUrls = (sso.ssoServiceEndpoints ?? []).map(e => e.url).filter(Boolean);
    items.push({
      id: sp.id,
      name: sp.name,
      type: 'saml',
      enabled: sp.active !== false,
      capabilities: {
        acsUrls,
        entityId: sp.entityId,
        nameIdFormat: SAML_NAMEID_MAP[sso.spSamlIdentityMapping] ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        signAssertions: sso.signAssertions ?? false,
        signResponse: sso.signResponseAsRequired ?? true,
        protocol: sso.protocol ?? 'SAML20',
      },
      concerns: [],
      classification: null,
      skipReason: null,
      source: sp,
    });
  }

  // --- Token managers (ATM) ---
  const atmOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'oauth/accessTokenManagers');
  const atms = atmOp?.items ?? [];
  for (const atm of atms) {
    const fields = atm.configuration?.fields ?? [];
    const lifetimeField = fields.find(f => f.name === 'Token Lifetime');
    const tokenLifetimeMins = parseInt(lifetimeField?.value ?? '60', 10);
    const ac = atm.accessControlSettings ?? {};
    const allowedClients = ac.restrictClients
      ? (ac.allowedClients ?? []).map(c => c.id)
      : [];
    items.push({
      id: atm.id,
      name: atm.name ?? atm.id,
      type: 'atm',
      enabled: true,
      capabilities: {
        introspectionEnabled: true,
        allowedClients,
        tokenLifetimeMins,
      },
      concerns: [],
      classification: null,
      skipReason: null,
      source: atm,
    });
  }

  // --- Signing key pairs ---
  const signingOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'keyPairs/signing');
  const signingItems = signingOp?.items ?? [];
  for (const kp of signingItems) {
    items.push({
      id: kp.id,
      name: kp.id,
      type: 'key',
      enabled: true,
      capabilities: {
        algorithm: kp.keyAlgorithm ?? 'RSA',
        keySize: kp.keySize ?? null,
        validityDays: CERT_DEFAULTS.validityPeriod,
        signatureAlgorithm: kp.signatureAlgorithm ?? null,
        subjectDN: kp.subjectDN ?? null,
      },
      concerns: [],
      classification: null,
      skipReason: null,
      source: kp,
    });
  }

  // --- SP-side IdP connections ---
  const idpConnOp = operations.find(op => (op.resourceType ?? '').replace(/^\//, '') === 'sp/idpConnections');
  const idpConns = idpConnOp?.items ?? [];
  for (const conn of idpConns) {
    const sso = conn.idpBrowserSso ?? {};
    const ssoEndpoints = sso.ssoServiceEndpoints ?? [];
    items.push({
      id: conn.id,
      name: conn.name,
      type: 'idp',
      enabled: conn.active !== false,
      capabilities: {
        protocol: sso.protocol ?? '',
        wsTrust: !!(conn.wsTrust),
        idpBrowserSso: !!(conn.idpBrowserSso),
        entityId: conn.entityId,
        ssoEndpoints,
        certs: conn.credentials?.certs ?? [],
      },
      concerns: [],
      classification: null,
      skipReason: null,
      source: conn,
    });
  }

  return { items, inventory, operations };
}

// ---------------------------------------------------------------------------
// Adapter interface
// ---------------------------------------------------------------------------

module.exports = {
  name: 'pingfederate',

  // CLI params needed in live mode (not needed when --import-file is set)
  params() {
    return ['pf-host', 'pf-user', 'pf-pass'];
  },

  /**
   * extract(args, workDir)
   *
   * If args.importFile is set, reads the native PF bulk JSON from disk.
   * Otherwise calls exportPf() to pull from the live PF API.
   *
   * Either way, normalizes to canonical item array and also returns
   * { inventory, signingItemsRaw, authAnalysis, bulkFilePath }
   * on args so ping-migration.js can access enriched key data and auth analysis.
   *
   * @returns {Array} canonical items
   */
  async extract(args, workDir) {
    let bulkFilePath;

    if (args.importFile) {
      // Offline mode: skip configure, auth, env create, and PF export
      if (!args.dryRun) {
        if (args.useProfile) {
          // profile already has credentials — nothing to do
        } else {
          configureProfile(args);
          authenticate(args);
        }
        if (args.skipEnvCreate) {
          info(`Skipping environment creation — targeting existing environment: ${args.destEnvId}`);
          resolveEnvName(args);
        } else {
          createTargetEnvironment(args);
        }
      } else {
        args.resolvedEnvName = args.destEnvName ?? 'offline-assessment';
      }
      bulkFilePath = loadBulkFile(args, workDir);
    } else {
      if (!args.useProfile) {
        configureProfile(args);
        authenticate(args);
      }
      if (args.skipEnvCreate) {
        info(`Skipping environment creation — targeting existing environment: ${args.destEnvId}`);
        resolveEnvName(args);
      } else {
        createTargetEnvironment(args);
      }
      bulkFilePath = exportPf(args, workDir);
    }

    const { items, inventory, operations } = normalizeToCanonical(bulkFilePath);

    // Enrich signing keys from live PF API (best-effort; silent on failure)
    const signingItems = items.filter(i => i.type === 'key').map(i => i.source);
    const enrichedKeys = enrichSigningKeys(signingItems, args);

    // Back-patch enriched key data into canonical items
    const enrichedMap = Object.fromEntries(enrichedKeys.map(e => [e.kp.id, e]));
    for (const item of items) {
      if (item.type === 'key') {
        const enriched = enrichedMap[item.id];
        if (enriched) {
          item.capabilities.algorithm = enriched.algorithm;
          item.capabilities.keySize = enriched.keyLength;
          item.capabilities.signatureAlgorithm = enriched.signatureAlgorithm;
          item._enriched = enriched; // stash for pingone-adapter to use
        }
      }
    }

    // Stash auth analysis on args for report writing
    args._bulkFilePath = bulkFilePath;
    args._authAnalysis = analyzeAuthPolicies(bulkFilePath);
    args._enrichedKeys = enrichedKeys;
    args._inventory = inventory;
    args._operations = operations;

    return items;
  },

  // Expose helpers so ping-migration.js can call them directly if needed
  configureProfile,
  authenticate,
  createTargetEnvironment,
  resolveEnvName,
  loadBulkFile,
  exportPf,
  enrichSigningKeys,
  analyzeAuthPolicies,
  normalizeToCanonical,
};
