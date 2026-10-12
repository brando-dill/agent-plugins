#!/usr/bin/env node
/**
 * ping-migration.js
 *
 * Migration orchestrator.
 * Migrates identity applications from any supported source to any supported destination.
 *
 * Usage:
 *   node ping-migration.js --source <source> --destination <dest> [options]
 *
 * Required:
 *   --source           Source system: pingfederate | p14e
 *   --destination      Destination system: pingone
 *
 * Source credentials (required in live mode when source=pingfederate):
 *   --pf-host          PingFederate admin HTTPS host (e.g. https://pf-admin.example.com:9999)
 *   --pf-user          PingFederate admin username
 *   --pf-pass          PingFederate admin password
 *
 * Source credentials (required in live mode when source=p14e):
 *   --p14e-url                    PingOne for Enterprise admin API base URL
 *                                 (default: https://admin-api.pingone.com/v3)
 *   --p14e-username               P14E admin username
 *   --p14e-password               P14E admin password
 *   --p14e-cloud-migration-key    Optional key to decrypt exported certificate PKCS12 bundles
 *
 * Destination credentials (required when destination=pingone, except --import-file --dry-run):
 *   --dest-env-id      Destination PingOne environment UUID
 *   --dest-client-id   PingOne worker app client ID
 *   --dest-client-secret PingOne worker app client secret
 *
 * Optional:
 *   --import-file      Path to a pre-exported source-native file (skips live source steps)
 *   --dest-env-name    Name for the new destination environment (default: prompted)
 *   --dest-region      PingOne region root domain (default: pingone.com)
 *   --dest-auth-env-id Environment ID where the worker app lives (if different from --dest-env-id)
 *   --use-profile      Use an existing configured pingcli profile as-is
 *   --skip-env-create  Skip environment creation; migrate into existing --dest-env-id
 *   --work-dir         Directory for payload files (default: ./migration-output)
 *   --enable-apps      Create applications as enabled (default: disabled)
 *   --insecure-pf      Trust all TLS on PingFederate (useful for dev/self-signed certs)
 *   --dry-run          Export and classify only; do not apply to destination
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// Adapter registry
// ---------------------------------------------------------------------------

const SOURCES = {
  'pingfederate': require('./adapters/sources/pf-adapter'),
  'p14e': require('./adapters/sources/p14e-adapter'),
};

const DESTINATIONS = {
  'pingone': require('./adapters/destinations/pingone-adapter'),
};

// ---------------------------------------------------------------------------
// Classifier + report writer
// ---------------------------------------------------------------------------

const { rationalize } = require('./classifier');
const { writeAssessmentReport, writeMigrationReport } = require('./reports');

// ---------------------------------------------------------------------------
// ANSI helpers
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
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs() {
  const argv = process.argv.slice(2);
  const args = {
    source: null,
    destination: null,
    importFile: null,
    // Destination (PingOne) params — also kept as legacy aliases
    destEnvId: null,
    destClientId: null,
    destClientSecret: null,
    destRegion: 'pingone.com',
    destAuthEnvId: null,
    destEnvName: null,
    // Legacy PF params
    pfHost: null,
    pfUser: null,
    pfPass: null,
    insecurePf: false,
    // P14E params
    p14eUrl: null,
    p14eUsername: null,
    p14ePassword: null,
    p14eCloudMigrationKey: null,
    // Profile
    profile: 'migration-run',
    useProfile: null,
    // Behaviour
    skipEnvCreate: false,
    workDir: './migration-output',
    dryRun: false,
    enableApps: false,
  };

  const flagMap = {
    '--source': 'source',
    '--destination': 'destination',
    '--import-file': 'importFile',
    '--dest-env-id': 'destEnvId',
    '--dest-client-id': 'destClientId',
    '--dest-client-secret': 'destClientSecret',
    '--dest-region': 'destRegion',
    '--dest-auth-env-id': 'destAuthEnvId',
    '--dest-env-name': 'destEnvName',
    '--pf-host': 'pfHost',
    '--pf-user': 'pfUser',
    '--pf-pass': 'pfPass',
    '--p14e-url': 'p14eUrl',
    '--p14e-username': 'p14eUsername',
    '--p14e-password': 'p14ePassword',
    '--p14e-cloud-migration-key': 'p14eCloudMigrationKey',
    '--profile': 'profile',
    '--use-profile': 'useProfile',
    '--work-dir': 'workDir',
  };

  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--dry-run') { args.dryRun = true; continue; }
    if (flag === '--insecure-pf') { args.insecurePf = true; continue; }
    if (flag === '--skip-env-create') { args.skipEnvCreate = true; continue; }
    if (flag === '--enable-apps') { args.enableApps = true; continue; }
    if (flagMap[flag]) {
      args[flagMap[flag]] = argv[++i];
      continue;
    }
    if (flag === '--help' || flag === '-h') {
      // Print the header JSDoc block
      console.log(fs.readFileSync(__filename, 'utf8').match(/\/\*\*([\s\S]*?)\*\//)[0]);
      process.exit(0);
    }
    // Unknown flag — ignore silently (adapter-specific flags flow through args)
  }

  // --use-profile mode
  if (args.useProfile) {
    args.profile = args.useProfile;
    if (!args.destEnvId) {
      try {
        const out = execFileSync(
          'pingcli', ['config', 'get', '--profile', args.useProfile,
          'service.pingOne.endpoint.environmentID'],
          { encoding: 'utf8' }
        );
        const match = out.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
        args.destEnvId = match ? match[0] : null;
      } catch { /* ignore */ }
    }
  }

  // Validate required args
  if (!args.source) {
    console.error('Missing required argument: --source');
    console.error(`  Supported sources: ${Object.keys(SOURCES).join(', ')}`);
    process.exit(1);
  }
  if (!args.destination) {
    console.error('Missing required argument: --destination');
    console.error(`  Supported destinations: ${Object.keys(DESTINATIONS).join(', ')}`);
    process.exit(1);
  }
  if (!SOURCES[args.source]) {
    console.error(`Unknown source '${args.source}'. Supported: ${Object.keys(SOURCES).join(', ')}`);
    process.exit(1);
  }
  if (!DESTINATIONS[args.destination]) {
    console.error(`Unknown destination '${args.destination}'. Supported: ${Object.keys(DESTINATIONS).join(', ')}`);
    process.exit(1);
  }

  return args;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs();

  const src = SOURCES[args.source];
  const dest = DESTINATIONS[args.destination];

  const srcName = src.displayName ?? args.source;
  const destName = dest.displayName ?? args.destination;

  console.log(`\n${BOLD}${srcName} → ${destName} Migration${RESET}`);
  console.log(`  Source       : ${args.source}`);
  console.log(`  Destination  : ${args.destination}`);
  console.log(`  Profile      : ${args.profile}${args.useProfile ? ' (existing — skipping configure + auth)' : ''}`);
  console.log(`  Import file  : ${args.importFile ?? '(live mode)'}`);
  console.log(`  Dest env     : ${args.destEnvId ?? '(none — dry run)'}`);
  console.log(`  Work dir     : ${args.workDir}`);
  console.log(`  Dry run      : ${args.dryRun}`);

  // -------------------------------------------------------------------------
  // Step 1–4: Extract canonical items from source
  // -------------------------------------------------------------------------
  section(`Step 1–4 — Extract from ${srcName}`);
  const workDir = path.resolve(args.workDir);
  fs.mkdirSync(workDir, { recursive: true });

  let items;
  try {
    items = await src.extract(args, workDir);
  } catch (err) {
    console.error(`${RED}${BOLD}Source extraction failed:${RESET} ${err.message}`);
    process.exit(1);
  }

  ok(`Extracted ${items.length} items from ${srcName}`);

  // -------------------------------------------------------------------------
  // Step 5: Classify
  // -------------------------------------------------------------------------
  section('Step 5 — Rationalize & classify');
  const destCaps = dest.caps();
  const classified = rationalize(items, destCaps);

  const { direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect,
    signingDirect, idpConnDirect, idpConnOutOfScope, inventory } = classified;

  // Retrieve enriched key data stashed by pf-adapter during extraction
  const enrichedKeys = args._enrichedKeys ?? signingDirect.map(s => ({ kp: s.kp ?? s, algorithm: 'RSA', keyLength: 3072, signatureAlgorithm: 'SHA256withRSA', deficient: false }));

  // -------------------------------------------------------------------------
  // Step 6: Write assessment report (always, even on dry-run)
  // -------------------------------------------------------------------------
  section('Step 6 — Write assessment report');
  writeAssessmentReport(
    args, direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect, signingDirect,
    idpConnDirect, idpConnOutOfScope, inventory, args._authAnalysis ?? null,
    srcName, destName
  );

  if (args.dryRun) {
    info(`Dry run — stopping before apply. Review payload files in ${workDir}`);
    process.exit(0);
  }

  // -------------------------------------------------------------------------
  // Steps 6a–6e: Build payload files (pingone-adapter exposes batch builders)
  // -------------------------------------------------------------------------

  // For PingOne destination, delegate to the adapter's batch pipeline
  // (which preserves all the detailed file-per-item output, metadata, grants, validation).
  // Other destinations use the generic transform/apply/validate loop below.
  if (args.destination === 'pingone' && typeof dest.buildOidcPayloads === 'function') {
    return await runPingOnePipeline(dest, args, workDir, direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect, enrichedKeys, idpConnDirect, idpConnOutOfScope, srcName, destName);
  }

  // -------------------------------------------------------------------------
  // Generic transform → apply → validate loop (for non-PingOne destinations)
  // -------------------------------------------------------------------------
  section('Step 7 — Apply to destination');
  const results = [];
  const directItems = classified.direct ?? [];

  for (const entry of directItems) {
    const item = entry.item ?? entry;
    try {
      const payload = dest.transform(item);
      const { id, status } = await dest.apply(payload, { item, args, workDir });
      ok(`${item.name ?? item.id} | ${status} | id=${id}`);
      results.push({ item, id, status, success: true });
    } catch (err) {
      fail(`${item.name ?? item.id} | ${err.message}`);
      results.push({ item, id: null, status: 'failed', success: false, error: err.message });
    }
  }

  section('Step 8 — Validate');
  let overallSuccess = true;
  const validationResults = [];
  for (const r of results) {
    if (!r.success) {
      validationResults.push({ id: r.item.id, name: r.item.name, pass: false, details: { issues: [r.error] } });
      overallSuccess = false;
      continue;
    }
    try {
      const { pass, details } = await dest.validate(r.id, r.item, { args, workDir });
      if (pass) {
        ok(`${r.item.name ?? r.item.id} | PASS`);
      } else {
        fail(`${r.item.name ?? r.item.id} | FAIL | ${(details.issues ?? []).join(', ')}`);
        overallSuccess = false;
      }
      validationResults.push({ id: r.item.id, name: r.item.name, pass, details });
    } catch (err) {
      fail(`${r.item.name ?? r.item.id} | validate error: ${err.message}`);
      overallSuccess = false;
      validationResults.push({ id: r.item.id, name: r.item.name, pass: false, details: { issues: [err.message] } });
    }
  }

  // Write migration report (minimal for non-PingOne destinations)
  writeMigrationReport(
    args,
    results.filter(r => r.item.type === 'oidc').map(r => ({ clientId: r.item.id, appId: r.id, poGrants: r.item.capabilities?.grantTypes ?? [], success: r.success, pf: r.item.source ?? r.item })),
    results.filter(r => r.item.type === 'saml').map(r => ({ name: r.item.name, appId: r.id, success: r.success, pf: r.item.source ?? r.item })),
    results.filter(r => r.item.type === 'atm').map(r => ({ name: r.item.name, resourceId: r.id, success: r.success, pf: r.item.source ?? r.item, tokenLifetimeSecs: 0, originalTokenSecs: 0 })),
    results.filter(r => r.item.type === 'key').map(r => ({ name: r.item.name, keyId: r.id, success: r.success, deficient: false })),
    results.filter(r => r.item.type === 'idp').map(r => ({ name: r.item.name, idpId: r.id, success: r.success, pf: r.item.source ?? r.item })),
    redesign, outOfScope, samlOutOfScope,
    {},
    validationResults.map(v => ({ clientId: v.name ?? v.id, enabled: true, grants: [], pkce: '?', resourceGrants: 0, pass: v.pass, issues: v.details?.issues ?? [] })),
    srcName, destName
  );

  process.exit(overallSuccess ? 0 : 1);
}

// ---------------------------------------------------------------------------
// PingOne-specific pipeline (full metadata, grants, validation, reporting)
// ---------------------------------------------------------------------------

async function runPingOnePipeline(dest, args, workDir, direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect, enrichedKeys, idpConnDirect, idpConnOutOfScope, srcName, destName) {
  const payloads = dest.buildOidcPayloads(direct, workDir, args.enableApps);
  const samlPayloads = dest.buildSamlPayloads(samlDirect, workDir, args.enableApps);
  const atmPayloads = dest.buildAtmPayloads(atmDirect, workDir);
  const signingPayloads = dest.buildSigningKeyPayloads(enrichedKeys, workDir);
  const idpConnPayloads = dest.buildIdpConnPayloads(idpConnDirect, workDir, args.enableApps);

  const appResults = dest.applyApps(payloads, args);
  const samlResults = dest.applySamlApps(samlPayloads, args);
  const atmResults = dest.applyAtms(atmPayloads, args);
  const signingResults = dest.applySigningKeys(signingPayloads, args);
  const idpConnResults = dest.applyIdpConnections(idpConnPayloads, args);

  dest.writeAppMetadata(appResults, samlResults, atmResults, signingResults, args, workDir);

  const grantDetails = dest.createGrants(appResults, args, workDir);

  const { success, details: validationDetails } = dest.validateBatch(appResults, args);

  dest.printSummary(appResults, samlResults, atmResults, signingResults, idpConnResults, args);

  writeMigrationReport(
    args, appResults, samlResults, atmResults, signingResults, idpConnResults,
    redesign, outOfScope, samlOutOfScope,
    grantDetails, validationDetails,
    srcName, destName
  );

  process.exit(success ? 0 : 1);
}

main().catch(err => {
  console.error(`${RED}${BOLD}Fatal error:${RESET} ${err.message}`);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
