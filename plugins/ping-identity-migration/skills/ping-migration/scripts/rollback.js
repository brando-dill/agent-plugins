#!/usr/bin/env node
/**
 * rollback.js
 *
 * Deletes all resources created by a migration run by parsing the migration report.
 *
 * Usage:
 *   node .claude/skills/ping-migration/rollback.js \
 *     --report  <path-to-migration-report.md> \
 *     --profile <pingcli-profile> \
 *     [--dry-run]
 *
 * Options:
 *   --report    Path to the migration report markdown file  (required)
 *   --profile   pingcli profile to use (required)
 *   --dry-run   Print what would be deleted without deleting anything
 *
 * The rollback is report-driven, not adapter-driven: it reads the "## Applied resources"
 * table from the migration report and issues deletes by resource type.  It does not need
 * to know anything about the source system.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');

const GREEN = '\x1b[32m';
const RED   = '\x1b[31m';
const BLUE  = '\x1b[34m';
const BOLD  = '\x1b[1m';
const RESET = '\x1b[0m';

const ok      = (msg) => console.log(`  ${GREEN}✔${RESET}  ${msg}`);
const fail    = (msg) => console.log(`  ${RED}✖${RESET}  ${msg}`);
const info    = (msg) => console.log(`  ${BLUE}→${RESET}  ${msg}`);
const section = (msg) => console.log(`\n${BOLD}${msg}${RESET}`);

function parseArgs() {
  const argv = process.argv.slice(2);
  const args = { report: null, profile: null, dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--report')  { args.report  = argv[++i]; continue; }
    if (argv[i] === '--profile') { args.profile = argv[++i]; continue; }
    if (argv[i] === '--dry-run') { args.dryRun  = true;      continue; }
    if (argv[i] === '--help' || argv[i] === '-h') {
      console.log(fs.readFileSync(__filename, 'utf8').match(/\/\*\*([\s\S]*?)\*\//)[0]);
      process.exit(0);
    }
  }
  if (!args.report || !args.profile) {
    console.error('Usage: node rollback.js --report <path> --profile <profile> [--dry-run]');
    process.exit(1);
  }
  return args;
}

function parseReport(reportPath) {
  const text = fs.readFileSync(reportPath, 'utf8');

  // Extract environment ID from "## Summary" block
  const envMatch = text.match(/- Environment: `([0-9a-f-]{36})`/);
  if (!envMatch) throw new Error('Could not find environment ID in report');
  const envId = envMatch[1];

  const apps = [];       // OIDC + SAML — deleted via applications delete
  const resources = [];  // ATM — deleted via resources delete
  const keys = [];       // Signing keys — deleted via raw API

  // Parse the "## Applied resources" table
  // Format: | Name | Type | `id` | Created... |
  const tableRegex = /^\| .+? \| (OIDC|SAML|ATM|Signing key)[^\|]* \| `([0-9a-f-]{36})` \| Created/gm;
  let match;
  while ((match = tableRegex.exec(text)) !== null) {
    const typePrefix = match[1];
    const id = match[2];
    if (typePrefix === 'ATM') {
      resources.push(id);
    } else if (typePrefix === 'Signing key') {
      keys.push(id);
    } else {
      apps.push(id);
    }
  }

  return { envId, apps, resources, keys };
}

function pingcliDelete(args, cmd) {
  const { profile, dryRun } = args;
  if (dryRun) {
    info(`[dry-run] pingcli --profile ${profile} ${cmd.join(' ')}`);
    return;
  }
  try {
    execFileSync('pingcli', ['--profile', profile, ...cmd], { encoding: 'utf8' });
  } catch (err) {
    const msg = err.stderr?.toString() ?? err.message;
    throw new Error(msg.trim());
  }
}

function deleteApps(apps, args) {
  section(`Step 1 — Delete applications (${apps.length})`);
  let deleted = 0, errored = 0;
  for (const appId of apps) {
    try {
      pingcliDelete(args, [
        'pingone', 'applications', 'delete',
        '--environment-id', args.envId,
        '--application-id', appId,
      ]);
      ok(appId);
      deleted++;
    } catch (err) {
      fail(`${appId} | ${err.message}`);
      errored++;
    }
  }
  info(`${deleted} deleted${errored ? `  Errors: ${errored}` : ''}`);
}

function deleteResources(resources, args) {
  section(`Step 2 — Delete ATM resources (${resources.length})`);
  let deleted = 0, errored = 0;
  for (const resourceId of resources) {
    try {
      pingcliDelete(args, [
        'pingone', 'resources', 'delete',
        '--environment-id', args.envId,
        '--resource-id', resourceId,
      ]);
      ok(resourceId);
      deleted++;
    } catch (err) {
      fail(`${resourceId} | ${err.message}`);
      errored++;
    }
  }
  info(`${deleted} deleted${errored ? `  Errors: ${errored}` : ''}`);
}

function deleteKeys(keys, args) {
  section(`Step 3 — Delete signing keys (${keys.length})`);
  let deleted = 0, errored = 0;
  for (const keyId of keys) {
    try {
      pingcliDelete(args, [
        '--output-format', 'json',
        'pingone', 'api',
        '--http-method', 'DELETE',
        `environments/${args.envId}/keys/${keyId}`,
      ]);
      ok(keyId);
      deleted++;
    } catch (err) {
      fail(`${keyId} | ${err.message}`);
      errored++;
    }
  }
  info(`${deleted} deleted${errored ? `  Errors: ${errored}` : ''}`);
}

function main() {
  const args = parseArgs();

  const { envId, apps, resources, keys } = parseReport(args.report);
  args.envId = envId;

  console.log(`\n${BOLD}Migration Rollback${RESET}`);
  console.log(`  Report   : ${args.report}`);
  console.log(`  Env ID   : ${envId}`);
  console.log(`  Profile  : ${args.profile}`);
  console.log(`  Dry run  : ${args.dryRun}`);
  console.log(`  Apps     : ${apps.length}`);
  console.log(`  Resources: ${resources.length}`);
  console.log(`  Keys     : ${keys.length}`);
  console.log(`  Total    : ${apps.length + resources.length + keys.length}`);

  if (!args.dryRun) {
    console.log(`\n${RED}${BOLD}This will permanently delete ${apps.length + resources.length + keys.length} resources from PingOne env ${envId}.${RESET}`);
    console.log('Starting in 3 seconds — Ctrl+C to abort...');
    // Synchronous 3-second pause
    const end = Date.now() + 3000;
    while (Date.now() < end) { /* spin */ }
  }

  deleteApps(apps, args);
  deleteResources(resources, args);
  deleteKeys(keys, args);

  section('Done');
  console.log(`  Apps deleted     : ${apps.length}`);
  console.log(`  Resources deleted: ${resources.length}`);
  console.log(`  Keys deleted     : ${keys.length}`);
  if (args.dryRun) console.log(`\n  (Dry run — nothing was actually deleted)`);
}

main();
