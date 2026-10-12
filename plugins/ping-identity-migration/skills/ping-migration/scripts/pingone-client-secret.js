#!/usr/bin/env node
/**
 * pingone-client-secret.js
 *
 * Three related actions for PingOne "imported" OIDC applications and custom
 * resources:
 *
 *   --action import        Create a new application or custom resource with a
 *                           custom clientId, so it qualifies as "imported".
 *                           This script never sends a clientSecret on import —
 *                           PingOne always auto-generates one — use
 *                           --action set-secret afterward to assign a custom value.
 *   --action set-secret     (default) Set a custom clientSecret value on an
 *                           app/resource that was already imported (created with
 *                           a custom clientId via --action import).
 *   --action rollback       Delete (roll back) a previously imported app/resource,
 *                           e.g. to undo a test import or a failed migration wave.
 *
 * Each action can run once (via --type/--id/--client-id/--secret/--name flags)
 * or in batch against a CSV file (via --csv). See "CSV batch mode" below.
 *
 * Background:
 *   An application or custom resource becomes "imported" when it is created
 *   via POST /applications or POST /resources with a custom `clientId` in the
 *   request body. The `clientSecret` property is documented as optional on
 *   that same import request, but this script deliberately never sends it —
 *   every import lets PingOne auto-generate the secret. `--action set-secret`
 *   then lets you go back and set that secret to a custom value once you have
 *   it — e.g. once a secret recovered from the source system (PingFederate,
 *   etc.) becomes available.
 *
 *   Set-secret applies ONLY to imported applications/resources — it cannot be
 *   used to set a custom secret on an app/resource that was created normally
 *   (without a custom clientId) via the admin console or a plain API create
 *   call. PingOne returns an error in that case. `--action import` exists so
 *   you have something import-eligible to test set-secret against.
 *
 *   Setting a custom clientId/clientSecret on import requires the environment
 *   to have the underlying feature flags enabled (P14C-61681 for custom
 *   clientId on import, P14C-68917 for the set-secret capability) — without
 *   them, PingOne rejects the request. Contact your PingOne representative to
 *   confirm these are enabled for the target environment before running
 *   --action import or --action set-secret.
 *
 * Endpoints:
 *   POST   /environments/{envId}/applications                         (import, Content-Type: application/json)
 *   POST   /environments/{envId}/resources                            (import, Content-Type: application/json)
 *   POST   /environments/{envId}/applications/{applicationId}/secret   (set-secret, Content-Type: application/vnd.pingidentity.secret+json)
 *   POST   /environments/{envId}/resources/{resourceId}/secret        (set-secret, Content-Type: application/vnd.pingidentity.secret+json)
 *   GET    /environments/{envId}/applications | /resources            (rollback/set-secret --csv: resolve id by clientId)
 *   DELETE on /environments/{envId}/applications/{applicationId}      (rollback)
 *   DELETE on /environments/{envId}/resources/{resourceId}            (rollback)
 *
 * Required PingOne worker-app permissions (granted via Environment Admin role):
 *   applications:import:application  — for --action import   --type application
 *   resources:import:resource        — for --action import   --type resource
 *   applications:set:secret          — for --action set-secret --type application
 *   resources:set:secret             — for --action set-secret --type resource
 *   (standard read/delete application/resource permissions — for --action rollback,
 *    and for resolving ids by clientId when using --csv)
 *
 * Secret input:
 *   For --action set-secret, the secret value is best supplied via the PINGONE_CLIENT_SECRET
 *   environment variable rather than --secret, since command-line arguments are visible to
 *   other local users via `ps`/`/proc` and get written to shell history. --secret still works
 *   (for scripting contexts where an env var isn't practical) but PINGONE_CLIENT_SECRET takes
 *   precedence when both are set, and a warning is printed if --secret is used at all.
 *
 * Usage:
 *   # Import: create a single application or custom resource with a custom clientId
 *   # (PingOne auto-generates the secret; follow up with --action set-secret for a custom value)
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action         import \
 *     --type           application | resource \
 *     --env-id         <pingone-environment-uuid> \
 *     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
 *     [--client-id     <custom-client-id>] \
 *     [--name          <display-name>] \
 *     [--description   <description>] \
 *     [--app-type      <WEB_APP|NATIVE_APP|SPA|WORKER|CUSTOM|...>] \
 *     [--dry-run]
 *
 *   # Set-secret: assign a custom clientSecret to a single already-imported app/resource
 *   PINGONE_CLIENT_SECRET=<custom-secret-value> node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --type           application | resource \
 *     --id             <applicationId-or-resourceId> \
 *     --env-id         <pingone-environment-uuid> \
 *     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
 *     [--previous-expires-at <ISO-8601-timestamp>] \
 *     [--dry-run]
 *
 *   # Rollback: delete a single previously imported app/resource
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action         rollback \
 *     --type           application | resource \
 *     --id             <applicationId-or-resourceId> \
 *     --env-id         <pingone-environment-uuid> \
 *     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
 *     [--dry-run]
 *
 *   # CSV batch mode — any action (import, set-secret, or rollback), looping over every row in a CSV file
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action         import | set-secret | rollback \
 *     --csv            <path-to.csv> \
 *     --env-id         <pingone-environment-uuid> \
 *     [--profile       <pingcli-profile>]   (uses pingcli's default profile if omitted) \
 *     [--type          application | resource]   (optional filter — process only matching rows) \
 *     [--dry-run]
 *
 * Examples:
 *   # Import: create a WEB_APP application with a custom clientId (secret is auto-generated)
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        import \
 *     --type          application \
 *     --client-id     legacy-crm-app-001 \
 *     --name          "Legacy CRM App" \
 *     --app-type      WEB_APP \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # Import: create a CUSTOM resource with a custom clientId
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        import \
 *     --type          resource \
 *     --client-id     billing-api-resource-001 \
 *     --name          "Billing API" \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # Set-secret: assign a custom clientSecret to an already-imported application (by its PingOne id)
 *   PINGONE_CLIENT_SECRET=S3cr3t-Crm-App-001 node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        set-secret \
 *     --type          application \
 *     --id            b1ad4ce0-f873-4807-9094-9d9b787e7d0f \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # Set-secret: assign a custom clientSecret and keep the old one valid for 30 more days
 *   PINGONE_CLIENT_SECRET=S3cr3t-Billing-Res-001 node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        set-secret \
 *     --type          resource \
 *     --id            65316d5c-8dc4-4c74-9251-4bff66c1973d \
 *     --previous-expires-at 2026-08-07T00:00:00Z \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # Rollback: delete a previously imported application by its PingOne id
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        rollback \
 *     --type          application \
 *     --id            b1ad4ce0-f873-4807-9094-9d9b787e7d0f \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # CSV batch — import: create every row in migration-secrets/pf-secrets.csv (5 apps + 5 resources)
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        import \
 *     --csv           migration-secrets/pf-secrets.csv \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # CSV batch — set-secret: set/rotate secrets for every row, resolving each id by its clientId
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        set-secret \
 *     --csv           migration-secrets/pf-secrets.csv \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox
 *
 *   # CSV batch — rollback: delete only the application rows, previewing first
 *   node .claude/skills/ping-migration/pingone-client-secret.js \
 *     --action        rollback \
 *     --csv           migration-secrets/pf-secrets.csv \
 *     --type          application \
 *     --env-id        6b3de08f-caaa-4b4c-827a-bfd8b4d93d16 \
 *     --profile       sandbox \
 *     --dry-run
 *
 * CSV batch mode:
 *   Required columns: recordType, name, type, clientId, clientSecret
 *     recordType   "application" or "resource"
 *     name         Display name
 *     type         PingOne app type (WEB_APP, NATIVE_APP, SPA, WORKER, ...) or resource
 *                  type (CUSTOM) — passed through to --app-type per row
 *     clientId     Custom clientId. For --action import, this is set on creation.
 *                  For --action set-secret / rollback, this is used to look up the
 *                  PingOne-generated id (there is no id column in the CSV).
 *     clientSecret Custom secret. Used ONLY for --action set-secret (sets/rotates the
 *                  secret). Ignored for --action import (PingOne always auto-generates
 *                  the secret on import — see note above) and for --action rollback.
 *   See migration-secrets/pf-secrets.csv for an example file.
 *   Rows with an invalid recordType are skipped with a warning; unresolvable clientIds
 *   (set-secret/rollback) are skipped with a warning. A per-row failure does not abort
 *   the batch — a summary of succeeded/failed/skipped is printed at the end, and the
 *   process exits 1 if any row failed.
 *
 * Options:
 *   --action                 Optional. "set-secret" (default), "import", or "rollback".
 *   --type                   Required unless --csv is used. "application" or "resource".
 *                             With --csv, optional — filters the batch to matching rows.
 *   --id                     Required for --action set-secret/rollback when not using --csv.
 *                             The applicationId or resourceId (PingOne-generated `id`, not
 *                             the custom clientId) of the imported app/resource.
 *   --secret                 Required for --action set-secret unless PINGONE_CLIENT_SECRET is
 *                             set (preferred — avoids the secret appearing in shell history or
 *                             `ps` output). Custom secret value, 8-1024 characters. Not used by
 *                             --action import — PingOne always auto-generates the secret on
 *                             import; use --action set-secret afterward to assign a custom value.
 *   --client-id               Optional, --action import only. Custom clientId, 8-256 characters,
 *                             unique within the environment. If omitted, a sample value is
 *                             generated so the created item still qualifies as "imported".
 *   --name                   Optional, --action import only. Display name. Defaults to a
 *                             generated sample name.
 *   --description             Optional, --action import only. Defaults to a generic note that
 *                             this is a sample created by this script.
 *   --app-type                Optional, --action import only. PingOne application type
 *                             (WEB_APP, NATIVE_APP, SPA, WORKER) or resource type (CUSTOM).
 *                             Defaults to WEB_APP for applications, CUSTOM for resources.
 *   --csv                    Path to a CSV file — see "CSV batch mode" above. When provided,
 *                             --id/--client-id/--secret/--name/--description are ignored in
 *                             favor of per-row CSV values (--secret/CSV clientSecret still
 *                             only applies to --action set-secret, never --action import).
 *   --env-id                 Required. PingOne environment UUID.
 *   --profile                Optional. pingcli profile with worker-app credentials for that env.
 *                             If omitted, pingcli's own configured default profile is used.
 *   --previous-expires-at    Optional, --action set-secret only. ISO-8601 timestamp. If set, the
 *                             app/resource's current secret is retained as a valid "previous"
 *                             secret until this time (max 30 days out) instead of being
 *                             invalidated immediately.
 *   --dry-run                Print the request(s) that would be sent without sending them.
 *                             In CSV mode with set-secret/rollback, id lookups still run live
 *                             (read-only) so the preview reflects real resolved ids.
 *
 * Note: the exact request body schema for set-secret (a top-level `secret` property, with an
 * optional `previous: { expiresAt }` object) is inferred from the sibling "Update Application
 * Secret" (rotate) endpoint's documented `previous` behavior, which is expected to apply the
 * same semantics here. The sample import payloads use minimal, reasonable defaults per
 * app/resource type — verify field names against the current PingOne Platform API Reference
 * before relying on this in production, in case anything changed before GA.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const GREEN = '\x1b[32m';
const RED   = '\x1b[31m';
const BLUE  = '\x1b[34m';
const BOLD  = '\x1b[1m';
const RESET = '\x1b[0m';

const ok      = (msg) => console.log(`  ${GREEN}✔${RESET}  ${msg}`);
const fail    = (msg) => console.log(`  ${RED}✖${RESET}  ${msg}`);
const info    = (msg) => console.log(`  ${BLUE}→${RESET}  ${msg}`);
const section = (msg) => console.log(`\n${BOLD}${msg}${RESET}`);

const TYPE_TO_PATH_SEGMENT   = { application: 'applications', resource: 'resources' };
const TYPE_TO_SET_PERMISSION = { application: 'applications:set:secret', resource: 'resources:set:secret' };
const TYPE_TO_IMPORT_PERMISSION = { application: 'applications:import:application', resource: 'resources:import:resource' };
const CSV_RECORD_TYPES = new Set(['application', 'resource']);

/** Omitting --profile lets pingcli fall back to its own configured default profile. */
function profileFlags(profile) {
  return profile ? ['--profile', profile] : [];
}

const profileLabel = (profile) => profile || '(pingcli default)';

// ---------------------------------------------------------------------------
// pingcli invocation + API error extraction
// ---------------------------------------------------------------------------

/**
 * Runs a pingcli command and returns { ok, stdout } on success, or throws an
 * Error carrying { summary, apiError, raw } on failure so callers can surface
 * the actual API error response, not just a generic exit-code message.
 */
function callPingcli(cliArgs) {
  try {
    const stdout = execFileSync('pingcli', cliArgs, { encoding: 'utf8' });
    return { stdout };
  } catch (err) {
    const stdoutText = err.stdout?.toString() ?? '';
    const stderrText = err.stderr?.toString() ?? '';
    let apiError = null;
    try { apiError = JSON.parse(stdoutText); } catch { /* not JSON */ }
    if (!apiError) {
      try { apiError = JSON.parse(stderrText); } catch { /* not JSON */ }
    }

    const apiErrors = apiError?.errors ?? apiError?.data?.errors ?? [];
    const summary = apiErrors[0]?.message ?? apiError?.message ?? (stderrText.trim() || err.message);

    const wrapped = new Error(summary);
    wrapped.summary = summary;
    wrapped.apiError = apiError;
    wrapped.raw = stdoutText.trim() || stderrText.trim();
    throw wrapped;
  }
}

/** Prints the full API error response body under a failure, when available. */
function printApiErrorDetail(err) {
  if (err.apiError) {
    console.error(`\n  ${BOLD}API error response:${RESET}`);
    console.error(JSON.stringify(err.apiError, null, 2).replace(/^/gm, '    '));
  } else if (err.raw) {
    console.error(`\n  ${BOLD}API error response (raw):${RESET}`);
    console.error(err.raw.replace(/^/gm, '    '));
  }
}

function parseArgs() {
  const argv = process.argv.slice(2);
  const args = {
    action: 'set-secret', type: null, id: null, secret: null, envId: null, profile: null,
    previousExpiresAt: null, clientId: null, name: null, description: null, appType: null,
    csv: null, dryRun: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--action')              { args.action            = argv[++i]; continue; }
    if (flag === '--type')                { args.type              = argv[++i]; continue; }
    if (flag === '--id')                  { args.id                = argv[++i]; continue; }
    if (flag === '--secret')              { args.secret            = argv[++i]; continue; }
    if (flag === '--client-id')           { args.clientId          = argv[++i]; continue; }
    if (flag === '--name')                { args.name              = argv[++i]; continue; }
    if (flag === '--description')         { args.description       = argv[++i]; continue; }
    if (flag === '--app-type')            { args.appType           = argv[++i]; continue; }
    if (flag === '--csv')                 { args.csv               = argv[++i]; continue; }
    if (flag === '--env-id')              { args.envId             = argv[++i]; continue; }
    if (flag === '--profile')             { args.profile           = argv[++i]; continue; }
    if (flag === '--previous-expires-at') { args.previousExpiresAt = argv[++i]; continue; }
    if (flag === '--dry-run')             { args.dryRun            = true;      continue; }
    if (flag === '--help' || flag === '-h') {
      console.log(fs.readFileSync(__filename, 'utf8').match(/\/\*\*([\s\S]*?)\*\//)[0]);
      process.exit(0);
    }
  }

  // PINGONE_CLIENT_SECRET takes precedence over --secret — command-line arguments are visible
  // to other local users via `ps`/`/proc` and get written to shell history, so the env var is
  // the preferred way to supply a secret. --secret still works for scripting contexts where an
  // env var isn't practical, but using it prints a warning.
  if (process.env.PINGONE_CLIENT_SECRET) {
    if (args.secret) {
      info('Both --secret and PINGONE_CLIENT_SECRET are set — using PINGONE_CLIENT_SECRET.');
    }
    args.secret = process.env.PINGONE_CLIENT_SECRET;
  } else if (args.secret) {
    info('--secret was passed on the command line — prefer the PINGONE_CLIENT_SECRET environment variable instead, since command-line arguments are visible to other local users via `ps`/`/proc` and get written to shell history.');
  }

  const errors = [];
  if (!['set-secret', 'import', 'rollback'].includes(args.action)) {
    errors.push('--action must be "set-secret", "import", or "rollback"');
  }
  if (!args.envId) errors.push('--env-id is required');

  if (args.csv) {
    if (args.type && !TYPE_TO_PATH_SEGMENT[args.type]) errors.push('--type must be "application" or "resource" when provided with --csv');
    if (!fs.existsSync(args.csv)) errors.push(`--csv file not found: ${args.csv}`);
  } else {
    if (!args.type || !TYPE_TO_PATH_SEGMENT[args.type]) errors.push('--type must be "application" or "resource"');

    if (args.action === 'set-secret' || args.action === 'rollback') {
      if (!args.id) errors.push(`--id is required for --action ${args.action}`);
    }
    if (args.action === 'set-secret' && !args.secret) {
      errors.push('--secret or PINGONE_CLIENT_SECRET is required for --action set-secret');
    }
    if (args.secret && (args.secret.length < 8 || args.secret.length > 1024)) {
      errors.push('--secret/PINGONE_CLIENT_SECRET must be between 8 and 1024 characters');
    }
    if (args.action === 'import' && args.secret) {
      info('--secret/PINGONE_CLIENT_SECRET is ignored for --action import — PingOne always auto-generates the secret on import. Use --action set-secret afterward to assign a custom value.');
      args.secret = null;
    }
    if (args.clientId && (args.clientId.length < 8 || args.clientId.length > 256)) {
      errors.push('--client-id must be between 8 and 256 characters');
    }
  }

  if (errors.length) {
    console.error('Usage:');
    console.error('  Import:     create a new app/resource with a custom clientId (secret is auto-generated)');
    console.error('    node pingone-client-secret.js --action import --type <application|resource> --env-id <uuid>');
    console.error('      [--profile <profile>] [--client-id <id>] [--name <name>] [--description <text>] [--app-type <type>] [--dry-run]');
    console.error('  Set secret: assign a custom clientSecret to an already-imported app/resource');
    console.error('    PINGONE_CLIENT_SECRET=<value> node pingone-client-secret.js --type <application|resource> --id <id> --env-id <uuid>');
    console.error('      [--profile <profile>] [--previous-expires-at <iso8601>] [--dry-run]');
    console.error('  Rollback:   delete a previously imported app/resource');
    console.error('    node pingone-client-secret.js --action rollback --type <application|resource> --id <id> --env-id <uuid> [--profile <profile>] [--dry-run]');
    console.error('  CSV batch:  run import/set-secret/rollback for every row in a CSV file');
    console.error('    node pingone-client-secret.js --action <import|set-secret|rollback> --csv <path.csv> --env-id <uuid>');
    console.error('      [--profile <profile>] [--type <application|resource>] [--dry-run]');
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }

  return args;
}

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

/** Minimal RFC4180-ish CSV parser: handles quoted fields, escaped quotes, commas/newlines inside quotes. */
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"') { inQuotes = true; continue; }
    if (c === ',') { row.push(field); field = ''; continue; }
    if (c === '\r') continue;
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue; }
    field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.length > 1 || r[0] !== '');
}

function loadCsvRows(csvPath, typeFilter) {
  const text = fs.readFileSync(csvPath, 'utf8');
  const rows = parseCsv(text);
  if (rows.length === 0) throw new Error(`--csv file is empty: ${csvPath}`);

  const header = rows[0].map(h => h.trim());
  const required = ['recordType', 'name', 'type', 'clientId', 'clientSecret'];
  const missing = required.filter(h => !header.includes(h));
  if (missing.length) {
    throw new Error(`--csv file missing required column(s): ${missing.join(', ')} (found: ${header.join(', ')})`);
  }

  const records = [];
  for (let i = 1; i < rows.length; i++) {
    const values = rows[i];
    const rec = {};
    header.forEach((h, idx) => { rec[h] = (values[idx] ?? '').trim(); });
    rec._rowNum = i + 1;

    if (!CSV_RECORD_TYPES.has(rec.recordType)) {
      info(`[csv row ${rec._rowNum}] skipped — recordType "${rec.recordType}" must be "application" or "resource"`);
      continue;
    }
    if (typeFilter && rec.recordType !== typeFilter) continue;
    records.push(rec);
  }
  return records;
}

/** Resolves a PingOne-generated id from a custom clientId via a filtered list call. Returns null if not found. */
function resolveIdByClientId(recordType, clientId, args) {
  const pathSegment = TYPE_TO_PATH_SEGMENT[recordType];
  const { stdout } = callPingcli([
    ...profileFlags(args.profile), '--output-format', 'json',
    'pingone', pathSegment === 'applications' ? 'applications' : 'resources', 'list',
    '--environment-id', args.envId,
    '--query', `data[?clientId=='${clientId}']`,
  ]);
  const matches = JSON.parse(stdout || '[]');
  return matches[0]?.id ?? null;
}

function buildSecretPayload(secret, previousExpiresAt) {
  const payload = { secret };
  if (previousExpiresAt) payload.previous = { expiresAt: previousExpiresAt };
  return payload;
}

/**
 * Core set-secret call. Returns { success, response, error }. Does not print
 * section headers or "Common causes" — callers (single-item / CSV batch) own that.
 */
function doSetSecret({ type, id, secret, previousExpiresAt, envId, profile, dryRun }) {
  const pathSegment = TYPE_TO_PATH_SEGMENT[type];
  const apiPath = `environments/${envId}/${pathSegment}/${id}/secret`;
  const payload = buildSecretPayload(secret, previousExpiresAt);

  if (dryRun) {
    info(`[dry-run] POST ${apiPath}`);
    info(`[dry-run] Content-Type: application/vnd.pingidentity.secret+json`);
    info(`[dry-run] Body: ${JSON.stringify({ ...payload, secret: '***redacted***' })}`);
    return { success: true, dryRun: true };
  }

  const tmpFile = path.join(os.tmpdir(), `set-secret-${process.pid}-${Math.floor(process.hrtime()[1])}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify(payload));

  try {
    const { stdout } = callPingcli([
      ...profileFlags(profile), '--output-format', 'json',
      'pingone', 'api', '--http-method', 'POST',
      '--fail',
      '--header', 'Content-Type: application/vnd.pingidentity.secret+json',
      '--data', tmpFile,
      apiPath,
    ]);
    let response = null;
    try { response = JSON.parse(stdout)?.data ?? null; } catch { /* non-JSON output */ }
    return { success: true, response };
  } catch (err) {
    return { success: false, error: err };
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function printSetSecretCommonCauses(type) {
  console.error('\n  Common causes:');
  console.error(`    - The ${type} was not imported with a custom clientId (this endpoint only works on imported ${TYPE_TO_PATH_SEGMENT[type]})`);
  console.error(`    - The worker app is missing the ${TYPE_TO_SET_PERMISSION[type]} permission`);
  console.error('    - The secret is outside the 8-1024 character range');
  console.error('    - The environment may not have the required feature flag enabled for set-secret (see Background above)');
}

function setSecretSingle(args) {
  section(`Set ${args.type} secret`);
  info(`Target       : ${TYPE_TO_PATH_SEGMENT[args.type]}/${args.id}`);
  info(`Environment  : ${args.envId}`);
  info(`Profile      : ${profileLabel(args.profile)}`);
  info(`Permission   : ${TYPE_TO_SET_PERMISSION[args.type]} (worker app must be granted this)`);
  info(`Previous kept: ${args.previousExpiresAt ? `until ${args.previousExpiresAt}` : 'no — old secret invalidated immediately'}`);

  const result = doSetSecret(args);
  if (result.dryRun) return;

  if (result.success) {
    ok(`Secret set on ${args.type} ${args.id}`);
    if (result.response) info(`Response: ${JSON.stringify(result.response)}`);
  } else {
    fail(`Failed to set secret: ${result.error.summary}`);
    printApiErrorDetail(result.error);
    printSetSecretCommonCauses(args.type);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// --action import — create an imported application or custom resource
// ---------------------------------------------------------------------------

const APP_TYPE_DEFAULTS = {
  WEB_APP:    { grantTypes: ['AUTHORIZATION_CODE'], responseTypes: ['CODE'], tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC', pkceEnforcement: 'S256_REQUIRED', redirectUris: ['https://example.com/callback'] },
  NATIVE_APP: { grantTypes: ['AUTHORIZATION_CODE'], responseTypes: ['CODE'], tokenEndpointAuthMethod: 'NONE', pkceEnforcement: 'S256_REQUIRED', redirectUris: ['com.example.app://callback'] },
  SPA:        { grantTypes: ['AUTHORIZATION_CODE'], responseTypes: ['CODE'], tokenEndpointAuthMethod: 'NONE', pkceEnforcement: 'S256_REQUIRED', redirectUris: ['https://example.com/callback'] },
  WORKER:     { grantTypes: ['CLIENT_CREDENTIALS'], tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC' },
};
const DEFAULT_APP_TYPE = 'WEB_APP';
const DEFAULT_RESOURCE_TYPE = 'CUSTOM';

function sampleSuffix() {
  // Not Date.now()/Math.random() — those are unavailable under the Workflow
  // harness. A PID + high-res tick is unique enough for a sample clientId.
  const [sec, nsec] = process.hrtime();
  return `${process.pid}${sec}${nsec}`.slice(-12);
}

/**
 * spec: { recordType: 'application'|'resource', appType, clientId, name, description }
 * Any field left null/undefined is filled with a generated sample value.
 *
 * Deliberately has no `secret`/`clientSecret` field: this script never sends a
 * custom secret on import, even though `clientSecret` is documented as an
 * optional import-request property. PingOne always auto-generates the
 * secret; use --action set-secret afterward to assign a custom value.
 */
function buildImportPayload(spec) {
  const suffix = sampleSuffix();
  const clientId = spec.clientId || `sample-imported-${spec.recordType}-${suffix}`;
  const name = spec.name || `Sample imported ${spec.recordType} ${suffix}`;
  const description = spec.description || `Sample ${spec.recordType} created by pingone-client-secret.js --action import`;

  const payload = { clientId, name, description };

  if (spec.recordType === 'application') {
    const appType = APP_TYPE_DEFAULTS[spec.appType] ? spec.appType : DEFAULT_APP_TYPE;
    Object.assign(payload, {
      enabled: false,
      protocol: 'OPENID_CONNECT',
      type: appType,
      ...APP_TYPE_DEFAULTS[appType],
    });
    return payload;
  }

  // Custom resource — clientId/clientSecret import is only valid for type=CUSTOM.
  Object.assign(payload, { type: DEFAULT_RESOURCE_TYPE, audience: clientId, accessTokenValiditySeconds: 3600 });
  return payload;
}

/** Core import call. Returns { success, id, clientId, response, error }. */
function doImport(spec, { envId, profile, dryRun }) {
  const pathSegment = TYPE_TO_PATH_SEGMENT[spec.recordType];
  const apiPath = `environments/${envId}/${pathSegment}`;
  const payload = buildImportPayload(spec);

  if (dryRun) {
    info(`[dry-run] POST ${apiPath}`);
    info(`[dry-run] Content-Type: application/json`);
    info(`[dry-run] Body: ${JSON.stringify(payload)}`);
    return { success: true, dryRun: true, clientId: payload.clientId };
  }

  const tmpFile = path.join(os.tmpdir(), `import-${spec.recordType}-${process.pid}-${Math.floor(process.hrtime()[1])}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify(payload));

  try {
    const { stdout } = callPingcli([
      ...profileFlags(profile), '--output-format', 'json',
      'pingone', 'api', '--http-method', 'POST',
      '--fail',
      '--header', 'Content-Type: application/json',
      '--data', tmpFile,
      apiPath,
    ]);
    const created = JSON.parse(stdout)?.data ?? {};
    return { success: true, id: created.id, clientId: created.clientId ?? payload.clientId, response: created };
  } catch (err) {
    return { success: false, clientId: payload.clientId, error: err };
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function printImportCommonCauses(type, clientId) {
  console.error('\n  Common causes:');
  console.error(`    - clientId "${clientId}" is already in use in this environment`);
  console.error(`    - The worker app is missing the ${TYPE_TO_IMPORT_PERMISSION[type]} permission`);
  console.error('    - The environment may not have the required feature flag enabled for custom clientId on import (see Background above)');
}

function importSingle(args) {
  const spec = {
    recordType: args.type, appType: args.appType, clientId: args.clientId,
    name: args.name, description: args.description,
  };

  section(`Import ${args.type}`);
  info(`Environment  : ${args.envId}`);
  info(`Profile      : ${profileLabel(args.profile)}`);
  info(`Permission   : ${TYPE_TO_IMPORT_PERMISSION[args.type]} (worker app must be granted this)`);
  info('clientSecret : (none sent — PingOne will auto-generate one)');

  const result = doImport(spec, args);
  if (result.dryRun) return;

  if (result.success) {
    ok(`Imported ${args.type} created | id=${result.id} clientId=${result.clientId}`);
    info(`Use --action set-secret --id ${result.id} to assign a custom secret`);
  } else {
    fail(`Failed to import ${args.type}: ${result.error.summary}`);
    printApiErrorDetail(result.error);
    printImportCommonCauses(args.type, result.clientId);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// --action rollback — delete a previously imported application or resource
// ---------------------------------------------------------------------------

/** Core rollback (delete) call. Returns { success, error }. */
function doRollback({ type, id, envId, profile, dryRun }) {
  const pathSegment = TYPE_TO_PATH_SEGMENT[type];
  const apiPath = `environments/${envId}/${pathSegment}/${id}`;

  if (dryRun) {
    info(`[dry-run] DELETE ${apiPath}`);
    return { success: true, dryRun: true };
  }

  try {
    callPingcli([
      ...profileFlags(profile), '--output-format', 'json',
      'pingone', 'api', '--http-method', 'DELETE',
      '--fail',
      apiPath,
    ]);
    return { success: true };
  } catch (err) {
    return { success: false, error: err };
  }
}

function rollbackSingle(args) {
  section(`Rollback ${args.type}`);
  info(`Target       : ${TYPE_TO_PATH_SEGMENT[args.type]}/${args.id}`);
  info(`Environment  : ${args.envId}`);
  info(`Profile      : ${profileLabel(args.profile)}`);

  const result = doRollback(args);
  if (result.dryRun) return;

  if (result.success) {
    ok(`Deleted ${args.type} ${args.id}`);
  } else {
    fail(`Failed to delete ${args.type} ${args.id}: ${result.error.summary}`);
    printApiErrorDetail(result.error);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// CSV batch mode
// ---------------------------------------------------------------------------

function runCsvBatch(args) {
  const records = loadCsvRows(args.csv, args.type);
  section(`CSV batch — ${args.action} (${records.length} row(s) from ${args.csv})`);

  if (records.length === 0) {
    info('No matching rows to process.');
    return;
  }

  const outcomes = []; // { row, recordType, name, clientId, status: 'ok'|'failed'|'skipped', detail }

  for (const rec of records) {
    const label = `[row ${rec._rowNum}] ${rec.recordType} "${rec.name}" (clientId=${rec.clientId})`;

    if (args.action === 'import') {
      // rec.clientSecret is intentionally not passed through — this script never
      // sends a custom secret on import; PingOne always auto-generates one.
      const spec = {
        recordType: rec.recordType, appType: rec.type || undefined,
        clientId: rec.clientId || undefined, name: rec.name || undefined,
      };
      const result = doImport(spec, args);
      if (result.dryRun) {
        info(`${label} — dry-run OK`);
        outcomes.push({ rec, status: 'dry-run' });
      } else if (result.success) {
        ok(`${label} — imported id=${result.id}`);
        outcomes.push({ rec, status: 'ok', id: result.id });
      } else {
        fail(`${label} — ${result.error.summary}`);
        printApiErrorDetail(result.error);
        outcomes.push({ rec, status: 'failed', detail: result.error.summary });
      }
      continue;
    }

    // set-secret and rollback both need the PingOne id resolved from clientId first.
    if (!rec.clientId) {
      fail(`${label} — skipped: no clientId in CSV row to resolve`);
      outcomes.push({ rec, status: 'skipped', detail: 'no clientId' });
      continue;
    }

    let id;
    try {
      id = resolveIdByClientId(rec.recordType, rec.clientId, args);
    } catch (err) {
      fail(`${label} — failed to look up id: ${err.summary}`);
      printApiErrorDetail(err);
      outcomes.push({ rec, status: 'failed', detail: `lookup failed: ${err.summary}` });
      continue;
    }
    if (!id) {
      fail(`${label} — skipped: no ${rec.recordType} found with this clientId`);
      outcomes.push({ rec, status: 'skipped', detail: 'clientId not found' });
      continue;
    }

    if (args.action === 'set-secret') {
      if (!rec.clientSecret) {
        fail(`${label} — skipped: no clientSecret in CSV row`);
        outcomes.push({ rec, status: 'skipped', detail: 'no clientSecret', id });
        continue;
      }
      const result = doSetSecret({
        type: rec.recordType, id, secret: rec.clientSecret,
        previousExpiresAt: args.previousExpiresAt, envId: args.envId, profile: args.profile, dryRun: args.dryRun,
      });
      if (result.dryRun) {
        info(`${label} — id=${id} — dry-run OK`);
        outcomes.push({ rec, status: 'dry-run', id });
      } else if (result.success) {
        ok(`${label} — id=${id} — secret set`);
        outcomes.push({ rec, status: 'ok', id });
      } else {
        fail(`${label} — id=${id} — ${result.error.summary}`);
        printApiErrorDetail(result.error);
        outcomes.push({ rec, status: 'failed', detail: result.error.summary, id });
      }
    } else if (args.action === 'rollback') {
      const result = doRollback({ type: rec.recordType, id, envId: args.envId, profile: args.profile, dryRun: args.dryRun });
      if (result.dryRun) {
        info(`${label} — id=${id} — dry-run OK`);
        outcomes.push({ rec, status: 'dry-run', id });
      } else if (result.success) {
        ok(`${label} — id=${id} — deleted`);
        outcomes.push({ rec, status: 'ok', id });
      } else {
        fail(`${label} — id=${id} — ${result.error.summary}`);
        printApiErrorDetail(result.error);
        outcomes.push({ rec, status: 'failed', detail: result.error.summary, id });
      }
    }
  }

  const counts = outcomes.reduce((acc, o) => { acc[o.status] = (acc[o.status] ?? 0) + 1; return acc; }, {});
  section('CSV batch summary');
  console.log(`  Total    : ${outcomes.length}`);
  console.log(`  Succeeded: ${counts.ok ?? 0}`);
  if (counts['dry-run']) console.log(`  Dry-run  : ${counts['dry-run']}`);
  console.log(`  Skipped  : ${counts.skipped ?? 0}`);
  console.log(`  Failed   : ${counts.failed ?? 0}`);
  if (counts.failed) {
    console.log('\n  Failed rows:');
    for (const o of outcomes.filter(o => o.status === 'failed')) {
      console.log(`    – row ${o.rec._rowNum} (${o.rec.recordType} "${o.rec.name}", clientId=${o.rec.clientId}) — ${o.detail}`);
    }
    process.exitCode = 1;
  }
  if (counts.skipped) {
    console.log('\n  Skipped rows:');
    for (const o of outcomes.filter(o => o.status === 'skipped')) {
      console.log(`    – row ${o.rec._rowNum} (${o.rec.recordType} "${o.rec.name}", clientId=${o.rec.clientId}) — ${o.detail}`);
    }
  }
}

function main() {
  const args = parseArgs();

  if (args.csv) {
    runCsvBatch(args);
    return;
  }

  if (args.action === 'import') {
    importSingle(args);
  } else if (args.action === 'rollback') {
    rollbackSingle(args);
  } else {
    setSecretSingle(args);
  }
}

main();
