'use strict';

/**
 * reports.js
 *
 * Assessment and migration report writers extracted from pf-to-pingone-migrate.js.
 * Both functions accept a sourceName and destName so reports label the source/destination pair.
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Helpers (duplicated from ping-migration.js to keep reports.js self-contained)
// ---------------------------------------------------------------------------

function slugify(name) {
  return (name ?? 'unknown')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// ---------------------------------------------------------------------------
// Authentication infrastructure analysis (PF-specific but lives here since
// it is only used by writeAssessmentReport)
// ---------------------------------------------------------------------------

function buildAuthAnalysisSection(analysis) {
  if (!analysis) return [];
  const { adapters, adapterMap, pluginShort, fragments, fragMap, apcs, oidcPolicies,
          dataStores, pcvs, lips, trees, clients, clientOidcPolicyMap, idpConns } = analysis;

  const lines = [
    '',
    '---',
    '',
    '## Authentication infrastructure analysis',
    '',
    'This section is derived directly from the bulk export and describes the authentication',
    'policy configuration that backs the migrated applications.',
    '',
  ];

  // --- IDP Adapters ---
  lines.push('### IDP adapters', '');
  lines.push(`${adapters.length} adapters defined.`, '');
  lines.push('| ID | Plugin type |', '|---|---|');
  for (const a of adapters) {
    const short = pluginShort[a.pluginDescriptorRef?.id] ?? a.pluginDescriptorRef?.id ?? '—';
    lines.push(`| \`${a.id}\` | ${short} |`);
  }

  // --- Authentication Policy Contracts ---
  lines.push('', '### Authentication Policy Contracts (APCs)', '');
  lines.push(`${apcs.length} APCs defined.`, '');
  lines.push('| APC ID | Extended attributes |', '|---|---|');
  for (const a of apcs) {
    const ext = (a.extendedAttributes ?? []).map(x => x.name).join(', ') || '_(none beyond subject)_';
    lines.push(`| \`${a.id}\` | ${ext} |`);
  }

  // --- Fragments ---
  lines.push('', '### Authentication policy fragments', '');
  lines.push(`${fragments.length} fragments defined.`, '');
  lines.push('| Fragment ID | Root adapter / ref | Output APC |', '|---|---|---|');
  for (const f of fragments) {
    const refs = analysis.collectFragmentRefs(f.rootNode);
    const rootAdapters = refs.adapters.length ? refs.adapters.map(id => `\`${id}\``).join(', ') : '—';
    const rootFrags = refs.fragments.length ? refs.fragments.map(id => `fragment:\`${id}\``).join(', ') : null;
    const rootStr = [rootAdapters !== '—' ? rootAdapters : null, rootFrags].filter(Boolean).join('; ') || '—';
    const outputApc = f.outputs?.id ? `\`${f.outputs.id}\`` : '—';
    lines.push(`| \`${f.id}\` | ${rootStr} | ${outputApc} |`);
  }

  // --- Policy trees ---
  lines.push('', '### Default policy trees', '');
  lines.push(`${trees.length} selection trees in the default authentication policy.`, '');
  for (const t of trees) {
    lines.push(`**${t.name}** (\`${t.id}\`) — enabled: ${t.enabled}`);
    const ra = t.rootNode?.action ?? {};
    const rootType = ra.type;
    const rootTarget = ra.authenticationSelectorRef?.id ?? ra.fragment?.id ?? '—';
    lines.push(`- Root node: ${rootType} → \`${rootTarget}\``);
    const branches = analysis.walkTreeBranches(t.rootNode);
    if (branches.length) {
      const seen = new Set();
      for (const b of branches) {
        const key = `${b.context}|${b.type}|${b.target}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const ctx = b.context ? `\`${b.context}\`` : '_(default)_';
        const tgt = b.target ? `\`${b.target}\`` : b.type;
        lines.push(`  - ${ctx} → ${b.type}: ${tgt}`);
      }
    }
    lines.push('');
  }

  // --- OIDC policies ---
  lines.push('### OIDC policies (`oauth/openIdConnect/policies`)', '');
  if (oidcPolicies.length === 0) {
    lines.push('None defined.');
  } else {
    lines.push(
      'OIDC policies define the ID token contract: which attributes are included in the ID token,',
      'which ATM issues the token used for API access, and any issuance criteria (e.g. admin-only gates).',
      '',
      '| Policy ID | Name | ID token lifetime | ATM ref | Extended attributes | Consumers |',
      '|---|---|---|---|---|---|',
    );
    for (const p of oidcPolicies) {
      const atm = p.accessTokenManagerRef?.id ?? '—';
      const ext = (p.attributeContract?.extendedAttributes ?? []).map(x => x.name).join(', ') || '_(none)_';
      const consumers = clients
        .filter(c => clientOidcPolicyMap[c.clientId] === p.id)
        .map(c => c.clientId)
        .join(', ') || '_(default — no explicit assignment)_';
      lines.push(`| \`${p.id}\` | ${p.name} | ${p.idTokenLifetime ?? '—'} min | \`${atm}\` | ${ext} | ${consumers} |`);
    }
    lines.push(
      '',
      'Clients with no explicit `oidcPolicy.policyGroup` assignment use the server default OIDC policy.',
      'Only `PingAdmin` has an explicit assignment (`adminOIDCPolicy`) — all other clients use the default.',
      '',
      '**Migration note:** PingOne OIDC applications have their own claim mappings configured directly on the',
      'application, not via a shared policy object. Each OIDC policy\'s attribute contract and ATM binding',
      'must be re-created as per-application claim mappings in PingOne.',
    );
  }

  // --- Data stores ---
  lines.push('', '### Data stores', '');
  lines.push('| ID | Name | Type | Role |', '|---|---|---|---|');
  for (const d of dataStores) {
    let role = '—';
    if (d.id === 'LDAP-PingDirectory') role = 'Primary identity store — authentication, attribute lookup, registration';
    else if (d.type === 'PING_ONE_LDAP_GATEWAY') role = 'PingOne-bridged LDAP gateway — defined but not consumed by any adapter';
    else if (d.type === 'JDBC') role = 'PF provisioner internal state only — does not migrate';
    lines.push(`| \`${d.id}\` | ${d.name ?? d.id} | ${d.type} | ${role} |`);
  }

  if (pcvs.length) {
    lines.push('', '**Password Credential Validators**', '');
    lines.push('| PCV ID | Data store |', '|---|---|');
    for (const p of pcvs) {
      const ds = p.configuration?.fields?.find(f => f.name === 'LDAP Datastore')?.value ?? '—';
      lines.push(`| \`${p.id}\` | \`${ds}\` |`);
    }
  }

  if (lips.length) {
    lines.push('', '**Local Identity Profiles**', '');
    lines.push('| Profile ID | Name | Data store |', '|---|---|---|');
    for (const l of lips) {
      const ds = l.dataStoreConfig?.dataStoreRef?.id ?? '—';
      lines.push(`| \`${l.id}\` | ${l.name ?? l.id} | \`${ds}\` |`);
    }
  }

  // --- SP-side IdP connections ---
  if (idpConns && idpConns.length) {
    lines.push(
      '',
      '### External IdP connections (`sp/idpConnections`)',
      '',
      'PingFederate SP-side connections where PF acts as the SP, federating inbound to an external IdP.',
      'These map to **PingOne Identity Providers** (`POST environments/{envId}/identityProviders`).',
      '',
      '| Name | Protocol | Active | Entity ID | Migration path | Notes |',
      '|---|---|---|---|---|---|',
    );
    for (const conn of idpConns) {
      const protocol = conn.wsTrust ? 'WS-Trust'
        : conn.idpBrowserSso?.protocol ?? 'Unknown';
      const active = conn.active ? 'Yes' : 'No';
      const entityId = conn.entityId ?? '—';
      const certs = conn.credentials?.certs ?? [];
      const certExpiry = (() => {
        const c = certs.find(x => x.primaryVerificationCert) ?? certs[0];
        return c?.expirationDate ? `cert expires ${c.expirationDate.split('T')[0]}` : 'no cert';
      })();
      let migPath, notes;
      if (!conn.active) {
        migPath = 'Skip';
        notes = 'Disabled; cert may be expired';
      } else if (conn.wsTrust || !conn.idpBrowserSso) {
        migPath = '**Out of scope**';
        notes = 'WS-Trust — no PingOne IdP equivalent; keep PF bridge or redesign with DaVinci';
      } else if (protocol.startsWith('SAML')) {
        migPath = '**Direct → PingOne IdP**';
        notes = certExpiry + (conn.metadata ? '; metadata auto-reload configured' : '');
      } else {
        migPath = 'Out of scope';
        notes = `Unsupported protocol: ${protocol}`;
      }
      lines.push(`| \`${conn.name}\` | ${protocol} | ${active} | \`${entityId}\` | ${migPath} | ${notes} |`);
    }
    lines.push('');
    lines.push('> **Attribute mapping note:** Each SAML IdP connection maps inbound assertions to an Authentication Policy Contract (APC). Re-create these as PingOne Identity Provider attribute mappings after the IdP connection is created.');
  }

  // --- Migration implications ---
  lines.push(
    '',
    '### Migration implications',
    '',
    '| Observation | Action required |',
    '|---|---|',
    '| `LDAP-PingDirectory` is the single identity source for all password-based flows | Map to a PingOne Population before any auth flow can work |',
    '| `LDAP-PingOneGateway` is defined but not consumed by any adapter | Verify no hidden dependency; safe to defer |',
    '| `ProvisionerDS` (HSQLDB) is internal PF state only | Does not migrate — discard |',
    '| All SAML SPs and OIDC ATM mappings converge on `samplePolicyContract` | A single PingOne sign-on policy can serve all apps once LDAP → Population is mapped |',
    '| OIDC policies define ID token attributes + ATM binding — no shared policy object in PingOne | Re-create as per-application claim mappings in PingOne |',
    '| Only `PingAdmin` has an explicit OIDC policy (`adminOIDCPolicy`) with admin-role gating | Replicate the `isAdmin` issuance criterion in PingOne claim mapping rules |',
    '| Social adapters (Facebook, Google) feed `regIdentityProfile` in LDAP | Configure PingOne Identity Provider connections; define provisioning strategy |',
    '| `ciamHTMLForm` uses `CAPTCHA Provider: PingOneProtect` | PingOneProtect integration must be re-configured in a DaVinci flow or native form policy |',
    '| Fragment nesting: `SecondFactor` → `Adaptive_Auth` → risk-based `stepUpFragment` | Replicate as nested DaVinci sub-flows in PingOne |',
    '| DaVinci adapters (`dvBiographic`, `dvBiographicExternal`) used in credential issuance | DaVinci flows must be migrated before credential issuance paths can function |',
  );

  return lines;
}

// ---------------------------------------------------------------------------
// writeAssessmentReport
// ---------------------------------------------------------------------------

/**
 * Write assessment report.
 *
 * @param {Object} args          - Parsed CLI args (provides pfHost, poEnvId, resolvedEnvName, etc.)
 * @param {Array}  direct        - OIDC direct-migrate items
 * @param {Array}  redesign      - OIDC redesign items
 * @param {Array}  outOfScope    - OIDC out-of-scope items
 * @param {Array}  samlDirect    - SAML direct-migrate items
 * @param {Array}  samlOutOfScope- SAML out-of-scope items
 * @param {Array}  atmDirect     - ATM direct-migrate items
 * @param {Array}  signingDirect - Signing key items (pre-enrichment)
 * @param {Array}  idpConnDirect - External IdP connection direct items
 * @param {Array}  idpConnOutOfScope - External IdP connection out-of-scope items
 * @param {Object} inventory     - { resourceType: count }
 * @param {Object|null} authAnalysis - Result of analyzeAuthPolicies() or null
 * @param {string} sourceName    - Human-readable source name (e.g. 'PingFederate')
 * @param {string} destName      - Human-readable destination name (e.g. 'PingOne')
 */
function writeAssessmentReport(args, direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect, signingDirect, idpConnDirect, idpConnOutOfScope, inventory, authAnalysis, sourceName, destName) {
  const now = new Date();
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const tzAbbr = now.toLocaleString('en-US', { timeZoneName: 'short' }).split(' ').pop();
  const today = now.toLocaleDateString('en-CA', { timeZone: tz }); // YYYY-MM-DD in local TZ
  const timestamp = now.toLocaleString('en-US', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(',', '') + ` ${tzAbbr}`;
  const reportDir = './migration-reports';
  fs.mkdirSync(reportDir, { recursive: true });

  const src = sourceName ?? 'source';
  const dst = destName ?? 'destination';

  const envSlug = slugify(args.resolvedEnvName ?? args.poEnvId ?? args.destEnvId ?? 'migration');
  let reportPath = path.join(reportDir, `${envSlug}-assessment-report-${today}.md`);
  let seq = 2;
  while (fs.existsSync(reportPath)) {
    reportPath = path.join(reportDir, `${envSlug}-assessment-report-${today}-${seq}.md`);
    seq++;
  }

  const totalEntities = Object.values(inventory).reduce((a, b) => a + b, 0);
  const oauthClients = (inventory['oauth/clients'] ?? inventory['oidc'] ?? 0);
  const atmCount = (inventory['oauth/accessTokenManagers'] ?? inventory['atm'] ?? 0);
  const signingKeyCount = (inventory['keyPairs/signing'] ?? inventory['key'] ?? 0);

  const lines = [
    `# Assessment Report — ${timestamp}`,
    `**Source:** ${src}  **Destination:** ${dst}`,
    '',
    '## Migration objective',
    `Migrate all OIDC applications from ${src} to ${dst} with equivalent grant types, PKCE enforcement, and resource grants.`,
    '',
    '## Current-state summary',
    `- ${src} host: \`${args.pfHost ?? args.sourceHost ?? '(from profile or file)'}\``,
    `- Total entities inventoried: ${totalEntities}`,
    `- OAuth clients: ${oauthClients}`,
    `- Token managers (ATM): ${atmCount}`,
    `- Signing key pairs: ${signingKeyCount}`,
    '',
    '### Full resource inventory',
    '',
    '| Resource type | Count |',
    '|---|---|',
  ];

  for (const [type, count] of Object.entries(inventory).sort()) {
    lines.push(`| ${type} | ${count} |`);
  }

  lines.push(
    '',
    '## Scope matrix',
    '',
    '| Entity | Category | Count | Apps |',
    '|---|---|---|---|',
    `| OAuth clients — direct migrate | Direct | ${direct.length} | ${direct.map(d => d.item?.name ?? d.c.clientId ?? d.c.id ?? d.c.name).join(', ') || '—'} |`,
    `| OAuth clients — redesign required | Redesign | ${redesign.length} | ${redesign.map(r => r.item?.name ?? r.c.clientId ?? r.c.id ?? r.c.name).join(', ') || '—'} |`,
    `| OAuth clients — out-of-scope | Out-of-scope | ${outOfScope.length} | ${outOfScope.map(o => `${o.item?.name ?? o.c.clientId ?? o.c.id ?? o.c.name} (${o.reason})`).join('; ') || '—'} |`,
    `| SAML SP connections — direct migrate | Direct | ${samlDirect.length} | ${samlDirect.map(s => s.sp.name ?? s.sp.id).join(', ') || '—'} |`,
    `| SAML SP connections — out-of-scope | Out-of-scope | ${samlOutOfScope.length} | ${samlOutOfScope.map(s => `${s.sp.name ?? s.sp.id} (${s.reason})`).join('; ') || '—'} |`,
    `| External IdP connections (SAML) — direct migrate | Direct | ${idpConnDirect.length} | ${idpConnDirect.map(i => i.conn.name ?? i.conn.id).join(', ') || '—'} |`,
    `| External IdP connections — out-of-scope | Out-of-scope | ${idpConnOutOfScope.length} | ${idpConnOutOfScope.map(i => `${i.conn.name ?? i.conn.id} (${i.reason})`).join('; ') || '—'} |`,
    `| Token managers (ATM) — direct migrate | Direct | ${atmDirect.length} | ${atmDirect.map(a => a.atm.name ?? a.atm.id).join(', ') || '—'} |`,
    `| Signing key pairs — provision new | Direct | ${signingDirect.length} | ${signingDirect.map(s => s.kp.id ?? s.kp.name).join(', ') || '—'} |`,
    '',
    '### Redesign detail',
    '',
  );

  if (redesign.length) {
    lines.push('| App | Reason |', '|---|---|');
    for (const { c, item, reason } of redesign) lines.push(`| ${item?.name ?? c.clientId ?? c.id ?? c.name} | ${reason} |`);
  } else {
    lines.push('None — all clients can be directly migrated or are out-of-scope.');
  }

  lines.push(
    '',
    '### Out-of-scope detail',
    '',
  );

  if (outOfScope.length) {
    lines.push('| App | Reason |', '|---|---|');
    for (const { c, item, reason } of outOfScope) lines.push(`| ${item?.name ?? c.clientId ?? c.id ?? c.name} | ${reason} |`);
  } else {
    lines.push('None.');
  }

  lines.push(
    '',
    '## Wave plan',
    '',
    '| Wave | Scope | Owner | Target date | Acceptance criteria |',
    '|---|---|---|---|---|',
    `| 1 | ${direct.filter(d => !((d.c.clientId ?? d.c.id ?? '').toLowerCase()).includes('ciam') && (d.poGrants ?? []).includes('CLIENT_CREDENTIALS')).map(d => d.item?.name ?? d.c.clientId ?? d.c.id ?? d.c.name).join(', ') || 'Internal worker apps'} | | | All apps enabled, grants present, validation PASS |`,
    `| 2 | ${direct.filter(d => (d.poGrants ?? []).includes('AUTHORIZATION_CODE')).map(d => d.item?.name ?? d.c.clientId ?? d.c.id ?? d.c.name).join(', ') || 'Auth-code apps'} | | | PKCE S256 enforced, token flows verified |`,
    `| 3 | ${redesign.map(r => r.item?.name ?? r.c.clientId ?? r.c.id ?? r.c.name).join(', ') || '—'} | | | Client code updated to PKCE, re-run migration |`,
    '',
    '## Risks and mitigations',
    '',
    '| Risk | Likelihood | Impact | Mitigation |',
    '|---|---|---|---|',
    `| ${src} client secrets not exportable (OBF:JWE) | High | Medium | Rotate secrets after migration via \`application-secrets rotate\` |`,
    '| IMPLICIT-only apps break without code changes | High | High | Exclude from wave 1–2; redesign first |',
    `| Worker app lacks org-admin for env creation | Medium | Low | Use \`--skip-env-create\` and target existing env |`,
    '| SAML SP connections not automated | Low | Medium | Migrate manually using migration skill after OIDC waves |',
    '| ATM custom scopes not auto-migrated | Medium | Medium | Re-create attribute contract scopes as destination resource scopes manually |',
    '| ATM allowed-client restrictions not enforced in destination | Medium | Medium | Review allowedClients list and configure access policies accordingly |',
    `| Signing keys provisioned new — not the original ${src} private key | High | Medium | SPs must be updated with the new destination signing certificate |`,
    `| Deficient ${src} key (weak algo/size) upgraded to best-practice defaults | Low | Low | Note the upgrade in change record; verify SP trust updated |`,
    '',
    '## Validation gates',
    '',
    '- All apps enabled in destination',
    '- AUTHORIZATION_CODE apps: `pkceEnforcement=S256_REQUIRED`',
    '- All apps have at least one resource grant (openid scope)',
    '- No IMPLICIT grant present in migrated apps',
    '- Token issuance confirmed for at least one app per wave before proceeding',
    '',
    '## Cutover and rollback steps',
    '',
    '1. Run `--dry-run` per wave to preview payloads before applying',
    '2. Apply wave, validate — proceed only on PASS',
    `3. Keep ${src} running in parallel during pilot (dual-run)`,
    '4. Rollback trigger: >5% auth failure rate in first 30 minutes post-cutover',
    `5. Rollback: redirect traffic back to ${src}; investigate failures; re-run`,
    '',
    '## Decisions made',
    '',
    '- IMPLICIT grant dropped across all apps (deprecated per RFC 6749)',
    '- ACCESS_TOKEN_VALIDATION excluded — no destination equivalent',
    '- AUTHORIZATION_CODE + PKCE S256 enforced on all migrated auth-code flows',
    `- Disabled ${src} apps excluded from migration scope`,
    '',
    '## Open items',
    '',
    '- Sign-on policy assignments: assign once policies are configured in destination',
    '- Data stores → Populations: LDAP/DB/AD directory mapping not yet completed',
    '- SAML SP connections: not in automated scope; plan manual migration wave',
    `- Redesign apps (${redesign.length}): client code changes required before migration`,
    `- ATM custom scopes: re-create attribute contract scopes as destination resource scopes for each migrated ATM`,
    `- ATM allowed-client restrictions: review and enforce via destination access policies`,
    `- Signing keys: new keys are provisioned (${src} private keys cannot be exported); update SP/IdP trust with new destination signing certificates`,
    `- Deficient key upgrades: any keys upgraded from weak algorithms/sizes are noted in sidecar meta-key-*.json files`,
    ...(idpConnDirect.length ? [`- External IdP connections (SAML): ${idpConnDirect.map(i => i.conn.name ?? i.conn.id).join(', ')} — verify attribute mappings and APC re-creation in destination after apply`] : []),
    ...(idpConnOutOfScope.length ? [`- External IdP connections (out-of-scope): ${idpConnOutOfScope.map(i => `${i.conn.name ?? i.conn.id} (${i.reason})`).join('; ')} — no automated migration path; retain ${src} bridge or redesign with DaVinci`] : []),
  );

  if (authAnalysis) {
    lines.push(...buildAuthAnalysisSection(authAnalysis));
  }

  fs.writeFileSync(reportPath, lines.join('\n') + '\n');
  const BLUE = '\x1b[34m';
  const RESET = '\x1b[0m';
  console.log(`  ${BLUE}→${RESET}  Assessment report written → ${reportPath}`);
  return reportPath;
}

// ---------------------------------------------------------------------------
// writeMigrationReport
// ---------------------------------------------------------------------------

/**
 * Write migration execution report.
 *
 * @param {Object} args
 * @param {Array}  appResults
 * @param {Array}  samlResults
 * @param {Array}  atmResults
 * @param {Array}  signingResults
 * @param {Array}  idpConnResults
 * @param {Array}  redesign
 * @param {Array}  outOfScope
 * @param {Array}  samlOutOfScope
 * @param {Object} grantDetails     - { clientId: [scopeNames] }
 * @param {Array}  validationDetails
 * @param {string} sourceName
 * @param {string} destName
 */
function writeMigrationReport(args, appResults, samlResults, atmResults, signingResults, idpConnResults, redesign, outOfScope, samlOutOfScope, grantDetails, validationDetails, sourceName, destName) {
  const now = new Date();
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const tzAbbr = now.toLocaleString('en-US', { timeZoneName: 'short' }).split(' ').pop();
  const today = now.toLocaleDateString('en-CA', { timeZone: tz }); // YYYY-MM-DD in local TZ
  const timestamp = now.toLocaleString('en-US', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(',', '') + ` ${tzAbbr}`;
  const reportDir = './migration-reports';
  fs.mkdirSync(reportDir, { recursive: true });

  const src = sourceName ?? 'source';
  const dst = destName ?? 'destination';

  const envSlug = slugify(args.resolvedEnvName ?? args.poEnvId ?? args.destEnvId ?? 'migration');
  let reportPath = path.join(reportDir, `${envSlug}-migration-report-${today}.md`);
  let seq = 2;
  while (fs.existsSync(reportPath)) {
    reportPath = path.join(reportDir, `${envSlug}-migration-report-${today}-${seq}.md`);
    seq++;
  }

  const applied = appResults.filter(r => r.success);
  const failedApps = appResults.filter(r => !r.success);
  const overall = validationDetails.every(v => v.pass) ? 'PASS' : 'FAIL';

  const envId = args.poEnvId ?? args.destEnvId ?? '—';
  const rollbackScript = path.join(__dirname, 'rollback.js');
  const rollbackCmd = [
    `node ${rollbackScript} \\`,
    `  --report  ${path.resolve(reportPath)} \\`,
    `  --profile ${args.profile ?? '<pingcli-profile>'}`,
  ].join('\n');

  const lines = [
    `# Migration Report — ${timestamp}`,
    `**Source:** ${src}  **Destination:** ${dst}`,
    '',
    '## Summary',
    `- Environment: \`${envId}\``,
    `- ${src} host: \`${args.pfHost ?? args.sourceHost ?? '(from profile)'}\``,
    `- Profile: \`${args.profile ?? '—'}\``,
    `- Flags: \`${args.skipEnvCreate ? '--skip-env-create' : '--env-create'}\`${args.dryRun ? ' `--dry-run`' : ''}`,
    '',
    '## Applied resources',
    '',
    '| App | Type | PingOne ID | Result |',
    '|---|---|---|---|',
  ];

  for (const r of appResults) {
    const appType = (r.poGrants ?? []).join(',') === 'CLIENT_CREDENTIALS' ? 'WORKER' : 'WEB_APP';
    const appId = r.appId ?? '—';
    const resultStr = r.success ? 'Created' : 'FAILED';
    lines.push(`| ${r.name ?? r.clientId ?? r.id} | OIDC / ${appType} | \`${appId}\` | ${resultStr} |`);
  }
  for (const r of samlResults) {
    const appId = r.appId ?? '—';
    const resultStr = r.success ? 'Created' : 'FAILED';
    lines.push(`| ${r.name ?? r.id} | SAML / WEB_APP | \`${appId}\` | ${resultStr} |`);
  }
  for (const r of atmResults) {
    const resourceId = r.resourceId ?? '—';
    const resultStr = r.success ? 'Created' : 'FAILED';
    lines.push(`| ${r.name ?? r.id} | ATM / pingone_resource | \`${resourceId}\` | ${resultStr} |`);
  }
  for (const r of signingResults) {
    const keyId = r.keyId ?? '—';
    const upgraded = r.deficient ? ' *(upgraded)*' : '';
    const resultStr = r.success ? `Created${upgraded}` : 'FAILED';
    lines.push(`| ${r.name ?? r.id} | Signing key | \`${keyId}\` | ${resultStr} |`);
  }
  for (const r of idpConnResults) {
    const idpId = r.idpId ?? '—';
    const resultStr = r.success ? 'Created' : 'FAILED';
    lines.push(`| ${r.name ?? r.id} | External IdP (SAML) | \`${idpId}\` | ${resultStr} |`);
  }

  lines.push('', '## Resource grants applied', '', '| App | Scopes |', '|---|---|');
  for (const r of applied) {
    // grantDetails is keyed by clientId (the lookup key); display the
    // canonical name when available, falling back to clientId/id.
    const key = r.clientId ?? r.name ?? r.id;
    const label = r.name ?? key;
    const scopes = (grantDetails[key] ?? ['—']).join(', ');
    lines.push(`| ${label} | ${scopes} |`);
  }

  lines.push('', '## Skipped / out-of-scope', '', '| App | Reason |', '|---|---|');
  for (const { c, reason } of redesign) {
    lines.push(`| ${c.clientId ?? c.id ?? c.name} | OIDC — Redesign required — ${reason} |`);
  }
  for (const { c, reason } of outOfScope) {
    lines.push(`| ${c.clientId ?? c.id ?? c.name} | OIDC — ${reason} |`);
  }
  for (const { sp, reason } of samlOutOfScope) {
    lines.push(`| ${sp.name ?? sp.id} | SAML — ${reason} |`);
  }
  if (!redesign.length && !outOfScope.length && !samlOutOfScope.length) lines.push('| — | None |');

  lines.push('', '## Validation results', '', '| App | Enabled | Grants | PKCE | Resource Grants | Pass/Fail |', '|---|---|---|---|---|---|');
  for (const v of validationDetails) {
    const enabledStr = v.enabled ? '✔' : '✖';
    const grantsStr = v.grants.join(', ') || '—';
    const passStr = v.pass ? '**PASS**' : `**FAIL** (${v.issues.join('; ')})`;
    lines.push(`| ${v.name ?? v.clientId ?? v.id} | ${enabledStr} | ${grantsStr} | ${v.pkce} | ${v.resourceGrants} | ${passStr} |`);
  }

  lines.push(
    '',
    '## Result',
    `- OIDC applied: ${applied.length}  Failed: ${failedApps.length}  Skipped: ${redesign.length + outOfScope.length}`,
    `- SAML applied: ${samlResults.filter(r => r.success).length}  Failed: ${samlResults.filter(r => !r.success).length}  Skipped: ${samlOutOfScope.length}`,
    `- ATMs applied: ${atmResults.filter(r => r.success).length}  Failed: ${atmResults.filter(r => !r.success).length}`,
    `- Signing keys applied: ${signingResults.filter(r => r.success).length}  Failed: ${signingResults.filter(r => !r.success).length}  Upgraded: ${signingResults.filter(r => r.deficient).length}`,
    `- Overall: **${overall}**`,
    '',
    '## Rollback',
    '',
    'To reverse this migration and delete every resource listed under "Applied resources" above, run:',
    '',
    '```bash',
    rollbackCmd,
    '```',
    '',
    'Add `--dry-run` to the command above first to confirm the delete list before anything is actually removed.',
    '',
    '## Next steps',
    `1. **Rotate client secrets** — ${src} secrets use OBF:JWE and cannot be exported; ` +
      'run `pingcli pingone applications application-secrets rotate` for each app',
    '2. **Assign sign-on policies** — use `sop-assignments create` once policies are configured',
    '3. **Migrate data stores → Populations** — LDAP/DB/AD directories need mapping',
    '4. **Redesign IMPLICIT-only apps** — see skipped list above',
    '5. **Update client endpoints** — point applications to destination token/authorize endpoints',
    '6. **Validate SAML apps** — confirm ACS URLs, entity IDs, signing certs, and SP/IdP-initiated flows',
    '7. **ATM custom scopes** — re-create attribute contract scopes as destination resource scopes for each migrated ATM',
    '8. **ATM allowed-client restrictions** — review allowed clients per ATM and enforce via destination access policies',
    '9. **Update SP trust** — distribute new destination signing certificates to all SPs/IdPs',
    '10. **Review upgraded keys** — any deficient keys were upgraded; confirm the new algorithm/size in the change record',
  );

  fs.writeFileSync(reportPath, lines.join('\n') + '\n');
  const BLUE = '\x1b[34m';
  const RESET = '\x1b[0m';
  console.log(`  ${BLUE}→${RESET}  Report written → ${reportPath}`);
  console.log(`  ${BLUE}→${RESET}  Rollback command →`);
  console.log(rollbackCmd.split('\n').map(l => `      ${l}`).join('\n'));
  return reportPath;
}

module.exports = { writeAssessmentReport, writeMigrationReport };
