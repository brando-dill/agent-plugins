'use strict';

/**
 * classifier.js
 *
 * Destination-aware classification of canonical migration items.
 * Takes a flat array of canonical items and the destination's caps() output,
 * returns the same array with classification, skipReason, and concerns set on each item.
 *
 * This is the ONLY place classification business rules live — neither source nor
 * destination adapters contain classification logic.
 */

// ---------------------------------------------------------------------------
// Grant type mapping: PF → PingOne (and generic canonical names)
// ---------------------------------------------------------------------------
const GRANT_MAP = {
  AUTHORIZATION_CODE:     'AUTHORIZATION_CODE',
  CLIENT_CREDENTIALS:     'CLIENT_CREDENTIALS',
  IMPLICIT:               null,  // deprecated — drop
  REFRESH_TOKEN:          'REFRESH_TOKEN',
  CIBA:                   'CIBA',
  ACCESS_TOKEN_VALIDATION: null, // no PingOne equivalent
  DEVICE_CODE:            'DEVICE_CODE',
};

/**
 * rationalize(items, destCaps)
 *
 * @param {Array} items      - Array of canonical items (from source adapter's extract())
 * @param {Object} destCaps  - Capability declaration from dest.caps()
 * @returns {Object}         - Classified result: { direct, redesign, outOfScope,
 *                              samlDirect, samlOutOfScope, atmDirect, signingDirect,
 *                              idpConnDirect, idpConnOutOfScope, inventory }
 *
 * Each item in the returned arrays carries:
 *   classification: 'direct' | 'redesign' | 'out-of-scope'
 *   skipReason: String | null
 *   concerns: [String]
 *
 * The function also prints a summary to stdout (same colored output style as the
 * legacy pf-to-pingone-migrate.js).
 */
function rationalize(items, destCaps) {
  const direct = [], redesign = [], outOfScope = [];
  const samlDirect = [], samlOutOfScope = [];
  const atmDirect = [];
  const signingDirect = [];
  const idpConnDirect = [], idpConnOutOfScope = [];
  const inventory = {};

  // Supported grant types at destination (default to full set if not declared)
  const supportedGrants = new Set(
    destCaps.grantTypes ?? [
      'AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS', 'REFRESH_TOKEN',
      'CIBA', 'DEVICE_CODE',
    ]
  );

  for (const item of items) {
    // Track inventory by type
    const itype = item.type ?? 'unknown';
    inventory[itype] = (inventory[itype] ?? 0) + 1;

    if (item.type === 'oidc') {
      const rawGrants = item.capabilities?.grantTypes ?? [];
      // Map source grants to canonical names, filter unmapped
      const poGrants = rawGrants
        .map(g => GRANT_MAP[g] !== undefined ? GRANT_MAP[g] : g)
        .filter(g => g !== null && supportedGrants.has(g));

      if (!item.enabled) {
        const classified = { ...item, classification: 'out-of-scope', skipReason: 'Disabled', concerns: [] };
        outOfScope.push({ c: item.source ?? item, reason: 'Disabled', item: classified });
        continue;
      }

      if (rawGrants.every(g => g === 'ACCESS_TOKEN_VALIDATION')) {
        const reason = 'ACCESS_TOKEN_VALIDATION only — no destination equivalent';
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        outOfScope.push({ c: item.source ?? item, reason, item: classified });
        continue;
      }

      if (poGrants.length === 0) {
        const reason = 'All grant types have no destination equivalent';
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        outOfScope.push({ c: item.source ?? item, reason, item: classified });
        continue;
      }

      if (rawGrants.length === 1 && rawGrants[0] === 'IMPLICIT') {
        const reason = 'IMPLICIT-only → requires AUTHORIZATION_CODE + PKCE code changes';
        const classified = { ...item, classification: 'redesign', skipReason: reason, concerns: [] };
        redesign.push({ c: item.source ?? item, reason, item: classified });
        continue;
      }

      const concerns = [];
      if (destCaps.pkceEnforced && rawGrants.includes('AUTHORIZATION_CODE')) {
        concerns.push('PKCE will be enforced at destination — client must support S256');
      }
      const classified = { ...item, classification: 'direct', skipReason: null, concerns, poGrants };
      direct.push({ c: item.source ?? item, poGrants, item: classified });

    } else if (item.type === 'saml') {
      if (!item.enabled) {
        const reason = 'Disabled';
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        samlOutOfScope.push({ sp: item.source ?? item, reason, item: classified });
        continue;
      }
      const protocol = item.capabilities?.protocol ?? 'SAML';
      if (!protocol.startsWith('SAML')) {
        const reason = `Unsupported protocol: ${protocol}`;
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        samlOutOfScope.push({ sp: item.source ?? item, reason, item: classified });
        continue;
      }
      const acsUrls = item.capabilities?.acsUrls ?? [];
      const hasRelativeAcs = acsUrls.some(u => !u.startsWith('http://') && !u.startsWith('https://'));
      if (acsUrls.length === 0 || hasRelativeAcs) {
        const reason = `ACS URL is missing or relative (${acsUrls[0] ?? 'none'}) — must be an absolute URL`;
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        samlOutOfScope.push({ sp: item.source ?? item, reason, item: classified });
        continue;
      }
      const concerns = [];
      const classified = { ...item, classification: 'direct', skipReason: null, concerns };
      samlDirect.push({ sp: item.source ?? item, item: classified });

    } else if (item.type === 'atm') {
      const classified = { ...item, classification: 'direct', skipReason: null, concerns: [] };
      atmDirect.push({ atm: item.source ?? item, item: classified });

    } else if (item.type === 'key') {
      const classified = { ...item, classification: 'direct', skipReason: null, concerns: [] };
      signingDirect.push({ kp: item.source ?? item, item: classified });

    } else if (item.type === 'idp') {
      if (!item.enabled) {
        const reason = 'Disabled';
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        idpConnOutOfScope.push({ conn: item.source ?? item, reason, item: classified });
        continue;
      }
      if (item.capabilities?.wsTrust || !item.capabilities?.idpBrowserSso) {
        const reason = 'WS-Trust/non-SSO protocol — no destination external IdP equivalent';
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        idpConnOutOfScope.push({ conn: item.source ?? item, reason, item: classified });
        continue;
      }
      const protocol = item.capabilities?.protocol ?? '';
      if (!protocol.startsWith('SAML')) {
        const reason = `Unsupported protocol: ${protocol}`;
        const classified = { ...item, classification: 'out-of-scope', skipReason: reason, concerns: [] };
        idpConnOutOfScope.push({ conn: item.source ?? item, reason, item: classified });
        continue;
      }
      const concerns = [];
      const classified = { ...item, classification: 'direct', skipReason: null, concerns };
      idpConnDirect.push({ conn: item.source ?? item, item: classified });
    }
    // Unknown types are silently skipped (could add to inventory but not classified)
  }

  // Print summary (same style as legacy script)
  console.log('  OIDC:');
  console.log(`    Direct 1:1  : ${direct.length}`);
  console.log(`    Redesign    : ${redesign.length}`);
  console.log(`    Out-of-scope: ${outOfScope.length}`);
  console.log('  SAML:');
  console.log(`    Direct 1:1  : ${samlDirect.length}`);
  console.log(`    Out-of-scope: ${samlOutOfScope.length}`);
  console.log('  ATMs:');
  console.log(`    Direct 1:1  : ${atmDirect.length}`);
  console.log('  Signing keys:');
  console.log(`    Direct 1:1  : ${signingDirect.length}`);
  console.log('  External IdP connections (sp/idpConnections):');
  console.log(`    Direct 1:1  : ${idpConnDirect.length}`);
  console.log(`    Out-of-scope: ${idpConnOutOfScope.length}`);

  if (redesign.length) {
    console.log('\n  OIDC redesign items (not migrated automatically):');
    for (const { c, reason } of redesign) {
      console.log(`    ⚠  ${c.clientId ?? c.id ?? c.name} — ${reason}`);
    }
  }

  if (outOfScope.length) {
    console.log('\n  OIDC out-of-scope items (skipped):');
    for (const { c, reason } of outOfScope) {
      console.log(`    –  ${c.clientId ?? c.id ?? c.name} — ${reason}`);
    }
  }

  if (samlOutOfScope.length) {
    console.log('\n  SAML out-of-scope items (skipped):');
    for (const { sp, reason } of samlOutOfScope) {
      console.log(`    –  ${sp.name ?? sp.id} — ${reason}`);
    }
  }

  if (idpConnOutOfScope.length) {
    console.log('\n  External IdP connection out-of-scope items (skipped):');
    for (const { conn, reason } of idpConnOutOfScope) {
      console.log(`    –  ${conn.name ?? conn.id} — ${reason}`);
    }
  }

  return { direct, redesign, outOfScope, samlDirect, samlOutOfScope, atmDirect, signingDirect, idpConnDirect, idpConnOutOfScope, inventory };
}

module.exports = { rationalize, GRANT_MAP };
