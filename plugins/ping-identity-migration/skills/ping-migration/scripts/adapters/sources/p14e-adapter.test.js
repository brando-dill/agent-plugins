'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const p14eAdapter = require('./p14e-adapter');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'p14e-adapter-test-'));
}

function writeExport(dir, data) {
  const file = path.join(dir, 'p14e-export.json');
  fs.writeFileSync(file, JSON.stringify(data));
  return file;
}

test('extract() in file mode detects OIDC and SAML applications by templateRef', async () => {
  const dir = tmpDir();
  const importFile = writeExport(dir, {
    applications: [
      {
        // P14E returns grant types lowercase and app status via `state`.
        id: 'app-1', name: 'oidc-app', templateRef: '/templates/oidc', state: 'ENABLED',
        grantTypes: ['authorization_code'], redirectUris: ['https://example.com/cb'], scopes: ['openid'],
      },
      {
        // P14E returns a single `acsUrl` string, not an array of endpoints,
        // and has no explicit sign-assertions/sign-response toggle — a
        // configured signingCertId implies the response is signed.
        id: 'app-2', name: 'saml-app', templateRef: '/templates/saml20', state: 'ENABLED',
        spEntityId: 'urn:example:sp', acsUrl: 'https://example.com/acs',
        signingCertId: 'cert-1', signingAlgorithm: 'RSA_SHA256',
      },
    ],
    metadata: [],
    accountCertificates: [],
  });

  const items = await p14eAdapter.extract({ importFile }, dir);

  assert.equal(items.length, 2);
  const oidc = items.find((i) => i.type === 'oidc');
  const saml = items.find((i) => i.type === 'saml');
  assert.ok(oidc, 'expected an oidc item');
  assert.ok(saml, 'expected a saml item');
  assert.deepEqual(oidc.capabilities.grantTypes, ['AUTHORIZATION_CODE']);
  assert.equal(saml.capabilities.entityId, 'urn:example:sp');
  assert.deepEqual(saml.capabilities.acsUrls, ['https://example.com/acs']);
  assert.equal(saml.capabilities.signResponse, true);
});

test('extract() in file mode leaves signResponse false for a SAML app with no signingCertId', async () => {
  const dir = tmpDir();
  const importFile = writeExport(dir, {
    applications: [
      { id: 'app-3', name: 'unsigned-saml', templateRef: '/templates/saml20', state: 'ENABLED', spEntityId: 'urn:example:sp2', acsUrl: 'https://example.com/acs2' },
    ],
    metadata: [],
    accountCertificates: [],
  });

  const items = await p14eAdapter.extract({ importFile }, dir);

  assert.equal(items[0].capabilities.signResponse, false);
});

test('extract() in file mode skips applications with an unrecognized templateRef', async () => {
  const dir = tmpDir();
  const importFile = writeExport(dir, {
    applications: [{ id: 'app-1', name: 'mystery-app', templateRef: '/templates/wsfed', enabled: true }],
    metadata: [],
    accountCertificates: [],
  });

  const items = await p14eAdapter.extract({ importFile }, dir);

  assert.equal(items.length, 0);
});

test('extract() in file mode maps accountCertificates to key items', async () => {
  const dir = tmpDir();
  const future = new Date(Date.now() + 30 * 86400000).toISOString();
  const importFile = writeExport(dir, {
    applications: [],
    metadata: [],
    accountCertificates: [
      { id: 'cert-1', subjectDN: 'CN=example', status: 'VALID', keyAlgorithm: 'RSA', keySize: 2048, expires: future },
    ],
  });

  const items = await p14eAdapter.extract({ importFile }, dir);

  assert.equal(items.length, 1);
  assert.equal(items[0].type, 'key');
  assert.equal(items[0].enabled, true);
  assert.equal(items[0].capabilities.algorithm, 'RSA');
  assert.equal(items[0].capabilities.keySize, 2048);
});

test('extract() in live mode throws when credentials are missing', async () => {
  await assert.rejects(
    () => p14eAdapter.extract({}, tmpDir()),
    /--p14e-username and --p14e-password/
  );
});
