#!/usr/bin/env node
/**
 * Set the AI server's statement key that statement-signer pins for
 * coinbase_attestation_v2 and oidc_domain_attestation.
 *
 *   node scripts/statement-signer/set-server-key.js --kms <key version>
 *       <key version> = projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
 *       Runs `gcloud kms keys versions get-public-key` for it. The key's
 *       algorithm must be EC_SIGN_P256_SHA256.
 *   node scripts/statement-signer/set-server-key.js --pem <public key .pem>
 *   node scripts/statement-signer/set-server-key.js --test-key
 *       Puts the INSECURE test key back (see anchors.js).
 *   node scripts/statement-signer/set-server-key.js --show
 *       Prints the pinned key and whether it is the test key.
 *   node scripts/statement-signer/set-server-key.js --require-real
 *       Exits 1 while the test key is pinned (deploy_verifier.sh calls this).
 *
 * It rewrites exactly one line, `pub global SERVER_KEY: [u8; 64] = [...];`
 * in statement-signer/src/server_key.nr. Changing the key changes BOTH
 * circuits, their vks and their verifiers: rebuild (scripts/build.sh
 * coinbase-attestation-v2, scripts/build.sh oidc-domain-attestation) and
 * redeploy both afterwards.
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const a = require('./anchors');

function main() {
  const args = process.argv.slice(2);
  const mode = args[0];
  const show = xy => {
    console.log(`SERVER_KEY X||Y: 0x${xy.toString('hex')}`);
    console.log(a.isTestServerKey(xy)
      ? 'This is the INSECURE TEST KEY: anyone can sign server statements for it.'
      : 'This is not the test key.');
  };
  if (mode === '--show') return show(a.readServerKey());
  if (mode === '--require-real') {
    const xy = a.readServerKey();
    if (a.isTestServerKey(xy)) {
      console.error(`${a.SERVER_KEY_FILE} pins the INSECURE test server key. Set the real one first: set-server-key.js --kms <key version>`);
      process.exit(1);
    }
    return show(xy);
  }
  let xy;
  if (mode === '--test-key') {
    const k = a.testServerKey();
    xy = Buffer.concat([k.x, k.y]);
  } else if (mode === '--pem') {
    if (!args[1]) throw new Error('--pem needs a file');
    xy = a.p256FromPem(fs.readFileSync(args[1], 'utf8'));
  } else if (mode === '--kms') {
    const version = args[1];
    if (!version || !/^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/\d+$/.test(version)) {
      throw new Error('--kms needs projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V');
    }
    const parts = version.split('/');
    const [project, location, ring, key, ver] = [parts[1], parts[3], parts[5], parts[7], parts[9]];
    const where = ['--key', key, '--keyring', ring, '--location', location, '--project', project];
    const meta = JSON.parse(execFileSync('gcloud', ['kms', 'keys', 'versions', 'describe', ver, ...where, '--format', 'json'], { encoding: 'utf8' }));
    if (meta.algorithm !== 'EC_SIGN_P256_SHA256') {
      throw new Error(`${version} is ${meta.algorithm}; the circuit verifies EC_SIGN_P256_SHA256`);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'server-key-'));
    const pemFile = path.join(dir, 'public.pem');
    let pem;
    try {
      execFileSync('gcloud', ['kms', 'keys', 'versions', 'get-public-key', ver, ...where, '--output-file', pemFile], { stdio: 'inherit' });
      pem = fs.readFileSync(pemFile, 'utf8');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    xy = a.p256FromPem(pem);
  } else {
    throw new Error(`Unknown mode ${mode}. Known: --kms, --pem, --test-key, --show, --require-real.`);
  }
  a.writeServerKey(xy);
  if (!a.readServerKey().equals(xy)) throw new Error('server_key.nr does not hold the key just written');
  console.log(`wrote ${a.SERVER_KEY_FILE}`);
  show(xy);
  console.log('Now rebuild both circuits: scripts/build.sh coinbase-attestation-v2 and scripts/build.sh oidc-domain-attestation (their vks and verifiers change).');
}

try {
  main();
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
}
