#!/usr/bin/env node
/**
 * Re-check the real App Attest chain in apple-vector.json against Apple's
 * published root, and check the intermediate coinbase_attestation_v2 pins
 * (coinbase-attestation-v2/src/apple_ca.nr) IS the CA 1 key that root signed.
 *
 *   node scripts/coinbase-attestation-v2/check-apple-vector.js
 *
 * Downloads Apple_App_Attestation_Root_CA.pem from apple.com (the root's
 * public location) and checks, in order:
 *   1. the vector's root key is that certificate's key;
 *   2. the root signed the intermediate TBS (ecdsa-with-SHA384);
 *   3. the intermediate key in the vector is the one inside that TBS;
 *   4. the intermediate signed the credential TBS with ecdsa-with-SHA256 --
 *      and NOT with SHA-384, which is why the circuit hashes the credential
 *      certificate with SHA-256.
 *   5. the circuit's APPLE_APP_ATTESTATION_CA_KEY is that intermediate key
 *      (SHA256(X || Y) printed; 0x8ef85f95...747f for CA 1).
 * app-attest-libs tests verify links 2 and 4 in-circuit on these bytes; the
 * circuit itself verifies only link 4. This script is the independent check
 * against apple.com.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { readAppleCa, APPLE_CA_FILE } = require('./anchors');

const ROOT_URL = 'https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem';

async function main() {
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'apple-vector.json'), 'utf8'));
  const hex = h => Buffer.from(h, 'hex');
  const res = await fetch(ROOT_URL);
  if (!res.ok) throw new Error(`${ROOT_URL} answered ${res.status}`);
  const root = new crypto.X509Certificate(await res.text());
  const jwk = root.publicKey.export({ format: 'jwk' });
  const rootXY = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);

  const check = (ok, what) => {
    if (!ok) throw new Error(`FAILED: ${what}`);
    console.log(`  ok  ${what}`);
  };
  console.log(`root: ${root.subject.replace(/\n/g, ', ')}; valid to ${root.validTo}`);
  check(rootXY.equals(hex(v.root_key_xy)), 'vector root key is Apple\'s published root key');
  const p1363 = { dsaEncoding: 'ieee-p1363' };
  check(crypto.verify('sha384', hex(v.intermediate_tbs), { key: root.publicKey, ...p1363 }, hex(v.intermediate_sig)),
    'root signed the intermediate TBS (SHA-384)');
  const ik = hex(v.intermediate_key_xy);
  check(hex(v.intermediate_tbs).includes(Buffer.concat([Buffer.from([4]), ik])), 'intermediate key is the one in its TBS');
  const ikey = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-384', x: ik.subarray(0, 48).toString('base64url'), y: ik.subarray(48).toString('base64url') },
    format: 'jwk',
  });
  check(crypto.verify('sha256', hex(v.credential_tbs), { key: ikey, ...p1363 }, hex(v.credential_sig)),
    'intermediate signed the credential TBS with SHA-256');
  check(!crypto.verify('sha384', hex(v.credential_tbs), { key: ikey, ...p1363 }, hex(v.credential_sig)),
    'and not with SHA-384');
  const pinned = readAppleCa();
  check(pinned.equals(ik), `the circuit pins the intermediate apple.com's root signed (${path.relative(process.cwd(), APPLE_CA_FILE)}), SHA256(X||Y) = 0x${crypto.createHash('sha256').update(pinned).digest('hex')}`);
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
