#!/usr/bin/env node
/**
 * Re-check the real App Attest chain in apple-vector.json against Apple's
 * published root, and print the production `app_attest_ca_key_hash`.
 *
 *   node scripts/coinbase-app-attest-poc/check-apple-vector.js
 *
 * Downloads Apple_App_Attestation_Root_CA.pem from apple.com (the root's
 * public location) and checks, in order:
 *   1. the vector's root key is that certificate's key;
 *   2. the root signed the intermediate TBS (ecdsa-with-SHA384);
 *   3. the intermediate key in the vector is the one inside that TBS;
 *   4. the intermediate signed the credential TBS with ecdsa-with-SHA256 --
 *      and NOT with SHA-384, which is why the circuit hashes the credential
 *      certificate with SHA-256.
 * Then prints SHA256(intermediate X || Y): the value a verifier pins as
 * app_attest_ca_key_hash for real devices. This is the off-circuit half of
 * the chain; the circuit takes over from the intermediate key.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
  console.log(`app_attest_ca_key_hash (Apple App Attestation CA 1): 0x${crypto.createHash('sha256').update(ik).digest('hex')}`);
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
