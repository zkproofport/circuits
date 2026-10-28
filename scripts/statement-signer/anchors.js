/**
 * The two trust anchors of the statement signers, as the scripts see them.
 *
 * statement-signer (the Noir library coinbase_attestation_v2 and
 * oidc_domain_attestation both use) pins two public keys as constants:
 *   statement-signer/src/apple_ca.nr    Apple App Attestation CA 1, the
 *                      intermediate (P-384), valid to 2030-03-13 -- new
 *                      circuits when Apple replaces it
 *   statement-signer/src/server_key.nr  the AI server's statement key
 *                      (P-256, Cloud KMS), ONE line
 *
 * The TEST KEY below has a private key derived from a public string, so
 * ANYONE can sign with it: a verifier deployed with it accepts forged server
 * statements. set-server-key.js swaps a key in; deploy_verifier.sh refuses a
 * mainnet deploy of either circuit while the test key is in place.
 *
 * The SYNTHETIC CA stands in for Apple's intermediate in the acceptance run's
 * synthetic-anchors copy, because no fixture can carry an Apple-signed
 * credential certificate for our App ID with a known device key.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SIGNER_DIR = path.resolve(__dirname, '../../statement-signer');
const SERVER_KEY_FILE = path.join(SIGNER_DIR, 'src/server_key.nr');
const APPLE_CA_FILE = path.join(SIGNER_DIR, 'src/apple_ca.nr');

const N_P256 = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const N_P384 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973');

const TEST_SERVER_KEY_SEED = 'ZKProofport coinbase_attestation_v2 INSECURE test server key';
const SYNTHETIC_CA_SEED = 'ZKProofport coinbase_attestation_v2 INSECURE synthetic App Attest intermediate';
const SYNTHETIC_ANDROID_ROOT_SEED = 'ZKProofport statement-signer INSECURE synthetic Android key attestation root';
const ANDROID_ROOT_FILE = path.join(SIGNER_DIR, 'src/android_root.nr');

/** A key pair whose private scalar is SHA256(seed) (mod n, never zero). */
function keyFromSeed(seed, curve) {
  const [ecdhName, crv, size, n] = {
    'P-256': ['prime256v1', 'P-256', 32, N_P256],
    'P-384': ['secp384r1', 'P-384', 48, N_P384],
  }[curve] || (() => { throw new Error(`Unknown curve ${curve}. Known: P-256, P-384.`); })();
  let d = BigInt('0x' + crypto.createHash('sha256').update(seed).digest('hex')) % n;
  if (d === 0n) throw new Error(`seed ${seed} gives a zero key`);
  const dBuf = Buffer.from(d.toString(16).padStart(size * 2, '0'), 'hex');
  const ecdh = crypto.createECDH(ecdhName);
  ecdh.setPrivateKey(dBuf);
  const pub = ecdh.getPublicKey(); // 04 || X || Y
  const x = pub.subarray(1, 1 + size);
  const y = pub.subarray(1 + size);
  const b64 = b => Buffer.from(b).toString('base64url');
  const privateKey = crypto.createPrivateKey({ key: { kty: 'EC', crv, d: b64(dBuf), x: b64(x), y: b64(y) }, format: 'jwk' });
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey, x: Buffer.from(x), y: Buffer.from(y) };
}

const testServerKey = () => keyFromSeed(TEST_SERVER_KEY_SEED, 'P-256');
const syntheticCa = () => keyFromSeed(SYNTHETIC_CA_SEED, 'P-384');
/** Stands in for Google's Key Attestation CA1 in the synthetic-anchors copy. */
const syntheticAndroidRoot = () => keyFromSeed(SYNTHETIC_ANDROID_ROOT_SEED, 'P-384');

/** X || Y of a P-256 public key in PEM (SPKI), refusing any other curve. */
function p256FromPem(pem) {
  const key = crypto.createPublicKey(pem);
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error(`The server key must be EC P-256 (Cloud KMS EC_SIGN_P256_SHA256); this one is ${jwk.kty} ${jwk.crv || ''}`);
  }
  return Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

const noirBytes = b => '[' + Array.from(b).map(v => `0x${v.toString(16).padStart(2, '0')}`).join(', ') + ']';

/** The one line server_key.nr's constant lives on. */
const serverKeyLine = xy => `pub global SERVER_KEY: [u8; 64] = ${noirBytes(xy)};`;
const SERVER_KEY_LINE_RE = /^pub global SERVER_KEY: \[u8; 64\] = \[[^\]]*\];$/m;

/** The 64 bytes server_key.nr pins now. */
function readServerKey(file = SERVER_KEY_FILE) {
  const m = fs.readFileSync(file, 'utf8').match(SERVER_KEY_LINE_RE);
  if (!m) throw new Error(`${file} has no single-line SERVER_KEY constant`);
  const bytes = m[0].slice(m[0].indexOf('= [') + 3, -2).split(',').map(s => parseInt(s.trim(), 16));
  if (bytes.length !== 64 || bytes.some(b => Number.isNaN(b))) throw new Error(`${file}: SERVER_KEY is not 64 bytes`);
  return Buffer.from(bytes);
}

/** Replace the SERVER_KEY line, and only it. */
function writeServerKey(xy, file = SERVER_KEY_FILE) {
  const src = fs.readFileSync(file, 'utf8');
  const matches = src.match(new RegExp(SERVER_KEY_LINE_RE.source, 'gm')) || [];
  if (matches.length !== 1) throw new Error(`${file}: expected exactly one SERVER_KEY line, found ${matches.length}`);
  const out = src.replace(SERVER_KEY_LINE_RE, serverKeyLine(xy));
  if (out === src && !readServerKey(file).equals(xy)) throw new Error(`${file}: SERVER_KEY was not replaced`);
  fs.writeFileSync(file, out);
}

const CA_LINE_RE = /pub global APPLE_APP_ATTESTATION_CA_KEY: \[u8; 96\] = \[([^\]]*)\];/;

/** Replace the Apple intermediate constant (used only for the synthetic copy). */
function writeAppleCa(xy, file) {
  const src = fs.readFileSync(file, 'utf8');
  if (!CA_LINE_RE.test(src)) throw new Error(`${file} has no APPLE_APP_ATTESTATION_CA_KEY constant`);
  fs.writeFileSync(file, src.replace(CA_LINE_RE, `pub global APPLE_APP_ATTESTATION_CA_KEY: [u8; 96] = ${noirBytes(xy)};`));
  if (!readAppleCa(file).equals(xy)) throw new Error(`${file}: APPLE_APP_ATTESTATION_CA_KEY was not replaced`);
}

/** Apple's intermediate X || Y as the circuit pins it. */
function readAppleCa(file = APPLE_CA_FILE) {
  const m = fs.readFileSync(file, 'utf8').match(CA_LINE_RE);
  if (!m) throw new Error(`${file} has no APPLE_APP_ATTESTATION_CA_KEY constant`);
  const bytes = m[1].split(',').map(s => s.trim()).filter(Boolean).map(s => parseInt(s, 16));
  if (bytes.length !== 96) throw new Error(`${file}: the CA key is ${bytes.length} bytes, not 96`);
  return Buffer.from(bytes);
}

const ANDROID_ROOT_LINE_RE = /pub global GOOGLE_KEY_ATTESTATION_ROOT: \[u8; 96\] = \[([^\]]*)\];/;

/** Google's Key Attestation CA1 X || Y as the circuit pins it. */
function readAndroidRoot(file = ANDROID_ROOT_FILE) {
  const m = fs.readFileSync(file, 'utf8').match(ANDROID_ROOT_LINE_RE);
  if (!m) throw new Error(`${file} has no GOOGLE_KEY_ATTESTATION_ROOT constant`);
  const bytes = m[1].split(',').map(v => v.trim()).filter(Boolean).map(v => parseInt(v, 16));
  if (bytes.length !== 96) throw new Error(`${file}: the Android root key is ${bytes.length} bytes, not 96`);
  return Buffer.from(bytes);
}

/** Replace the Android root constant (used only for the synthetic copy). */
function writeAndroidRoot(xy, file) {
  const src = fs.readFileSync(file, 'utf8');
  if (!ANDROID_ROOT_LINE_RE.test(src)) throw new Error(`${file} has no GOOGLE_KEY_ATTESTATION_ROOT constant`);
  fs.writeFileSync(file, src.replace(ANDROID_ROOT_LINE_RE, `pub global GOOGLE_KEY_ATTESTATION_ROOT: [u8; 96] = ${noirBytes(xy)};`));
  if (!readAndroidRoot(file).equals(xy)) throw new Error(`${file}: GOOGLE_KEY_ATTESTATION_ROOT was not replaced`);
}

const isTestServerKey = xy => {
  const t = testServerKey();
  return Buffer.concat([t.x, t.y]).equals(xy);
};

module.exports = {
  SIGNER_DIR, SERVER_KEY_FILE, APPLE_CA_FILE, ANDROID_ROOT_FILE, N_P256, N_P384,
  keyFromSeed, testServerKey, syntheticCa, syntheticAndroidRoot, p256FromPem,
  readServerKey, writeServerKey, writeAppleCa, readAppleCa, writeAndroidRoot, readAndroidRoot,
  isTestServerKey,
};
