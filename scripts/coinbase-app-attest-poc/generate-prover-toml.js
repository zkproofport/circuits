#!/usr/bin/env node
/**
 * Fixtures for coinbase_app_attest_poc: a REAL Coinbase attestation and
 * SYNTHETIC App Attest material.
 *
 *   node generate-prover-toml.js --coinbase <coinbase-attestation Prover.toml> --out-dir <circuit dir>
 *
 * Needs ATTESTED_WALLET_KEY in the environment: the key of the wallet the
 * Coinbase fixture is for (make-fixtures.sh reads it from proofport-ai/.env.test
 * and never prints it).
 *
 * WHAT IS REAL. raw_transaction, the attester key, the signer Merkle proof
 * and root come from coinbase-attestation/Prover.toml, which
 * proofport-ai/scripts/gen-prover-toml.ts builds from Base. The wallet signs
 * a fresh request here.
 *
 * WHAT IS SYNTHETIC, AND HOW IT DIFFERS FROM APPLE'S. No device sample exists
 * yet. A P-384 key of ours plays "Apple App Attestation CA 1" and a P-256 key
 * plays the Secure Enclave key. The credential certificate is built in the
 * shape of the real one in app-attest-libs/src/tests.nr (same field order, same
 * issuer and subject attribute types, same extensions and OIDs, the 8.5 items
 * copied with our App ID in item [1204], the 8.7 extension copied verbatim,
 * the nonce extension computed). Differences: the signer key, the serial, the
 * validity dates, and authData/assertion bytes produced by this script rather
 * than a device (assertion flags are 0x00; no CBOR extensions in either
 * authData). README.md lists what the real-device step must confirm.
 *
 * Writes Prover.toml (EIP-712 action), Prover.no-action.toml, and the
 * refusal fixtures under test-vectors/ that need re-signing -- the ones the
 * one-field tamper script cannot produce.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('../node_modules/ethers');

const args = process.argv.slice(2);
const opt = name => {
  const i = args.indexOf(name);
  if (i === -1 || !args[i + 1]) throw new Error(`${name} is required`);
  return args[i + 1];
};
const COINBASE_TOML = path.resolve(opt('--coinbase'));
const OUT_DIR = path.resolve(opt('--out-dir'));

// ---- constants that must match the circuit ---------------------------------
const APP_ID = 'R4G32CVY29.com.masselabs.zkproofport';
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase_attestation')));
const MAGIC = Buffer.from('ZKProofport/AA/1');
const KYC_SCHEMA = ethers.getBytes('0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9');
const COINBASE_ATTESTER = ethers.getBytes('0x357458739F90461b99789350868CD7CF330Dd7EE');
const SCOPE_STRING = 'proofport';
const TBS_MAX = 1000;
const ATT_AUTH_MAX = 256;
const ASSERT_AUTH_MAX = 128;
const AAGUID_PROD = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
const N_P256 = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const N_P384 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973');

const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest();

// ---- the Coinbase half ------------------------------------------------------
function parseToml(text) {
  const out = {};
  const re = /^(\w+)\s*=\s*/gm;
  let m;
  while ((m = re.exec(text))) {
    let i = re.lastIndex;
    if (text[i] === '[') {
      let depth = 0;
      let j = i;
      for (; j < text.length; j++) {
        if (text[j] === '[') depth++;
        if (text[j] === ']' && --depth === 0) break;
      }
      const body = text.slice(i, j + 1);
      out[m[1]] = JSON.parse(body.replace(/,\s*\]/g, ']'));
      re.lastIndex = j + 1;
    } else {
      out[m[1]] = text.slice(i).split('\n')[0].trim();
    }
  }
  return out;
}

// ---- DER --------------------------------------------------------------------
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}
const tlv = (tag, ...content) => {
  const body = Buffer.concat(content.map(c => Buffer.from(c)));
  return Buffer.concat([Buffer.from(typeof tag === 'number' ? [tag] : tag), derLen(body.length), body]);
};
const seq = (...c) => tlv(0x30, ...c);
const oid = hex => tlv(0x06, Buffer.from(hex, 'hex'));
const utf8 = s => tlv(0x0c, Buffer.from(s));
const rdn = (oidHex, value) => tlv(0x31, seq(oid(oidHex), utf8(value)));
const OID_CN = '550403';
const OID_OU = '55040b';
const OID_O = '55040a';
const OID_ST = '550408';
const utcTime = d => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));

// The 8.5 items of the real certificate, in order, with [1204] (the App ID)
// rebuilt for whichever id is asked for.
function appIdExtensionValue(appId) {
  const items = [
    'a40302010a', 'bf893003020101', 'bf893103020100', 'bf893203020101', 'bf893303020101',
    null, // [1204] App ID
    'a5060404736b7320', 'bf893603020105', 'bf893703020100', 'bf893903020100', 'bf893a03020100',
    'bf893b03020100', 'aa03020100', 'bf893c060204736b7320',
  ];
  const body = items.map(h => (h ? Buffer.from(h, 'hex') : tlv([0xbf, 0x89, 0x34], tlv(0x04, Buffer.from(appId)))));
  return seq(...body);
}
// 1.2.840.113635.100.8.7, verbatim from the real certificate (OS version and
// similar device data; the circuit only skips it).
const EXT_8_7_VALUE = Buffer.from(
  '3081c6bf8a7808040631382e362e32bf885003020102bf8a79090407312e302e313938bf8a7b080406323247313030bf8a7c08040631382e362e32bf8a7d08040631382e362e32bf8a7e03020100bf8a7f03020100bf8b0003020100bf8b0103020100bf8b0203020100bf8b0303020100bf8b0403020101bf8b0503020100bf8b0a10040e32322e372e3130302e302e302c30bf8b0b10040e32322e372e3130302e302e302c30bf8b0c10040e32322e372e3130302e302e302c30bf88020a04086970686f6e656f73',
  'hex',
);

function credentialTbs({ x, y, keyId, nonce, appId, serial }) {
  const now = Date.now();
  return seq(
    Buffer.from('a003020102', 'hex'),
    tlv(0x02, serial),
    Buffer.from('300a06082a8648ce3d040302', 'hex'),
    seq(rdn(OID_CN, 'Apple App Attestation CA 1'), rdn(OID_O, 'Apple Inc.'), rdn(OID_ST, 'California')),
    seq(utcTime(new Date(now - 86400e3)), utcTime(new Date(now + 270 * 86400e3))),
    seq(rdn(OID_CN, keyId.toString('hex')), rdn(OID_OU, 'AAA Certification'), rdn(OID_O, 'Apple Inc.'), rdn(OID_ST, 'California')),
    Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Buffer.from([4]), x, y]),
    tlv(0xa3, seq(
      Buffer.from('300c0603551d130101ff04023000', 'hex'),
      Buffer.from('300e0603551d0f0101ff0404030204f0', 'hex'),
      seq(oid('2a864886f763640805'), tlv(0x04, appIdExtensionValue(appId))),
      seq(oid('2a864886f763640807'), tlv(0x04, EXT_8_7_VALUE)),
      seq(oid('2a864886f763640802'), tlv(0x04, seq(tlv(0xa1, tlv(0x04, nonce))))),
    )),
  );
}

// ---- keys and signatures ----------------------------------------------------
function ecKey(curve) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, publicKey, x: Buffer.from(jwk.x, 'base64url'), y: Buffer.from(jwk.y, 'base64url') };
}
/** r || s with s in low form: the circuit's verifiers refuse s > n/2. */
function signLowS(alg, msg, key, n, size) {
  const sig = crypto.sign(alg, msg, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  const r = sig.subarray(0, size);
  let s = BigInt('0x' + sig.subarray(size).toString('hex'));
  if (s > n / 2n) s = n - s;
  return Buffer.concat([r, Buffer.from(s.toString(16).padStart(size * 2, '0'), 'hex')]);
}
function highS(sig, n, size) {
  const s = BigInt('0x' + sig.subarray(size).toString('hex'));
  return Buffer.concat([sig.subarray(0, size), Buffer.from((n - s).toString(16).padStart(size * 2, '0'), 'hex')]);
}
function p1363ToDer(sig, size) {
  const int = b => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.subarray(i);
    return tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
  };
  return seq(int(sig.subarray(0, size)), int(sig.subarray(size)));
}

// ---- authenticator data -----------------------------------------------------
function attestationAuthData(cred, rpId) {
  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const cose = Buffer.concat([Buffer.from('a50102032620012158 20'.replace(/ /g, ''), 'hex'), cred.x, Buffer.from('225820', 'hex'), cred.y]);
  return Buffer.concat([sha256(rpId), Buffer.from([0x40]), Buffer.alloc(4), AAGUID_PROD, Buffer.from([0, 32]), keyId, cose]);
}
function assertionAuthData(rpId, counter) {
  const c = Buffer.alloc(4);
  c.writeUInt32BE(counter);
  return Buffer.concat([sha256(rpId), Buffer.from([0x00]), c]);
}

// ---- TOML -------------------------------------------------------------------
const arr = bytes => {
  const a = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const rows = [];
  for (let i = 0; i < a.length; i += 16) rows.push('    ' + a.slice(i, i + 16).join(', '));
  return '[\n' + rows.join(',\n') + '\n]';
};
const pad = (b, n, what) => {
  if (b.length > n) throw new Error(`${what} is ${b.length} bytes; the circuit takes ${n}`);
  return Buffer.concat([Buffer.from(b), Buffer.alloc(n - b.length)]);
};

function main() {
  if (!process.env.ATTESTED_WALLET_KEY) throw new Error('ATTESTED_WALLET_KEY is required');
  const wallet = new ethers.Wallet(process.env.ATTESTED_WALLET_KEY);
  const cb = parseToml(fs.readFileSync(COINBASE_TOML, 'utf8'));
  const userAddress = Buffer.from(cb.user_address);
  if (ethers.getAddress(ethers.hexlify(userAddress)) !== wallet.address) {
    throw new Error(`${COINBASE_TOML} is for ${ethers.hexlify(userAddress)}, the key is for ${wallet.address}`);
  }
  const pub = ethers.getBytes(wallet.signingKey.publicKey);
  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(SCOPE_STRING)));
  const secret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  const nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([secret, scope])));
  const ZERO32 = new Uint8Array(32);

  // The two requests a wallet can sign.
  const signalHash = ethers.getBytes(ethers.solidityPackedKeccak256(
    ['address', 'string', 'string'], [wallet.address, SCOPE_STRING, 'coinbase_attestation']));
  const domain = { name: 'ZKProofport Coinbase App Attest PoC', version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' };
  const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
  const message = { member: wallet.address, nonce: 'coinbase-app-attest-poc-1' };
  const requests = {
    action: {
      signal: ZERO32,
      domainSeparator: ethers.getBytes(ethers.TypedDataEncoder.hashDomain(domain)),
      actionHash: ethers.getBytes(ethers.TypedDataEncoder.hashStruct('Join', types, message)),
      digest: ethers.getBytes(ethers.TypedDataEncoder.hash(domain, types, message)),
    },
    noAction: {
      signal: signalHash,
      domainSeparator: ZERO32,
      actionHash: ZERO32,
      digest: ethers.getBytes(ethers.hashMessage(signalHash)),
    },
  };
  for (const r of Object.values(requests)) {
    const sig = wallet.signingKey.sign(r.digest);
    r.userSignature = ethers.getBytes(ethers.concat([sig.r, sig.s]));
  }

  // ---- one synthetic device -----------------------------------------------
  const ca = ecKey('secp384r1');
  const otherCa = ecKey('secp384r1');
  const cred = ecKey('prime256v1');
  const otherCred = ecKey('prime256v1');
  const caKey = Buffer.concat([ca.x, ca.y]);
  const caKeyHash = sha256(caKey);

  const attAuth = attestationAuthData(cred, APP_ID);
  const attCdh = sha256(crypto.randomBytes(32));
  const certNonce = sha256(attAuth, attCdh);
  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const serial = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(5)]);
  const certFor = (appId, nonce = certNonce) => credentialTbs({ x: cred.x, y: cred.y, keyId, nonce, appId, serial });
  const tbs = certFor(APP_ID);
  const certSig = signLowS('sha256', tbs, ca, N_P384, 48);

  // Self-check: a full certificate built from these parts parses as X.509 and
  // verifies with the CA key, so a refusal in the circuit is the circuit's.
  const certDer = seq(tbs, Buffer.from('300a06082a8648ce3d040302', 'hex'), tlv(0x03, Buffer.from([0]), p1363ToDer(certSig, 48)));
  const x509 = new crypto.X509Certificate(certDer);
  if (!x509.verify(ca.publicKey)) throw new Error('synthetic credential certificate does not verify');
  if (tbs.length > TBS_MAX) throw new Error(`TBS is ${tbs.length} bytes`);

  const attestedAt = Math.floor(Date.now() / 1000);
  const easUid = crypto.randomBytes(32); // what the app would have found; not checked in-circuit

  function clientData(req, o = {}) {
    const t = Buffer.alloc(8);
    t.writeBigUInt64BE(BigInt(o.timestamp ?? attestedAt));
    const cd = Buffer.concat([
      MAGIC, Buffer.from(CIRCUIT_TAG), Buffer.from(o.wallet ?? userAddress), t,
      Buffer.from(o.schema ?? KYC_SCHEMA), Buffer.from(COINBASE_ATTESTER), easUid,
      Buffer.from([o.revoked ?? 0]), Buffer.from(o.digest ?? req.digest), Buffer.from(o.scope ?? scope),
    ]);
    if (cd.length !== 225) throw new Error(`clientData is ${cd.length} bytes`);
    return cd;
  }
  function assertion(cd, o = {}) {
    const auth = assertionAuthData(o.rpId ?? APP_ID, o.counter ?? 1);
    const nonce = sha256(auth, sha256(cd));
    const sig = signLowS('sha256', nonce, o.key ?? cred, N_P256, 32);
    // Same self-check for the assertion: Node verifies it as Apple's
    // validators do (ECDSA-SHA256 over nonce).
    if (!crypto.verify('sha256', nonce, { key: (o.key ?? cred).publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
      throw new Error('synthetic assertion does not verify');
    }
    return { auth, sig };
  }

  function toml(req, o = {}) {
    const cd = o.clientData ?? clientData(req);
    const as = o.assertion ?? assertion(cd);
    return `# Generated by scripts/coinbase-app-attest-poc/generate-prover-toml.js
# Coinbase part: real (from ${path.basename(path.dirname(COINBASE_TOML))}/Prover.toml).
# App Attest part: SYNTHETIC -- our own P-384 "CA" and P-256 "device" key.
# Case: ${o.label ?? 'accepted'}

signal_hash = ${arr(req.signal)}
domain_separator = ${arr(req.domainSeparator)}
action_hash = ${arr(req.actionHash)}
signer_list_merkle_root = ${arr(cb.signer_list_merkle_root)}
scope = ${arr(scope)}
nullifier = ${arr(nullifier)}
app_attest_ca_key_hash = ${arr(o.caKeyHash ?? caKeyHash)}
attested_at = ${o.attestedAt ?? attestedAt}
app_attest_production = ${o.production ?? true}

user_address = ${arr(userAddress)}
user_signature = ${arr(req.userSignature)}
user_pubkey_x = ${arr(pub.slice(1, 33))}
user_pubkey_y = ${arr(pub.slice(33, 65))}
raw_transaction = ${arr(cb.raw_transaction)}
tx_length = ${cb.tx_length}
coinbase_attester_pubkey_x = ${arr(cb.coinbase_attester_pubkey_x)}
coinbase_attester_pubkey_y = ${arr(cb.coinbase_attester_pubkey_y)}
coinbase_signer_merkle_proof = [
${cb.coinbase_signer_merkle_proof.map(row => arr(row)).join(',\n')}
]
coinbase_signer_leaf_index = ${cb.coinbase_signer_leaf_index}
merkle_proof_depth = ${cb.merkle_proof_depth}

client_data = ${arr(cd)}
app_attest_ca_key = ${arr(o.caKey ?? caKey)}
credential_tbs = ${arr(pad(o.tbs ?? tbs, TBS_MAX, 'TBS'))}
credential_tbs_len = ${(o.tbs ?? tbs).length}
credential_sig = ${arr(o.certSig ?? certSig)}
att_auth_data = ${arr(pad(attAuth, ATT_AUTH_MAX, 'attestation authData'))}
att_auth_data_len = ${attAuth.length}
att_client_data_hash = ${arr(o.attCdh ?? attCdh)}
assertion_auth_data = ${arr(pad(as.auth, ASSERT_AUTH_MAX, 'assertion authData'))}
assertion_auth_data_len = ${as.auth.length}
assertion_sig = ${arr(as.sig)}
`;
  }

  const A = requests.action;
  const vectors = path.join(OUT_DIR, 'test-vectors');
  fs.mkdirSync(vectors, { recursive: true });
  const write = (file, text) => {
    fs.writeFileSync(path.join(OUT_DIR, file), text);
    console.log('wrote', file);
  };
  write('Prover.toml', toml(A));
  write('Prover.no-action.toml', toml(requests.noAction));

  // Refusals that need something re-signed. Each changes ONE thing.
  const otherTbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce: certNonce, appId: APP_ID, serial: Buffer.from('02aabbccddee', 'hex') });
  const otherAppId = APP_ID.slice(0, -1) + 's'; // same length, so only the comparison can refuse
  const otherAppTbs = certFor(otherAppId);
  const otherWallet = ethers.getBytes(ethers.Wallet.createRandom().address);
  const cases = {
    // The CA key is the right one; the signature is over a different TBS.
    cert_bad_signature: { certSig: signLowS('sha256', otherTbs, ca, N_P384, 48) },
    // A certificate properly signed by another P-384 key, presented with that key.
    cert_other_ca: { caKey: Buffer.concat([otherCa.x, otherCa.y]), certSig: signLowS('sha256', tbs, otherCa, N_P384, 48) },
    // Properly signed by the CA, for another app.
    cert_other_app: { tbs: otherAppTbs, certSig: signLowS('sha256', otherAppTbs, ca, N_P384, 48) },
    // Apple's signature in high-s form: the same signature, refused by the library.
    cert_high_s: { certSig: highS(certSig, N_P384, 48) },
    // The attestation clientDataHash is not the one the certificate's nonce covers.
    attestation_not_certified: { attCdh: sha256(Buffer.from('another challenge')) },
    // Public input says development; the key is a production key.
    env_mismatch: { production: false },
    assertion_other_key: { assertion: assertion(clientData(A), { key: otherCred }) },
    assertion_wrong_rpid: { assertion: assertion(clientData(A), { rpId: otherAppId }) },
    assertion_counter_zero: { assertion: assertion(clientData(A), { counter: 0 }) },
    assertion_high_s: (() => {
      const as = assertion(clientData(A));
      return { assertion: { auth: as.auth, sig: highS(as.sig, N_P256, 32) } };
    })(),
    client_wallet_mismatch: { clientData: clientData(A, { wallet: otherWallet }) },
    client_revoked: { clientData: clientData(A, { revoked: 1 }) },
    client_other_schema: { clientData: clientData(A, { schema: sha256(Buffer.from('another schema')) }) },
    // A genuine assertion, made for the no-action request, replayed into the action proof.
    client_other_request: { clientData: clientData(A, { digest: requests.noAction.digest }) },
    client_other_scope: { clientData: clientData(A, { scope: ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('another-scope'))) }) },
    // The public timestamp moved; the app signed the old one.
    timestamp_changed: { attestedAt: attestedAt + 1 },
    stale_timestamp_resigned: { clientData: clientData(A, { timestamp: attestedAt - 3600 }) },
  };
  for (const [name, o] of Object.entries(cases)) {
    write(path.join('test-vectors', `${name}.toml`), toml(A, { ...o, label: name }));
  }

  console.log('wallet:            ', wallet.address);
  console.log('App ID:            ', APP_ID);
  console.log('CA key hash:       ', caKeyHash.toString('hex'), '(synthetic CA)');
  console.log('credential TBS:    ', tbs.length, 'bytes; attestation authData', attAuth.length, 'bytes');
  console.log('attested_at:       ', attestedAt);
}

try {
  main();
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
}
