#!/usr/bin/env node
/**
 * Fixtures for coinbase_attestation_v2: a REAL Coinbase attestation, and
 * statements signed by SYNTHETIC App Attest material or by the server test key.
 *
 *   node generate-prover-toml.js --coinbase <coinbase-attestation Prover.toml> \
 *        --synthetic-dir <synthetic-anchors copy> --real-dir <coinbase-attestation-v2>
 *
 * Needs ATTESTED_WALLET_KEY in the environment: the key of the wallet the
 * Coinbase fixture is for (make-fixtures.sh reads it from proofport-ai/.env.test
 * and never prints it).
 *
 * TWO TARGETS.
 *   --synthetic-dir  the synthetic-anchors copy of the circuit (make-fixtures.sh
 *                    makes it): Apple's CA 1 replaced by the SYNTHETIC CA
 *                    (anchors.js), the server key by the test key. Every
 *                    acceptance and refusal case runs here, because no fixture
 *                    can carry an Apple-signed credential certificate for our
 *                    App ID together with that device's private key.
 *                    Writes Prover.toml (app kind, EIP-712 action),
 *                    Prover.no-action.toml, and test-vectors/*.toml.
 *   --real-dir       the real circuit, Apple's CA 1 pinned. Writes
 *                    test-vectors/real_*.toml: a server-kind statement (accepted
 *                    while the test key is pinned, refused after the swap), the
 *                    synthetic chain (refused: not signed by Apple's CA 1), and
 *                    a REAL credential certificate CA 1 signed (zkPassport's
 *                    vector), which must pass the P-384 check and stop at the
 *                    App ID.
 *
 * WHAT IS REAL. raw_transaction, the attester key, the signer Merkle proof
 * and root come from coinbase-attestation/Prover.toml, which
 * proofport-ai/scripts/gen-prover-toml.ts builds from Base. apple-vector.json
 * is a real Apple chain. The wallet signs a fresh request here.
 *
 * HOW THE SYNTHETIC CHAIN DIFFERS FROM APPLE'S. The intermediate is only a
 * key (anchors.js syntheticCa, pinned in the copy as CA 1 is in the circuit).
 * The credential certificate copies the real
 * one's structure (field order, attribute types, extensions and OIDs; the 8.5
 * items with our App ID; the 8.7 extension verbatim; the nonce computed).
 * Assertion flags are 0x00; no CBOR extensions in either authData.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('../node_modules/ethers');
const anchors = require('./anchors');

const opt = name => {
  const args = process.argv.slice(2);
  const i = args.indexOf(name);
  if (i === -1 || !args[i + 1]) throw new Error(`${name} is required`);
  return args[i + 1];
};

// ---- constants that must match the circuit ---------------------------------
const APP_ID = 'R4G32CVY29.com.masselabs.zkproofport';
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase_attestation')));
const MAGIC = Buffer.from('ZKProofport/AA/1');
const KYC_SCHEMA = ethers.getBytes('0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9');
const COINBASE_ATTESTER = ethers.getBytes('0x357458739F90461b99789350868CD7CF330Dd7EE');
const SCOPE_STRING = 'proofport';
const KIND_APP = 1;
const KIND_SERVER = 2;
const TBS_MAX = 1000;
const ATT_AUTH_MAX = 256;
const ASSERT_AUTH_MAX = 128;
const AAGUID_PROD = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
const AAGUID_DEV = Buffer.from('appattestdevelop');
const { N_P256, N_P384 } = anchors;

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
const SIG_ALG_SHA256 = Buffer.from('300a06082a8648ce3d040302', 'hex');

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
    SIG_ALG_SHA256,
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
const toLowS = (sig, n, size) => {
  let s = BigInt('0x' + sig.subarray(size).toString('hex'));
  if (s > n / 2n) s = n - s;
  return Buffer.concat([sig.subarray(0, size), Buffer.from(s.toString(16).padStart(size * 2, '0'), 'hex')]);
};
/** r || s with s in low form: the circuit's verifiers refuse s > n/2. */
function signLowS(alg, msg, key, n, size) {
  return toLowS(crypto.sign(alg, msg, { key: key.privateKey, dsaEncoding: 'ieee-p1363' }), n, size);
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
const certDer = (tbs, alg, sig, size) => seq(tbs, alg, tlv(0x03, Buffer.from([0]), p1363ToDer(sig, size)));

// ---- authenticator data -----------------------------------------------------
function attestationAuthData(cred, rpId, aaguid) {
  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), cred.x, Buffer.from('225820', 'hex'), cred.y]);
  return Buffer.concat([sha256(rpId), Buffer.from([0x40]), Buffer.alloc(4), aaguid, Buffer.from([0, 32]), keyId, cose]);
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

/** What the server does: ECDSA P-256 over SHA256(clientData), DER from
 *  Cloud KMS, converted to r || s with s low. Signing the message with
 *  'sha256' here is the same signature KMS makes from digest.sha256. */
function serverSign(clientData, key) {
  const der = crypto.sign('sha256', clientData, key.privateKey); // DER, as KMS returns
  const p1363 = derToP1363(der, 32);
  const sig = toLowS(p1363, N_P256, 32);
  if (!crypto.verify('sha256', clientData, { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
    throw new Error('server signature does not verify');
  }
  return sig;
}
function derToP1363(der, size) {
  if (der[0] !== 0x30) throw new Error('not a DER signature');
  let p = 2;
  const read = () => {
    if (der[p] !== 0x02) throw new Error('not a DER INTEGER');
    const len = der[p + 1];
    let v = der.subarray(p + 2, p + 2 + len);
    p += 2 + len;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error('DER integer too long');
    return Buffer.concat([Buffer.alloc(size - v.length), v]);
  };
  return Buffer.concat([read(), read()]);
}

function main() {
  const COINBASE_TOML = path.resolve(opt('--coinbase'));
  const SYN_DIR = path.resolve(opt('--synthetic-dir'));
  const REAL_DIR = path.resolve(opt('--real-dir'));
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
  const domain = { name: 'ZKProofport Coinbase KYC v2 fixture', version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' };
  const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
  const message = { member: wallet.address, nonce: 'coinbase-attestation-v2-1' };
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

  // ---- anchors: the synthetic CA and the server test key ---------------------
  const inter = anchors.syntheticCa();
  const otherInter = ecKey('secp384r1');
  const server = anchors.testServerKey();
  const otherServer = ecKey('prime256v1');
  const syntheticCaXY = Buffer.concat([inter.x, inter.y]);
  // The real circuit must pin Apple's CA 1, never the synthetic one.
  if (anchors.readAppleCa().equals(syntheticCaXY)) throw new Error('the real circuit pins the synthetic CA');

  // ---- one synthetic device ---------------------------------------------------
  const cred = ecKey('prime256v1');
  const otherCred = ecKey('prime256v1');

  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const serial = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(5)]);
  const attCdh = sha256(crypto.randomBytes(32));
  const device = (aaguid = AAGUID_PROD, appId = APP_ID) => {
    const attAuth = attestationAuthData(cred, APP_ID, aaguid);
    const nonce = sha256(attAuth, attCdh);
    const tbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce, appId, serial });
    const sig = signLowS('sha256', tbs, inter, N_P384, 48);
    return { attAuth, tbs, sig };
  };
  const dev = device();
  const x509 = new crypto.X509Certificate(certDer(dev.tbs, SIG_ALG_SHA256, dev.sig, 48));
  if (!x509.verify(crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-384', x: inter.x.toString('base64url'), y: inter.y.toString('base64url') }, format: 'jwk' }))) {
    throw new Error('synthetic credential certificate does not verify');
  }
  if (dev.tbs.length > TBS_MAX) throw new Error(`TBS is ${dev.tbs.length} bytes`);

  const attestedAt = Math.floor(Date.now() / 1000);
  const easUid = crypto.randomBytes(32); // what the signer found; not checked in-circuit

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
    if (!crypto.verify('sha256', nonce, { key: (o.key ?? cred).publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
      throw new Error('synthetic assertion does not verify');
    }
    return { auth, sig };
  }

  const EMPTY_CHAIN = {
    tbs: Buffer.alloc(0), certSig: Buffer.alloc(96),
    attAuth: Buffer.alloc(0), attCdh: Buffer.alloc(32), assertAuth: Buffer.alloc(0),
  };

  /** One Prover TOML. kind 'app' builds the chain unless overridden; 'server'
   *  passes zeros for every App Attest input, exactly as README.md says. */
  function toml(req, o = {}) {
    const kindName = o.kind ?? 'app';
    const cd = o.clientData ?? clientData(req);
    let chain;
    let statementSig;
    if (kindName === 'app') {
      const as = o.assertion ?? assertion(cd);
      chain = {
        tbs: o.tbs ?? dev.tbs, certSig: o.certSig ?? dev.sig,
        attAuth: o.attAuth ?? dev.attAuth, attCdh: o.attCdh ?? attCdh, assertAuth: as.auth,
      };
      statementSig = o.statementSig ?? as.sig;
    } else if (kindName === 'server') {
      chain = o.chain ?? EMPTY_CHAIN;
      statementSig = o.statementSig ?? serverSign(cd, o.serverKey ?? server);
    } else {
      throw new Error(`Unknown fixture kind ${kindName}. Known: app, server.`);
    }
    const kindByte = o.kindByte ?? { app: KIND_APP, server: KIND_SERVER }[kindName];
    return `# Generated by scripts/coinbase-attestation-v2/generate-prover-toml.js
# Coinbase part: real (from ${path.basename(path.dirname(COINBASE_TOML))}/Prover.toml).
# Statement: ${kindName} kind${kindName === 'app' ? ', SYNTHETIC App Attest chain' : ', INSECURE test server key'}.
# Case: ${o.label ?? 'accepted'}

signal_hash = ${arr(req.signal)}
domain_separator = ${arr(req.domainSeparator)}
action_hash = ${arr(req.actionHash)}
signer_list_merkle_root = ${arr(cb.signer_list_merkle_root)}
scope = ${arr(scope)}
nullifier = ${arr(nullifier)}
attested_at = ${o.attestedAt ?? attestedAt}

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
signer_kind = ${kindByte}
statement_sig = ${arr(statementSig)}

credential_tbs = ${arr(pad(chain.tbs, TBS_MAX, 'TBS'))}
credential_tbs_len = ${chain.tbs.length}
credential_sig = ${arr(chain.certSig)}
att_auth_data = ${arr(pad(chain.attAuth, ATT_AUTH_MAX, 'attestation authData'))}
att_auth_data_len = ${chain.attAuth.length}
att_client_data_hash = ${arr(chain.attCdh)}
assertion_auth_data = ${arr(pad(chain.assertAuth, ASSERT_AUTH_MAX, 'assertion authData'))}
assertion_auth_data_len = ${chain.assertAuth.length}
`;
  }

  const A = requests.action;
  const writer = dir => (file, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), text);
    console.log('wrote', path.relative(path.dirname(dir), path.join(dir, file)));
  };
  const syn = writer(SYN_DIR);
  syn('Prover.toml', toml(A));
  syn('Prover.no-action.toml', toml(requests.noAction));

  // ---- the synthetic-anchors cases. Each changes ONE thing. ------------------
  const otherAppId = APP_ID.slice(0, -1) + 's'; // same length, so only the comparison can refuse
  const otherWallet = ethers.getBytes(ethers.Wallet.createRandom().address);
  const reSignCred = tbs => signLowS('sha256', tbs, inter, N_P384, 48);
  const otherCredTbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce: sha256(dev.attAuth, attCdh), appId: APP_ID, serial: Buffer.from('02aabbccddee', 'hex') });
  const appCd = clientData(A);
  const devEnv = device(AAGUID_DEV);
  const otherApp = device(AAGUID_PROD, otherAppId);

  const cases = {
    // ---- server kind
    server_action: { kind: 'server' },
    server_ignores_chain_fields: {
      kind: 'server',
      chain: { tbs: dev.tbs, certSig: dev.sig, attAuth: dev.attAuth, attCdh, assertAuth: assertion(appCd).auth },
    },
    server_other_key: { kind: 'server', serverKey: otherServer },
    server_client_revoked: { kind: 'server', clientData: clientData(A, { revoked: 1 }) },
    server_high_s: { kind: 'server', statementSig: highS(serverSign(appCd, server), N_P256, 32) },
    // ---- the private kind byte
    kind_flipped_app_to_server: { kindByte: KIND_SERVER },
    kind_flipped_server_to_app: { kind: 'server', kindByte: KIND_APP },
    // Server-signed with an unknown kind byte: without the kind assert these
    // would take the server path and be ACCEPTED, so the assert is what refuses.
    kind_zero: { kind: 'server', kindByte: 0 },
    kind_unknown: { kind: 'server', kindByte: 3 },
    app_chain_with_server_signature: { statementSig: serverSign(appCd, server) },
    // ---- intermediate -> credential
    cert_bad_signature: { certSig: reSignCred(otherCredTbs) },
    cert_other_ca: { certSig: signLowS('sha256', dev.tbs, otherInter, N_P384, 48) },
    cert_other_app: { tbs: otherApp.tbs, certSig: otherApp.sig, attAuth: otherApp.attAuth },
    cert_high_s: { certSig: highS(dev.sig, N_P384, 48) },
    attestation_not_certified: { attCdh: sha256(Buffer.from('another challenge')) },
    env_development: { tbs: devEnv.tbs, certSig: devEnv.sig, attAuth: devEnv.attAuth },
    // ---- the assertion
    assertion_other_key: { assertion: assertion(appCd, { key: otherCred }) },
    assertion_wrong_rpid: { assertion: assertion(appCd, { rpId: otherAppId }) },
    assertion_counter_zero: { assertion: assertion(appCd, { counter: 0 }) },
    assertion_high_s: (() => {
      const as = assertion(appCd);
      return { assertion: { auth: as.auth, sig: highS(as.sig, N_P256, 32) } };
    })(),
    // ---- the statement
    client_wallet_mismatch: { clientData: clientData(A, { wallet: otherWallet }) },
    client_revoked: { clientData: clientData(A, { revoked: 1 }) },
    client_other_schema: { clientData: clientData(A, { schema: sha256(Buffer.from('another schema')) }) },
    client_other_request: { clientData: clientData(A, { digest: requests.noAction.digest }) },
    client_other_scope: { clientData: clientData(A, { scope: ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('another-scope'))) }) },
    timestamp_changed: { attestedAt: attestedAt + 1 },
    stale_timestamp_resigned: { clientData: clientData(A, { timestamp: attestedAt - 3600 }) },
  };
  for (const [name, o] of Object.entries(cases)) {
    syn(path.join('test-vectors', `${name}.toml`), toml(A, { ...o, label: name }));
  }
  syn(path.join('test-vectors', 'server_no_action.toml'), toml(requests.noAction, { kind: 'server', label: 'server_no_action' }));

  // ---- the real circuit (Apple's CA 1 pinned) ---------------------------------
  const real = writer(REAL_DIR);
  real(path.join('test-vectors', 'real_server_action.toml'), toml(A, { kind: 'server', label: 'real_server_action' }));
  real(path.join('test-vectors', 'real_synthetic_ca.toml'), toml(A, { label: 'real_synthetic_ca' }));
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'apple-vector.json'), 'utf8'));
  const hex = h => Buffer.from(h, 'hex');
  if (!anchors.readAppleCa().equals(hex(v.intermediate_key_xy))) throw new Error('the real circuit does not pin apple-vector.json\'s intermediate (CA 1)');
  real(path.join('test-vectors', 'real_apple_chain.toml'), toml(A, {
    label: 'real_apple_chain: CA 1 -> zkPassport credential (another App ID)',
    tbs: hex(v.credential_tbs),
    certSig: toLowS(hex(v.credential_sig), N_P384, 48),
  }));

  console.log('wallet:            ', wallet.address);
  console.log('App ID:            ', APP_ID);
  console.log('synthetic CA:      ', syntheticCaXY.toString('hex'));
  console.log('server test key:   ', Buffer.concat([server.x, server.y]).toString('hex'));
  console.log('credential TBS:    ', dev.tbs.length, 'bytes; attestation authData', dev.attAuth.length, 'bytes');
  console.log('attested_at:       ', attestedAt);
}

// The certificate builder and signing helpers are shared with
// ../coinbase-app-attest-poc/generate-trust-anchor-fixtures.js.
module.exports = {
  APP_ID, N_P256, N_P384, TBS_MAX, sha256, seq, tlv, credentialTbs, ecKey, signLowS, p1363ToDer, arr, pad,
};

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
}
