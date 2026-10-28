/**
 * The two statement signers, as fixtures see them: a SYNTHETIC App Attest
 * device under the synthetic intermediate (anchors.js), and the server's
 * Cloud KMS signature shape made with any P-256 key. Shared by the
 * coinbase_attestation_v2 and oidc_domain_attestation fixture generators,
 * because both circuits verify statements through one Noir library
 * (statement-signer).
 *
 * HOW THE SYNTHETIC CHAIN DIFFERS FROM APPLE'S. The intermediate is only a
 * key (anchors.js syntheticCa, pinned in the synthetic-anchors copy as CA 1
 * is in the real library). The credential certificate copies the real one's
 * structure (field order, attribute types, extensions and OIDs; the 8.5
 * items with our App ID; the 8.7 extension verbatim; the nonce computed).
 * Assertion flags are 0x00; no CBOR extensions in either authData.
 */
const crypto = require('crypto');
const anchors = require('./anchors');

const APP_ID = 'R4G32CVY29.com.masselabs.zkproofport';
const KIND_APP = 1;
const KIND_SERVER = 2;
const TBS_MAX = 1000;
const ATT_AUTH_MAX = 256;
const ASSERT_AUTH_MAX = 128;
const AAGUID_PROD = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
const AAGUID_DEV = Buffer.from('appattestdevelop');
const { N_P256, N_P384 } = anchors;

const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest();

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

/**
 * One synthetic App Attest device: a credential key certified by `inter`
 * (default: the synthetic CA), with its attestation authData and the
 * attestation clientDataHash. `aaguid` / `appId` make the refusal variants.
 */
function syntheticDevice({ inter = anchors.syntheticCa(), cred = ecKey('prime256v1'), attCdh = sha256(crypto.randomBytes(32)) } = {}) {
  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const serial = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(5)]);
  const certify = (aaguid = AAGUID_PROD, appId = APP_ID) => {
    const attAuth = attestationAuthData(cred, APP_ID, aaguid);
    const nonce = sha256(attAuth, attCdh);
    const tbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce, appId, serial });
    const sig = signLowS('sha256', tbs, inter, N_P384, 48);
    return { attAuth, tbs, sig };
  };
  const dev = certify();
  const x509 = new crypto.X509Certificate(certDer(dev.tbs, SIG_ALG_SHA256, dev.sig, 48));
  if (!x509.verify(crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-384', x: inter.x.toString('base64url'), y: inter.y.toString('base64url') }, format: 'jwk' }))) {
    throw new Error('synthetic credential certificate does not verify');
  }
  if (dev.tbs.length > TBS_MAX) throw new Error(`TBS is ${dev.tbs.length} bytes`);
  return { inter, cred, keyId, serial, attCdh, certify, ...dev };
}

/** An App Attest assertion over `statement` by `key`: what generateAssertion
 *  returns for clientDataHash = SHA256(statement), r || s with s low. */
function assertion(statement, key, o = {}) {
  const auth = assertionAuthData(o.rpId ?? APP_ID, o.counter ?? 1);
  const nonce = sha256(auth, sha256(statement));
  const sig = signLowS('sha256', nonce, key, N_P256, 32);
  if (!crypto.verify('sha256', nonce, { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
    throw new Error('synthetic assertion does not verify');
  }
  return { auth, sig };
}

module.exports = {
  APP_ID, KIND_APP, KIND_SERVER, TBS_MAX, ATT_AUTH_MAX, ASSERT_AUTH_MAX, AAGUID_PROD, AAGUID_DEV,
  N_P256, N_P384, SIG_ALG_SHA256,
  sha256, tlv, seq, credentialTbs, ecKey, toLowS, signLowS, highS, p1363ToDer, derToP1363, certDer,
  attestationAuthData, assertionAuthData, serverSign, arr, pad, syntheticDevice, assertion,
};
