/**
 * A SYNTHETIC Android key attestation chain, for the acceptance runs of the
 * circuits that verify statements through statement-signer's
 * verify_statement_android (oidc-domain-attestation-android,
 * coinbase-attestation-v2-android).
 *
 * No fixture can hold a Google-signed chain together with the leaf's private
 * key, so the chain is rebuilt under the SYNTHETIC root (anchors.js
 * syntheticAndroidRoot, pinned in the synthetic-anchors copy). Its shape
 * copies a real Remote Key Provisioning chain (android/keyattestation testdata
 * tegu/sdk36, Android 16; android-key-attestation/test-vectors): field order,
 * name attributes, extensions and OIDs, the key description's layout and the
 * provisioning-information value. Every value a test may want to change is
 * an option, so each refusal case changes exactly one thing.
 *
 *   const A = require('./android');
 *   const dev = A.androidDevice({ now });          // a chain valid at `now`
 *   dev.inputs                                     // AndroidChain inputs
 *   A.androidSign(statement, dev.leaf)             // statement_sig, r || s low
 */
const crypto = require('crypto');
const anchors = require('./anchors');
const { chainInputs } = require('../android-key-attestation/chain');

const { N_P256 } = anchors;
const PACKAGE = 'com.masselabs.zkproofport';
/** Play app signing certificate SHA-256 (statement-signer ANDROID_SIGNING_DIGEST). */
const SIGNING_DIGEST = Buffer.from('c39b407187d84ce59e90be7fcd0be834a226782c240257102f1d0a8816c6931f', 'hex');

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
const set = (...c) => tlv(0x31, ...c);
const oid = hex => tlv(0x06, Buffer.from(hex, 'hex'));
const octet = b => tlv(0x04, b);
const printable = s => tlv(0x13, Buffer.from(s));
function int(v) {
  let h = BigInt(v).toString(16);
  if (h.length % 2) h = '0' + h;
  let b = Buffer.from(h, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
const enumerated = v => tlv(0x0a, Buffer.from([v]));
const bool = byte => tlv(0x01, Buffer.from([byte]));
/** [n] EXPLICIT, the AuthorizationList tag form: A0|n below 31, else BF + base-128. */
function ctx(n, ...content) {
  let tag;
  if (n < 31) tag = [0xa0 | n];
  else if (n < 128) tag = [0xbf, n];
  else tag = [0xbf, 0x80 | (n >> 7), n & 0x7f];
  return tlv(tag, ...content);
}
const rdn = (oidHex, value) => set(seq(oid(oidHex), printable(value)));
const OID_CN = '550403';
const OID_O = '55040a';
const OID_OU = '55040b';
const OID_C = '550406';
/** UTCTime YYMMDDHHMMSSZ of unix seconds. */
function utc(seconds) {
  const d = new Date(seconds * 1000);
  return tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
}
const SIG_SHA256 = Buffer.from('300a06082a8648ce3d040302', 'hex');
const SIG_SHA384 = Buffer.from('300a06082a8648ce3d040303', 'hex');
const SPKI_P256 = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
const SPKI_P384 = Buffer.from('3076301006072a8648ce3d020106052b8104002203620004', 'hex');
const spki = k => (k.x.length === 32
  ? Buffer.concat([SPKI_P256, Buffer.from([4]), k.x, k.y])
  : Buffer.concat([SPKI_P384, k.x, k.y]));
const ext = (oidHex, value, critical = false) =>
  seq(oid(oidHex), ...(critical ? [bool(0xff)] : []), octet(value));
const keyUsage = bits => ext('551d0f', bits, true);
const basicCa = ca => ext('551d13', ca ? seq(bool(0xff)) : seq(), true);
const ski = k => ext('551d0e', octet(crypto.createHash('sha1').update(spki(k)).digest()));
const aki = k => ext('551d23', seq(tlv(0x80, crypto.createHash('sha1').update(spki(k)).digest())));
/** The provisioning-information value of the real attestation-key certificate (CBOR). */
const PROVISIONING_INFO = Buffer.from('a20118400366476f6f676c65', 'hex');
const OID_PROVISIONING_INFO = '2b06010401d67902011e';
const OID_KEY_ATTESTATION = '2b06010401d679020111';

function ecKey(curve) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
  const jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, publicKey, x: Buffer.from(jwk.x, 'base64url'), y: Buffer.from(jwk.y, 'base64url') };
}

function tbs({ sigAlg, issuer, validity, subject, key, extensions, serial }) {
  return seq(
    Buffer.from('a003020102', 'hex'),
    int(serial),
    sigAlg,
    issuer,
    seq(utc(validity[0]), utc(validity[1])),
    subject,
    spki(key),
    tlv(0xa3, seq(...extensions)),
  );
}
/** The certificate, signed by `issuerKey` with `hash` (DER ECDSA, any s: chain.js normalises). */
function certify(t, sigAlg, hash, issuerKey) {
  const sig = crypto.sign(hash, t, issuerKey.privateKey);
  return seq(t, sigAlg, tlv(0x03, Buffer.from([0]), sig));
}

/**
 * The key description, from the real tegu leaf's layout, with every field a
 * refusal case needs as an option.
 */
function keyDescription(o) {
  const appId = seq(
    set(...o.packages.map(p => seq(octet(Buffer.from(p)), int(1)))),
    set(...o.digests.map(d => octet(d))),
  );
  const rootOfTrust = seq(
    octet(Buffer.alloc(32, 0x33)),
    bool(o.lockedByte),
    enumerated(o.bootState),
    octet(Buffer.alloc(32, 0xec)),
  );
  const sw = [ctx(701, int(1771718777000n))];
  if (o.appIdIn === 'software') sw.push(ctx(709, octet(appId)));
  if (o.appIdIn === 'software-twice') sw.push(ctx(709, octet(appId)), ctx(709, octet(appId)));
  const hw = [
    ctx(1, set(int(2), int(3))), ctx(2, int(3)), ctx(3, int(256)), ctx(5, set(int(4))), ctx(10, int(1)),
    ctx(503, Buffer.from('0500', 'hex')),
  ];
  if (o.origin !== null) hw.push(ctx(702, int(o.origin)));
  if (o.rootOfTrust) hw.push(ctx(704, rootOfTrust));
  hw.push(ctx(705, int(160000)), ctx(706, int(202602)));
  if (o.appIdIn === 'hardware') hw.push(ctx(709, octet(appId)));
  hw.push(ctx(718, int(20260205)), ctx(719, int(20260205)));
  return seq(
    int(400), enumerated(o.level), int(400), enumerated(o.kmLevel),
    octet(o.challenge), octet(Buffer.alloc(0)),
    seq(...sw), seq(...hw),
  );
}

const DAY = 86400;

/**
 * A device with a chain valid at `now`. Options (all optional):
 *   root            the root key (default: the synthetic root)
 *   level, kmLevel  security levels (1 TEE, 2 StrongBox, 0 Software)
 *   packages        package names in attestationApplicationId
 *   digests         signing-certificate digests there
 *   lockedByte      deviceLocked's content byte (0xff locked, 0x00 unlocked)
 *   bootState       verifiedBootState (0 Verified, 1, 2, 3)
 *   origin          [702] value, or null for none
 *   rootOfTrust     false: no [704]
 *   appIdIn         'software' | 'hardware' | 'software-twice' | 'none'
 *   validity        { ca2, ca3, att }: [notBefore, notAfter] in unix seconds
 *   attProvisioning false: no provisioning-information extension
 *   attIsCa         false: the attestation-key certificate is not a CA
 *   keyDescriptionInAtt  true: the attestation-key certificate carries one
 *   challenge       attestationChallenge (default 32 zero bytes)
 *   mutateLeafTbs   (tbs) => tbs, applied before the attestation key signs
 *   ca2Signer, ca3Signer, attSigner, leafSigner   sign that certificate
 *                   with another key (the chain then breaks at that link)
 */
function androidDevice(opts = {}) {
  const now = opts.now;
  if (!Number.isInteger(now)) throw new Error('androidDevice needs `now` (unix seconds) for the validity windows');
  const o = {
    level: 1, packages: [PACKAGE], digests: [SIGNING_DIGEST], lockedByte: 0xff, bootState: 0,
    origin: 0, rootOfTrust: true, appIdIn: 'software', attProvisioning: true, attIsCa: true,
    keyDescriptionInAtt: false, challenge: Buffer.alloc(32), ...opts,
  };
  if (o.kmLevel === undefined) o.kmLevel = o.level;
  const validity = {
    ca2: [now - 30 * DAY, now + 3 * 365 * DAY],
    ca3: [now - 20 * DAY, now + 50 * DAY],
    att: [now - 3 * DAY, now + 11 * DAY],
    ...(opts.validity || {}),
  };
  const root = o.root || anchors.syntheticAndroidRoot();
  const ca2 = o.ca2Key || ecKey('secp384r1');
  const ca3 = o.ca3Key || ecKey('prime256v1');
  const att = o.attKey || ecKey('prime256v1');
  const leaf = o.leafKey || ecKey('prime256v1');

  const rootName = seq(rdn(OID_CN, 'Key Attestation CA1'), rdn(OID_OU, 'Android'), rdn(OID_O, 'Google LLC'), rdn(OID_C, 'US'));
  const ca2Name = seq(rdn(OID_O, 'Google LLC'), rdn(OID_CN, 'Droid CA2'));
  const ca3Name = seq(rdn(OID_O, 'Google LLC'), rdn(OID_CN, 'Droid CA3'));
  const attName = seq(rdn(OID_O, 'TEE'), rdn(OID_CN, crypto.randomBytes(16).toString('hex')));

  const rootCert = certify(tbs({
    sigAlg: SIG_SHA384, issuer: rootName, validity: [now - 400 * DAY, now + 3650 * DAY], subject: rootName, key: root,
    extensions: [basicCa(true), keyUsage(Buffer.from('03020106', 'hex')), ski(root)], serial: 0x0084a9d0297b0eb58ae7ff0e80de760605n,
  }), SIG_SHA384, 'sha384', root);
  const ca2Cert = certify(tbs({
    sigAlg: SIG_SHA384, issuer: rootName, validity: validity.ca2, subject: ca2Name, key: ca2,
    extensions: [ski(ca2), keyUsage(Buffer.from('03020106', 'hex')), basicCa(true), aki(root)], serial: 0x3c5f2a9b8e7d6c5b4a39281706f5e4d3n,
  }), SIG_SHA384, 'sha384', o.ca2Signer || root);
  const ca3Cert = certify(tbs({
    sigAlg: SIG_SHA384, issuer: ca2Name, validity: validity.ca3, subject: ca3Name, key: ca3,
    extensions: [keyUsage(Buffer.from('03020204', 'hex')), basicCa(true), ski(ca3), aki(ca2)], serial: 0x7a1b2c3d4e5f60718293a4b5c6d7e8f9n,
  }), SIG_SHA384, 'sha384', o.ca3Signer || ca2);
  const attExt = [ski(att), aki(ca3), basicCa(o.attIsCa), keyUsage(Buffer.from('03020204', 'hex'))];
  if (o.attProvisioning) attExt.push(ext(OID_PROVISIONING_INFO, PROVISIONING_INFO));
  // A minimal key description (empty lists): the attestation-key certificate
  // must not carry one at all, and a full one would not fit its TBS limit.
  if (o.keyDescriptionInAtt) {
    attExt.push(ext(OID_KEY_ATTESTATION, seq(int(400), enumerated(1), int(400), enumerated(1), octet(Buffer.alloc(0)), octet(Buffer.alloc(0)), seq(), seq())));
  }
  const attCert = certify(tbs({
    sigAlg: SIG_SHA256, issuer: ca3Name, validity: validity.att, subject: attName, key: att,
    extensions: attExt, serial: 0x0d3dc446fe9db9a6n,
  }), SIG_SHA256, 'sha256', o.attSigner || ca3);
  const leafExt = [keyUsage(Buffer.from('03020780', 'hex'))];
  leafExt.push(ext(OID_KEY_ATTESTATION, keyDescription(o)));
  let leafTbs = tbs({
    sigAlg: SIG_SHA256, issuer: attName, validity: [0, 2461449600], subject: seq(rdn(OID_CN, 'Android Keystore Key')), key: leaf,
    extensions: leafExt, serial: 1n,
  });
  // A malformed leaf, still signed by the attestation key: the refusal must
  // come from the structure check, not the signature.
  if (o.mutateLeafTbs) leafTbs = o.mutateLeafTbs(Buffer.from(leafTbs));
  const leafCert = certify(leafTbs, SIG_SHA256, 'sha256', o.leafSigner || att);

  const ders = [leafCert, attCert, ca3Cert, ca2Cert, rootCert];
  const inputs = chainInputs(ders, Buffer.concat([root.x, root.y]));
  return { root, ca2, ca3, att, leaf, ders, inputs };
}

/** What the phone does: SHA256withECDSA over the statement, as r || s, s low. */
function androidSign(statement, key) {
  const sig = crypto.sign('sha256', statement, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  let s = BigInt('0x' + sig.subarray(32).toString('hex'));
  if (s > N_P256 / 2n) s = N_P256 - s;
  const out = Buffer.concat([sig.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
  if (!crypto.verify('sha256', statement, { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, out)) {
    throw new Error('synthetic Android statement signature does not verify');
  }
  return out;
}

module.exports = { PACKAGE, SIGNING_DIGEST, androidDevice, androidSign, ecKey, keyDescription };
