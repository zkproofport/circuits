/**
 * An Android key attestation chain (leaf first, as KeyStore.getCertificateChain
 * returns it) -> the AndroidChain inputs of android-key-attestation.
 *
 * The circuit takes each certificate's TBS (zero-padded to its limit) and
 * its issuer's signature as r || s with s in LOW form. Both curves' checks in
 * the circuit refuse a high s, and n - s is the same signature, so it is
 * normalised here. The root certificate itself is not an input: the circuit
 * pins its key; this file checks the chain's root is that key and refuses
 * any other shape by name (the circuit would refuse it anyway, less clearly).
 *
 *   const { chainInputs, GOOGLE_KEY_ATTESTATION_CA1 } = require('./chain');
 *   chainInputs([leafDer, attDer, ca3Der, ca2Der, rootDer], GOOGLE_KEY_ATTESTATION_CA1)
 *
 * proofport-app's input builder (src/utils/androidKeyAttestation.ts) does the
 * same conversion on the phone; scripts/android-key-attestation/
 * export-vector.js writes a real chain through this file for its tests.
 */
const crypto = require('crypto');

const N_P256 = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const N_P384 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973');

const LIMITS = { ca2: 600, ca3: 768, att: 512, leaf: 1024 };

/** Key Attestation CA1, X || Y (P-384): Google's root for attestation chains
 * from 2026-02-01 (developer.android.com/privacy-and-security/security-key-attestation). */
const GOOGLE_KEY_ATTESTATION_CA1 = Buffer.from(
  '23da23714edf3e5b050a3c72e8846ace078ea0ad1bf98b15f453d0cb08b2c3c110453909f6edeac1f9c8e031a848b941'
  + 'a829535c97e07c2719beceb416290d3079eee1f911cce6df803914d8a3577b34fdfd143e5ef36c9713c7ac70a8c211ab',
  'hex',
);

/** (tag, header length, content length) of the DER element at `pos`. */
function der(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let hl = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3) throw new Error(`Unsupported DER length form 0x${len.toString(16)} at ${pos}`);
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hl = 2 + n;
  }
  return { tag, hl, len, end: pos + hl + len };
}

/** TBS bytes and the raw signature BIT STRING content of a certificate. */
function splitCertificate(certDer) {
  const outer = der(certDer, 0);
  if (outer.tag !== 0x30 || outer.end !== certDer.length) throw new Error('Not a DER certificate');
  const tbs = der(certDer, outer.hl);
  const alg = der(certDer, tbs.end);
  const sig = der(certDer, alg.end);
  if (sig.tag !== 0x03 || certDer[alg.end + sig.hl] !== 0) throw new Error('Certificate signature is not a BIT STRING');
  return {
    tbs: certDer.subarray(outer.hl, tbs.end),
    sigDer: certDer.subarray(alg.end + sig.hl + 1, sig.end),
  };
}

/** ECDSA-Sig-Value DER -> r || s (each `size` bytes), s in low form for `n`. */
function rawLowS(sigDer, size, n) {
  const seq = der(sigDer, 0);
  if (seq.tag !== 0x30 || seq.end !== sigDer.length) throw new Error('Signature is not a DER SEQUENCE');
  const r = der(sigDer, seq.hl);
  const s = der(sigDer, r.end);
  if (r.tag !== 0x02 || s.tag !== 0x02 || s.end !== seq.end) throw new Error('Signature is not two INTEGERs');
  const int = e => BigInt('0x' + Buffer.from(sigDer.subarray(e.end - e.len, e.end)).toString('hex'));
  const rv = int(r);
  let sv = int(s);
  if (sv > n / 2n) sv = n - sv;
  const fixed = v => Buffer.from(v.toString(16).padStart(size * 2, '0'), 'hex');
  const out = Buffer.concat([fixed(rv), fixed(sv)]);
  if (out.length !== 2 * size) throw new Error('Signature component longer than the curve');
  return out;
}

/** X || Y of a certificate's EC key, refusing any other curve than `crv`. */
function certKey(certDer, crv) {
  const x509 = new crypto.X509Certificate(Buffer.from(certDer));
  const jwk = x509.publicKey.export({ format: 'jwk' });
  if (jwk.crv !== crv) throw new Error(`Certificate key is ${jwk.crv || jwk.kty}, not ${crv}`);
  return Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

const pad = (b, n, what) => {
  if (b.length > n) throw new Error(`${what} TBS is ${b.length} bytes; the circuit takes at most ${n}`);
  return Buffer.concat([b, Buffer.alloc(n - b.length)]);
};

/**
 * AndroidChain inputs from a chain [leaf, attestation key, Droid CA3,
 * Droid CA2, root] (DER Buffers). The root may be omitted; when present it
 * must be `rootKey` -- GOOGLE_KEY_ATTESTATION_CA1 for the real circuit, the
 * synthetic root for an acceptance copy. Named by the caller, never assumed.
 */
function chainInputs(ders, rootKey) {
  if (!Buffer.isBuffer(rootKey) || rootKey.length !== 96) throw new Error('chainInputs needs the pinned root key (96 bytes, X || Y)');
  if (ders.length !== 4 && ders.length !== 5) {
    throw new Error(`An RKP chain has 4 certificates below the root (leaf, attestation key, Droid CA3, Droid CA2); got ${ders.length} in all. Factory-provisioned chains are not accepted.`);
  }
  const [leaf, att, ca3, ca2, root] = ders.map(d => Buffer.from(d));
  if (root && !certKey(root, 'P-384').equals(rootKey)) {
    throw new Error('The chain does not end at the pinned Google root (Key Attestation CA1)');
  }
  const L = splitCertificate(leaf);
  const A = splitCertificate(att);
  const C3 = splitCertificate(ca3);
  const C2 = splitCertificate(ca2);
  return {
    ca2_tbs: pad(C2.tbs, LIMITS.ca2, 'Droid CA2'),
    ca2_tbs_len: C2.tbs.length,
    ca2_sig: rawLowS(C2.sigDer, 48, N_P384), // root (P-384)
    ca3_tbs: pad(C3.tbs, LIMITS.ca3, 'Droid CA3'),
    ca3_tbs_len: C3.tbs.length,
    ca3_sig: rawLowS(C3.sigDer, 48, N_P384), // CA2 (P-384)
    att_tbs: pad(A.tbs, LIMITS.att, 'Attestation key'),
    att_tbs_len: A.tbs.length,
    att_sig: rawLowS(A.sigDer, 32, N_P256), // CA3 (P-256)
    leaf_tbs: pad(L.tbs, LIMITS.leaf, 'Leaf'),
    leaf_tbs_len: L.tbs.length,
    leaf_sig: rawLowS(L.sigDer, 32, N_P256), // attestation key (P-256)
    leaf_key: certKey(leaf, 'P-256'),
  };
}

/** All certificates in a PEM bundle, as DER. */
function pemChain(text) {
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)]
    .map(m => Buffer.from(m[1].replace(/\s+/g, ''), 'base64'));
}

module.exports = {
  N_P256, N_P384, LIMITS, GOOGLE_KEY_ATTESTATION_CA1,
  der, splitCertificate, rawLowS, certKey, chainInputs, pemChain,
};
