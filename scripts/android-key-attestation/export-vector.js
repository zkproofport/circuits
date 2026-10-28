#!/usr/bin/env node
/**
 * Write android-key-attestation/src/test_vectors.nr from REAL Android key
 * attestation chains, so the library's tests run on Google-signed bytes.
 *
 *   node scripts/android-key-attestation/export-vector.js
 *
 * Sources (android-key-attestation/test-vectors/, Apache-2.0, from
 * github.com/android/keyattestation testdata at 34652d3): a Pixel ("tegu",
 * Android 16) TEE and StrongBox key, both Remote Key Provisioned under
 * Google's Key Attestation CA1 root. Their app is Google's test app
 * (com.google.android.attestation), so they verify end to end only when
 * that package and its certificate digest are passed; with ours they must
 * be refused -- the tests do both.
 *
 * Besides the chain inputs, the file names the offsets (inside the leaf TBS)
 * of the bytes the key-description tests flip: security levels,
 * deviceLocked, verifiedBootState, origin, package and digest. They are
 * found by walking the DER here, not typed in.
 */
const fs = require('fs');
const path = require('path');
const { chainInputs, pemChain, der, splitCertificate, GOOGLE_KEY_ATTESTATION_CA1 } = require('./chain');

const CIRCUITS = path.resolve(__dirname, '../..');
const VECTORS = path.join(CIRCUITS, 'android-key-attestation/test-vectors');
const OUT = path.join(CIRCUITS, 'android-key-attestation/src/test_vectors.nr');

const KA_OID = Buffer.from('060a2b06010401d679020111', 'hex');

/** Context tag number and tag-byte count at pos. */
function ctag(b, pos) {
  if ((b[pos] & 0x1f) !== 0x1f) return { n: b[pos] & 0x1f, size: 1 };
  if ((b[pos + 1] & 0x80) === 0) return { n: b[pos + 1], size: 2 };
  return { n: (b[pos + 1] & 0x7f) * 128 + b[pos + 2], size: 3 };
}
function lenAt(b, pos) {
  const e = der(Buffer.concat([Buffer.from([0]), b.subarray(pos)]), 0);
  return { hl: e.hl - 1, len: e.len };
}
function entries(b, start, end) {
  const out = {};
  let p = start;
  while (p < end) {
    const t = ctag(b, p);
    const l = lenAt(b, p + t.size);
    out[t.n] = p + t.size + l.hl;
    p = p + t.size + l.hl + l.len;
  }
  if (p !== end) throw new Error('authorization list overruns');
  return out;
}

/** Offsets of the key description's fields inside the leaf TBS. */
function offsets(tbs) {
  const ka = tbs.indexOf(KA_OID);
  if (ka < 0 || tbs.indexOf(KA_OID, ka + 1) >= 0) throw new Error('leaf has no single key attestation OID');
  const os = ka + KA_OID.length;
  const o = der(tbs, os); // OCTET STRING
  const kd = os + o.hl;
  const k = der(tbs, kd);
  let p = kd + k.hl;
  p = der(tbs, p).end; // attestationVersion
  const attLevel = p + 2;
  p += 3;
  p = der(tbs, p).end; // keyMintVersion
  const kmLevel = p + 2;
  p += 3;
  p = der(tbs, p).end; // challenge
  p = der(tbs, p).end; // uniqueId
  const sw = der(tbs, p);
  const hw = der(tbs, sw.end);
  const swE = entries(tbs, p + sw.hl, sw.end);
  const hwE = entries(tbs, sw.end + hw.hl, hw.end);
  // [709]: OCTET STRING { SEQ { SET { SEQ { OCTET STRING pkg, INT } }, SET { OCTET STRING digest } } }
  let a = swE[709];
  a += der(tbs, a).hl; // OCTET STRING
  a += der(tbs, a).hl; // SEQUENCE
  const set1 = der(tbs, a);
  let q = a + set1.hl;
  q += der(tbs, q).hl; // SEQUENCE
  const pkg = der(tbs, q);
  const pkgAt = q + pkg.hl;
  const set2 = der(tbs, set1.end);
  const digestAt = set1.end + set2.hl + 2;
  // [704]: SEQUENCE { OCTET STRING, BOOLEAN, ENUMERATED, ... }
  let r = hwE[704];
  r += der(tbs, r).hl;
  r = der(tbs, r).end;
  const locked = r + 2;
  const bootState = r + 5;
  const origin = hwE[702] + 2;
  return {
    ka_at: kd, ka_len: k.hl + k.len, att_level: attLevel, km_level: kmLevel,
    pkg_at: pkgAt, pkg_len: pkg.len, digest_at: digestAt, locked, boot_state: bootState, origin,
    package: tbs.subarray(pkgAt, pkgAt + pkg.len), digest: tbs.subarray(digestAt, digestAt + 32),
  };
}

const arr = b => '[' + Array.from(b).map(v => `0x${v.toString(16).padStart(2, '0')}`).join(', ') + ']';
const wrap = s => s.replace(/(.{1,96})(, |$)/g, '$1$2\n    ').trimEnd();

function emit(prefix, file) {
  const ders = pemChain(fs.readFileSync(path.join(VECTORS, file), 'utf8'));
  const c = chainInputs(ders, GOOGLE_KEY_ATTESTATION_CA1);
  const leaf = splitCertificate(ders[0]).tbs;
  const off = offsets(leaf);
  const g = (name, type, value) => `pub global ${prefix}_${name}: ${type} = ${value};\n`;
  let s = `// ${file}\n`;
  for (const [k, n] of [['ca2', 600], ['ca3', 768], ['att', 512], ['leaf', 1024]]) {
    s += g(`${k.toUpperCase()}_TBS`, `[u8; ${n}]`, wrap(arr(c[`${k}_tbs`])));
    s += g(`${k.toUpperCase()}_TBS_LEN`, 'u32', c[`${k}_tbs_len`]);
    s += g(`${k.toUpperCase()}_SIG`, `[u8; ${c[`${k}_sig`].length}]`, wrap(arr(c[`${k}_sig`])));
  }
  s += g('LEAF_KEY', '[u8; 64]', wrap(arr(c.leaf_key)));
  s += g('PACKAGE', `[u8; ${off.package.length}]`, wrap(arr(off.package)));
  s += g('DIGEST', '[u8; 32]', wrap(arr(off.digest)));
  for (const k of ['ka_at', 'ka_len', 'att_level', 'km_level', 'pkg_at', 'digest_at', 'locked', 'boot_state', 'origin']) {
    s += g(k.toUpperCase(), 'u32', off[k]);
  }
  return s + '\n';
}

const header = `// GENERATED by scripts/android-key-attestation/export-vector.js -- do not edit.
// Real Android key attestation chains (android-key-attestation/test-vectors,
// Apache-2.0, github.com/android/keyattestation testdata 34652d3), as the
// circuit takes them: TBS zero-padded to its limit, signatures r || s with s
// in low form. Offsets are inside the leaf TBS.

`;
fs.writeFileSync(OUT, header
  + emit('TEE', 'tegu-sdk36-tee-ec-2026-root.pem')
  + emit('SB', 'tegu-sdk36-sb-ec-2026-root.pem'));
console.log(`wrote ${path.relative(CIRCUITS, OUT)}`);
