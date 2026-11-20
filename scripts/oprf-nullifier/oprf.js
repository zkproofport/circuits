/**
 * OPRF nullifier inputs for the circuits' fixtures, from TACEO's crates
 * (oprf-fixture, this folder's Rust tool) and a LOCAL test key per circuit id.
 * Nothing here talks to an OPRF network: the nodes' answer is computed with
 * the key below, which is a published test value, never a deployment key.
 *
 *   const oprf = require('../oprf-nullifier/oprf');
 *   const v = oprf.values({ circuitId: 'giwa_attestation', address: '0x..', scopeString: 'giwa-poc-scope' });
 *   oprf.toml(v)            // the public and private lines a Prover.toml needs
 *   oprf.fieldBytes(v.scope) // the scope as the 32 bytes a signed statement binds
 *
 * What the circuits publish (oprf-nullifier-libs): oprf_key_hash, domain,
 * scope, nullifier -- each one Field. Private: oprf_public_key_x/_y,
 * oprf_beta, oprf_dlog_e, oprf_dlog_s, oprf_response_x/_y.
 *
 * Also a CLI, for the acceptance runs' OPRF refusals and the v1 fixtures:
 *   node oprf.js tamper <in.toml> <out.toml> <circuit-id> <case>
 *   node oprf.js convert <Prover.toml> <circuit-id> <scope-string>
 * (see the functions of those names below).
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ethers } = require('../node_modules/ethers');

/** BN254 scalar field: what a Noir Field holds. */
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** BabyJubJub prime-order subgroup order: what an OPRF key and beta are below. */
const R = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

const TOOL_DIR = __dirname;
const TOOL = path.join(TOOL_DIR, 'target', 'release', 'oprf-fixture');

/** constants.sh, the one place the published test values are written. */
const CONSTANTS = Object.fromEntries(
  fs.readFileSync(path.join(TOOL_DIR, 'constants.sh'), 'utf8')
    .split('\n')
    .filter(l => /^[A-Z_]+=/.test(l))
    .map(l => l.split('=')),
);

const hex32 = v => '0x' + v.toString(16).padStart(64, '0');
const fieldOfString = s => hex32(BigInt(ethers.keccak256(ethers.toUtf8Bytes(s))) % P);
/** A field value (0x hex, below p) as the 32 bytes big-endian a statement carries. */
const fieldBytes = h => {
  const v = BigInt(h);
  if (v >= P) throw new Error(`${h} is not below p`);
  return ethers.getBytes(hex32(v));
};

/**
 * One test key per circuit id: the circuits publish the key hash, and a
 * verifier pins one key per proof type, so the fixtures do too -- that is
 * what makes "another circuit's nullifier" a refusal here. Derived from a
 * public string, so anybody can recompute it; NOT a deployment key.
 * An id not in this table is an error, never another id's key.
 */
const CIRCUIT_IDS = [
  'coinbase_attestation',
  'coinbase_country_attestation',
  'giwa_attestation',
  'dojang_playground',
  'human_passport_score',
];
function fixtureKey(circuitId) {
  if (!CIRCUIT_IDS.includes(circuitId)) {
    throw new Error(`No OPRF fixture key for circuit '${circuitId}'. Known: ${CIRCUIT_IDS.join(', ')}.`);
  }
  const k = BigInt(ethers.keccak256(ethers.toUtf8Bytes(`ZKProofport OPRF fixture key/${circuitId}`))) % R;
  if (k === 0n) throw new Error(`fixture key for ${circuitId} is zero`);
  return hex32(k);
}

/** The domain every fixture uses: keccak256("zkproofport.app") mod p. */
const FIXTURE_DOMAIN = CONSTANTS.FIXTURE_DOMAIN;
if (FIXTURE_DOMAIN !== fieldOfString('zkproofport.app')) {
  throw new Error('constants.sh FIXTURE_DOMAIN is not keccak256("zkproofport.app") mod p');
}

let built = false;
function buildTool() {
  if (built) return;
  execFileSync(path.join(TOOL_DIR, 'build-tool.sh'), { stdio: ['ignore', 'ignore', 'inherit'] });
  built = true;
}

/**
 * An honest OPRF evaluation for `address` in (domain, scope) under the
 * circuit's fixture key (or `key`). `scope` / `domain` are field hex; give
 * `scopeString` instead of `scope` to map a string with keccak256 mod p.
 */
function values({ circuitId, address, domain = FIXTURE_DOMAIN, scope, scopeString, key, seed = 1 }) {
  if ((scope === undefined) === (scopeString === undefined)) throw new Error('give exactly one of scope, scopeString');
  const s = scope ?? fieldOfString(scopeString);
  const addr = typeof address === 'string' ? address : ethers.hexlify(address);
  buildTool();
  const out = execFileSync(TOOL, [
    'values', '--address', addr.toLowerCase(), '--domain', domain, '--scope', s,
    '--key', key ?? fixtureKey(circuitId), '--beta', CONSTANTS.FIXTURE_BETA, '--seed', String(seed),
  ]);
  return JSON.parse(out.toString());
}

const PUBLIC_FIELDS = ['oprf_key_hash', 'domain', 'scope', 'nullifier'];
const PRIVATE_FIELDS = [
  'oprf_public_key_x', 'oprf_public_key_y', 'oprf_beta', 'oprf_dlog_e', 'oprf_dlog_s',
  'oprf_response_x', 'oprf_response_y',
];
const ALL_FIELDS = [...PUBLIC_FIELDS, ...PRIVATE_FIELDS];

/** `fields` as TOML lines; `o` overrides some (a refusal case), and a field
 *  neither holds is an error, never an empty line. */
function lines(fields, v, o) {
  return fields.map(f => {
    const val = Object.prototype.hasOwnProperty.call(o, f) ? o[f] : v[f];
    if (typeof val !== 'string') throw new Error(`OPRF value ${f} is missing`);
    return `${f} = "${val}"`;
  }).join('\n');
}
/** The public lines (oprf_key_hash, domain, scope, nullifier). */
const publicToml = (v, o = {}) => lines(PUBLIC_FIELDS, v, o);
/** The private lines (the nodes' answer and the blinding factor). */
const privateToml = (v, o = {}) => lines(PRIVATE_FIELDS, v, o);
const toml = (v, o = {}) => `${publicToml(v, o)}\n${privateToml(v, o)}`;

// ---- reading and rewriting a Prover.toml ------------------------------------

/** `name = "..."` / `name = 123` value, or null. */
function scalar(text, name) {
  const m = text.match(new RegExp(`^${name}\\s*=\\s*"?([^"\\n]*)"?\\s*$`, 'm'));
  return m ? m[1] : null;
}
/** `name = [ ... ]` byte array, or null. */
function byteArray(text, name) {
  const m = text.match(new RegExp(`^${name}\\s*=\\s*\\[([^\\]]*)\\]`, 'm'));
  if (!m) return null;
  return m[1].split(',').map(t => t.trim()).filter(Boolean).map(t => Number(t));
}
function setScalar(text, name, value) {
  const re = new RegExp(`^${name}\\s*=.*$`, 'm');
  if (!re.test(text)) throw new Error(`${name} not found`);
  return text.replace(re, `${name} = "${value}"`);
}
function walletOf(text) {
  const a = byteArray(text, 'user_address');
  if (!a || a.length !== 20) throw new Error('user_address (20 bytes) not found');
  return ethers.hexlify(Uint8Array.from(a));
}
function fieldsOf(text) {
  const v = {};
  for (const f of ALL_FIELDS) {
    v[f] = scalar(text, f);
    if (v[f] === null) throw new Error(`${f} not found: not an OPRF-nullifier Prover.toml`);
  }
  return v;
}
const replaceFields = (text, v) => ALL_FIELDS.reduce((t, f) => setScalar(t, f, v[f]), text);

/**
 * One refusal case derived from an accepted fixture, changing ONE thing. Each
 * case says which assert must refuse it; the acceptance run checks the name.
 */
const TAMPER = {
  // The published nullifier one more than the honest one.
  nullifier_plus_one: (t) => setScalar(t, 'nullifier', hex32((BigInt(scalar(t, 'nullifier')) + 1n) % P)),
  // Another key hash than the key the answer came from.
  key_hash_plus_one: (t) => setScalar(t, 'oprf_key_hash', hex32((BigInt(scalar(t, 'oprf_key_hash')) + 1n) % P)),
  // Domain and scope exchanged in the public inputs.
  domain_scope_swapped: (t) => {
    const d = scalar(t, 'domain');
    return setScalar(setScalar(t, 'domain', scalar(t, 'scope')), 'scope', d);
  },
  // The nodes' honest answer for ANOTHER wallet, presented with this wallet's
  // credential: the address the credential proved is not the one queried.
  other_wallet_answer: (t, id) => {
    const v = fieldsOf(t);
    const other = ethers.hexlify(ethers.toBeArray((BigInt(walletOf(t)) + 1n) % (1n << 160n)));
    return replaceFields(t, values({ circuitId: id, address: ethers.zeroPadValue(other, 20), domain: v.domain, scope: v.scope }));
  },
  // Another circuit's key: its honest answer and key hash. The circuit
  // ACCEPTS this (any key holder can make a valid proof); what refuses it is
  // the verifier pinning this circuit's key hash. The acceptance run checks
  // the key hash it publishes differs.
  other_circuit_key: (t, id) => {
    const v = fieldsOf(t);
    const otherId = CIRCUIT_IDS.find(c => c !== id);
    return replaceFields(t, values({ circuitId: otherId, address: walletOf(t), domain: v.domain, scope: v.scope }));
  },
  // Another circuit's answer under THIS circuit's key hash.
  other_circuit_answer: (t, id) => {
    const v = fieldsOf(t);
    const otherId = CIRCUIT_IDS.find(c => c !== id);
    const o = values({ circuitId: otherId, address: walletOf(t), domain: v.domain, scope: v.scope });
    return replaceFields(t, { ...o, oprf_key_hash: v.oprf_key_hash });
  },
  // scope written as scope + p: the same Field, a different 256-bit number.
  scope_plus_p: (t) => setScalar(t, 'scope', '0x' + (BigInt(scalar(t, 'scope')) + P).toString(16)),
};

function tamper(inPath, outPath, circuitId, kase) {
  if (!Object.prototype.hasOwnProperty.call(TAMPER, kase)) {
    throw new Error(`Unknown OPRF tamper case '${kase}'. Known: ${Object.keys(TAMPER).join(', ')}.`);
  }
  const text = fs.readFileSync(inPath, 'utf8');
  const out = TAMPER[kase](text, circuitId);
  if (out === text) throw new Error(`tamper ${kase} changed nothing in ${inPath}`);
  fs.writeFileSync(outPath, out);
  console.log(`${kase} -> ${outPath}`);
}

/**
 * A Prover.toml built for the keccak nullifier (scope and nullifier as
 * [u8; 32], as proofport-ai/scripts/gen-prover-toml.ts still writes for the v1
 * Coinbase circuits) rewritten for the OPRF nullifier: scope becomes
 * keccak256(scopeString) mod p, and the OPRF lines are added. An already
 * converted file is re-derived the same way (idempotent). The scope string
 * must be the one the old scope bytes were made from; that is checked.
 */
function convert(file, circuitId, scopeString) {
  let text = fs.readFileSync(file, 'utf8');
  const oldScope = byteArray(text, 'scope');
  if (oldScope && ethers.hexlify(Uint8Array.from(oldScope)) !== ethers.keccak256(ethers.toUtf8Bytes(scopeString))) {
    throw new Error(`${file}: scope is not keccak256("${scopeString}")`);
  }
  // Drop the old scope / nullifier and any earlier OPRF lines.
  for (const f of ['scope', 'nullifier']) {
    text = text.replace(new RegExp(`^${f}\\s*=\\s*\\[[^\\]]*\\]\\s*\\n`, 'm'), '');
  }
  for (const f of ALL_FIELDS) text = text.replace(new RegExp(`^${f}\\s*=.*\\n`, 'm'), '');
  text = text.replace(/^# ============ OPRF nullifier[^\n]*\n/m, '');
  const v = values({ circuitId, address: walletOf(text), scopeString });
  const block = `# ============ OPRF nullifier: 4 public values, then 7 private (scripts/oprf-nullifier/oprf.js convert, test key for ${circuitId}) ============\n${toml(v)}\n`;
  // Before the first private section, so the file still reads public-first.
  const at = text.indexOf('# ============ Private Inputs');
  text = at === -1 ? `${text.trimEnd()}\n\n${block}` : `${text.slice(0, at)}${block}\n${text.slice(at)}`;
  // One blank line between sections, however often the file is converted.
  text = text.replace(/\n{3,}/g, '\n\n');
  fs.writeFileSync(file, text);
  console.log(`converted ${file}: scope ${v.scope}, nullifier ${v.nullifier}, key hash ${v.oprf_key_hash}`);
}

module.exports = {
  P, R, CIRCUIT_IDS, FIXTURE_DOMAIN, fieldOfString, fieldBytes, fixtureKey, values, toml, publicToml,
  privateToml, PUBLIC_FIELDS, PRIVATE_FIELDS, TAMPER, tamper, convert,
};

if (require.main === module) {
  const [cmd, ...a] = process.argv.slice(2);
  try {
    if (cmd === 'tamper' && a.length === 4) tamper(a[0], a[1], a[2], a[3]);
    else if (cmd === 'convert' && a.length === 3) convert(a[0], a[1], a[2]);
    else if (cmd === 'fixture-key' && a.length === 1) console.log(fixtureKey(a[0]));
    else {
      console.error('usage: oprf.js tamper <in.toml> <out.toml> <circuit-id> <case> | convert <Prover.toml> <circuit-id> <scope-string> | fixture-key <circuit-id>');
      process.exit(1);
    }
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
}
