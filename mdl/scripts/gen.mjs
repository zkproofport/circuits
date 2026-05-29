#!/usr/bin/env node
// Generate Prover.toml for mdl_kr_ownership / mdl_kr_age / mdl_kr_region
// from an OmniOne CX response. Writes Prover.toml directly into the
// matching circuit directory.
//
// Usage:
//   node scripts/gen.mjs --circuit ownership [options]
//   node scripts/gen.mjs --circuit age       [options]
//   node scripts/gen.mjs --circuit region    [options]
//
// Options:
//   --input <oacx-response.json>  use a real OmniOne CX response (else demo)
//   --scope <STR>                 default "openstoa:login:v1"
//   --signal-hash-hex <0x...>     deterministic signal_hash (32 bytes)
//   --flags 0x0F                  ownership: disclose_flags
//   --age-threshold N             age: minimum age (default 19)
//   --current-year N              age: reference year (default 2026)
//   --region "경기도"             region: dApp target si/do
//   --address-override <STR>      replace demo address (test leading space / empty)
//
// Negative-test overrides (produce intentionally invalid Prover.toml):
//   --corrupt-integrity           randomize cx_integrity_root
//   --corrupt-nullifier           randomize nullifier_value
//   --corrupt-owner-commit        randomize owner_commit (ownership only)
//   --anon-with-nonzero           ownership flags=0 + nonzero owner_commit
//   --nonanon-with-zero           ownership flags!=0 + zero owner_commit
//   --corrupt-birth               mutate output birth_date after derivation
//   --corrupt-address             mutate output address after derivation
//   --year-before-birth           age: current_year := birth_year - 1
//   --corrupt-signal-hash         randomize public signal_hash (mismatch)
//   --corrupt-scope               randomize public scope (mismatch)

import sha3 from 'js-sha3';
const { keccak256 } = sha3;
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { argv, exit } from 'node:process';
import { randomBytes } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MDL_DIR = dirname(__dirname);  // circuits/mdl
const CIRCUITS_ROOT = dirname(MDL_DIR);  // circuits/

// ───────────────────────────────────────────────
// CLI args (supports boolean flags + `--key value` pairs)
// ───────────────────────────────────────────────
const args = {};
{
  const rest = argv.slice(2);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = rest[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
}

const CIRCUIT = typeof args['circuit'] === 'string' ? args['circuit'] : null;
if (!['ownership', 'age', 'region'].includes(CIRCUIT)) {
  console.error('--circuit must be one of: ownership, age, region');
  exit(2);
}

const FLAGS_HEX   = typeof args['flags'] === 'string' ? args['flags'] : '0x0F';
const SCOPE_STR   = typeof args['scope'] === 'string' ? args['scope'] : 'openstoa:login:v1';
const REGION      = typeof args['region'] === 'string' ? args['region'] : '경기도';
const CURR_YEAR   = parseInt(typeof args['current-year']  === 'string' ? args['current-year']  : '2026', 10);
const AGE_THRESH  = parseInt(typeof args['age-threshold'] === 'string' ? args['age-threshold'] : '19',   10);

const CORRUPT_INTEGRITY     = args['corrupt-integrity']     === true;
const CORRUPT_NULLIFIER     = args['corrupt-nullifier']     === true;
const CORRUPT_OWNER_COMMIT  = args['corrupt-owner-commit']  === true;
const ANON_WITH_NONZERO     = args['anon-with-nonzero']     === true;
const NONANON_WITH_ZERO     = args['nonanon-with-zero']     === true;
const YEAR_BEFORE_BIRTH     = args['year-before-birth']     === true;
const CORRUPT_BIRTH         = args['corrupt-birth']         === true;
const CORRUPT_ADDRESS       = args['corrupt-address']       === true;
const CORRUPT_SIGNAL_HASH   = args['corrupt-signal-hash']   === true;
const CORRUPT_SCOPE         = args['corrupt-scope']         === true;
const ADDRESS_OVERRIDE      = typeof args['address-override'] === 'string'
  ? args['address-override']
  : null;
const SIGNAL_HASH_OVERRIDE  = typeof args['signal-hash-hex'] === 'string'
  ? args['signal-hash-hex']
  : null;
const EXPECTED_NAME_OVERRIDE  = typeof args['expected-name']  === 'string' ? args['expected-name']  : null;
const EXPECTED_BIRTH_OVERRIDE = typeof args['expected-birth'] === 'string' ? args['expected-birth'] : null;
const EXPECTED_SEX_OVERRIDE   = typeof args['expected-sex']   === 'string' ? args['expected-sex']   : null;
const EXPECTED_TELNO_OVERRIDE = typeof args['expected-telno'] === 'string' ? args['expected-telno'] : null;

const DEMO_RESPONSE = {
  ci: '258NYBwTVSUV7ph8dL55wJXVkalUCp1xiVqm5pIxVEY1wiq2/4uCH0QjI2rQKSXG1wQ9q/Z0+s5NlQHzJva+iQ==',
  name: '현제혁',
  birth: '19850130',
  telno: '01046564126',
  sex: '',
  jti: '6c53fdbc92be40388afc649166cb71419dhga1oi',
  pri: 'kJfvI0WelD8x9c29ab8ep3z1H8mHkn+91yTM3XbcKUw=',
  address: '경기도 파주시 교하로 100, 910동 2903호 (목동동, 힐스테이트운정)',
};

const inputPath = typeof args['input'] === 'string' ? args['input'] : null;
const oacx = inputPath ? JSON.parse(readFileSync(inputPath, 'utf8')).data : { ...DEMO_RESPONSE };
if (ADDRESS_OVERRIDE !== null) {
  oacx.address = ADDRESS_OVERRIDE;
}

// ───────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────
const k256 = (bytes) => Buffer.from(keccak256.arrayBuffer(new Uint8Array(bytes)));
const padZero = (input, totalLen, encoding = 'utf8') => {
  const buf = Buffer.from(input, encoding);
  if (buf.length > totalLen) {
    throw new Error(`Input "${input}" exceeds ${totalLen} bytes (got ${buf.length})`);
  }
  return Buffer.concat([buf, Buffer.alloc(totalLen - buf.length)]);
};
const tomlArray = (bytes) => '[' + Array.from(bytes).join(', ') + ']';

// ───────────────────────────────────────────────
// Buffers (must match mdl_kr_common globals)
// ───────────────────────────────────────────────
const ci      = padZero(oacx.ci,    88, 'utf8');
const jti     = padZero(oacx.jti,   40, 'utf8');
const pri     = padZero(oacx.pri,   44, 'utf8');
const name    = padZero(oacx.name,  64, 'utf8');
const telno   = padZero(oacx.telno, 16, 'utf8');
const sex     = oacx.sex && oacx.sex.length > 0 ? oacx.sex.charCodeAt(0) : 0;
const birth   = padZero(oacx.birth, 8,  'utf8');
const address = padZero(oacx.address || '', 256, 'utf8');
const targetRegion = padZero(REGION, 64, 'utf8');

// Expected-value tuple for the ownership circuit. Defaults to the mDL
// values themselves so honest PASS fixtures don't need explicit
// overrides. Negative-test fixtures override one or more to a
// different value and expect the circuit to reject.
const expectedNameStr  = EXPECTED_NAME_OVERRIDE  ?? oacx.name;
const expectedBirthStr = EXPECTED_BIRTH_OVERRIDE ?? oacx.birth;
const expectedSexStr   = EXPECTED_SEX_OVERRIDE   ?? (oacx.sex ?? '');
const expectedTelnoStr = EXPECTED_TELNO_OVERRIDE ?? oacx.telno;
const expected_name  = padZero(expectedNameStr,  64, 'utf8');
const expected_birth = padZero(expectedBirthStr, 8,  'utf8');
const expected_telno = padZero(expectedTelnoStr, 16, 'utf8');
const expected_sex   = expectedSexStr && expectedSexStr.length > 0
  ? expectedSexStr.charCodeAt(0)
  : 0;

// ───────────────────────────────────────────────
// Derivation (honest)
// ───────────────────────────────────────────────
let cx_integrity_root = k256(Buffer.concat([jti, pri]));
if (CORRUPT_INTEGRITY) cx_integrity_root = randomBytes(32);

const mdl_buf = Buffer.concat([ci, jti, pri, birth, address]); // 88+40+44+8+256 = 436
const mdl_commit = k256(mdl_buf);
const self_id_20 = mdl_commit.subarray(0, 20);

let scope = k256(Buffer.from(SCOPE_STR, 'utf8'));
let signal_hash = SIGNAL_HASH_OVERRIDE
  ? Buffer.from(SIGNAL_HASH_OVERRIDE.replace(/^0x/, ''), 'hex')
  : randomBytes(32);
if (signal_hash.length !== 32) {
  throw new Error(`signal_hash must be 32 bytes, got ${signal_hash.length}`);
}

const user_secret = k256(Buffer.concat([self_id_20, signal_hash]));
let nullifier_value = k256(Buffer.concat([user_secret, scope]));
if (CORRUPT_NULLIFIER) nullifier_value = randomBytes(32);

// Public-input tamper: mutate the *published* signal_hash / scope after
// the nullifier has been derived, so the circuit's recomputation
// disagrees with the published nullifier_value.
if (CORRUPT_SIGNAL_HASH) signal_hash = randomBytes(32);
if (CORRUPT_SCOPE)       scope       = randomBytes(32);

const region_code = k256(targetRegion);

const disclose_flags = parseInt(FLAGS_HEX, 16);
// owner_commit is derived from the EXPECTED values masked by the flag
// bits. The mDL values themselves are not in the hash; the circuit
// instead asserts (when the flag is set) that mDL.X == expected.X
// byte-for-byte, so the two are forced equal anyway.
const owner_buf = Buffer.alloc(89);
if (disclose_flags & 0x01) expected_name.copy(owner_buf, 0);
if (disclose_flags & 0x02) expected_birth.copy(owner_buf, 64);
if (disclose_flags & 0x04) owner_buf[72] = expected_sex;
if (disclose_flags & 0x08) expected_telno.copy(owner_buf, 73);

let owner_commit;
if (disclose_flags === 0) {
  owner_commit = Buffer.alloc(32);
} else {
  owner_commit = k256(Buffer.concat([Buffer.from([disclose_flags]), owner_buf]));
}
if (CORRUPT_OWNER_COMMIT)   owner_commit = randomBytes(32);
if (ANON_WITH_NONZERO && disclose_flags === 0) owner_commit = randomBytes(32);
if (NONANON_WITH_ZERO && disclose_flags !== 0) owner_commit = Buffer.alloc(32);

// Mutate private inputs *after* derivation so the circuit's recomputed
// mdl_commit no longer matches the published nullifier_value.
let outBirth   = birth;
let outAddress = address;
if (CORRUPT_BIRTH) {
  outBirth = Buffer.from(birth);
  outBirth[7] = outBirth[7] === 0x39 ? 0x30 : 0x39;
}
if (CORRUPT_ADDRESS) {
  outAddress = Buffer.from(address);
  outAddress[200] = outAddress[200] ^ 0xff;
}

let outCurrYear = CURR_YEAR;
if (YEAR_BEFORE_BIRTH) {
  const birthYear = parseInt(oacx.birth.slice(0, 4), 10);
  outCurrYear = birthYear - 1;
}

// ───────────────────────────────────────────────
// Emit
// ───────────────────────────────────────────────
const lines = [
  `# Auto-generated by scripts/gen.mjs --circuit ${CIRCUIT}`,
  `# Demo: Korean mobile driver license (${oacx.name})`,
  '',
  '# ============ Public Inputs ============',
  `signal_hash       = ${tomlArray(signal_hash)}`,
  `scope             = ${tomlArray(scope)}`,
  `nullifier_value   = ${tomlArray(nullifier_value)}`,
  `cx_integrity_root = ${tomlArray(cx_integrity_root)}`,
];

if (CIRCUIT === 'ownership') {
  lines.push(`disclose_flags    = ${disclose_flags}`);
  lines.push(`owner_commit      = ${tomlArray(owner_commit)}`);
} else if (CIRCUIT === 'age') {
  lines.push(`age_threshold     = ${AGE_THRESH}`);
  lines.push(`current_year      = ${outCurrYear}`);
} else if (CIRCUIT === 'region') {
  lines.push(`region_code       = ${tomlArray(region_code)}`);
}

lines.push('');
lines.push('# ============ Private Inputs ============');
lines.push(`ci          = ${tomlArray(ci)}`);
lines.push(`cx_jti      = ${tomlArray(jti)}`);
lines.push(`cx_pri      = ${tomlArray(pri)}`);

if (CIRCUIT === 'ownership') {
  lines.push(`name           = ${tomlArray(name)}`);
  lines.push(`birth_date     = ${tomlArray(outBirth)}`);
  lines.push(`telno          = ${tomlArray(telno)}`);
  lines.push(`sex            = ${sex}`);
  lines.push(`address        = ${tomlArray(outAddress)}`);
  lines.push(`expected_name  = ${tomlArray(expected_name)}`);
  lines.push(`expected_birth = ${tomlArray(expected_birth)}`);
  lines.push(`expected_telno = ${tomlArray(expected_telno)}`);
  lines.push(`expected_sex   = ${expected_sex}`);
} else {
  // age + region share the same minimal private set
  lines.push(`birth_date  = ${tomlArray(outBirth)}`);
  lines.push(`address     = ${tomlArray(outAddress)}`);
}

lines.push('');

const outDir = join(MDL_DIR, `kr-${CIRCUIT}`);
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const outPath = join(outDir, 'Prover.toml');
writeFileSync(outPath, lines.join('\n'));

console.log('Wrote:', outPath);
console.log('  circuit          =', CIRCUIT);
console.log('  nullifier_value  = 0x' + nullifier_value.toString('hex'));
console.log('  signal_hash      = 0x' + signal_hash.toString('hex'));
console.log('  scope            = 0x' + scope.toString('hex'));
if (CIRCUIT === 'ownership') {
  console.log('  disclose_flags   = 0x' + disclose_flags.toString(16).padStart(2, '0'));
  console.log('  owner_commit     = 0x' + owner_commit.toString('hex'));
} else if (CIRCUIT === 'age') {
  console.log('  age_threshold    =', AGE_THRESH);
  console.log('  current_year     =', outCurrYear);
} else if (CIRCUIT === 'region') {
  console.log('  region_code      = 0x' + region_code.toString('hex'));
}
