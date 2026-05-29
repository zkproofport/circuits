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
//   --signal-hash-hex <0x...>     INERT in v4 — accepted but value is dropped.
//                                 Used by D1 re-login determinism test to prove
//                                 that nullifier is independent of signal_hash.
//   --flags 0x0F                  ownership: disclose_flags
//   --age-threshold N             age: minimum age (default 19)
//   --current-year N              age: reference year (default 2026)
//   --region "경기도"             region: dApp target si/do
//   --address-override <STR>      replace demo address (test leading space / empty)
//
// Negative-test overrides (produce intentionally invalid Prover.toml):
//   --corrupt-nullifier           randomize nullifier_value
//   --corrupt-owner-commit        randomize owner_commit (ownership only)
//   --anon-with-nonzero           ownership flags=0 + nonzero owner_commit
//   --nonanon-with-zero           ownership flags!=0 + zero owner_commit
//   --corrupt-birth               mutate output birth_date after derivation
//   --corrupt-address             mutate output address after derivation
//   --year-before-birth           age: current_year := birth_year - 1
//   --corrupt-scope               randomize public scope (mismatch)
//   --corrupt-ci                  mutate ci bytes (different user)
//
// NOTE (v4 — HS256 path dormant):
//   --corrupt-integrity and --corrupt-signal-hash are accepted as INERT flags
//   (parsed but not emitted into Prover.toml) because signal_hash and
//   cx_integrity_root have been commented out of the v4 circuits pending RAON
//   RP registration. Keep the flags to avoid breaking existing invocations.
//
// TODO(HS256): Re-enable --corrupt-integrity / --corrupt-signal-hash emission
// when RAON registration provides the RP shared secret.

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

// INERT in v4 — accepted for CLI compatibility + D1 regression guard.
// TODO(HS256): Re-enable when RAON registration provides the RP shared
// secret. Currently disabled because no off-chain HS256 verifier exists,
// so cx_integrity_root cannot anchor anything meaningfully.
// const CORRUPT_INTEGRITY   = args['corrupt-integrity']   === true;  // INERT
const SIGNAL_HASH_OVERRIDE  = typeof args['signal-hash-hex'] === 'string'
  ? args['signal-hash-hex']
  : null;
// INERT — accepted but has no effect on the generated Prover.toml in v4.
// const CORRUPT_SIGNAL_HASH = args['corrupt-signal-hash'] === true;  // INERT

const CORRUPT_NULLIFIER     = args['corrupt-nullifier']     === true;
const CORRUPT_OWNER_COMMIT  = args['corrupt-owner-commit']  === true;
const ANON_WITH_NONZERO     = args['anon-with-nonzero']     === true;
const NONANON_WITH_ZERO     = args['nonanon-with-zero']     === true;
const YEAR_BEFORE_BIRTH     = args['year-before-birth']     === true;
const CORRUPT_BIRTH         = args['corrupt-birth']         === true;
// Corrupt the year digits (bytes 0-3) of birth_date so assert_age fails.
// --corrupt-birth only mutates byte 7 (day digit) which assert_age ignores.
const CORRUPT_BIRTH_YEAR    = args['corrupt-birth-year']    === true;
const CORRUPT_ADDRESS       = args['corrupt-address']       === true;
// Corrupt bytes in the FIRST token of address (bytes 0-8) so extract_region_token fails.
const CORRUPT_ADDRESS_TOKEN = args['corrupt-address-token'] === true;
const CORRUPT_SCOPE         = args['corrupt-scope']         === true;
const CORRUPT_CI            = args['corrupt-ci']            === true;
const ADDRESS_OVERRIDE      = typeof args['address-override'] === 'string'
  ? args['address-override']
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
let ci     = padZero(oacx.ci,    88, 'utf8');
// TODO(HS256): Re-enable when RAON registration provides the RP shared
// secret. Currently disabled because no off-chain HS256 verifier exists,
// so cx_integrity_root cannot anchor anything meaningfully.
// const jti  = padZero(oacx.jti,   40, 'utf8');
// const pri  = padZero(oacx.pri,   44, 'utf8');
const name    = padZero(oacx.name,  64, 'utf8');
const telno   = padZero(oacx.telno, 16, 'utf8');
const sex     = oacx.sex && oacx.sex.length > 0 ? oacx.sex.charCodeAt(0) : 0;
const birth   = padZero(oacx.birth, 8,  'utf8');
const address = padZero(oacx.address || '', 256, 'utf8');
const targetRegion = padZero(REGION, 64, 'utf8');

// "Expected" overrides only affect the off-circuit owner_commit hash.
const expectedNameStr  = EXPECTED_NAME_OVERRIDE  ?? oacx.name;
const expectedBirthStr = EXPECTED_BIRTH_OVERRIDE ?? oacx.birth;
const expectedSexStr   = EXPECTED_SEX_OVERRIDE   ?? (oacx.sex ?? '');
const expectedTelnoStr = EXPECTED_TELNO_OVERRIDE ?? oacx.telno;
const expected_name_buf  = padZero(expectedNameStr,  64, 'utf8');
const expected_birth_buf = padZero(expectedBirthStr, 8,  'utf8');
const expected_telno_buf = padZero(expectedTelnoStr, 16, 'utf8');
const expected_sex_byte  = expectedSexStr && expectedSexStr.length > 0
  ? expectedSexStr.charCodeAt(0)
  : 0;

// ───────────────────────────────────────────────
// v4 nullifier: keccak(keccak(ci) || scope)
// Matches mdl_kr_common::verify_nullifier and the OIDC circuit formula.
// ───────────────────────────────────────────────

// --corrupt-ci: mutate a ci byte BEFORE nullifier derivation so the
// circuit's recomputed keccak(ci) disagrees with nullifier_value.
if (CORRUPT_CI) {
  ci = Buffer.from(ci);
  ci[0] = ci[0] === 0x41 ? 0x42 : 0x41;
}

const ci_hash = k256(ci);
let scope = k256(Buffer.from(SCOPE_STR, 'utf8'));

// --signal-hash-hex is INERT in v4 (accepted for D1 regression guard,
// not emitted). Log it so callers can see it was received.
if (SIGNAL_HASH_OVERRIDE !== null) {
  const shBuf = Buffer.from(SIGNAL_HASH_OVERRIDE.replace(/^0x/, ''), 'hex');
  if (shBuf.length !== 32) {
    throw new Error(`signal_hash must be 32 bytes, got ${shBuf.length}`);
  }
  // NOTE: value intentionally unused — v4 nullifier does not use signal_hash.
}

let nullifier_value = k256(Buffer.concat([ci_hash, scope]));
if (CORRUPT_NULLIFIER) nullifier_value = randomBytes(32);

// --corrupt-scope: mutate the *published* scope after nullifier derivation.
if (CORRUPT_SCOPE) scope = randomBytes(32);

const region_code = k256(targetRegion);

const disclose_flags = parseInt(FLAGS_HEX, 16);
// owner_commit computed OFF-CIRCUIT from expected values.
// Buffer layout (89 bytes): name(64) || telno(16) || birth(8) || sex(1).
const owner_buf = Buffer.alloc(89);
if (disclose_flags & 0x01) expected_name_buf.copy(owner_buf, 0);
if (disclose_flags & 0x08) expected_telno_buf.copy(owner_buf, 64);
if (disclose_flags & 0x02) expected_birth_buf.copy(owner_buf, 80);
if (disclose_flags & 0x04) owner_buf[88] = expected_sex_byte;

let owner_commit;
if (disclose_flags === 0) {
  owner_commit = Buffer.alloc(32);
} else {
  owner_commit = k256(Buffer.concat([Buffer.from([disclose_flags]), owner_buf]));
}
if (CORRUPT_OWNER_COMMIT)   owner_commit = randomBytes(32);
if (ANON_WITH_NONZERO && disclose_flags === 0) owner_commit = randomBytes(32);
if (NONANON_WITH_ZERO && disclose_flags !== 0) owner_commit = Buffer.alloc(32);

// Mutate private inputs *after* derivation.
let outBirth   = birth;
let outAddress = address;
if (CORRUPT_BIRTH) {
  // Flips the day digit (byte 7). NOTE: assert_age only reads bytes 0-3
  // (the year), so this does NOT cause a circuit failure in v4. This flag
  // is kept for compatibility; use --corrupt-birth-year for a real FAIL.
  outBirth = Buffer.from(birth);
  outBirth[7] = outBirth[7] === 0x39 ? 0x30 : 0x39;
}
if (CORRUPT_BIRTH_YEAR) {
  // Flips the first year digit (byte 0: '1' -> '2'), so birth_year becomes
  // 2985 and assert_age fails with "Birth year exceeds current year".
  outBirth = Buffer.from(birth);
  outBirth[0] = outBirth[0] === 0x31 ? 0x32 : 0x31; // '1' <-> '2'
}
if (CORRUPT_ADDRESS) {
  // Flips a byte deep in the address buffer (byte 200). NOTE: extract_region_token
  // reads only the first whitespace-separated token (bytes 0-~15 for Korean
  // si/do), so this does NOT cause a region mismatch in v4. This flag is kept
  // for compatibility; use --corrupt-address-token for a real FAIL.
  outAddress = Buffer.from(address);
  outAddress[200] = outAddress[200] ^ 0xff;
}
if (CORRUPT_ADDRESS_TOKEN) {
  // Flips byte 0 of the address, corrupting the first character of the first
  // token that extract_region_token extracts. This reliably fails the region
  // assertion even after the v4 nullifier change.
  outAddress = Buffer.from(address);
  outAddress[0] = outAddress[0] ^ 0x01;
}

let outCurrYear = CURR_YEAR;
if (YEAR_BEFORE_BIRTH) {
  const birthYear = parseInt(oacx.birth.slice(0, 4), 10);
  outCurrYear = birthYear - 1;
}

// ───────────────────────────────────────────────
// Emit Prover.toml
// ───────────────────────────────────────────────
const lines = [
  `# Auto-generated by scripts/gen.mjs --circuit ${CIRCUIT} (v4)`,
  `# Demo: Korean mobile driver license (${oacx.name})`,
  `# v4 nullifier: keccak(keccak(ci) || scope) — signal_hash and cx_integrity_root`,
  `# are commented out pending RAON RP registration (HS256 path dormant).`,
  '',
  '# ============ Public Inputs ============',
  // TODO(HS256): Re-enable signal_hash emission when RAON registration provides
  // the RP shared secret.
  // `signal_hash       = ${tomlArray(signal_hash)}`,
  `scope             = ${tomlArray(scope)}`,
  `nullifier_value   = ${tomlArray(nullifier_value)}`,
  // TODO(HS256): Re-enable cx_integrity_root emission when RAON registration
  // provides the RP shared secret.
  // `cx_integrity_root = ${tomlArray(cx_integrity_root)}`,
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
// TODO(HS256): Re-enable cx_jti / cx_pri emission when RAON registration
// provides the RP shared secret.
// lines.push(`cx_jti      = ${tomlArray(jti)}`);
// lines.push(`cx_pri      = ${tomlArray(pri)}`);

if (CIRCUIT === 'ownership') {
  lines.push(`name        = ${tomlArray(name)}`);
  lines.push(`birth_date  = ${tomlArray(outBirth)}`);
  lines.push(`telno       = ${tomlArray(telno)}`);
  lines.push(`sex         = ${sex}`);
  // address not needed in v4 ownership
  // TODO(HS256): Re-enable address when derive_self_id_20 is re-enabled.
  // lines.push(`address     = ${tomlArray(outAddress)}`);
} else if (CIRCUIT === 'age') {
  lines.push(`birth_date  = ${tomlArray(outBirth)}`);
  // address not needed in v4 age
  // TODO(HS256): Re-enable address when derive_self_id_20 is re-enabled.
  // lines.push(`address     = ${tomlArray(outAddress)}`);
} else if (CIRCUIT === 'region') {
  // birth_date not needed in v4 region
  // TODO(HS256): Re-enable birth_date when derive_self_id_20 is re-enabled.
  // lines.push(`birth_date  = ${tomlArray(outBirth)}`);
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
console.log('  ci_hash          = 0x' + ci_hash.toString('hex'));
console.log('  scope            = 0x' + scope.toString('hex'));
// NOTE: signal_hash is INERT in v4 — not emitted to Prover.toml.
if (SIGNAL_HASH_OVERRIDE !== null) {
  console.log('  signal_hash_hex  = (INERT in v4 — accepted but not used for nullifier)');
}
if (CIRCUIT === 'ownership') {
  console.log('  disclose_flags   = 0x' + disclose_flags.toString(16).padStart(2, '0'));
  console.log('  owner_commit     = 0x' + owner_commit.toString('hex'));
} else if (CIRCUIT === 'age') {
  console.log('  age_threshold    =', AGE_THRESH);
  console.log('  current_year     =', outCurrYear);
} else if (CIRCUIT === 'region') {
  console.log('  region_code      = 0x' + region_code.toString('hex'));
}
