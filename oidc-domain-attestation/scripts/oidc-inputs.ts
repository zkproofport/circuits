/**
 * Reference input builder for oidc_domain_attestation v2.
 *
 * The app (src/utils/oidcDomain.ts), the AI server (src/prover/oidcProver.ts)
 * and the AI SDK (packages/sdk/src/oidc-inputs.ts) each carry their own copy
 * of this logic. This one is what the circuit's acceptance run uses, so it is
 * the one that is known to agree with the circuit.
 *
 * Public input layout, in order (field elements):
 *   0-17     pubkey_modulus_limbs   18 x u128 (120-bit limbs, little-endian)
 *   18-81    domain.storage         64 x u8
 *   82       domain.len
 *   83-114   scope                  32 x u8   keccak256(utf8(scope string))
 *   115-146  nullifier              32 x u8   keccak256(keccak256(email) || scope)
 *   147      provider               0 = Google, 1 = Microsoft
 *   148-179  aud_hash               32 x u8   keccak256(utf8(aud))
 *   180      nonce_mode             1 = nonce bound, 0 = none
 *   181-212  nonce_binding          32 x u8   token nonce == lowercase hex of these bytes
 *   213      now                    u64 unix seconds, iat <= now < exp
 *
 * What changed from v1 for a builder:
 *   - The SHA precompute stops at the 64-byte block holding the `.` between
 *     header and payload (v1 stopped at "email"), so partial_data carries the
 *     whole payload: the circuit reads iss and aud, which come before email.
 *   - base64_decode_offset is the index just after that `.` within
 *     partial_data (1..64). The circuit refuses anything else.
 *   - MAX_PARTIAL_DATA_LENGTH is 2048 (v1: 768).
 *   - Four new public inputs; nonce_mode 1 needs the nonce the token was
 *     requested with, decoded from its 64 hex characters.
 *
 * Provider-key statement (2026-10-28, fix list item 12). The public inputs
 * do not change (still 214). Ten private inputs follow signature_limbs:
 * signer_kind, statement_sig and the App Attest chain, the same names and
 * sizes as coinbase_attestation v2. Before building, a signer the circuit
 * trusts must have checked that the modulus is in the provider's live JWKS
 * and signed providerKeyStatement(provider, now, n):
 *   server (kind 2): Cloud KMS ECDSA P-256 over SHA256(statement), r || s
 *                    with low s; every App Attest input zero (serverSigner).
 *   app    (kind 1): an App Attest assertion with clientDataHash =
 *                    SHA256(statement), r || s with low s, plus the credential
 *                    certificate TBS/signature and both authenticator datas
 *                    (appSigner).
 */

import * as crypto from "node:crypto";
import { keccak256 as ethersKeccak256 } from "ethers";

export const MAX_PARTIAL_DATA_LENGTH = 2048;
export const MAX_DOMAIN_LENGTH = 64;
export const PUBLIC_INPUT_COUNT = 214;

// Provider-key statement (src/provider_key.nr) and the signer inputs
// (../statement-signer, app-attest-libs).
export const STATEMENT_LEN = 313;
export const STATEMENT_MAGIC = "ZKProofport/PK/1";
export const CIRCUIT_ID = "oidc_domain_attestation";
export const SIGNER_KIND_APP = 1;
export const SIGNER_KIND_SERVER = 2;
export const CREDENTIAL_TBS_MAX_LEN = 1000;
export const ATT_AUTH_DATA_MAX_LEN = 256;
export const ASSERT_AUTH_DATA_MAX_LEN = 128;

export const PROVIDER_GOOGLE = 0;
export const PROVIDER_MICROSOFT = 1;
export const OIDC_NONCE_DOMAIN = "zkproofport-oidc-v1";

export type Provider = typeof PROVIDER_GOOGLE | typeof PROVIDER_MICROSOFT;

export interface CircuitInputs {
  pubkey_modulus_limbs: bigint[];
  domain: { storage: Uint8Array; len: number };
  scope: Uint8Array;
  nullifier: Uint8Array;
  provider: number;
  aud_hash: Uint8Array;
  nonce_mode: number;
  nonce_binding: Uint8Array;
  now: bigint;
  partial_data: { storage: Uint8Array; len: number };
  partial_hash: Uint32Array;
  full_data_length: number;
  base64_decode_offset: number;
  redc_params_limbs: bigint[];
  signature_limbs: bigint[];
  signer_kind: number;
  statement_sig: Uint8Array;
  credential_tbs: Uint8Array;
  credential_tbs_len: number;
  credential_sig: Uint8Array;
  att_auth_data: Uint8Array;
  att_auth_data_len: number;
  att_client_data_hash: Uint8Array;
  assertion_auth_data: Uint8Array;
  assertion_auth_data_len: number;
}

/** Who signed the provider-key statement, as the circuit takes it. */
export interface SignerInputs {
  signer_kind: number;
  statement_sig: Uint8Array;
  credential_tbs: Uint8Array;
  credential_tbs_len: number;
  credential_sig: Uint8Array;
  att_auth_data: Uint8Array;
  att_auth_data_len: number;
  att_client_data_hash: Uint8Array;
  assertion_auth_data: Uint8Array;
  assertion_auth_data_len: number;
}

export interface BuildOptions {
  provider: Provider;
  /** The scope string; the circuit receives keccak256 of its UTF-8 bytes. */
  scope: string;
  /** 1 with `nonceBinding` (the requested nonce's 32 bytes), 0 for device flow. */
  nonceMode: 0 | 1;
  nonceBinding?: Uint8Array;
  /** Unix seconds. */
  now: bigint;
  /** serverSigner(...) or appSigner(...) over providerKeyStatement(provider, now, n). */
  signer: SignerInputs;
}

export function keccak(data: Uint8Array): Uint8Array {
  return Uint8Array.from(Buffer.from(ethersKeccak256(data).slice(2), "hex"));
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/** The app's nonce: keccak256(tag || keccak256(scope) || requestId), as bytes. */
export function deriveNonceBinding(scope: string, requestId: string): Uint8Array {
  return keccak(Buffer.concat([utf8(OIDC_NONCE_DOMAIN), keccak(utf8(scope)), utf8(requestId)]));
}

function toLimbs(value: bigint, n = 18, bits = 120): bigint[] {
  const mask = (1n << BigInt(bits)) - 1n;
  return Array.from({ length: n }, (_, i) => (value >> (BigInt(i) * BigInt(bits))) & mask);
}

const bufToBigInt = (b: Buffer) => BigInt("0x" + b.toString("hex"));

/** SHA-256 midstate after the first `blocks` 64-byte blocks of `data`. */
export function sha256Midstate(data: Uint8Array, blocks: number): Uint32Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const rotr = (n: number, x: number) => (x >>> n) | (x << (32 - n));
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  if (blocks * 64 > data.length) throw new Error(`midstate past the end: ${blocks} blocks of ${data.length} bytes`);
  for (let blk = 0; blk < blocks; blk++) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const o = blk * 64 + i * 4;
      w[i] = (data[o] << 24) | (data[o + 1] << 16) | (data[o + 2] << 8) | data[o + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(6, e) ^ rotr(11, e) ^ rotr(25, e)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(2, a) ^ rotr(13, a) ^ rotr(22, a)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H;
}

const padTo = (b: Uint8Array, n: number, what: string): Uint8Array => {
  if (b.length > n) throw new Error(`${what} is ${b.length} bytes; the circuit takes ${n}`);
  const out = new Uint8Array(n);
  out.set(b);
  return out;
};

/** The JWKS `n` as exactly 256 big-endian bytes (an RSA-2048 modulus). */
export function modulusBytes(modulusB64url: string): Uint8Array {
  let n = Buffer.from(modulusB64url, "base64url");
  while (n.length > 256 && n[0] === 0) n = n.subarray(1);
  if (n.length !== 256 || (n[0] & 0x80) === 0) {
    throw new Error(`the provider key is not a 2048-bit RSA modulus (${n.length} bytes)`);
  }
  return Uint8Array.from(n);
}

/**
 * The 313 bytes a signer signs: "ZKProofport/PK/1" || keccak256(circuit id) ||
 * provider || now (u64 big-endian) || n (256 bytes big-endian). The circuit
 * builds the same bytes from its public inputs (src/provider_key.nr).
 */
export function providerKeyStatement(provider: number, now: bigint, modulusB64url: string): Uint8Array {
  if (provider !== PROVIDER_GOOGLE && provider !== PROVIDER_MICROSOFT) throw new Error(`Unknown provider ${provider}`);
  if (now < 0n || now >= 1n << 64n) throw new Error(`now ${now} is not a u64`);
  const t = Buffer.alloc(8);
  t.writeBigUInt64BE(now);
  const s = Buffer.concat([
    Buffer.from(STATEMENT_MAGIC, "ascii"),
    keccak(utf8(CIRCUIT_ID)),
    Buffer.from([provider]),
    t,
    modulusBytes(modulusB64url),
  ]);
  if (s.length !== STATEMENT_LEN) throw new Error(`statement is ${s.length} bytes`);
  return Uint8Array.from(s);
}

/** The server kind: a KMS signature (r || s, low s) and zeros for App Attest. */
export function serverSigner(statementSig: Uint8Array): SignerInputs {
  if (statementSig.length !== 64) throw new Error("statement_sig must be r || s, 64 bytes");
  return {
    signer_kind: SIGNER_KIND_SERVER,
    statement_sig: Uint8Array.from(statementSig),
    credential_tbs: new Uint8Array(CREDENTIAL_TBS_MAX_LEN),
    credential_tbs_len: 0,
    credential_sig: new Uint8Array(96),
    att_auth_data: new Uint8Array(ATT_AUTH_DATA_MAX_LEN),
    att_auth_data_len: 0,
    att_client_data_hash: new Uint8Array(32),
    assertion_auth_data: new Uint8Array(ASSERT_AUTH_DATA_MAX_LEN),
    assertion_auth_data_len: 0,
  };
}

/** The app kind: an App Attest assertion over SHA256(statement) and its chain. */
export function appSigner(a: {
  assertionSig: Uint8Array;
  credentialTbs: Uint8Array;
  credentialSig: Uint8Array;
  attAuthData: Uint8Array;
  attClientDataHash: Uint8Array;
  assertionAuthData: Uint8Array;
}): SignerInputs {
  if (a.assertionSig.length !== 64) throw new Error("assertion signature must be r || s, 64 bytes");
  if (a.credentialSig.length !== 96) throw new Error("credential signature must be r || s, 96 bytes");
  if (a.attClientDataHash.length !== 32) throw new Error("attestation clientDataHash must be 32 bytes");
  return {
    signer_kind: SIGNER_KIND_APP,
    statement_sig: Uint8Array.from(a.assertionSig),
    credential_tbs: padTo(a.credentialTbs, CREDENTIAL_TBS_MAX_LEN, "credential TBS"),
    credential_tbs_len: a.credentialTbs.length,
    credential_sig: Uint8Array.from(a.credentialSig),
    att_auth_data: padTo(a.attAuthData, ATT_AUTH_DATA_MAX_LEN, "attestation authData"),
    att_auth_data_len: a.attAuthData.length,
    att_client_data_hash: Uint8Array.from(a.attClientDataHash),
    assertion_auth_data: padTo(a.assertionAuthData, ASSERT_AUTH_DATA_MAX_LEN, "assertion authData"),
    assertion_auth_data_len: a.assertionAuthData.length,
  };
}

/**
 * Build the circuit inputs for an RS256 ID token.
 *
 * `modulusB64url` is the provider key's `n` (from its JWKS). This function
 * does not check the token's claims beyond what it needs to fill the inputs;
 * the circuit is what refuses a token, and the acceptance run relies on being
 * able to hand it tokens a careful builder would reject.
 */
export function buildInputs(jwt: string, modulusB64url: string, opts: BuildOptions): CircuitInputs {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error(`JWT has ${parts.length} parts, expected 3`);
  const [headerB64, payloadB64, sigB64] = parts;
  const signed = utf8(`${headerB64}.${payloadB64}`);

  // Cut at the block that holds the `.`; the payload then starts 1..64 bytes in.
  const dot = headerB64.length;
  const cutBlocks = Math.floor(dot / 64);
  const cut = cutBlocks * 64;
  const remaining = signed.slice(cut);
  if (remaining.length > MAX_PARTIAL_DATA_LENGTH) {
    throw new Error(
      `ID token too large: ${remaining.length} bytes after the SHA precompute, the circuit holds ${MAX_PARTIAL_DATA_LENGTH}`,
    );
  }
  const partialStorage = new Uint8Array(MAX_PARTIAL_DATA_LENGTH);
  partialStorage.set(remaining);

  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  const email: string = payload.email;
  if (typeof email !== "string" || !email.includes("@")) throw new Error("ID token has no email claim");
  const domainStr = email.slice(email.lastIndexOf("@") + 1);
  const domainBytes = utf8(domainStr);
  if (domainBytes.length > MAX_DOMAIN_LENGTH) throw new Error(`domain longer than ${MAX_DOMAIN_LENGTH} bytes`);
  const domainStorage = new Uint8Array(MAX_DOMAIN_LENGTH);
  domainStorage.set(domainBytes);

  const scope = keccak(utf8(opts.scope));
  const nullifier = keccak(Buffer.concat([keccak(utf8(email)), scope]));

  const audHash = keccak(utf8(typeof payload.aud === "string" ? payload.aud : ""));

  let binding = new Uint8Array(32);
  if (opts.nonceMode === 1) {
    if (!opts.nonceBinding || opts.nonceBinding.length !== 32) throw new Error("nonce_mode 1 needs a 32-byte nonceBinding");
    binding = Uint8Array.from(opts.nonceBinding);
  }

  const n = bufToBigInt(Buffer.from(modulusB64url, "base64url"));
  const redc = (1n << (2n * 2048n + 4n)) / n;
  const sig = bufToBigInt(Buffer.from(sigB64, "base64url"));

  return {
    pubkey_modulus_limbs: toLimbs(n),
    domain: { storage: domainStorage, len: domainBytes.length },
    scope,
    nullifier,
    provider: opts.provider,
    aud_hash: audHash,
    nonce_mode: opts.nonceMode,
    nonce_binding: binding,
    now: opts.now,
    partial_data: { storage: partialStorage, len: remaining.length },
    partial_hash: sha256Midstate(signed, cutBlocks),
    full_data_length: signed.length,
    base64_decode_offset: dot + 1 - cut,
    redc_params_limbs: toLimbs(redc),
    signature_limbs: toLimbs(sig),
    ...opts.signer,
  };
}

/** The public inputs as the verifier sees them, in circuit order (214 values). */
export function publicInputs(i: CircuitInputs): bigint[] {
  const out: bigint[] = [];
  out.push(...i.pubkey_modulus_limbs);
  out.push(...Array.from(i.domain.storage, BigInt), BigInt(i.domain.len));
  out.push(...Array.from(i.scope, BigInt), ...Array.from(i.nullifier, BigInt));
  out.push(BigInt(i.provider));
  out.push(...Array.from(i.aud_hash, BigInt));
  out.push(BigInt(i.nonce_mode));
  out.push(...Array.from(i.nonce_binding, BigInt));
  out.push(i.now);
  if (out.length !== PUBLIC_INPUT_COUNT) throw new Error(`built ${out.length} public inputs, expected ${PUBLIC_INPUT_COUNT}`);
  return out;
}

const hexArr = (b: Uint8Array) => `[${Array.from(b, (x) => `"0x${x.toString(16).padStart(2, "0")}"`).join(", ")}]`;
const decArr = (v: bigint[]) => `[${v.map((x) => `"${x.toString()}"`).join(", ")}]`;

export function toProverToml(i: CircuitInputs): string {
  return [
    `pubkey_modulus_limbs = ${decArr(i.pubkey_modulus_limbs)}`,
    `scope = ${hexArr(i.scope)}`,
    `nullifier = ${hexArr(i.nullifier)}`,
    `provider = ${i.provider}`,
    `aud_hash = ${hexArr(i.aud_hash)}`,
    `nonce_mode = ${i.nonce_mode}`,
    `nonce_binding = ${hexArr(i.nonce_binding)}`,
    `now = "${i.now.toString()}"`,
    `partial_hash = [${Array.from(i.partial_hash).join(", ")}]`,
    `full_data_length = ${i.full_data_length}`,
    `base64_decode_offset = ${i.base64_decode_offset}`,
    `redc_params_limbs = ${decArr(i.redc_params_limbs)}`,
    `signature_limbs = ${decArr(i.signature_limbs)}`,
    `signer_kind = ${i.signer_kind}`,
    `statement_sig = ${hexArr(i.statement_sig)}`,
    `credential_tbs = ${hexArr(i.credential_tbs)}`,
    `credential_tbs_len = ${i.credential_tbs_len}`,
    `credential_sig = ${hexArr(i.credential_sig)}`,
    `att_auth_data = ${hexArr(i.att_auth_data)}`,
    `att_auth_data_len = ${i.att_auth_data_len}`,
    `att_client_data_hash = ${hexArr(i.att_client_data_hash)}`,
    `assertion_auth_data = ${hexArr(i.assertion_auth_data)}`,
    `assertion_auth_data_len = ${i.assertion_auth_data_len}`,
    ``,
    `[domain]`,
    `storage = ${hexArr(i.domain.storage)}`,
    `len = ${i.domain.len}`,
    ``,
    `[partial_data]`,
    `storage = ${hexArr(i.partial_data.storage)}`,
    `len = ${i.partial_data.len}`,
    ``,
  ].join("\n");
}

/** Sign `payloadJson` (raw text, so tests control key order and duplicates) with RS256. */
export function signJwt(payloadJson: string, privateKey: crypto.KeyObject, kid = "synthetic"): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid, typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(payloadJson, "utf8").toString("base64url");
  const sig = crypto.sign("sha256", Buffer.from(`${header}.${payload}`), privateKey);
  return `${header}.${payload}.${sig.toString("base64url")}`;
}
