/**
 * Fixtures for the oidc_domain_attestation ANDROID package's acceptance run.
 *
 *   ../../oidc-domain-attestation/scripts/node_modules/.bin/tsx scripts/make-fixtures.ts
 *   (run by scripts/post-build.sh)
 *
 * The token half comes from the iOS package's reference builder
 * (../../oidc-domain-attestation/scripts/oidc-inputs.ts buildTokenInputs):
 * both packages share ../oidc-libs, and the iOS acceptance run already walks
 * every token refusal, so only a few token cases are repeated here. What is
 * new is the signer: a SYNTHETIC Android key attestation chain
 * (scripts/statement-signer/android.js) under the synthetic root the
 * synthetic-anchors copy pins, with every refusal changing one thing.
 *
 * Writes ../../oidc-domain-attestation-android-synthetic-anchors/test-vectors/
 * <case>.toml and test-vectors/real_<case>.toml (cases for the real circuit's
 * pinned Google root); both gitignored. Every key is made on the spot.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import {
  androidSigner,
  buildTokenInputs,
  deriveNonceBinding,
  providerKeyStatement,
  publicInputs,
  signJwt,
  toProverTomlAndroid,
  type BuildOptions,
  type TokenInputs,
} from "../../oidc-domain-attestation/scripts/oidc-inputs.ts";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CIRCUIT = path.resolve(HERE, "..");
const CIRCUITS = path.resolve(CIRCUIT, "..");
const SYN = path.resolve(CIRCUITS, "oidc-domain-attestation-android-synthetic-anchors");
const OUT = path.join(SYN, "test-vectors");
const REAL_OUT = path.join(CIRCUIT, "test-vectors");
if (!fs.existsSync(path.join(SYN, "Nargo.toml"))) {
  throw new Error(`${SYN} is missing: run scripts/statement-signer/make-synthetic-anchors.sh oidc-domain-attestation-android`);
}
for (const dir of [OUT, REAL_OUT]) {
  fs.mkdirSync(dir, { recursive: true });
  for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f), { recursive: true });
}

const require = createRequire(import.meta.url);
const A = require(path.join(CIRCUITS, "scripts/statement-signer/android.js"));
const chainJs = require(path.join(CIRCUITS, "scripts/android-key-attestation/chain.js"));

const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const modulus = (k: crypto.KeyObject) => (k.export({ format: "jwk" }) as { n: string }).n;
const N = modulus(key.publicKey);
const OTHER_N = modulus(otherKey.publicKey);

const SCOPE = "proofport:default";
const REQUEST_ID = "8499ba71-c19f-4c96-961a-d7fd4f3dd112";
const BINDING = deriveNonceBinding(SCOPE, REQUEST_ID);
const NONCE = Buffer.from(BINDING).toString("hex");
const GOOGLE_WEB = "491923400813-5bb3up7dhejns2unvbrt6mku520hrr5g.apps.googleusercontent.com";
const GOOGLE_ANDROID = "491923400813-android0000000000000000000000.apps.googleusercontent.com";
const GOOGLE_DEVICE = "491923400813-pr17m6kpin2rsbbes18jpb60j1s3qmv4.apps.googleusercontent.com";
const MS_CLIENT = "8b09c842-d7a8-4d9c-a6ea-46c797412bac";
const MS_TENANT = "b9419818-09af-49c2-b0c3-653adc1f376e";

const IAT = 1761555600;
const EXP = IAT + 3600;
const NOW = IAT + 60;
const DAY = 86400;

const google = (nonce: string | null, iat = IAT, aud = GOOGLE_WEB) => JSON.stringify({
  iss: "https://accounts.google.com", azp: GOOGLE_ANDROID, aud, sub: "104857291038475610293",
  hd: "example-corp.com", email: "alice.lastname@example-corp.com", email_verified: true,
  ...(nonce === null ? {} : { nonce }), name: "Alice Lastname", iat, exp: iat + 3600,
});
const microsoft = (nonce: string) => JSON.stringify({
  aud: MS_CLIENT, iss: `https://login.microsoftonline.com/${MS_TENANT}/v2.0`, iat: IAT, nbf: IAT, exp: EXP,
  email: "bob@contoso-example.com", name: "Bob Example", nonce, tid: MS_TENANT, ver: "2.0", xms_edov: true,
});

type Opts = Omit<BuildOptions, "signer">;
const G: Opts = { provider: 0, scope: SCOPE, now: BigInt(NOW), nonceMode: 1, nonceBinding: BINDING };
const M: Opts = { provider: 1, scope: SCOPE, now: BigInt(NOW), nonceMode: 1, nonceBinding: BINDING };

/** One device per case unless a case needs a specific one: keys are cheap. */
const device = (o: Record<string, unknown> = {}) => A.androidDevice({ now: NOW, ...o });

interface Case {
  /** Device options, or a ready device. */
  dev?: Record<string, unknown>;
  /** What the leaf key signs instead of the honest statement. */
  statement?: Uint8Array;
  /** Replace the statement signature. */
  statementSig?: Buffer;
  /** Sign with another P-256 key. */
  otherSigner?: boolean;
  /** Change the chain inputs after conversion. */
  chain?: (c: Record<string, unknown>) => void;
  /** Change the token inputs. */
  tweak?: (i: TokenInputs) => void;
  payload?: string;
  opts?: Opts;
  out?: string;
  /** A ready chain (real vectors), with no private key. */
  chainInputs?: Record<string, unknown>;
}

const N_P256 = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const N_P384 = BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
function highS(sig: Buffer, n: bigint, size: number): Buffer {
  const s = BigInt("0x" + sig.subarray(size).toString("hex"));
  return Buffer.concat([sig.subarray(0, size), Buffer.from((n - s).toString(16).padStart(size * 2, "0"), "hex")]);
}

const written: string[] = [];
function write(name: string, c: Case = {}) {
  const opts = c.opts ?? G;
  const payload = c.payload ?? google(opts.nonceMode === 1 ? NONCE : null);
  const jwt = signJwt(payload, key.privateKey, "0123456789abcdef0123456789abcdef01234567");
  const token = buildTokenInputs(jwt, N, opts);
  c.tweak?.(token);
  const honest = providerKeyStatement(opts.provider, opts.now, N);
  let chain: Record<string, unknown>;
  let sig: Buffer;
  if (c.chainInputs) {
    chain = { ...c.chainInputs };
    const garbage = Buffer.alloc(64);
    garbage[31] = 1;
    garbage[63] = 1;
    sig = c.statementSig ?? garbage;
  } else {
    const d = device(c.dev);
    chain = { ...d.inputs };
    const signer = c.otherSigner ? A.ecKey("prime256v1") : d.leaf;
    sig = c.statementSig ?? A.androidSign(Buffer.from(c.statement ?? honest), signer);
  }
  c.chain?.(chain);
  delete chain.leaf_key;
  const a = androidSigner(sig, chain as never);
  publicInputs(token);
  const out = c.out ?? OUT;
  fs.writeFileSync(path.join(out, `${name}.toml`), toProverTomlAndroid(token, a));
  const hex = publicInputs(token).map((v) => v.toString(16).padStart(64, "0")).join("");
  fs.writeFileSync(path.join(out, `${name}.public_inputs.hex`), hex);
  written.push(`${name} (leaf TBS ${a.leaf_tbs_len}, att ${a.att_tbs_len}, CA3 ${a.ca3_tbs_len}, CA2 ${a.ca2_tbs_len})`);
}

// ---------------- accepted ----------------
write("google_bound");
write("microsoft_bound", { opts: M, payload: microsoft(NONCE) });
write("google_device_no_nonce", { opts: { ...G, nonceMode: 0, nonceBinding: undefined }, payload: google(null, IAT, GOOGLE_DEVICE) });
write("strongbox", { dev: { level: 2 } });
write("locked_ber_true", { dev: { lockedByte: 0x01 } });
write("att_first_second", { dev: { validity: { att: [NOW, NOW + 14 * DAY] } } });
write("att_last_second", { dev: { validity: { att: [NOW - 14 * DAY, NOW] } } });

// ---------------- refused: the statement ----------------
write("stmt_other_key_vouched", { statement: providerKeyStatement(0, BigInt(NOW), OTHER_N) });
write("stmt_other_provider", { statement: providerKeyStatement(1, BigInt(NOW), N) });
write("stmt_other_time", { statement: providerKeyStatement(0, BigInt(NOW + 1), N) });
{
  // A Coinbase v2 statement (225 bytes, "ZKProofport/AA/1") signed by the
  // same device key: the same key signs both kinds, so it must not pass here.
  const cb = Buffer.alloc(225);
  Buffer.from("ZKProofport/AA/1").copy(cb, 0);
  write("stmt_coinbase_replay", { statement: cb });
}
write("stmt_signed_by_other_key", { otherSigner: true });
{
  const d = device();
  const honest = providerKeyStatement(0, BigInt(NOW), N);
  write("stmt_high_s", { dev: { leafKey: d.leaf }, statementSig: highS(A.androidSign(Buffer.from(honest), d.leaf), N_P256, 32) });
}
write("stmt_zero_signature", { statementSig: Buffer.alloc(64) });

// ---------------- refused: what the key description says ----------------
write("other_package", { dev: { packages: ["com.masselabs.zkproofport.debug"] } });
write("debug_signing_certificate", { dev: { digests: [crypto.createHash("sha256").update("debug.keystore").digest()] } });
write("two_packages", { dev: { packages: ["com.masselabs.zkproofport", "com.example.shareduid"] } });
write("two_signing_certificates", { dev: { digests: [A.SIGNING_DIGEST, crypto.createHash("sha256").update("rotated").digest()] } });
write("bootloader_unlocked", { dev: { lockedByte: 0x00 } });
write("boot_self_signed", { dev: { bootState: 1 } });
write("boot_unverified", { dev: { bootState: 2 } });
write("software_key", { dev: { level: 0 } });
write("software_keymint_under_tee", { dev: { level: 1, kmLevel: 0 } });
write("imported_key", { dev: { origin: 2 } });
write("no_origin", { dev: { origin: null } });
write("no_root_of_trust", { dev: { rootOfTrust: false } });
write("app_id_in_hardware_list", { dev: { appIdIn: "hardware" } });
write("app_id_twice", { dev: { appIdIn: "software-twice" } });
write("no_app_id", { dev: { appIdIn: "none" } });
{
  // The key description's SEQUENCE claims one byte more than its extension
  // holds; the attestation key still signs it.
  write("key_description_overlong", {
    dev: {
      mutateLeafTbs: (t: Buffer) => {
        const at = t.indexOf(Buffer.from("060a2b06010401d679020111", "hex")) + 12;
        // OCTET STRING 04 82 hh ll, then SEQUENCE 30 82 hh ll
        const len = t.readUInt16BE(at + 6);
        t.writeUInt16BE(len + 1, at + 6);
        return t;
      },
    },
  });
}

// ---------------- refused: the chain ----------------
write("att_expired", { dev: { validity: { att: [NOW - 15 * DAY, NOW - 1] } } });
write("att_not_yet_valid", { dev: { validity: { att: [NOW + 1, NOW + 14 * DAY] } } });
write("ca3_expired", { dev: { validity: { ca3: [NOW - 80 * DAY, NOW - 1] } } });
write("ca2_not_yet_valid", { dev: { validity: { ca2: [NOW + 1, NOW + 1000 * DAY] } } });
write("att_not_remotely_provisioned", { dev: { attProvisioning: false } });
write("att_not_a_ca", { dev: { attIsCa: false } });
write("att_carries_key_description", { dev: { keyDescriptionInAtt: true } });
write("other_root", { dev: { root: A.ecKey("secp384r1") } });
write("ca3_signed_by_other_key", { dev: { ca3Signer: A.ecKey("secp384r1") } });
write("att_signed_by_other_key", { dev: { attSigner: A.ecKey("prime256v1") } });
write("leaf_signed_by_other_key", { dev: { leafSigner: A.ecKey("prime256v1") } });
write("ca2_sig_high_s", { chain: (c) => { c.ca2_sig = highS(c.ca2_sig as Buffer, N_P384, 48); } });
write("leaf_sig_high_s", { chain: (c) => { c.leaf_sig = highS(c.leaf_sig as Buffer, N_P256, 32); } });
write("leaf_length_short", { chain: (c) => { c.leaf_tbs_len = (c.leaf_tbs_len as number) - 1; } });
write("leaf_padding_not_zero", { chain: (c) => { (c.leaf_tbs as Buffer)[c.leaf_tbs_len as number] = 1; } });
write("leaf_length_over_limit", { chain: (c) => { c.leaf_tbs_len = 1025; } });
write("chain_shifted", {
  // The attestation-key certificate in CA3's place: one intermediate missing.
  chain: (c) => {
    const ca3 = Buffer.alloc(768);
    (c.att_tbs as Buffer).copy(ca3);
    c.ca3_tbs = ca3;
    c.ca3_tbs_len = c.att_tbs_len;
    const sig = Buffer.alloc(96);
    (c.att_sig as Buffer).copy(sig, 16, 0, 32);
    (c.att_sig as Buffer).copy(sig, 64, 32, 64);
    c.ca3_sig = sig;
  },
});
write("empty_chain", {
  chain: (c) => {
    for (const k of ["ca2", "ca3", "att", "leaf"]) {
      c[`${k}_tbs`] = Buffer.alloc((c[`${k}_tbs`] as Buffer).length);
      c[`${k}_tbs_len`] = 0;
    }
  },
});

// ---------------- refused: the token (shared ../oidc-libs; a sample) ----------------
write("token_expired", { opts: { ...G, now: BigInt(EXP) } , dev: { validity: { att: [NOW - DAY, EXP + DAY] } } });
write("wrong_nullifier", { tweak: (i) => { i.nullifier = new Uint8Array(32); } });

// ---------------- the real circuit, Google's root as committed ----------------
// A synthetic chain: not under Google's Key Attestation CA1.
write("real_synthetic_root", { out: REAL_OUT });
{
  // A REAL Google-signed chain (Pixel "tegu", Android 16, Google's test app):
  // every link verifies under the pinned root at 2026-03-01, and the key
  // description is then refused because the app is not ours. No private key
  // exists for its leaf; the refusal comes before the statement signature.
  const pem = fs.readFileSync(path.join(CIRCUITS, "android-key-attestation/test-vectors/tegu-sdk36-tee-ec-2026-root.pem"), "utf8");
  const real = chainJs.chainInputs(chainJs.pemChain(pem), chainJs.GOOGLE_KEY_ATTESTATION_CA1);
  const at = 1772323200; // 2026-03-01T00:00:00Z
  write("real_google_chain_other_app", {
    out: REAL_OUT,
    chainInputs: real,
    payload: google(NONCE, at - 60),
    opts: { ...G, now: BigInt(at) },
  });
}

fs.writeFileSync(path.join(OUT, "make-fixtures.log"), written.join("\n") + "\n");
console.log(`wrote ${written.length} cases`);
