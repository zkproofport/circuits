/**
 * Fixtures for the oidc_domain_attestation ANDROID FACTORY package.
 *
 *   run by scripts/post-build.sh (tsx from ../../oidc-domain-attestation/scripts)
 *
 * Token half: the iOS package's reference builder (buildTokenInputs). Signer:
 * a SYNTHETIC factory chain under the synthetic RSA root and a Play Integrity
 * verdict signed with the INSECURE test Play key
 * (scripts/statement-signer/android.js factoryDevice / playToken), both pinned
 * in the synthetic-anchors copy. Real-circuit cases use Google's RSA root, our
 * real Play key and a real Google-signed factory chain (Sony, Android 13).
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import {
  buildTokenInputs,
  deriveNonceBinding,
  providerKeyStatement,
  publicInputs,
  signJwt,
  toProverTomlAndroidFactory,
  type BuildOptions,
  type TokenInputs,
} from "../../oidc-domain-attestation/scripts/oidc-inputs.ts";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const CIRCUIT = path.resolve(HERE, "..");
const CIRCUITS = path.resolve(CIRCUIT, "..");
const SYN = path.resolve(CIRCUITS, "oidc-domain-attestation-android-factory-synthetic-anchors");
const OUT = path.join(SYN, "test-vectors");
const REAL_OUT = path.join(CIRCUIT, "test-vectors");
if (!fs.existsSync(path.join(SYN, "Nargo.toml"))) {
  throw new Error(`${SYN} is missing: run scripts/statement-signer/make-synthetic-anchors.sh oidc-domain-attestation-android-factory`);
}
for (const dir of [OUT, REAL_OUT]) {
  fs.mkdirSync(dir, { recursive: true });
  for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f), { recursive: true });
}

const require = createRequire(import.meta.url);
const A = require(path.join(CIRCUITS, "scripts/statement-signer/android.js"));
const anchors = require(path.join(CIRCUITS, "scripts/statement-signer/anchors.js"));
const chainJs = require(path.join(CIRCUITS, "scripts/android-key-attestation/chain.js"));

const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const modulus = (k: crypto.KeyObject) => (k.export({ format: "jwk" }) as { n: string }).n;
const N = modulus(key.publicKey);
const OTHER_N = modulus(otherKey.publicKey);

const SCOPE = "proofport:default";
const BINDING = deriveNonceBinding(SCOPE, "8499ba71-c19f-4c96-961a-d7fd4f3dd112");
const NONCE = Buffer.from(BINDING).toString("hex");
const GOOGLE_WEB = "491923400813-5bb3up7dhejns2unvbrt6mku520hrr5g.apps.googleusercontent.com";
const MS_CLIENT = "8b09c842-d7a8-4d9c-a6ea-46c797412bac";
const MS_TENANT = "b9419818-09af-49c2-b0c3-653adc1f376e";
const IAT = 1761555600;
const EXP = IAT + 3600;
const NOW = IAT + 60;

const google = (nonce: string | null, iat = IAT) => JSON.stringify({
  iss: "https://accounts.google.com", aud: GOOGLE_WEB, sub: "104857291038475610293",
  email: "alice.lastname@example-corp.com", email_verified: true,
  ...(nonce === null ? {} : { nonce }), iat, exp: iat + 3600,
});
const microsoft = (nonce: string) => JSON.stringify({
  aud: MS_CLIENT, iss: `https://login.microsoftonline.com/${MS_TENANT}/v2.0`, iat: IAT, exp: EXP,
  email: "bob@contoso-example.com", nonce, xms_edov: true,
});

type Opts = Omit<BuildOptions, "signer">;
const G: Opts = { provider: 0, scope: SCOPE, now: BigInt(NOW), nonceMode: 1, nonceBinding: BINDING };
const M: Opts = { provider: 1, scope: SCOPE, now: BigInt(NOW), nonceMode: 1, nonceBinding: BINDING };

const syntheticRsa = chainJs.rsa4096Params(anchors.syntheticAndroidRsaRoot().modulusHex);
const realRsa = chainJs.rsa4096Params(chainJs.GOOGLE_RSA_ROOT_MODULUS_HEX);
const testPlay = anchors.testPlayKey();
const testPlayXY = Buffer.concat([testPlay.x, testPlay.y]);

interface Case {
  dev?: Record<string, unknown>;
  statement?: Uint8Array;
  /** Verdict field overrides (android.js playToken). */
  verdict?: Record<string, unknown>;
  /** Sign the verdict with another key. */
  verdictKey?: unknown;
  /** The nonce the verdict carries, when not this statement's. */
  verdictNonce?: Buffer;
  rsa?: { modulus: bigint[]; redc: bigint[] };
  playKey?: Buffer;
  chainInputs?: Record<string, unknown>;
  change?: (a: Record<string, unknown>) => void;
  /** Use Google's signature over ANOTHER verdict (these field overrides) for this payload. */
  signatureFrom?: Record<string, unknown>;
  tweak?: (i: TokenInputs) => void;
  payload?: string;
  opts?: Opts;
  out?: string;
}

const written: string[] = [];
function write(name: string, c: Case = {}) {
  const opts = c.opts ?? G;
  const jwt = signJwt(c.payload ?? google(NONCE), key.privateKey, "0123456789abcdef0123456789abcdef01234567");
  const token = buildTokenInputs(jwt, N, opts);
  c.tweak?.(token);
  const honest = Buffer.from(providerKeyStatement(opts.provider, opts.now, N));
  let chain: Record<string, unknown>;
  let sig: Buffer;
  if (c.chainInputs) {
    chain = { ...c.chainInputs };
    sig = Buffer.alloc(64);
    sig[31] = 1;
    sig[63] = 1;
  } else {
    const d = A.factoryDevice(c.dev ?? {});
    chain = { ...d.inputs };
    sig = A.androidSign(Buffer.from(c.statement ?? honest), d.leaf);
  }
  const nonce = c.verdictNonce ?? A.playIntegrityNonce(honest, sig);
  const t = A.playToken(nonce, c.verdictKey ?? testPlay, c.verdict ?? {});
  const rsa = c.rsa ?? syntheticRsa;
  const a: Record<string, unknown> = {
    statement_sig: sig,
    ik_tbs: chain.ik_tbs, ik_tbs_len: chain.ik_tbs_len, ik_sig: chain.ik_sig,
    batch_tbs: chain.batch_tbs, batch_tbs_len: chain.batch_tbs_len, batch_sig: chain.batch_sig,
    leaf_tbs: chain.leaf_tbs, leaf_tbs_len: chain.leaf_tbs_len, leaf_sig: chain.leaf_sig,
    integrity_payload_b64: t.payload_b64, integrity_payload_b64_len: t.payload_b64_len, integrity_signature: t.signature,
    rsa_root_modulus: rsa.modulus, rsa_root_redc: rsa.redc, play_integrity_key: c.playKey ?? testPlayXY,
  };
  if (c.signatureFrom) a.integrity_signature = A.playToken(nonce, c.verdictKey ?? testPlay, c.signatureFrom).signature;
  c.change?.(a);
  const out = c.out ?? OUT;
  fs.writeFileSync(path.join(out, `${name}.toml`), toProverTomlAndroidFactory(token, a as never));
  fs.writeFileSync(path.join(out, `${name}.public_inputs.hex`), publicInputs(token).map((v) => v.toString(16).padStart(64, "0")).join(""));
  written.push(`${name} (ik ${a.ik_tbs_len}, batch ${a.batch_tbs_len}, leaf ${a.leaf_tbs_len}, verdict ${a.integrity_payload_b64_len})`);
}

// ---------------- accepted ----------------
write("google_bound");
write("microsoft_bound", { opts: M, payload: microsoft(NONCE) });
write("strong_integrity_only", { verdict: { verdicts: ["MEETS_STRONG_INTEGRITY"] } });
write("strongbox_key", { dev: { level: 2 } });

// ---------------- refused: the statement ----------------
write("stmt_other_key_vouched", { statement: providerKeyStatement(0, BigInt(NOW), OTHER_N) });
{
  const cb = Buffer.alloc(225);
  Buffer.from("ZKProofport/AA/1").copy(cb, 0);
  write("stmt_coinbase_replay", { statement: cb });
}

// ---------------- refused: the chain and key description ----------------
write("other_package", { dev: { packages: ["com.masselabs.zkproofport.debug"] } });
write("debug_signing_certificate", { dev: { digests: [crypto.createHash("sha256").update("debug.keystore").digest()] } });
write("bootloader_unlocked", { dev: { lockedByte: 0 } });
write("boot_unverified", { dev: { bootState: 2 } });
write("software_key", { dev: { level: 0 } });
write("ik_not_a_ca", { dev: { ikIsCa: false } });
write("key_description_in_batch", { dev: { keyDescriptionInBatch: true } });
write("batch_signed_by_other_key", { dev: { batchSigner: A.ecKey("secp384r1") } });
write("leaf_signed_by_other_key", { dev: { leafSigner: A.ecKey("prime256v1") } });
{
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
  write("ik_signed_by_other_rsa_key", { dev: { ikSigner: { privateKey: other.privateKey } } });
}
write("other_rsa_root_inputs", { rsa: realRsa });
write("other_play_key_input", { playKey: Buffer.concat([A.ecKey("prime256v1").x, A.ecKey("prime256v1").y]) });

// ---------------- refused: the verdict ----------------
write("verdict_basic_only", { verdict: { verdicts: ["MEETS_BASIC_INTEGRITY"] } });
write("verdict_no_device_verdict", { verdict: { verdicts: [] } });
write("verdict_unrecognized", { verdict: { recognition: "UNRECOGNIZED_VERSION" } });
write("verdict_requested_by_other_app", { verdict: { requestPackage: "com.example.other" } });
write("verdict_for_other_app", { verdict: { package: "com.example.other" } });
write("verdict_for_other_statement", { verdictNonce: crypto.randomBytes(32) });
write("verdict_signed_by_other_key", { verdictKey: A.ecKey("prime256v1") });
// The honest payload with the signature Google made over a BASIC-only verdict
// for the same statement: well-formed, every field passes, only the signature
// check can refuse it.
write("verdict_tampered", { signatureFrom: { verdicts: ["MEETS_BASIC_INTEGRITY"] } });

// ---------------- refused: the token (a sample) ----------------
write("token_expired", { opts: { ...G, now: BigInt(EXP) } });

// ---------------- the real circuit: Google's RSA root and our Play key ----------------
write("real_synthetic_root", { out: REAL_OUT, playKey: anchors.readPlayKey() });
{
  // A REAL Google-signed factory chain (Sony Xperia 10 III, Android 13) with
  // Google's RSA root and our app's real Play key: every link verifies, then
  // its key description is refused (the key is the Play Store's, not ours).
  const pem = fs.readFileSync(path.join(CIRCUITS, "android-key-attestation/test-vectors/sony-xperia10iii-sdk33-factory.pem"), "utf8");
  write("real_google_factory_chain_other_app", {
    out: REAL_OUT,
    chainInputs: chainJs.factoryChainInputs(chainJs.pemChain(pem), chainJs.GOOGLE_RSA_ROOT_MODULUS_HEX),
    rsa: realRsa,
    playKey: anchors.readPlayKey(),
  });
}

fs.writeFileSync(path.join(OUT, "make-fixtures.log"), written.join("\n") + "\n");
console.log(`wrote ${written.length} cases`);
