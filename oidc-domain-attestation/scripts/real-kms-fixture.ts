/**
 * A REAL oidc_domain_attestation witness: a real Google ID token, the real
 * Google key it was signed with (read from Google's live JWKS), and a real
 * provider-key statement signed by the pinned Cloud KMS key -- the server
 * kind, exactly what proofport-ai does. This is the only fixture the real
 * circuit (anchors as committed) can ACCEPT, so it is what puts a real proof
 * in front of a deployed verifier.
 *
 *   ID_TOKEN=$(gcloud auth print-identity-token) \
 *   env -u NODE_OPTIONS node_modules/.bin/tsx real-kms-fixture.ts <out.toml>
 *
 * (oidc-domain-attestation/scripts/real-kms-proof.sh runs this, proves,
 * verifies, and deletes the witness file.)
 *
 * Needs: gcloud credentials allowed cloudkms.cryptoKeyVersions.useToSign on
 * the key below (the AI server's service accounts, or a project member who
 * holds it), and network access to Google's JWKS.
 *
 * WHAT IS SIGNED IS TRUE. The statement says "at <now>, this modulus was in
 * Google's published key list", and this script refuses to sign unless the
 * modulus is in the list it just fetched. Never point it at a key that is not
 * the provider's: the KMS key is the production key, and a statement it signs
 * for a self-made modulus would let anyone holding that modulus's private key
 * prove any email on every verifier.
 *
 * The token goes in through the environment, is never printed, and the
 * output file holds it in substance (partial_data, signature): it is written
 * under the gitignored test-vectors/ and the shell wrapper deletes it.
 */

import { execFileSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  buildInputs,
  providerKeyStatement,
  publicInputs,
  serverSigner,
  toProverToml,
  PROVIDER_GOOGLE,
} from "./oidc-inputs.ts";

const KMS_KEY_VERSION =
  "projects/masselabs-zkproofport/locations/us-central1/keyRings/proofport-ai/cryptoKeys/coinbase-kyc-v2-statement/cryptoKeyVersions/1";
const GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";
const N_P256 = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

const out = process.argv[2];
if (!out) throw new Error("usage: real-kms-fixture.ts <out.toml>");
const token = process.env.ID_TOKEN;
if (!token || token.split(".").length !== 3) throw new Error("ID_TOKEN must hold a Google ID token (gcloud auth print-identity-token)");

const [h64, p64] = token.split(".");
const header = JSON.parse(Buffer.from(h64, "base64url").toString("utf8"));
const payload = JSON.parse(Buffer.from(p64, "base64url").toString("utf8"));
if (header.alg !== "RS256") throw new Error(`token alg ${header.alg}, expected RS256`);
if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") throw new Error(`iss ${payload.iss} is not Google`);

// ---- the key, from the live list, or nothing --------------------------------
const res = await fetch(GOOGLE_JWKS);
if (!res.ok) throw new Error(`Google JWKS answered ${res.status}`);
const jwks = (await res.json()) as { keys: { kid: string; kty: string; n: string; e: string }[] };
const jwk = jwks.keys.find((k) => k.kid === header.kid && k.kty === "RSA");
if (!jwk) throw new Error(`kid ${header.kid} is not in Google's live JWKS: refusing to sign`);
const pub = crypto.createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
if (!crypto.verify("sha256", Buffer.from(`${h64}.${p64}`), pub, Buffer.from(token.split(".")[2], "base64url"))) {
  throw new Error("the token's signature does not verify under the live key");
}

// iat <= now < exp
const nowSec = BigInt(Math.floor(Date.now() / 1000));
const now = nowSec < BigInt(payload.iat) ? BigInt(payload.iat) : nowSec;
if (now >= BigInt(payload.exp)) throw new Error("the token has expired; fetch a new one");

// ---- KMS signs SHA256(statement) ---------------------------------------------
const statement = providerKeyStatement(PROVIDER_GOOGLE, now, jwk.n);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "oidc-kms-"));
let der: Buffer;
let kmsPem: string;
try {
  const parts = KMS_KEY_VERSION.split("/");
  const where = ["--key", parts[7], "--keyring", parts[5], "--location", parts[3], "--project", parts[1]];
  fs.writeFileSync(path.join(tmp, "statement"), statement);
  execFileSync("gcloud", ["kms", "asymmetric-sign", "--version", parts[9], ...where, "--digest-algorithm", "sha256",
    "--input-file", path.join(tmp, "statement"), "--signature-file", path.join(tmp, "sig")], { stdio: ["ignore", "ignore", "inherit"] });
  execFileSync("gcloud", ["kms", "keys", "versions", "get-public-key", parts[9], ...where, "--output-file", path.join(tmp, "pub.pem")], { stdio: ["ignore", "ignore", "inherit"] });
  der = fs.readFileSync(path.join(tmp, "sig"));
  kmsPem = fs.readFileSync(path.join(tmp, "pub.pem"), "utf8");
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

// DER -> r || s, s low; then the same check the circuit makes.
function derToRS(sig: Buffer): Buffer {
  if (sig[0] !== 0x30) throw new Error("KMS signature is not DER");
  let p = 2;
  const int = () => {
    if (sig[p] !== 0x02) throw new Error("not a DER INTEGER");
    const len = sig[p + 1];
    let v = sig.subarray(p + 2, p + 2 + len);
    p += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) throw new Error("DER integer too long");
    return Buffer.concat([Buffer.alloc(32 - v.length), v]);
  };
  const r = int();
  let s = BigInt("0x" + int().toString("hex"));
  if (s > N_P256 / 2n) s = N_P256 - s;
  return Buffer.concat([r, Buffer.from(s.toString(16).padStart(64, "0"), "hex")]);
}
const rs = derToRS(der);
if (!crypto.verify("sha256", Buffer.from(statement), { key: kmsPem, dsaEncoding: "ieee-p1363" }, rs)) {
  throw new Error("the KMS signature does not verify under the key's public key");
}

const inputs = buildInputs(token, jwk.n, {
  provider: PROVIDER_GOOGLE,
  scope: "zkproofport:oidc-signature:real-kms",
  nonceMode: 0,
  now,
  signer: serverSigner(rs),
});
fs.writeFileSync(out, toProverToml(inputs));
fs.writeFileSync(out.replace(/\.toml$/, ".public_inputs.hex"), publicInputs(inputs).map((v) => v.toString(16).padStart(64, "0")).join(""));
console.log(`wrote ${path.basename(out)}: Google kid ${header.kid}, now ${now}, server-kind statement signed by ${KMS_KEY_VERSION}`);
