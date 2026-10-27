/**
 * Fixtures for the oidc_domain_attestation acceptance run.
 *
 *   npx tsx scripts/make-fixtures.ts          (from oidc-domain-attestation/)
 *
 * Writes test-vectors/<case>.toml (gitignored). Every token is signed by an
 * RSA-2048 key generated on the spot; no real token, key or network is used.
 * The claim sets follow the shapes Google and Microsoft document and one real
 * Google token's claim names and lengths observed on 2026-10-27 (claims named
 * in README.md "Token layout"); every value here is invented.
 *
 * Payloads are written as raw JSON text so a case can control key order,
 * duplicates and escapes exactly.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  buildInputs,
  deriveNonceBinding,
  keccak,
  signJwt,
  toProverToml,
  publicInputs,
  type BuildOptions,
  type CircuitInputs,
} from "./oidc-inputs.ts";

const OUT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "test-vectors");
fs.mkdirSync(OUT, { recursive: true });
for (const f of fs.readdirSync(OUT)) fs.rmSync(path.join(OUT, f), { recursive: true });

const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const modulus = (k: crypto.KeyObject) => (k.export({ format: "jwk" }) as { n: string }).n;
const N = modulus(key.publicKey);

const SCOPE = "proofport:default";
const REQUEST_ID = "8499ba71-c19f-4c96-961a-d7fd4f3dd112";
const BINDING = deriveNonceBinding(SCOPE, REQUEST_ID);
const NONCE = Buffer.from(BINDING).toString("hex");
const OTHER_NONCE = Buffer.from(deriveNonceBinding(SCOPE, "00000000-0000-4000-8000-000000000000")).toString("hex");

const GOOGLE_WEB = "491923400813-5bb3up7dhejns2unvbrt6mku520hrr5g.apps.googleusercontent.com";
const GOOGLE_IOS = "491923400813-ei78mtmkjppvueb577lqai14e4jvbmqk.apps.googleusercontent.com";
const GOOGLE_DEVICE = "491923400813-pr17m6kpin2rsbbes18jpb60j1s3qmv4.apps.googleusercontent.com";
const MS_CLIENT = "8b09c842-d7a8-4d9c-a6ea-46c797412bac";
const MS_TENANT = "b9419818-09af-49c2-b0c3-653adc1f376e";
const MS_CONSUMER = "9188040d-6c67-4c5b-b112-36a304b66dad";

const IAT = 1761555600;
const EXP = IAT + 3600;
const NOW = BigInt(IAT + 60);

type Entry = [string, unknown] | [string, unknown, "raw"];
/** Compact JSON object from ordered entries; "raw" puts the text in verbatim. */
function obj(entries: Entry[]): string {
  return "{" + entries.map(([k, v, raw]) => `${JSON.stringify(k)}:${raw ? v : JSON.stringify(v)}`).join(",") + "}";
}
const set = (entries: Entry[], k: string, v: unknown, raw?: "raw"): Entry[] =>
  entries.map((e) => (e[0] === k ? (raw ? [k, v, raw] : [k, v]) : e)) as Entry[];
const drop = (entries: Entry[], k: string): Entry[] => entries.filter((e) => e[0] !== k);

// Google, in the order Google's own tokens use.
const google = (nonce: string | null, aud = GOOGLE_WEB): Entry[] => {
  const e: Entry[] = [
    ["iss", "https://accounts.google.com"],
    ["azp", GOOGLE_IOS],
    ["aud", aud],
    ["sub", "104857291038475610293"],
    ["hd", "example-corp.com"],
    ["email", "alice.lastname@example-corp.com"],
    ["email_verified", true],
    ["at_hash", "Hk6E_P6Dh8Y93mRNtsDB1Q"],
    ["nonce", nonce],
    ["name", "Alice Middlename Lastname"],
    ["picture", "https://lh3.googleusercontent.com/a/ACg8ocK" + "x".repeat(64) + "=s96-c"],
    ["given_name", "Alice Middlename"],
    ["family_name", "Lastname"],
    ["iat", IAT],
    ["exp", EXP],
  ];
  return nonce === null ? drop(e, "nonce") : e;
};

// Microsoft v2.0, work tenant, in the order of Microsoft's claims reference.
const microsoft = (nonce: string | null, aioLength = 200): Entry[] => {
  const e: Entry[] = [
    ["aud", MS_CLIENT],
    ["iss", `https://login.microsoftonline.com/${MS_TENANT}/v2.0`],
    ["iat", IAT],
    ["nbf", IAT],
    ["exp", EXP],
    ["aio", "A".repeat(aioLength)],
    ["email", "bob@contoso-example.com"],
    ["name", "Bob Example"],
    ["nonce", nonce],
    ["oid", "00000000-0000-0000-66f3-3332eca7ea81"],
    ["preferred_username", "bob@contoso-example.com"],
    ["rh", "1.AWoAo0" + "Q".repeat(72)],
    ["sid", "001c5e3a-0000-4d7b-9a7b-1f43c1f1e0a2"],
    ["sub", "MF4f-ggWMEji12KynJUNQZphaUTvLcQug5jdF2nl01Q"],
    ["tid", MS_TENANT],
    ["uti", "h24pI_afbE-JnGq1CmK8AA"],
    ["ver", "2.0"],
    ["xms_edov", true],
  ];
  return nonce === null ? drop(e, "nonce") : e;
};

// Microsoft personal account: Microsoft's documented example puts ver first
// and aud fourth.
const microsoftConsumer = (nonce: string): Entry[] => [
  ["ver", "2.0"],
  ["iss", `https://login.microsoftonline.com/${MS_CONSUMER}/v2.0`],
  ["sub", "AAAAAAAAAAAAAAAAAAAAAHJFryd6Gydo-XtTd1nhUNQ"],
  ["aud", MS_CLIENT],
  ["exp", EXP],
  ["iat", IAT],
  ["nbf", IAT],
  ["name", "Carol Example"],
  ["preferred_username", "carol@outlook-example.com"],
  ["oid", "00000000-0000-0000-3a33-fceb9b74cc15"],
  ["email", "carol@outlook-example.com"],
  ["tid", MS_CONSUMER],
  ["nonce", nonce],
  ["aio", "D".repeat(150)],
  ["xms_edov", true],
];

const G: Omit<BuildOptions, "nonceMode"> = { provider: 0, scope: SCOPE, now: NOW };
const M: Omit<BuildOptions, "nonceMode"> = { provider: 1, scope: SCOPE, now: NOW };
const BOUND = { nonceMode: 1 as const, nonceBinding: BINDING };
const NONE = { nonceMode: 0 as const };

const written: string[] = [];
function write(name: string, payload: string, opts: BuildOptions, tweak?: (i: CircuitInputs) => void, signer = key.privateKey) {
  const jwt = signJwt(payload, signer, "0123456789abcdef0123456789abcdef01234567");
  const inputs = buildInputs(jwt, N, opts);
  tweak?.(inputs);
  publicInputs(inputs); // layout self-check
  fs.writeFileSync(path.join(OUT, `${name}.toml`), toProverToml(inputs));
  // What bb must write to public_inputs for this case: 214 x 32-byte big-endian.
  const hex = publicInputs(inputs).map((v) => v.toString(16).padStart(64, "0")).join("");
  fs.writeFileSync(path.join(OUT, `${name}.public_inputs.hex`), hex);
  written.push(`${name} (token ${jwt.length} chars, partial_data ${inputs.partial_data.len}, offset ${inputs.base64_decode_offset})`);
}

// ---------------- accepted ----------------
write("google_bound", obj(google(NONCE)), { ...G, ...BOUND });
write("google_iss_bare", obj(set(google(NONCE), "iss", "accounts.google.com")), { ...G, ...BOUND });
write("google_device_no_nonce", obj(google(null, GOOGLE_DEVICE)), { ...G, ...NONE });
write("google_mode0_foreign_nonce", obj(google("0394852-3190485-2490358")), { ...G, ...NONE });
write("google_now_equals_iat", obj(google(NONCE)), { ...G, ...BOUND, now: BigInt(IAT) });
write("google_now_last_second", obj(google(NONCE)), { ...G, ...BOUND, now: BigInt(EXP - 1) });
{
  // Claim order: nonce first, exp before iat, email last (closing brace after it).
  const g = google(NONCE);
  const pick = (k: string) => g.find((e) => e[0] === k)! as Entry;
  const rest = g.filter((e) => !["nonce", "exp", "iat", "email"].includes(e[0]));
  write("google_reordered", obj([pick("nonce"), pick("exp"), pick("iat"), ...rest, pick("email")]), { ...G, ...BOUND });
}
write("microsoft_bound", obj(microsoft(NONCE)), { ...M, ...BOUND });
write("microsoft_consumer_order", obj(microsoftConsumer(NONCE)), { ...M, ...BOUND });
write("microsoft_no_nonce", obj(microsoft(null)), { ...M, ...NONE });
// The largest payload the circuit holds: aio grown until partial_data is near 2048.
{
  let aio = 1200;
  const fits = (n: number) => {
    try {
      buildInputs(signJwt(obj(microsoft(NONCE, n)), key.privateKey, "0123456789abcdef0123456789abcdef01234567"), N, { ...M, ...BOUND });
      return true;
    } catch {
      return false;
    }
  };
  while (!fits(aio)) aio--;
  write("microsoft_large", obj(microsoft(NONCE, aio)), { ...M, ...BOUND });
}

// Recorded limitation, not a guarantee: with the same key twice the honest
// witness uses the first occurrence. See README.md.
write("doc_duplicate_nonce_first_matches", obj([...google(NONCE), ["nonce", OTHER_NONCE]]), { ...G, ...BOUND });

// ---------------- refused ----------------
write("foreign_aud", obj(google(NONCE, "1234987819200.apps.googleusercontent.com")), { ...G, ...BOUND }, (i) => {
  i.aud_hash = keccak(new TextEncoder().encode(GOOGLE_WEB));
});
write("aud_empty", obj(google(NONCE, "")), { ...G, ...BOUND });
write("aud_array", obj(set(google(NONCE), "aud", `["${GOOGLE_WEB}"]`, "raw")), { ...G, ...BOUND });
{
  // aud_hash over the raw escaped bytes, so only the escape check can refuse it.
  const raw = "491923400813-x\\/y.apps.googleusercontent.com";
  write("aud_escaped", obj(set(google(NONCE), "aud", `"${raw}"`, "raw")), { ...G, ...BOUND }, (i) => {
    i.aud_hash = keccak(new TextEncoder().encode(raw));
  });
}
write("google_wrong_iss", obj(set(google(NONCE), "iss", "https://accounts.google.com.evil.example")), { ...G, ...BOUND });
write("google_token_as_microsoft", obj(google(NONCE)), { ...M, ...BOUND });
write("microsoft_v1_iss", obj(set(microsoft(NONCE), "iss", `https://sts.windows.net/${MS_TENANT}/`)), { ...M, ...BOUND });
write("microsoft_iss_uppercase_tenant", obj(set(microsoft(NONCE), "iss", `https://login.microsoftonline.com/${MS_TENANT.toUpperCase()}/v2.0`)), { ...M, ...BOUND });
write("microsoft_token_as_google", obj(microsoft(NONCE)), { ...G, ...BOUND });
write("expired", obj(google(NONCE)), { ...G, ...BOUND, now: BigInt(EXP) });
write("before_iat", obj(google(NONCE)), { ...G, ...BOUND, now: BigInt(IAT - 1) });
write("exp_not_integer", obj(set(google(NONCE), "exp", `${EXP}e0`, "raw")), { ...G, ...BOUND });
write("iat_quoted", obj(set(google(NONCE), "iat", `"${IAT}"`, "raw")), { ...G, ...BOUND });
write("missing_nonce_mode1", obj(google(null)), { ...G, ...BOUND });
write("nonzero_binding_mode0", obj(google(null, GOOGLE_DEVICE)), { ...G, ...NONE }, (i) => {
  i.nonce_binding = Uint8Array.from(BINDING);
});
// Mode 2 with a zero binding: the else-branch's checks pass, so only the
// mode check refuses it.
write("nonce_mode_2", obj(google(NONCE)), { ...G, ...NONE }, (i) => {
  i.nonce_mode = 2;
});
write("nonce_mismatch", obj(google(OTHER_NONCE)), { ...G, ...BOUND });
write("nonce_uppercase", obj(google(NONCE.toUpperCase())), { ...G, ...BOUND });
write("nonce_65_chars", obj(google(NONCE + "0")), { ...G, ...BOUND });
write("nonce_0x_prefixed", obj(google("0x" + NONCE)), { ...G, ...BOUND });
{
  // The right nonce spelled inside another claim's value, ahead of the real
  // (wrong) nonce claim.
  const g = drop(google(OTHER_NONCE), "name");
  write("nonce_inside_value", obj([["name", `x","nonce":"${NONCE}`], ...g]), { ...G, ...BOUND });
}
// The right nonce under a key that merely contains `"nonce"` (escaped quote).
write("nonce_escaped_key", obj([["x\"nonce", NONCE], ...google(OTHER_NONCE)]), { ...G, ...BOUND });
// `"nonce"` as an array element before the real claim: preceded by `,`, not followed by `:`.
write("nonce_as_array_element", obj([["amr", `["pwd","nonce"]`, "raw"], ...google(NONCE)]), { ...G, ...BOUND });
// `"nonce"` as an array element followed by the right nonce as the next element.
write("nonce_array_spoof", obj([["amr", `["x","nonce","${NONCE}","y"]`, "raw"], ...google(OTHER_NONCE)]), { ...G, ...BOUND });
write("duplicate_nonce_first_wrong", obj([...drop(google(NONCE), "nonce"), ["nonce", OTHER_NONCE], ["nonce", NONCE]]), { ...G, ...BOUND });
write("email_not_verified", obj(set(google(NONCE), "email_verified", false)), { ...G, ...BOUND });
write("xms_edov_false", obj(set(microsoft(NONCE), "xms_edov", false)), { ...M, ...BOUND });
// Decoding from a shifted position. +1 is misaligned (bits shifted by 6);
// +4 is aligned but skips the first three payload bytes `{"x`, which a
// leading claim makes harmless -- so only the payload-start check refuses it.
write("decode_offset_plus_1", obj(google(NONCE)), { ...G, ...BOUND }, (i) => {
  i.base64_decode_offset += 1;
});
write("decode_offset_plus_4", obj([["x", 1], ...google(NONCE)]), { ...G, ...BOUND }, (i) => {
  i.base64_decode_offset += 4;
});
write("wrong_nullifier", obj(google(NONCE)), { ...G, ...BOUND }, (i) => {
  i.nullifier = keccak(i.nullifier);
});
write("other_key_signed", obj(google(NONCE)), { ...G, ...BOUND }, undefined, otherKey.privateKey);

console.log(`${written.length} fixtures in ${OUT}`);
for (const w of written) console.log(`  ${w}`);
