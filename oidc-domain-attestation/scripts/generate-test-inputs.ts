/**
 * Test input generator for oidc_domain_attestation circuit.
 *
 * Generates a self-signed JWT (RSA-2048 / RS256), computes partial-SHA
 * circuit inputs, domain, scope, and nullifier, then writes Prover.toml.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { keccak256 as ethersKeccak256 } from "ethers";

// ---------------------------------------------------------------------------
// Constants matching the Noir circuit
// ---------------------------------------------------------------------------
const MAX_PARTIAL_DATA_LENGTH = 640;
const MAX_DOMAIN_LENGTH = 64;

const EMAIL = "testuser@proofport.com";
const DOMAIN = "proofport.com";
const SCOPE_STRING = "openstoa:topic:test";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Split a BigInt into `numChunks` chunks of `chunkSize` bits each. */
function splitBigIntToChunks(
  value: bigint,
  chunkSize: number,
  numChunks: number,
): bigint[] {
  const mask = (1n << BigInt(chunkSize)) - 1n;
  const chunks: bigint[] = [];
  for (let i = 0; i < numChunks; i++) {
    chunks.push((value >> (BigInt(i) * BigInt(chunkSize))) & mask);
  }
  return chunks;
}

/** Convert a base64url string to a Buffer. */
function base64urlToBuffer(b64url: string): Buffer {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64");
}

/** Convert a Buffer to a BigInt (big-endian). */
function bufferToBigInt(buf: Buffer): bigint {
  return BigInt("0x" + buf.toString("hex"));
}

// ---------------------------------------------------------------------------
// Partial SHA-256 (pure JS, matching noir-jwt partial-sha.ts)
// ---------------------------------------------------------------------------

const SHA256_K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(n: number, x: number): number {
  return (x >>> n) | (x << (32 - n));
}

function sha256Block(H: Uint32Array, block: Uint8Array): void {
  const w = new Uint32Array(64);
  let a = H[0],
    b = H[1],
    c = H[2],
    d = H[3];
  let e = H[4],
    f = H[5],
    g = H[6],
    h = H[7];

  for (let i = 0; i < 16; i++) {
    w[i] =
      (block[i * 4] << 24) |
      (block[i * 4 + 1] << 16) |
      (block[i * 4 + 2] << 8) |
      block[i * 4 + 3];
  }
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
    const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  for (let i = 0; i < 64; i++) {
    const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
    const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  H[0] = (H[0] + a) >>> 0;
  H[1] = (H[1] + b) >>> 0;
  H[2] = (H[2] + c) >>> 0;
  H[3] = (H[3] + d) >>> 0;
  H[4] = (H[4] + e) >>> 0;
  H[5] = (H[5] + f) >>> 0;
  H[6] = (H[6] + g) >>> 0;
  H[7] = (H[7] + h) >>> 0;
}

function generatePartialSHA256(
  data: Uint8Array,
  hashUntilIndex: number,
): { partialHash: Uint32Array; remainingData: Uint8Array } {
  const blockSize = 64;
  const blockIndex = Math.floor(hashUntilIndex / blockSize);
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ]);

  for (let i = 0; i < blockIndex; i++) {
    if (i * blockSize >= data.length) {
      throw new Error("Block index out of range.");
    }
    const block = new Uint8Array(blockSize);
    block.set(data.slice(i * blockSize, (i + 1) * blockSize));
    sha256Block(H, block);
  }

  return {
    partialHash: H,
    remainingData: data.slice(blockIndex * blockSize),
  };
}

// ---------------------------------------------------------------------------
// Keccak-256 helper (ethers returns 0x-prefixed hex)
// ---------------------------------------------------------------------------
function keccak256Bytes(data: Uint8Array): Uint8Array {
  const hex = ethersKeccak256(data);
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
}

// ---------------------------------------------------------------------------
// TOML formatting helpers
// ---------------------------------------------------------------------------
function toHexArray(bytes: Uint8Array | number[]): string {
  const arr = Array.from(bytes);
  const lines: string[] = [];
  for (let i = 0; i < arr.length; i += 16) {
    const chunk = arr.slice(i, i + 16);
    lines.push("    " + chunk.map((b) => `0x${b.toString(16).padStart(2, "0")}`).join(", "));
  }
  return "[\n" + lines.join(",\n") + "\n]";
}

function toDecimalArray(values: bigint[]): string {
  return (
    "[\n" +
    values
      .map((v, i) => {
        const comma = i < values.length - 1 ? "," : "";
        return `    "${v.toString()}"${comma}`;
      })
      .join("\n") +
    "\n]"
  );
}

function toU32Array(values: Uint32Array | number[]): string {
  const arr = Array.from(values);
  return (
    "[\n" +
    arr
      .map((v, i) => {
        const comma = i < arr.length - 1 ? "," : "";
        // u32 values — use plain decimal
        return `    ${v >>> 0}${comma}`;
      })
      .join("\n") +
    "\n]"
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log("=== OIDC Domain Attestation — Test Input Generator ===\n");

  // 1. Generate RSA-2048 key pair
  console.log("1. Generating RSA-2048 key pair...");
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
  });
  const pubJwk = await exportJWK(publicKey);
  console.log("   Key pair generated.\n");

  // 2. Create & sign JWT
  console.log("2. Creating self-signed JWT...");
  const jwt = await new SignJWT({
    iss: "https://accounts.google.com",
    email: EMAIL,
    email_verified: true,
    aud: "test-client-id",
    nonce: "test-nonce-123",
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setExpirationTime(9999999999)
    .setIssuedAt(1700000000)
    .sign(privateKey);

  console.log(`   JWT length: ${jwt.length}`);
  console.log(`   JWT: ${jwt.substring(0, 60)}...\n`);

  // 3. Extract components
  const [headerB64, payloadB64, signatureB64url] = jwt.split(".");
  const signedDataString = `${headerB64}.${payloadB64}`;
  const signedData = new TextEncoder().encode(signedDataString);

  // Signature as BigInt
  const signatureBuf = base64urlToBuffer(signatureB64url);
  const signatureBigInt = bufferToBigInt(signatureBuf);

  // Pubkey modulus as BigInt
  const modulusBuf = base64urlToBuffer(pubJwk.n!);
  const modulusBigInt = bufferToBigInt(modulusBuf);
  const redcParam = (1n << (2n * 2048n + 4n)) / modulusBigInt;

  const pubkeyLimbs = splitBigIntToChunks(modulusBigInt, 120, 18);
  const redcLimbs = splitBigIntToChunks(redcParam, 120, 18);
  const sigLimbs = splitBigIntToChunks(signatureBigInt, 120, 18);

  console.log("3. RSA limbs computed (18 × 120-bit).\n");

  // 4. Partial SHA-256
  console.log("4. Computing partial SHA-256...");
  // Decode payload to find "email" key position
  const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
  const emailKeyIndex = payloadJson.indexOf('"email":');
  if (emailKeyIndex === -1) {
    throw new Error("Could not find 'email' key in payload");
  }
  // Convert decoded-payload index → base64 index
  const emailKeyIndexB64 = Math.floor((emailKeyIndex * 4) / 3);
  // sliceStart in the full signed data
  const sliceStart = headerB64.length + 1 + emailKeyIndexB64; // +1 for '.'

  const { partialHash, remainingData } = generatePartialSHA256(
    signedData,
    sliceStart,
  );

  if (remainingData.length > MAX_PARTIAL_DATA_LENGTH) {
    throw new Error(
      `remainingData (${remainingData.length}) exceeds MAX_PARTIAL_DATA_LENGTH (${MAX_PARTIAL_DATA_LENGTH})`,
    );
  }

  // Pad to MAX_PARTIAL_DATA_LENGTH
  const partialDataPadded = new Uint8Array(MAX_PARTIAL_DATA_LENGTH);
  partialDataPadded.set(remainingData);

  // base64_decode_offset: how many bytes to trim from remaining data start
  // to make it a valid base64 boundary
  const shaCutoffIndex = signedData.length - remainingData.length;
  const payloadBytesInShaPrecompute = shaCutoffIndex - (headerB64.length + 1);
  const base64DecodeOffset = (4 - (payloadBytesInShaPrecompute % 4)) % 4;

  console.log(`   Signed data length: ${signedData.length}`);
  console.log(`   SHA cutoff index: ${shaCutoffIndex}`);
  console.log(`   Remaining data length: ${remainingData.length}`);
  console.log(`   base64_decode_offset: ${base64DecodeOffset}`);
  console.log(
    `   partialHash: [${Array.from(partialHash).map((v) => (v >>> 0).toString()).join(", ")}]`,
  );
  console.log();

  // 5. Domain (BoundedVec<u8, 64>)
  console.log("5. Computing domain BoundedVec...");
  const domainBytes = new TextEncoder().encode(DOMAIN);
  const domainStorage = new Uint8Array(MAX_DOMAIN_LENGTH);
  domainStorage.set(domainBytes);
  console.log(`   Domain: "${DOMAIN}" (${domainBytes.length} bytes)\n`);

  // 6. Scope = keccak256(SCOPE_STRING)
  console.log("6. Computing scope...");
  const scopeBytes = keccak256Bytes(new TextEncoder().encode(SCOPE_STRING));
  console.log(
    `   scope = keccak256("${SCOPE_STRING}") = 0x${Buffer.from(scopeBytes).toString("hex").substring(0, 16)}...\n`,
  );

  // 7. Nullifier = keccak256(keccak256(email_bytes) ++ scope)
  //    The circuit computes keccak256 over the *storage* array with *len* as the length.
  //    email BoundedVec has MAX_EMAIL_LENGTH=128, but keccak256(storage, len) uses only `len` bytes.
  console.log("7. Computing nullifier...");
  const emailBytes = new TextEncoder().encode(EMAIL);
  const emailHash = keccak256Bytes(emailBytes);
  const preimage = new Uint8Array(64);
  preimage.set(emailHash, 0);
  preimage.set(scopeBytes, 32);
  const nullifierBytes = keccak256Bytes(preimage);
  console.log(
    `   nullifier = keccak256(keccak256("${EMAIL}") ++ scope) = 0x${Buffer.from(nullifierBytes).toString("hex").substring(0, 16)}...\n`,
  );

  // 8. Write Prover.toml
  console.log("8. Writing Prover.toml...");
  // TOML layout: all top-level fields BEFORE any [table] headers,
  // because TOML treats everything after [table] as belonging to that table.
  const proverToml = `# ===================================================================
# OIDC Domain Attestation Circuit — Test Inputs
# Generated by generate-test-inputs.ts
# ===================================================================

# ============ Public Inputs ============

# RSA public key modulus (18 × 120-bit limbs, decimal strings)
pubkey_modulus_limbs = ${toDecimalArray(pubkeyLimbs)}

# Sybil resistance — scope = keccak256("${SCOPE_STRING}")
scope = ${toHexArray(scopeBytes)}

# Nullifier = keccak256(keccak256(email) ++ scope)
nullifier = ${toHexArray(nullifierBytes)}

# ============ Private Inputs ============

# Intermediate SHA-256 state (8 × u32)
partial_hash = ${toU32Array(partialHash)}

# Full signed-data length (header.payload in bytes)
full_data_length = ${signedData.length}

# Base64 decode offset for partial data
base64_decode_offset = ${base64DecodeOffset}

# RSA redc params (18 × 120-bit limbs)
redc_params_limbs = ${toDecimalArray(redcLimbs)}

# RSA signature (18 × 120-bit limbs)
signature_limbs = ${toDecimalArray(sigLimbs)}

# ============ BoundedVec Tables (must be last) ============

# Domain to prove (BoundedVec<u8, 64>)
[domain]
storage = ${toHexArray(domainStorage)}
len = ${domainBytes.length}

# JWT partial data after SHA precompute (BoundedVec<u8, 640>)
[partial_data]
storage = ${toHexArray(partialDataPadded)}
len = ${remainingData.length}
`;

  const outDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "..",
  );
  const outPath = path.join(outDir, "Prover.toml");
  fs.writeFileSync(outPath, proverToml, "utf-8");
  console.log(`   Written to: ${outPath}`);
  console.log(`   File size: ${fs.statSync(outPath).size} bytes\n`);

  console.log("=== Done ===");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
