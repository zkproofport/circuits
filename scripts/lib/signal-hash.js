#!/usr/bin/env node
/**
 * signal_hash for the circuits' fixture generators, by the rule the app, the
 * SDK and the AI server use (proofport-app-sdk packages/core/src/signalHash.ts):
 *
 *   signal_hash = keccak256(abi.encodePacked(string scope, string circuitId, string requestId))
 *
 * No wallet address: signal_hash is public, and an address in its preimage
 * lets anyone recover the prover from the public attestation set. No circuit
 * reads the preimage -- it only checks the wallet's signature over the value --
 * so a fixture must still follow the rule only so that what the circuit is
 * tested with is what the app sends.
 *
 * Validation is the core helper's: scope a non-blank, well-formed string of at
 * most 4096 UTF-8 bytes; requestId 1-128 of [A-Za-z0-9-]; circuitId one with a
 * signal_hash. Anything else throws, naming the value.
 *
 *   node lib/signal-hash.js --check   # every vector in lib/signal-hash-vectors.json
 *
 * lib/signal-hash-vectors.json is a byte-identical copy of the SDK's; the
 * parent repository's scripts/check-signal-hash-vectors.sh compares the copies.
 */
const path = require('path');
const { ethers } = require('../node_modules/ethers');

const CIRCUITS_WITH_SIGNAL_HASH = Object.freeze([
  'coinbase_attestation', 'coinbase_country_attestation', 'giwa_attestation', 'dojang_playground', 'human_passport_score',
]);
const MAX_SCOPE_BYTES = 4096;
const REQUEST_ID = /^[A-Za-z0-9-]{1,128}$/;
/** The request id the fixtures answer. Not a UUID on purpose: any id the rule allows works. */
const FIXTURE_REQUEST_ID = 'circuits-fixture-request-1';

function loneSurrogateAt(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) { i++; continue; }
      return i;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return i;
  }
  return -1;
}

function signalHash({ scope, circuitId, requestId }) {
  if (!CIRCUITS_WITH_SIGNAL_HASH.includes(circuitId)) {
    throw new Error(`No signal_hash for circuit '${circuitId}'. Known: ${CIRCUITS_WITH_SIGNAL_HASH.join(', ')}.`);
  }
  if (typeof scope !== 'string' || scope.trim() === '') throw new Error(`scope must be a non-blank string, got ${JSON.stringify(scope)}.`);
  const at = loneSurrogateAt(scope);
  if (at >= 0) throw new Error(`scope is not valid Unicode text: unpaired surrogate at index ${at}.`);
  if (Buffer.byteLength(scope, 'utf8') > MAX_SCOPE_BYTES) throw new Error(`scope is over ${MAX_SCOPE_BYTES} bytes.`);
  if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) {
    throw new Error(`requestId must be 1-128 of [A-Za-z0-9-], got ${JSON.stringify(requestId)}.`);
  }
  return ethers.getBytes(ethers.solidityPackedKeccak256(['string', 'string', 'string'], [scope, circuitId, requestId]));
}

module.exports = { signalHash, FIXTURE_REQUEST_ID, CIRCUITS_WITH_SIGNAL_HASH };

if (require.main === module) {
  if (!process.argv.includes('--check')) {
    console.error('usage: node lib/signal-hash.js --check');
    process.exit(2);
  }
  const { vectors } = require(path.join(__dirname, 'signal-hash-vectors.json'));
  let bad = 0;
  for (const v of vectors) {
    const got = ethers.hexlify(signalHash(v));
    if (got !== v.signalHash) { bad++; console.error(`MISMATCH ${v.note}: ${got} != ${v.signalHash}`); }
  }
  if (vectors.length === 0) { console.error('no vectors read'); process.exit(1); }
  console.log(`signal-hash vectors: ${vectors.length - bad}/${vectors.length} match`);
  process.exit(bad ? 1 : 0);
}
