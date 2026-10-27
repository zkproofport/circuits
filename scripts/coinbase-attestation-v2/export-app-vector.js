#!/usr/bin/env node
/**
 * Export the vector proofport-app's test holds its Coinbase KYC v2 builder to.
 *
 *   env -u NODE_OPTIONS node scripts/coinbase-attestation-v2/export-app-vector.js <out.json>
 *
 * The app builds clientData and the 2,769-value input vector itself; when a
 * byte differs from what this circuit expects, the proof fails on the phone
 * and names nothing. So the app's test (proofport-app
 * src/appAttest/__tests__/theAppBuildsTheCircuitsOwnVector.test.ts) compares
 * its output with what THIS circuit's own fixture generator produced.
 *
 * How: generate-prover-toml.js runs with a throwaway random wallet and an
 * all-zero Coinbase half (a synthetic coinbase-attestation Prover.toml in a
 * temporary directory), writing into temporary --synthetic-dir / --real-dir
 * directories -- never into the circuit directories. The app-kind Prover.toml
 * (EIP-712 action) and Prover.no-action.toml are read back, together with the
 * compiled ABI of the synthetic-anchors copy (identical to the real circuit's;
 * make-fixtures.sh refuses to build a copy that differs in anything but the
 * two anchor constants), and written as JSON:
 *
 *   { source, scopeString, caKeyHash, eip712: {domain, types, primaryType, messageNonce},
 *     abi: [{name, visibility, fields}], action: {...}, noAction: {...} }
 *
 * Byte arrays become one 0x-hex string, the Merkle proof a list of them,
 * scalars stay strings. Holds no real wallet, transaction or device data.
 *
 * Needs circuits/coinbase-attestation-v2-synthetic-anchors built
 * (scripts/build.sh coinbase-attestation-v2 runs make-fixtures.sh).
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { ethers } = require('../node_modules/ethers');
const anchors = require('./anchors');

const HERE = __dirname;
const CIRCUITS = path.resolve(HERE, '../..');
const SYN_ABI = path.join(CIRCUITS, 'coinbase-attestation-v2-synthetic-anchors/target/coinbase_attestation_v2.json');
const REAL_ABI = path.join(CIRCUITS, 'coinbase-attestation-v2/target/coinbase_attestation_v2.json');

// Must match generate-prover-toml.js.
const SCOPE_STRING = 'proofport';
const EIP712 = {
  domain: { name: 'ZKProofport Coinbase KYC v2 fixture', version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' },
  types: { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] },
  primaryType: 'Join',
  messageNonce: 'coinbase-attestation-v2-1',
};

function fieldCount(t) {
  if (t.kind === 'array') return t.length * fieldCount(t.type);
  if (t.kind === 'struct') return t.fields.reduce((n, f) => n + fieldCount(f.type), 0);
  if (['field', 'integer', 'boolean'].includes(t.kind)) return 1;
  throw new Error(`Unknown ABI kind ${t.kind}`);
}

function abiOf(file) {
  const abi = JSON.parse(fs.readFileSync(file, 'utf8')).abi.parameters;
  return abi.map(p => ({ name: p.name, visibility: p.visibility, fields: fieldCount(p.type) }));
}

/** The generator's TOML: `key = value` with byte arrays, one nested array, scalars. */
function readToml(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/^#.*$/gm, '');
  const out = {};
  const re = /^(\w+)\s*=\s*/gm;
  let m;
  while ((m = re.exec(text))) {
    const start = re.lastIndex;
    if (text[start] === '[') {
      let depth = 0;
      let j = start;
      for (; j < text.length; j++) {
        if (text[j] === '[') depth++;
        if (text[j] === ']' && --depth === 0) break;
      }
      const value = JSON.parse(text.slice(start, j + 1).replace(/0x([0-9a-f]{2})/gi, '"0x$1"').replace(/,\s*\]/g, ']'));
      const hex = bytes => '0x' + bytes.map(b => b.slice(2)).join('');
      out[m[1]] = Array.isArray(value[0]) ? value.map(hex) : hex(value);
      re.lastIndex = j + 1;
    } else {
      out[m[1]] = text.slice(start).split('\n')[0].trim();
    }
  }
  return out;
}

function main() {
  const outFile = process.argv[2];
  if (!outFile) throw new Error('usage: export-app-vector.js <out.json>');
  const synAbi = abiOf(SYN_ABI);
  if (JSON.stringify(synAbi) !== JSON.stringify(abiOf(REAL_ABI))) {
    throw new Error('the synthetic-anchors copy and the real circuit have different ABIs; rebuild (scripts/build.sh coinbase-attestation-v2)');
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbv2-app-vector-'));
  try {
    const wallet = ethers.Wallet.createRandom();
    // Decimal arrays: the format gen-prover-toml.ts writes and the generator parses.
    const zero = n => '[' + new Array(n).fill('0').join(', ') + ']';
    const coinbaseToml = path.join(tmp, 'coinbase', 'Prover.toml');
    fs.mkdirSync(path.dirname(coinbaseToml), { recursive: true });
    fs.writeFileSync(coinbaseToml, [
      `user_address = [${Array.from(ethers.getBytes(wallet.address)).join(', ')}]`,
      `signer_list_merkle_root = ${zero(32)}`,
      `raw_transaction = ${zero(300)}`,
      'tx_length = 1',
      `coinbase_attester_pubkey_x = ${zero(32)}`,
      `coinbase_attester_pubkey_y = ${zero(32)}`,
      `coinbase_signer_merkle_proof = [${new Array(8).fill(zero(32)).join(', ')}]`,
      'coinbase_signer_leaf_index = 0',
      'merkle_proof_depth = 2',
      '',
    ].join('\n'));
    const syn = path.join(tmp, 'synthetic');
    const real = path.join(tmp, 'real');
    fs.mkdirSync(syn);
    fs.mkdirSync(real);
    execFileSync(process.execPath, [path.join(HERE, 'generate-prover-toml.js'),
      '--coinbase', coinbaseToml, '--synthetic-dir', syn, '--real-dir', real],
      { env: { ...process.env, ATTESTED_WALLET_KEY: wallet.privateKey }, stdio: ['ignore', 'ignore', 'inherit'] });

    const commit = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: CIRCUITS, encoding: 'utf8' }).trim();
    const vector = {
      source: `circuits scripts/coinbase-attestation-v2/export-app-vector.js (generate-prover-toml.js) at ${commit}, ` +
        `run ${new Date().toISOString().slice(0, 10)} with a throwaway random wallet and an all-zero Coinbase half. ` +
        'Synthetic App Attest keys under the synthetic intermediate. Holds no real wallet, transaction or device data.',
      scopeString: SCOPE_STRING,
      // SHA256(X || Y) of the synthetic intermediate that signed this
      // vector's credential certificate -- what the app must be told to pin
      // in place of Apple's CA 1 (0x8ef85f95...747f) to accept the vector.
      caKeyHash: '0x' + crypto.createHash('sha256').update(Buffer.concat([anchors.syntheticCa().x, anchors.syntheticCa().y])).digest('hex'),
      eip712: EIP712,
      abi: synAbi,
      action: readToml(path.join(syn, 'Prover.toml')),
      noAction: readToml(path.join(syn, 'Prover.no-action.toml')),
    };
    for (const mode of ['action', 'noAction']) {
      const missing = synAbi.map(p => p.name).filter(n => !(n in vector[mode]));
      if (missing.length) throw new Error(`${mode} TOML lacks ${missing.join(', ')}`);
    }
    fs.writeFileSync(outFile, JSON.stringify(vector, null, 2) + '\n');
    console.log(`wrote ${outFile}: ${synAbi.reduce((n, p) => n + p.fields, 0)} values, ` +
      `${synAbi.filter(p => p.visibility === 'public').reduce((n, p) => n + p.fields, 0)} public`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

try {
  main();
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
}
