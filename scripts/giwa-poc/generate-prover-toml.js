#!/usr/bin/env node
/**
 * Generates Prover.toml for giwa_attestation circuit.
 *
 * Inputs come from circuits/.env.development + the captured attestAccount tx.
 * Single-attester Merkle (depth 0): leaf hash IS the root.
 */
const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

// Parse .env.development
const envPath = path.resolve(__dirname, '../../.env.development');
const env = Object.fromEntries(
  fs.readFileSync(envPath, 'utf8')
    .split('\n')
    .filter(l => l.trim() && !l.startsWith('#') && l.includes('='))
    .map(l => {
      const idx = l.indexOf('=');
      return [l.slice(0, idx).trim(), l.slice(idx + 1).trim()];
    })
);

const DEPLOYER_PK = env.PRIVATE_KEY;
const ATTESTER_PK = env.GIWA_MOCK_UPBIT_ATTESTER_PRIVATE_KEY;
const MOCK_ATTESTER_CONTRACT = env.GIWA_MOCK_ATTESTER_CONTRACT;
const ATTEST_TX_HASH = process.argv[2];

if (!ATTEST_TX_HASH) {
  console.error('Usage: node generate-prover-toml.js <attest_tx_hash>');
  process.exit(1);
}

const RPC = env.GIWA_SEPOLIA_RPC_URL;
const provider = new ethers.JsonRpcProvider(RPC);

function toTomlArray(bytes) {
  const arr = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const chunks = [];
  for (let i = 0; i < arr.length; i += 8) chunks.push('    ' + arr.slice(i, i + 8).join(', '));
  return '[\n' + chunks.join(',\n') + '\n]';
}

function toTomlArray2D(bytes2D) {
  return '[\n' + bytes2D.map(row => '    ' + '[' + Array.from(row).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ') + ']').join(',\n') + '\n]';
}

async function main() {
  const deployer = new ethers.Wallet(DEPLOYER_PK);
  const attester = new ethers.Wallet(ATTESTER_PK);

  // 1) Fetch raw tx
  const txObj = await provider.getTransaction(ATTEST_TX_HASH);
  if (!txObj) throw new Error('tx not found: ' + ATTEST_TX_HASH);

  // Reconstruct raw RLP using ethers Transaction.from
  const tx = ethers.Transaction.from({
    type: 2,
    chainId: txObj.chainId,
    nonce: txObj.nonce,
    maxPriorityFeePerGas: txObj.maxPriorityFeePerGas,
    maxFeePerGas: txObj.maxFeePerGas,
    gasLimit: txObj.gasLimit,
    to: txObj.to,
    value: txObj.value,
    data: txObj.data,
    accessList: txObj.accessList ?? [],
    signature: { r: txObj.signature.r, s: txObj.signature.s, yParity: txObj.signature.yParity },
  });
  const rawTxHex = tx.serialized;
  const rawTxBytes = ethers.getBytes(rawTxHex);
  if (rawTxBytes.length > 300) throw new Error('raw tx > 300 bytes: ' + rawTxBytes.length);
  const rawTxPadded = new Uint8Array(300);
  rawTxPadded.set(rawTxBytes, 0);
  const txLength = rawTxBytes.length;

  // 2) Deployer pubkey (user)
  const userAddress = ethers.getBytes(deployer.address);
  const userPub = ethers.getBytes(deployer.signingKey.publicKey);
  if (userPub[0] !== 0x04) throw new Error('expected uncompressed pubkey');
  const userPubX = userPub.slice(1, 33);
  const userPubY = userPub.slice(33, 65);

  // 3) signal_hash (anti-replay challenge from "dApp")
  const signalHash = ethers.getBytes(
    ethers.keccak256(ethers.toUtf8Bytes('giwa-poc-signal-2026-05-14'))
  );

  // 4) user_signature: deployer signs personal_sign(signal_hash)
  // Circuit uses create_eth_signed_message_hash, which is hashMessage in ethers.
  // signingKey.sign() takes a 32-byte digest; we feed it the EIP-191 prefixed digest.
  const msgDigest = ethers.hashMessage(signalHash);
  const sig = deployer.signingKey.sign(msgDigest);
  const sigBytes = new Uint8Array(64);
  sigBytes.set(ethers.getBytes(sig.r), 0);
  sigBytes.set(ethers.getBytes(sig.s), 32);

  // 5) Attester pubkey
  const attesterPub = ethers.getBytes(attester.signingKey.publicKey);
  const attesterPubX = attesterPub.slice(1, 33);
  const attesterPubY = attesterPub.slice(33, 65);

  // 6) Merkle (single-leaf tree, depth 0)
  const attesterAddrBytes = ethers.getBytes(attester.address);
  const leafHash = ethers.getBytes(ethers.keccak256(attesterAddrBytes));
  const merkleRoot = leafHash;
  const merkleProof = Array.from({ length: 8 }, () => new Uint8Array(32));

  // 7) scope + nullifier
  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('giwa-poc-scope')));
  const userSecret = ethers.getBytes(
    ethers.keccak256(ethers.concat([userAddress, signalHash]))
  );
  const nullifier = ethers.getBytes(
    ethers.keccak256(ethers.concat([userSecret, scope]))
  );

  // Sanity: tx.to must match MOCK_ATTESTER_CONTRACT
  if (txObj.to.toLowerCase() !== MOCK_ATTESTER_CONTRACT.toLowerCase()) {
    throw new Error(`tx.to mismatch: ${txObj.to} != ${MOCK_ATTESTER_CONTRACT}`);
  }

  console.log('=== Summary ===');
  console.log('user_address (deployer):', deployer.address);
  console.log('attester address:', attester.address);
  console.log('mock attester contract:', MOCK_ATTESTER_CONTRACT);
  console.log('raw tx length:', txLength);
  console.log('chainId:', Number(txObj.chainId));
  console.log('merkle root (== leaf at depth 0):', ethers.hexlify(merkleRoot));
  console.log('signal_hash:', ethers.hexlify(signalHash));
  console.log('scope:', ethers.hexlify(scope));
  console.log('nullifier:', ethers.hexlify(nullifier));

  const toml = `# Auto-generated by scripts/giwa-poc/generate-prover-toml.js
# Source attest tx: ${ATTEST_TX_HASH}

# ============ Public Inputs ============

signal_hash = ${toTomlArray(signalHash)}

signer_list_merkle_root = ${toTomlArray(merkleRoot)}

scope = ${toTomlArray(scope)}

nullifier = ${toTomlArray(nullifier)}


# ============ Private Inputs ============

# --- Part 1: User Ownership ---

user_address = ${toTomlArray(userAddress)}

user_signature = ${toTomlArray(sigBytes)}

user_pubkey_x = ${toTomlArray(userPubX)}

user_pubkey_y = ${toTomlArray(userPubY)}


# --- Part 2: GIWA Attest TX ---

tx_length = ${txLength}

raw_transaction = ${toTomlArray(rawTxPadded)}

coinbase_attester_pubkey_x = ${toTomlArray(attesterPubX)}

coinbase_attester_pubkey_y = ${toTomlArray(attesterPubY)}


# --- Part 3: Merkle Proof (single-leaf tree, depth 0) ---

coinbase_signer_merkle_proof = ${toTomlArray2D(merkleProof)}

coinbase_signer_leaf_index = 0
merkle_proof_depth = 0
`;

  const outPath = path.resolve(__dirname, '../../giwa-attestation/Prover.toml');
  fs.writeFileSync(outPath, toml);
  console.log('Wrote', outPath);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
