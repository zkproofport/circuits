#!/usr/bin/env node
/**
 * Build a Prover.toml for coinbase_eas_storage_poc from Base mainnet.
 *
 *   ATTESTED_WALLET_KEY=0x... node generate-prover-toml.js [options]
 *
 * Needs:
 *   circuits/.env.production   BASE_RPC_URL (must answer eth_getProof for a
 *                              recent block; it need not be an archive node)
 *   ATTESTED_WALLET_KEY        key of a wallet holding a live Coinbase
 *                              Verified Account attestation on Base.
 *                              make-fixtures.sh reads the one the e2e suites
 *                              already use.
 *
 * Options:
 *   --uid <0x..>     the attestation to prove; default: the wallet's newest
 *                    unrevoked one, found through the EAS explorer and then
 *                    read back from the chain
 *   --action         sign an EIP-712 action instead of signal_hash
 *   --block <n>      prove against block n; default: latest - 2
 *   --out <path>
 *
 * Every value the circuit is about to rely on is re-checked here against the
 * chain first -- the uid recomputed from the fields, the stored word read
 * directly -- so a fixture that fails in the circuit fails for a reason in the
 * circuit, not because this script assembled it wrong.
 */
const { ethers } = require('../node_modules/ethers');
const fs = require('fs');
const path = require('path');

const CIRCUITS_ROOT = path.resolve(__dirname, '../..');
const EAS = '0x4200000000000000000000000000000000000021';
const EAS_DB_SLOT = 50n;
const KYC_SCHEMA = '0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9';
const COINBASE_ATTESTER = '0x357458739F90461b99789350868CD7CF330Dd7EE';
const DATA_TRUE = ethers.zeroPadValue('0x01', 32);
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase_eas_storage_poc')));
const EAS_EXPLORER_GRAPHQL = 'https://base.easscan.org/graphql';

// Must match the circuit's globals.
const MAX_NODE_LEN = 532;
const MAX_DEPTH_NO_LEAF = 10;
const MAX_LEAF_LEN = 70;

const ZERO32 = new Uint8Array(32);
const args = process.argv.slice(2);
const opt = name => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
};
const WITH_ACTION = args.includes('--action');
const OUT = path.resolve(opt('--out') || path.join(CIRCUITS_ROOT, 'coinbase-eas-storage-poc/Prover.toml'));

const EAS_ABI = [
  'function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))',
];

function loadEnv() {
  const file = path.join(CIRCUITS_ROOT, '.env.production');
  if (!fs.existsSync(file)) throw new Error(`${file} is required (BASE_RPC_URL)`);
  const env = Object.fromEntries(
    fs.readFileSync(file, 'utf8').split('\n')
      .filter(l => l.trim() && !l.startsWith('#') && l.includes('='))
      .map(l => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]),
  );
  if (!env.BASE_RPC_URL) throw new Error(`BASE_RPC_URL missing from ${file}`);
  return env;
}

function toTomlArray(bytes) {
  const arr = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const rows = [];
  for (let i = 0; i < arr.length; i += 16) rows.push('    ' + arr.slice(i, i + 16).join(', '));
  return '[\n' + rows.join(',\n') + '\n]';
}

function padTo(bytes, len, what) {
  if (bytes.length > len) throw new Error(`${what} is ${bytes.length} bytes; the circuit takes ${len}`);
  const out = new Uint8Array(len);
  out.set(bytes);
  return out;
}

async function newestLiveUid(recipient) {
  const query = `{ attestations(take: 5, orderBy: {time: desc}, where: {schemaId: {equals: "${KYC_SCHEMA}"}, recipient: {equals: "${recipient}"}, revoked: {equals: false}, attester: {equals: "${COINBASE_ATTESTER}"}}) { id } }`;
  const res = await fetch(EAS_EXPLORER_GRAPHQL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) throw new Error(`EAS explorer answered ${res.status}`);
  const list = (await res.json()).data.attestations;
  if (!list.length) throw new Error(`${recipient} holds no unrevoked Coinbase KYC attestation on Base`);
  return list[0].id;
}

function attestationUid(a, bump) {
  return ethers.solidityPackedKeccak256(
    ['bytes32', 'address', 'address', 'uint64', 'uint64', 'bool', 'bytes32', 'bytes', 'uint32'],
    [a.schema, a.recipient, a.attester, a.time, a.expirationTime, a.revocable, a.refUID, a.data, bump],
  );
}

async function main() {
  const env = loadEnv();
  if (!process.env.ATTESTED_WALLET_KEY) throw new Error('ATTESTED_WALLET_KEY is required');
  const user = new ethers.Wallet(process.env.ATTESTED_WALLET_KEY);
  const provider = new ethers.JsonRpcProvider(env.BASE_RPC_URL);
  const network = await provider.getNetwork();
  if (network.chainId !== 8453n) throw new Error(`BASE_RPC_URL is chain ${network.chainId}, not Base (8453)`);

  const uid = opt('--uid') || await newestLiveUid(user.address);
  const eas = new ethers.Contract(EAS, EAS_ABI, provider);
  const a = await eas.getAttestation(uid);

  // Everything the circuit hard-codes, checked before it is asked.
  const expect = (cond, msg) => { if (!cond) throw new Error(`${uid}: ${msg}`); };
  expect(a.uid === uid, 'not found in EAS');
  expect(a.schema === KYC_SCHEMA, `schema is ${a.schema}`);
  expect(a.attester === COINBASE_ATTESTER, `attester is ${a.attester}`);
  expect(a.recipient === user.address, `recipient is ${a.recipient}, not the wallet ${user.address}`);
  expect(a.data === DATA_TRUE, `data is ${a.data}`);
  expect(a.expirationTime === 0n, `expirationTime is ${a.expirationTime}`);
  expect(a.revocationTime === 0n, `revoked at ${a.revocationTime}`);
  let bump = -1;
  for (let b = 0; b < 16; b++) if (attestationUid(a, b) === uid) { bump = b; break; }
  expect(bump >= 0, 'uid does not recompute from its fields for any bump below 16');

  const blockNumber = opt('--block') ? Number(opt('--block')) : (await provider.getBlockNumber()) - 2;
  const block = await provider.getBlock(blockNumber);
  const base = ethers.solidityPackedKeccak256(['bytes32', 'uint256'], [uid, EAS_DB_SLOT]);
  const slot = ethers.toBeHex(BigInt(base) + 2n, 32);
  const stored = await provider.getStorage(EAS, slot, blockNumber);
  expect(BigInt(stored) === a.time, `stored word ${stored} is not time ${a.time}`);

  const proof = await provider.send('eth_getProof', [EAS, [slot], ethers.toQuantity(blockNumber)]);
  const nodes = proof.storageProof[0].proof.map(n => ethers.getBytes(n));
  expect(nodes.length >= 1 && nodes.length - 1 <= MAX_DEPTH_NO_LEAF, `storage proof has ${nodes.length} nodes`);
  const internal = nodes.slice(0, -1);
  const leaf = nodes[nodes.length - 1];
  expect(ethers.keccak256(nodes[0]) === proof.storageHash, 'first node does not hash to the storage root');

  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase-eas-storage-poc-scope')));
  const userAddress = ethers.getBytes(user.address);
  const secret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  const nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([secret, scope])));

  let signalHash = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase-eas-storage-poc-signal')));
  let domainSeparator = ZERO32;
  let actionHash = ZERO32;
  let digest = ethers.hashMessage(signalHash);
  if (WITH_ACTION) {
    const domain = { name: 'Coinbase EAS Storage PoC', version: '1', chainId: 8453, verifyingContract: EAS };
    const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
    const message = { member: user.address, nonce: 'coinbase-eas-storage-poc-1' };
    domainSeparator = ethers.getBytes(ethers.TypedDataEncoder.hashDomain(domain));
    actionHash = ethers.getBytes(ethers.TypedDataEncoder.hashStruct('Join', types, message));
    signalHash = ZERO32;
    digest = ethers.TypedDataEncoder.hash(domain, types, message);
  }
  const sig = user.signingKey.sign(digest);
  const pub = ethers.getBytes(user.signingKey.publicKey);

  const nodeRows = [];
  for (let i = 0; i < MAX_DEPTH_NO_LEAF; i++) {
    nodeRows.push(toTomlArray(i < internal.length ? padTo(internal[i], MAX_NODE_LEN, `node ${i}`) : new Uint8Array(MAX_NODE_LEN)));
  }

  console.log('mode:        ', WITH_ACTION ? 'EIP-712 action' : 'signal hash');
  console.log('wallet:      ', user.address);
  console.log('attestation: ', uid, `(time ${a.time}, bump ${bump})`);
  console.log('block:       ', blockNumber, block.hash);
  console.log('state root:  ', block.stateRoot);
  console.log('EAS storage: ', proof.storageHash);
  console.log('proof:       ', `${internal.length} internal nodes + leaf of ${leaf.length} bytes`);

  const toml = `# Generated by scripts/coinbase-eas-storage-poc/generate-prover-toml.js
# Attestation ${uid}
# Base block ${blockNumber} ${block.hash}
# State root ${block.stateRoot}
# Mode: ${WITH_ACTION ? 'EIP-712 action' : 'signal hash'}

signal_hash = ${toTomlArray(signalHash)}

domain_separator = ${toTomlArray(domainSeparator)}

action_hash = ${toTomlArray(actionHash)}

eas_storage_root = ${toTomlArray(ethers.getBytes(proof.storageHash))}

scope = ${toTomlArray(scope)}

nullifier = ${toTomlArray(nullifier)}

user_address = ${toTomlArray(userAddress)}

user_signature = ${toTomlArray(ethers.getBytes(ethers.concat([sig.r, sig.s])))}

user_pubkey_x = ${toTomlArray(pub.slice(1, 33))}

user_pubkey_y = ${toTomlArray(pub.slice(33, 65))}

attestation_time = ${a.time}

attestation_revocable = ${a.revocable}

attestation_ref_uid = ${toTomlArray(ethers.getBytes(a.refUID))}

attestation_bump = ${bump}

proof_nodes = [
${nodeRows.join(',\n')}
]

proof_leaf = ${toTomlArray(padTo(leaf, MAX_LEAF_LEN, 'leaf'))}

proof_depth = ${nodes.length}
`;
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, toml);
  console.log('wrote', path.relative(CIRCUITS_ROOT, OUT));
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
