#!/usr/bin/env node
/**
 * Build a Prover.toml for dojang_playground.
 *
 * Two sources for the issuance transaction:
 *
 *   --tx <hash>        a REAL payAndIssueEAS() transaction on GIWA Sepolia,
 *                      re-serialized and checked to hash to <hash>, so the
 *                      parser is exercised on bytes the chain holds.
 *   --local <variant>  a transaction signed here and never broadcast. The
 *                      circuit does not check inclusion, so a signed-only
 *                      transaction is exactly what a dishonest prover could
 *                      hand it -- which is what the refusal cases need.
 *
 * Local variants:
 *   short-scalar     a faucet call whose r or s has a leading zero byte
 *                    (RLP drops it). Must be ACCEPTED.
 *   wrong-contract   to the GIWA mock attester instead of the faucet
 *   wrong-selector   to the faucet, calling revokeEAS()
 *   extra-calldata   payAndIssueEAS selector followed by 32 more bytes
 *   wrong-chain      EIP-1559 on Base Sepolia
 *   no-chain         legacy without EIP-155 (no chain in the signature)
 *   type-1           EIP-2930 access-list transaction
 *   other-signer     a faucet call signed by a different wallet
 *
 * Other options:
 *   --action               sign an EIP-712 action instead of signal_hash
 *   --tx-length-delta <n>  misstate tx_length by n
 *   --out <path>
 */
const { ethers } = require('../node_modules/ethers');
const fs = require('fs');
const path = require('path');
const { CIRCUITS_ROOT, FAUCET, GIWA_SEPOLIA_CHAIN_ID, loadEnv } = require('./common');

/**
 * The fixture wallet's own issuances, one per transaction shape, made with
 * issue.js on 2026-10-14. Recorded so nobody has to search the chain again.
 */
const RECORDED = {
  legacy: '0xc38c0b2418dfaa3127f70d8d33d72590e074965487905370dfd8394c187dea53',
  eip1559: '0xabeac22b039000e4396f933ea73463823551bec6be30310a7fe40ae1b95f8eb6',
};

const MOCK_ATTESTER = '0x6646d970499BBeD728636823A5A7e551E811b414';
const PAY_AND_ISSUE = '0xb19e5904';
const REVOKE = ethers.id('revokeEAS()').slice(0, 10);
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('dojang_playground')));
const ZERO32 = new Uint8Array(32);
const MAX_TX_LEN = 300;

const args = process.argv.slice(2);
const opt = name => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
};
const WITH_ACTION = args.includes('--action');
const TX_ARG = opt('--tx');
const LOCAL = opt('--local');
const LENGTH_DELTA = Number(opt('--tx-length-delta') || 0);
const OUT = path.resolve(opt('--out') || path.join(CIRCUITS_ROOT, 'dojang-playground/Prover.toml'));

if (!!TX_ARG === !!LOCAL) {
  console.error('Pass exactly one of --tx <hash|legacy|eip1559> or --local <variant>.');
  process.exit(1);
}

function toTomlArray(bytes) {
  const arr = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const rows = [];
  for (let i = 0; i < arr.length; i += 8) rows.push('    ' + arr.slice(i, i + 8).join(', '));
  return '[\n' + rows.join(',\n') + '\n]';
}

/** The exact signed bytes of a transaction the chain holds. */
async function fromChain(env, hash, user) {
  const provider = new ethers.JsonRpcProvider(env.GIWA_SEPOLIA_RPC_URL);
  const t = await provider.getTransaction(hash);
  if (!t) throw new Error('tx not found: ' + hash);
  if (t.from !== user.address) {
    throw new Error(`${hash} was sent by ${t.from}, not the fixture wallet ${user.address}`);
  }
  const receipt = await provider.getTransactionReceipt(hash);
  if (!receipt || receipt.status !== 1) throw new Error(`${hash} did not succeed on chain`);
  const tx = ethers.Transaction.from({
    type: t.type,
    chainId: t.chainId,
    nonce: t.nonce,
    gasLimit: t.gasLimit,
    to: t.to,
    value: t.value,
    data: t.data,
    ...(t.type === 2
      ? { maxPriorityFeePerGas: t.maxPriorityFeePerGas, maxFeePerGas: t.maxFeePerGas, accessList: t.accessList ?? [] }
      : { gasPrice: t.gasPrice }),
    signature: t.signature,
  });
  if (tx.hash !== hash) throw new Error(`re-serialized ${hash} hashes to ${tx.hash}; the bytes are not the chain's`);
  return { raw: tx.serialized, label: `${hash} (type ${t.type}, GIWA Sepolia)` };
}

/** A transaction signed here and never sent. */
function signedLocally(user, variant) {
  const base = {
    type: 2,
    chainId: GIWA_SEPOLIA_CHAIN_ID,
    nonce: 7,
    maxPriorityFeePerGas: 1000n,
    maxFeePerGas: 1000000n,
    gasLimit: 400000n,
    to: FAUCET,
    value: ethers.parseEther('0.001'),
    data: PAY_AND_ISSUE,
    accessList: [],
  };
  let signer = user;
  const legacy = { type: 0, gasPrice: 1000000n };
  const fields = {
    'short-scalar': base,
    'wrong-contract': { ...base, to: MOCK_ATTESTER },
    'wrong-selector': { ...base, data: REVOKE },
    'extra-calldata': { ...base, data: PAY_AND_ISSUE + '11'.repeat(32) },
    'wrong-chain': { ...base, chainId: 84532n },
    'no-chain': { ...base, ...legacy, maxPriorityFeePerGas: undefined, maxFeePerGas: undefined, accessList: undefined, chainId: 0n },
    'type-1': { ...base, type: 1, gasPrice: 1000000n, maxPriorityFeePerGas: undefined, maxFeePerGas: undefined },
    'other-signer': base,
  }[variant];
  if (!fields) throw new Error(`unknown --local variant '${variant}'`);
  if (variant === 'other-signer') signer = ethers.Wallet.createRandom();

  for (let nonce = fields.nonce; ; nonce++) {
    const tx = ethers.Transaction.from({ ...fields, nonce });
    tx.signature = signer.signingKey.sign(tx.unsignedHash);
    const short = tx.signature.r.slice(2, 4) === '00' || tx.signature.s.slice(2, 4) === '00';
    if (variant !== 'short-scalar' || short) {
      return { raw: tx.serialized, label: `signed locally, never sent (${variant}, nonce ${nonce})` };
    }
    if (nonce > fields.nonce + 5000) throw new Error('no short r/s found in 5000 signatures');
  }
}

async function main() {
  const env = loadEnv();
  const user = new ethers.Wallet(env.PRIVATE_KEY);

  const { raw, label } = TX_ARG
    ? await fromChain(env, RECORDED[TX_ARG] || TX_ARG, user)
    : signedLocally(user, LOCAL);
  const rawBytes = ethers.getBytes(raw);
  if (rawBytes.length > MAX_TX_LEN) throw new Error(`raw tx is ${rawBytes.length} bytes; the circuit takes ${MAX_TX_LEN}`);
  const padded = new Uint8Array(MAX_TX_LEN);
  padded.set(rawBytes);

  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('dojang-playground-scope')));
  const userAddress = ethers.getBytes(user.address);
  const secret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  const nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([secret, scope])));

  let signalHash = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('dojang-playground-signal')));
  let domainSeparator = ZERO32;
  let actionHash = ZERO32;
  let digest = ethers.hashMessage(signalHash);
  if (WITH_ACTION) {
    const domain = { name: 'Dojang Playground Demo', version: '1', chainId: Number(GIWA_SEPOLIA_CHAIN_ID), verifyingContract: FAUCET };
    const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
    const message = { member: user.address, nonce: 'dojang-playground-1' };
    domainSeparator = ethers.getBytes(ethers.TypedDataEncoder.hashDomain(domain));
    actionHash = ethers.getBytes(ethers.TypedDataEncoder.hashStruct('Join', types, message));
    signalHash = ZERO32;
    digest = ethers.TypedDataEncoder.hash(domain, types, message);
  }
  const sig = user.signingKey.sign(digest);
  const sigBytes = ethers.getBytes(ethers.concat([sig.r, sig.s]));
  const pub = ethers.getBytes(user.signingKey.publicKey);

  console.log('mode:      ', WITH_ACTION ? 'EIP-712 action' : 'signal hash');
  console.log('wallet:    ', user.address);
  console.log('issuance:  ', label);
  console.log('raw bytes: ', rawBytes.length, LENGTH_DELTA ? `(tx_length misstated by ${LENGTH_DELTA})` : '');

  const toml = `# Generated by scripts/dojang-playground/generate-prover-toml.js
# Issuance: ${label}
# Mode: ${WITH_ACTION ? 'EIP-712 action' : 'signal hash'}

signal_hash = ${toTomlArray(signalHash)}

domain_separator = ${toTomlArray(domainSeparator)}

action_hash = ${toTomlArray(actionHash)}

scope = ${toTomlArray(scope)}

nullifier = ${toTomlArray(nullifier)}

user_address = ${toTomlArray(userAddress)}

user_signature = ${toTomlArray(sigBytes)}

user_pubkey_x = ${toTomlArray(pub.slice(1, 33))}

user_pubkey_y = ${toTomlArray(pub.slice(33, 65))}

tx_length = ${rawBytes.length + LENGTH_DELTA}

raw_transaction = ${toTomlArray(padded)}
`;
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, toml);
  console.log('wrote', path.relative(CIRCUITS_ROOT, OUT));
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
