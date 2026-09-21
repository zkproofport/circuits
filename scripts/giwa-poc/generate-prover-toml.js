#!/usr/bin/env node
/**
 * Build a Prover.toml for giwa_attestation from a REAL attestation transaction
 * on GIWA Sepolia.
 *
 * Why a real transaction. The circuit parses raw EIP-1559 RLP and recovers the
 * attester's key from the signature inside it. A hand-made transaction would
 * exercise the parser against bytes we invented; these are the bytes the chain
 * actually holds, so a parsing mistake shows up here rather than on a phone.
 *
 * The one thing that cannot come from the chain is the user's signature: the
 * circuit needs the attested wallet to sign, so the fixture uses the wallet
 * whose key is in circuits/.env.development -- which is also the wallet the
 * recorded attestation names.
 *
 * TWO MODES, because the circuit has two:
 *
 *   (default)  no action. The wallet personal_signs signal_hash, and the
 *              EIP-712 pair is zero.
 *   --action   an action. The wallet signs EIP-712 typed data, and signal_hash
 *              is zero.
 *
 * Tamper options exist so the acceptance run can show the circuit REFUSING
 * things, not just accepting one fixture.
 *
 * Usage:
 *   node generate-prover-toml.js <attest_tx_hash> [--action] [--out PATH]
 *        [--tamper both-modes|half-action|empty|bad-signature|wrong-nullifier]
 */
const { ethers } = require('../node_modules/ethers');
const fs = require('fs');
const path = require('path');

const CIRCUITS_ROOT = path.resolve(__dirname, '../..');

const env = Object.fromEntries(
  fs.readFileSync(path.join(CIRCUITS_ROOT, '.env.development'), 'utf8')
    .split('\n')
    .filter(l => l.trim() && !l.startsWith('#') && l.includes('='))
    .map(l => {
      const idx = l.indexOf('=');
      return [l.slice(0, idx).trim(), l.slice(idx + 1).trim()];
    })
);

/**
 * The attestation this repository uses as its fixture, recorded so nobody has
 * to search the chain again. MockGiwaAttester calling attestAccount() for the
 * wallet whose key is in circuits/.env.development, GIWA Sepolia block
 * 25424198. Override with GIWA_ATTEST_TX, or pass another hash as an argument.
 */
const RECORDED_ATTEST_TX =
  '0x961ac707e3805289ba2a8fb7118080cb54a0bf60b7a4ad4f7f3ac42c8c8878f7';

const args = process.argv.slice(2);
const ATTEST_TX_HASH =
  args.find(a => a.startsWith('0x')) || process.env.GIWA_ATTEST_TX || RECORDED_ATTEST_TX;
const WITH_ACTION = args.includes('--action');
const TAMPER = (() => {
  const i = args.indexOf('--tamper');
  return i === -1 ? null : args[i + 1];
})();
const OUT = (() => {
  const i = args.indexOf('--out');
  return i === -1
    ? path.join(CIRCUITS_ROOT, 'giwa-attestation/Prover.toml')
    : path.resolve(args[i + 1]);
})();

/** keccak256("giwa_attestation") -- the constant compiled into the circuit. */
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('giwa_attestation')));

const ZERO32 = new Uint8Array(32);

function toTomlArray(bytes) {
  const arr = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const chunks = [];
  for (let i = 0; i < arr.length; i += 8) chunks.push('    ' + arr.slice(i, i + 8).join(', '));
  return '[\n' + chunks.join(',\n') + '\n]';
}

function toTomlArray2D(rows) {
  return '[\n' + rows.map(r =>
    '    [' + Array.from(r).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ') + ']'
  ).join(',\n') + '\n]';
}

async function main() {
  const user = new ethers.Wallet(env.PRIVATE_KEY);
  const attester = new ethers.Wallet(env.GIWA_MOCK_UPBIT_ATTESTER_PRIVATE_KEY);
  const provider = new ethers.JsonRpcProvider(env.GIWA_SEPOLIA_RPC_URL);

  // 1) The attestation transaction, re-serialized to the exact bytes the
  //    chain holds. ethers rebuilds the RLP from the fields plus signature.
  const txObj = await provider.getTransaction(ATTEST_TX_HASH);
  if (!txObj) throw new Error('tx not found: ' + ATTEST_TX_HASH);
  if (txObj.to.toLowerCase() !== env.GIWA_MOCK_ATTESTER_CONTRACT.toLowerCase()) {
    throw new Error(`tx.to ${txObj.to} is not the mock attester ${env.GIWA_MOCK_ATTESTER_CONTRACT}`);
  }
  const attestedAddress = ethers.getAddress('0x' + txObj.data.slice(34));
  if (attestedAddress !== user.address) {
    throw new Error(
      `this attestation is for ${attestedAddress}, but the key in .env.development is ${user.address}. ` +
      'The circuit needs the ATTESTED wallet to sign, so pick a tx that attests this wallet ' +
      '(or run attest-account.js to create one).'
    );
  }

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
  const rawTxBytes = ethers.getBytes(tx.serialized);
  if (rawTxBytes.length > 300) throw new Error('raw tx > 300 bytes: ' + rawTxBytes.length);
  const rawTxPadded = new Uint8Array(300);
  rawTxPadded.set(rawTxBytes, 0);

  // 2) The scope, and the nullifier the circuit will recompute.
  //    keccak(keccak(address ++ CIRCUIT_TAG) ++ scope) -- no signal_hash in it,
  //    so the value is the same in both modes and nothing the prover picks can
  //    move it.
  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('giwa-poc-scope')));
  const userAddress = ethers.getBytes(user.address);
  const userSecret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  let nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([userSecret, scope])));

  // 3) What the wallet signs, per mode.
  const action = {
    domain: {
      name: 'GIWA Attestation Demo',
      version: '1',
      chainId: Number(env.GIWA_SEPOLIA_CHAIN_ID),
      // A fixture has no gate contract yet. A real request names the contract
      // that will recompute these hashes and check them.
      verifyingContract: env.GIWA_MOCK_ATTESTER_CONTRACT,
    },
    types: {
      CredentialDelegation: [
        { name: 'delegate', type: 'address' },
        { name: 'action', type: 'string' },
        { name: 'amount', type: 'uint256' },
        { name: 'expiresAt', type: 'uint256' },
        { name: 'nonce', type: 'string' },
      ],
    },
    primaryType: 'CredentialDelegation',
    message: {
      delegate: user.address,
      action: 'stake',
      amount: 1000000n,
      expiresAt: 4102444800n, // 2100-01-01, so a committed fixture does not expire
      nonce: 'giwa-poc-1',
    },
  };

  let signalHash = ethers.getBytes(
    ethers.keccak256(ethers.toUtf8Bytes('giwa-poc-signal-2026-05-14'))
  );
  let domainSeparator = ZERO32;
  let actionHash = ZERO32;
  let digest;

  if (WITH_ACTION) {
    domainSeparator = ethers.getBytes(ethers.TypedDataEncoder.hashDomain(action.domain));
    actionHash = ethers.getBytes(
      ethers.TypedDataEncoder.hashStruct(action.primaryType, action.types, action.message)
    );
    signalHash = ZERO32;
    // The typed-data digest is signed as-is: no EIP-191 prefix.
    digest = ethers.TypedDataEncoder.hash(action.domain, action.types, action.message);
  } else {
    // personal_sign wraps its argument in the EIP-191 prefix, which is what
    // create_eth_signed_message_hash does inside the circuit.
    digest = ethers.hashMessage(signalHash);
  }

  // 4) Tampering, for the cases the circuit must REFUSE.
  if (TAMPER === 'both-modes') {
    // An action AND a signal hash: the ambiguity the circuit rejects.
    signalHash = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('giwa-poc-signal-2026-05-14')));
  } else if (TAMPER === 'half-action') {
    domainSeparator = ethers.getBytes(ethers.TypedDataEncoder.hashDomain(action.domain));
    actionHash = ZERO32;
    signalHash = ZERO32;
  } else if (TAMPER === 'empty') {
    signalHash = ZERO32;
    domainSeparator = ZERO32;
    actionHash = ZERO32;
  } else if (TAMPER === 'wrong-nullifier') {
    nullifier = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('not the nullifier')));
  }

  let sig = user.signingKey.sign(digest);
  if (TAMPER === 'bad-signature') {
    // A well-formed signature over a different message: the shape that must
    // not pass, and the one a length check would never catch.
    sig = user.signingKey.sign(ethers.keccak256(ethers.toUtf8Bytes('some other message')));
  }
  const sigBytes = new Uint8Array(64);
  sigBytes.set(ethers.getBytes(sig.r), 0);
  sigBytes.set(ethers.getBytes(sig.s), 32);

  const userPub = ethers.getBytes(user.signingKey.publicKey);
  if (userPub[0] !== 0x04) throw new Error('expected an uncompressed pubkey');
  const attesterPub = ethers.getBytes(attester.signingKey.publicKey);

  // 5) The signer list. One attester, so the tree is one leaf deep and the
  //    leaf hash IS the root.
  const leafHash = ethers.getBytes(ethers.keccak256(ethers.getBytes(attester.address)));
  const merkleProof = Array.from({ length: 8 }, () => new Uint8Array(32));

  console.log('mode:                ', WITH_ACTION ? 'EIP-712 action' : 'signal hash (no action)');
  if (TAMPER) console.log('tampered with:       ', TAMPER);
  console.log('attested wallet:     ', user.address);
  console.log('attester:            ', attester.address);
  console.log('attestation tx:      ', ATTEST_TX_HASH);
  console.log('raw tx bytes:        ', rawTxBytes.length);
  console.log('scope:               ', ethers.hexlify(scope));
  console.log('nullifier:           ', ethers.hexlify(nullifier));
  console.log('signed digest:       ', digest);

  const toml = `# Auto-generated by scripts/giwa-poc/generate-prover-toml.js
# Attestation tx: ${ATTEST_TX_HASH} (GIWA Sepolia)
# Mode: ${WITH_ACTION ? 'EIP-712 action' : 'signal hash, no action'}${TAMPER ? `\n# Tampered: ${TAMPER} -- this fixture is meant to FAIL` : ''}

# ============ Public Inputs ============

signal_hash = ${toTomlArray(signalHash)}

domain_separator = ${toTomlArray(domainSeparator)}

action_hash = ${toTomlArray(actionHash)}

signer_list_merkle_root = ${toTomlArray(leafHash)}

scope = ${toTomlArray(scope)}

nullifier = ${toTomlArray(nullifier)}


# ============ Private Inputs ============

user_address = ${toTomlArray(userAddress)}

user_signature = ${toTomlArray(sigBytes)}

user_pubkey_x = ${toTomlArray(userPub.slice(1, 33))}

user_pubkey_y = ${toTomlArray(userPub.slice(33, 65))}

tx_length = ${rawTxBytes.length}

raw_transaction = ${toTomlArray(rawTxPadded)}

coinbase_attester_pubkey_x = ${toTomlArray(attesterPub.slice(1, 33))}

coinbase_attester_pubkey_y = ${toTomlArray(attesterPub.slice(33, 65))}

coinbase_signer_merkle_proof = ${toTomlArray2D(merkleProof)}

coinbase_signer_leaf_index = 0
merkle_proof_depth = 0
`;

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, toml);
  console.log('wrote', OUT);
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
