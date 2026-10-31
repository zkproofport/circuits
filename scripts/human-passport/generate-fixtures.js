#!/usr/bin/env node
/**
 * Fixtures for human_passport_score, built from a REAL Human Passport scoreV2
 * issuance on Base.
 *
 * Two kinds, because no key we hold belongs to a wallet with a Passport score:
 *
 *   human-passport-real-issuer-check/test-vectors/*.toml
 *       The real request, the real `data` bytes and the real issuer signature,
 *       exactly as the verifyAndAttest transaction carried them. Runs the
 *       issuer half of the circuit (the same library function) against bytes
 *       the chain holds. The issuer's address is recovered here AND compared
 *       with GitcoinVerifier.issuer() on chain before anything is written.
 *
 *   human-passport-score/Prover.toml, human-passport-score/test-vectors/*.toml
 *       The full circuit. The score `data` is the real bytes; the request is
 *       re-signed by an INSECURE TEST ISSUER key for an INSECURE TEST WALLET
 *       (both derived from public strings below), and the issuer list holds
 *       the real Base issuer AND the test issuer, so the Merkle path is a real
 *       two-leaf path. Every refusal case changes ONE thing relative to the
 *       accepted fixture, and the script refuses to write a case that changed
 *       nothing.
 *
 * Usage:
 *   node generate-fixtures.js [<verifyAndAttest tx hash>]
 * Env:
 *   BASE_RPC_URL  Base mainnet RPC (else read from circuits/.env.production).
 */
const { ethers } = require('../node_modules/ethers');
const fs = require('fs');
const path = require('path');

const CIRCUITS_ROOT = path.resolve(__dirname, '../..');
const CIRCUIT_DIR = path.join(CIRCUITS_ROOT, 'human-passport-score');
const VECTORS = path.join(CIRCUIT_DIR, 'test-vectors');
const REAL_DIR = path.join(CIRCUITS_ROOT, 'human-passport-real-issuer-check');
const REAL_VECTORS = path.join(REAL_DIR, 'test-vectors');

/** Must equal MAX_DATA_BYTES in both main.nr files. Read, not restated. */
function maxDataBytes(file) {
  const m = fs.readFileSync(file, 'utf8').match(/global MAX_DATA_BYTES: u32 = (\d+);/);
  if (!m) throw new Error(`MAX_DATA_BYTES not found in ${file}`);
  return Number(m[1]);
}
const MAX_DATA = maxDataBytes(path.join(CIRCUIT_DIR, 'src/main.nr'));
const MAX_DATA_REAL = maxDataBytes(path.join(REAL_DIR, 'src/main.nr'));
if (MAX_DATA !== MAX_DATA_REAL) {
  throw new Error(`MAX_DATA_BYTES differs: circuit ${MAX_DATA}, real-issuer-check ${MAX_DATA_REAL}`);
}

/**
 * Every GitcoinVerifier Human Passport's production issuer (0x804233b9...88ED)
 * signs scoreV2 requests for, in issuer-list order: a person records their
 * score on the chain THEY choose, so a proof must accept each. Read from
 * passportxyz/passport deployments/onchainInfo.json (7603b7bb3f, 2025-09-03;
 * the eas-proxy repository it used to live in is gone) and checked on
 * 2026-10-31: issuer() on each verifier is that key, and every unexpired
 * scoreV2 attestation on each chain recovers it under that verifier's domain
 * (Base 284, Arbitrum 52, OP 47, Linea 8, zkSync Era 7, Scroll 4; Shape has
 * no EAS indexer, three recent issuances checked). Base's 0x16db... is the
 * verifier Passport's docs named; it carried issuances until 2025-08.
 * The testnet entries (OP Sepolia, zkSync Sepolia, Ethereum Sepolia) use
 * another issuer and are not listed.
 *
 * The order fixes the tree; HUMAN_PASSPORT_ISSUER_LEAVES in
 * proofport-app-sdk packages/core/src/circuits.ts holds the same list.
 */
const PRODUCTION_VERIFIERS = [
  { chainId: 8453, name: 'Base', verifier: '0x45fA2E93d79Fc44d44b697A94330031b8ccbF68e', schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912', rpc: null },
  { chainId: 8453, name: 'Base', verifier: '0x16db23c4b99bbC9A6Bf55dF7a787C9AEFD261185', schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912', rpc: null },
  { chainId: 10, name: 'OP Mainnet', verifier: '0x5e3fDCbCEB58104E8547D5810EB2ED0Fb42eADf4', schema: '0xda0257756063c891659fed52fd36ef7557f7b45d66f59645fd3c3b263b747254', rpc: 'https://mainnet.optimism.io' },
  { chainId: 42161, name: 'Arbitrum One', verifier: '0x62E6BE350d7b7116936EeD5DeB7951ed3AAfC3c4', schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912', rpc: 'https://arb1.arbitrum.io/rpc' },
  { chainId: 59144, name: 'Linea', verifier: '0xEd551a95f76E96D60e6fE2bD2D845C3b4A6F8cA8', schema: '0xa15ea01b11913fd412243156b40a8d5102ee9784172f82f9481e4c953fdd516d', rpc: 'https://rpc.linea.build' },
  { chainId: 534352, name: 'Scroll', verifier: '0x0EDEBAEaE920a6BFCFe7115566ceF5120ED2ff4C', schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912', rpc: 'https://rpc.scroll.io' },
  { chainId: 360, name: 'Shape', verifier: '0xB2cE7d0470c55be6212e197FF812B8dAE44EFD86', schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912', rpc: 'https://mainnet.shape.network' },
  { chainId: 324, name: 'zkSync Era', verifier: '0xcC3eab33A77135A09770AcAF7D911E5FEf6622F2', schema: '0xb68405dffc0b727188de5a3af2ecbbc544ab01aef5353409c5006ffff342d143', rpc: 'https://mainnet.era.zksync.io' },
];

/** Base, where the full-circuit suite's source issuance lives. */
const BASE = {
  chainId: 8453,
  verifiers: PRODUCTION_VERIFIERS.filter(v => v.chainId === 8453).map(v => v.verifier),
  scoreV2Schema: '0x1f3dce6501d8aad23563c0cf4f0c32264aed9311cb050056ebf72774f89ba912',
  // The retired `score` schema, used only to show another schema is refused.
  oldScoreSchema: '0x24620f482734b3806102678e4b8bb68baafb1adc1ec29e524bcd69c85f15b915',
};

/**
 * Real issuances the issuer half is checked against, one or more per chain:
 *   Base 0x9ca4...  1,184 data bytes, score 23.3860, via 0x45fA (the
 *                   full-circuit suite re-signs THIS one's data)
 *   Base 0xafba...    544 bytes, 2 stamps, via 0x45fA
 *   Base 0x197a...  5,888 bytes, 35 stamps (the largest on Base), via 0x16db
 *   Base 0x3973...  issued 2026-10-30 via 0x45fA
 *   then the newest unexpired issuance on each other chain, read 2026-10-31.
 * Passing a Base tx hash replaces the first.
 */
const REAL_TXS = [
  { chainId: 8453, tx: '0x9ca4f8e96354b108a30cd348250af1189fdc6f28606610577fd136e2a133a38d' },
  { chainId: 8453, tx: '0xafba233fd08e458ac233e973c55bcfcbab70ddb3aa77ab59b7266a04b294631c' },
  { chainId: 8453, tx: '0x197aa6eb673101ed00c377d2f31b1a7d5f41ce99b6c994e332719694150dbaf0' },
  { chainId: 8453, tx: '0x397380089bca063887cf6a62dd12956655d6ea95ca1fd573e509751f9c250a9f' },
  { chainId: 10, tx: '0x64dc2d85c86bbaf86ac8cbfb401363b6d4097e2496e410b7b86a18c73bf5dd0d' },
  { chainId: 42161, tx: '0x487d38ff07ffa0c3a3a9ffbc6925855c1a04a32cd7618909cdf2fc95ba29200c' },
  { chainId: 59144, tx: '0x72785006d5d6fa6d2db645bc2355937a10fa02264d0a45be4f9c4bc0cb3bb212' },
  { chainId: 534352, tx: '0x85da1716dc01101672a485534974053a91e3c5ce2ebaa7b495a2919cf24c9b82' },
  { chainId: 360, tx: '0x0709dc95bf0038f2b38e4112807fc399f43838dc5d7bdeb1a4a08c488d3ab13a' },
  { chainId: 324, tx: '0xe1e9848d9d1de6331bbb1236da865bfd64b6857d8d95e2da8463460fd0f1f4c3' },
];

/**
 * Root over the real issuer on every production verifier above (8 leaves,
 * depth 3). The same value is HUMAN_PASSPORT_ISSUER_ROOT in
 * proofport-app-sdk packages/core/src/circuits.ts.
 */
const PRODUCTION_ISSUER_ROOT = '0xea6d30773f6870aae6384b8aa91f9eb665c40719e13d98acd9afcbe3d79188c8';

const TEST_ISSUER_KEY = ethers.keccak256(ethers.toUtf8Bytes('zkproofport human_passport_score INSECURE TEST ISSUER'));
const ATTACKER_ISSUER_KEY = ethers.keccak256(ethers.toUtf8Bytes('zkproofport human_passport_score INSECURE ATTACKER ISSUER'));
const TEST_WALLET_KEY = ethers.keccak256(ethers.toUtf8Bytes('zkproofport human_passport_score INSECURE TEST WALLET'));
const OTHER_WALLET_KEY = ethers.keccak256(ethers.toUtf8Bytes('zkproofport human_passport_score INSECURE OTHER WALLET'));

const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('human_passport_score')));
const ZERO32 = new Uint8Array(32);
const DAY = 86400n;

const VERIFIER_ABI = [
  'function verifyAndAttest(((bytes32 schema,(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)[] data)[] multiAttestationRequest,uint256 nonce,uint256 fee) attestationRequest,uint8 v,bytes32 r,bytes32 s) payable returns (bytes32[])',
  'function issuer() view returns (address)',
];

const T = s => ethers.keccak256(ethers.toUtf8Bytes(s));
const enc = ethers.AbiCoder.defaultAbiCoder();
const STAMP_TYPEHASH = T('AttestationRequestData(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)');
const MULTI_TYPEHASH = T('MultiAttestationRequest(bytes32 schema,AttestationRequestData[] data)AttestationRequestData(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)');
const PASSPORT_TYPEHASH = T('PassportAttestationRequest(MultiAttestationRequest[] multiAttestationRequest,uint256 nonce,uint256 fee)AttestationRequestData(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)MultiAttestationRequest(bytes32 schema,AttestationRequestData[] data)');

function passportDomainSeparator(chainId, verifier) {
  return ethers.keccak256(enc.encode(
    ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
    [T('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'), T('GitcoinVerifier'), T('1'), chainId, verifier],
  ));
}

/** Mirrors GitcoinVerifier._hashAttestations for one request with one entry. */
function passportDigest(domain, r) {
  const entry = ethers.keccak256(enc.encode(
    ['bytes32', 'address', 'uint64', 'bool', 'bytes32', 'bytes32', 'uint256'],
    [STAMP_TYPEHASH, r.recipient, r.expirationTime, r.revocable, r.refUID, ethers.keccak256(r.data), r.value],
  ));
  const multi = ethers.keccak256(enc.encode(['bytes32', 'bytes32', 'bytes32'], [MULTI_TYPEHASH, r.schema, ethers.keccak256(entry)]));
  const struct = ethers.keccak256(enc.encode(['bytes32', 'bytes32', 'uint256', 'uint256'], [PASSPORT_TYPEHASH, ethers.keccak256(multi), r.nonce, r.fee]));
  return ethers.keccak256(ethers.concat(['0x1901', domain, struct]));
}

function issuerLeaf(issuer, domain, schema) {
  return ethers.keccak256(ethers.concat([issuer, domain, schema]));
}

/**
 * Positional tree: leaves in list order, padded with bytes32(0) to a power of
 * two, parent = keccak(left ++ right). The README states the same rule; the
 * verifier must build its root the same way.
 */
function merkle(leaves, index) {
  let level = leaves.slice();
  let size = 1;
  while (size < level.length) size *= 2;
  while (level.length < size) level.push(ethers.ZeroHash);
  const proof = [];
  let i = index;
  while (level.length > 1) {
    proof.push(level[i ^ 1]);
    const next = [];
    for (let k = 0; k < level.length; k += 2) next.push(ethers.keccak256(ethers.concat([level[k], level[k + 1]])));
    level = next;
    i >>= 1;
  }
  if (proof.length > 8) throw new Error(`issuer list too deep for the circuit: ${proof.length} > 8`);
  return { root: level[0], proof, depth: proof.length };
}

function readRpcUrl() {
  if (process.env.BASE_RPC_URL) return process.env.BASE_RPC_URL;
  const envFile = path.join(CIRCUITS_ROOT, '.env.production');
  if (fs.existsSync(envFile)) {
    const line = fs.readFileSync(envFile, 'utf8').split('\n').find(l => l.startsWith('BASE_RPC_URL='));
    if (line) return line.slice('BASE_RPC_URL='.length).trim();
  }
  throw new Error('BASE_RPC_URL is not set and circuits/.env.production has none.');
}

// ---------------------------------------------------------------- TOML

const hex = b => `0x${b.toString(16).padStart(2, '0')}`;
function arr(bytesLike) {
  const b = Array.from(ethers.getBytes(bytesLike));
  const rows = [];
  for (let i = 0; i < b.length; i += 16) rows.push('    ' + b.slice(i, i + 16).map(hex).join(', '));
  return '[\n' + rows.join(',\n') + '\n]';
}
function arr2(rows) {
  const padded = rows.slice();
  while (padded.length < 8) padded.push(ethers.ZeroHash);
  return '[\n' + padded.map(r => '    [' + Array.from(ethers.getBytes(r)).map(hex).join(', ') + ']').join(',\n') + '\n]';
}
function padData(data) {
  const b = ethers.getBytes(data);
  if (b.length > MAX_DATA) throw new Error(`score data is ${b.length} bytes; the circuit holds ${MAX_DATA}`);
  const out = new Uint8Array(MAX_DATA);
  out.set(b);
  return out;
}
function sig64(sig) {
  return ethers.concat([sig.r, sig.s]);
}
function pubXY(signingKey) {
  const p = ethers.getBytes(signingKey.publicKey);
  return { x: p.slice(1, 33), y: p.slice(33, 65) };
}

/** The issuer half, shared by both programs. */
function issuerToml(f) {
  return `passport_domain_separator = ${arr(f.domain)}
schema_uid = ${arr(f.req.schema)}
expiration_time = ${f.req.expirationTime}
revocable = ${f.req.revocable}
ref_uid = ${arr(f.req.refUID)}
attestation_value = ${arr(ethers.toBeHex(f.req.value, 32))}
request_nonce = ${arr(ethers.toBeHex(f.req.nonce, 32))}
request_fee = ${arr(ethers.toBeHex(f.req.fee, 32))}
score_data_len = ${f.dataLen ?? ethers.getBytes(f.req.data).length}
score_data = ${arr(padData(f.req.data))}
issuer_signature = ${arr(f.issuerSig)}
issuer_pubkey_x = ${arr(f.issuerPub.x)}
issuer_pubkey_y = ${arr(f.issuerPub.y)}
issuer_merkle_proof = ${arr2(f.tree.proof)}
issuer_leaf_index = ${f.leafIndex}
issuer_merkle_depth = ${f.tree.depth}
`;
}

function fullToml(f, note) {
  return `# Generated by scripts/human-passport/generate-fixtures.js -- ${note}
# Source issuance (real data bytes): ${f.sourceTx}
signal_hash = ${arr(f.signalHash)}
domain_separator = ${arr(f.actionDomain)}
action_hash = ${arr(f.actionHash)}
signer_list_merkle_root = ${arr(f.root ?? f.tree.root)}
scope = ${arr(f.scope)}
nullifier = ${arr(f.nullifier)}
min_score = ${f.minScore}
scorer_id = ${f.scorerId}
now = ${f.now}
user_address = ${arr(f.userAddress)}
user_signature = ${arr(f.userSig)}
user_pubkey_x = ${arr(f.userPub.x)}
user_pubkey_y = ${arr(f.userPub.y)}
${issuerToml(f)}`;
}

function realToml(f, note) {
  return `# Generated by scripts/human-passport/generate-fixtures.js -- ${note}
# Real issuance: ${f.sourceTx}
signer_list_merkle_root = ${arr(f.tree.root)}
min_score = ${f.minScore}
scorer_id = ${f.scorerId}
now = ${f.now}
recipient = ${arr(f.req.recipient)}
${issuerToml(f)}`;
}

// ---------------------------------------------------------------- main

function readHead(data) {
  const b = ethers.getBytes(data);
  const word = i => BigInt(ethers.hexlify(b.slice(i * 32, i * 32 + 32)));
  return { passing: word(0), decimals: word(1), scorerId: word(2), score: word(3), threshold: word(4), stampsOffset: word(5) };
}

function setWord(data, i, value) {
  const b = ethers.getBytes(data).slice();
  b.set(ethers.getBytes(ethers.toBeHex(value, 32)), i * 32);
  return ethers.hexlify(b);
}

async function loadIssuance(providers, { chainId, tx: txHash }) {
  const provider = providers[chainId];
  const iface = new ethers.Interface(VERIFIER_ABI);
  const tx = await provider.getTransaction(txHash);
  if (!tx) throw new Error(`tx not found on chain ${chainId}: ${txHash}`);
  const listed = PRODUCTION_VERIFIERS.find(p => p.chainId === chainId && p.verifier.toLowerCase() === tx.to.toLowerCase());
  if (!listed) throw new Error(`tx.to ${tx.to} is not a listed GitcoinVerifier on chain ${chainId}`);
  const verifier = listed.verifier;
  const parsed = iface.parseTransaction({ data: tx.data, value: tx.value });
  if (parsed.name !== 'verifyAndAttest') throw new Error(`not verifyAndAttest: ${parsed.name}`);
  const [request, v, r, s] = parsed.args;
  if (request.multiAttestationRequest.length !== 1) throw new Error(`expected 1 MultiAttestationRequest, got ${request.multiAttestationRequest.length}`);
  const multi = request.multiAttestationRequest[0];
  if (multi.data.length !== 1) throw new Error(`expected 1 AttestationRequestData, got ${multi.data.length}`);
  if (multi.schema.toLowerCase() !== listed.schema.toLowerCase()) throw new Error(`schema ${multi.schema} is not chain ${chainId}'s scoreV2`);
  const e = multi.data[0];
  const req = {
    schema: multi.schema, recipient: e.recipient, expirationTime: e.expirationTime, revocable: e.revocable,
    refUID: e.refUID, data: e.data, value: e.value, nonce: request.nonce, fee: request.fee,
  };
  const domain = passportDomainSeparator(chainId, verifier);
  const sig = ethers.Signature.from({ r, s, v });
  const pubHex = ethers.SigningKey.recoverPublicKey(passportDigest(domain, req), sig);
  const issuer = ethers.computeAddress(pubHex);
  const onchainIssuer = await new ethers.Contract(verifier, VERIFIER_ABI, provider).issuer();
  if (issuer !== onchainIssuer) throw new Error(`${txHash}: recovered issuer ${issuer} != ${verifier}.issuer() ${onchainIssuer}`);
  const head = readHead(req.data);
  if (head.decimals !== 4n) throw new Error(`${txHash}: data has ${head.decimals} decimals`);
  const pub = ethers.getBytes(pubHex);
  return {
    txHash, chainId, verifier, domain, req, head, issuer,
    issuerSig: sig64(sig), issuerPub: { x: pub.slice(1, 33), y: pub.slice(33, 65) },
    dataLen: ethers.getBytes(req.data).length,
  };
}

async function main() {
  const txs = REAL_TXS.slice();
  if (process.argv[2]) txs[0] = { chainId: 8453, tx: process.argv[2] };
  const providers = {};
  for (const p of PRODUCTION_VERIFIERS) {
    providers[p.chainId] ??= new ethers.JsonRpcProvider(p.rpc ?? readRpcUrl(), p.chainId, { staticNetwork: true });
  }
  const issuances = [];
  for (const h of txs) issuances.push(await loadIssuance(providers, h));
  const first = issuances[0];
  const txHash = first.txHash;
  const realReq = first.req;
  const domain = first.domain;
  const head = first.head;
  const dataLen = first.dataLen;
  const issuedAt = realReq.expirationTime - 90n * DAY;
  if (domain !== passportDomainSeparator(BASE.chainId, BASE.verifiers[0])) {
    throw new Error(`the full-circuit suite expects its source issuance to go through ${BASE.verifiers[0]}`);
  }
  const realIssuer = first.issuer;

  const testIssuer = new ethers.SigningKey(TEST_ISSUER_KEY);
  const attacker = new ethers.SigningKey(ATTACKER_ISSUER_KEY);
  const wallet = new ethers.Wallet(TEST_WALLET_KEY);
  const other = new ethers.Wallet(OTHER_WALLET_KEY);

  // The issuer list: the real issuer on each production verifier, then the test
  // issuer on Base's current verifier. Nine leaves, padded to sixteen: depth 4.
  const leaves = [
    ...PRODUCTION_VERIFIERS.map(p => issuerLeaf(realIssuer, passportDomainSeparator(p.chainId, p.verifier), p.schema)),
    issuerLeaf(ethers.computeAddress(testIssuer.publicKey), domain, BASE.scoreV2Schema),
  ];
  // The production list: the real issuer on each Base verifier, nothing else.
  // Its root is what @zkproofport-app/core pins (HUMAN_PASSPORT_ISSUER_ROOT);
  // the real issuances below prove against it, so a drift between the two
  // fails here instead of on a phone.
  const prodLeaves = leaves.slice(0, PRODUCTION_VERIFIERS.length);
  const prodRoot = merkle(prodLeaves, 0).root;
  if (prodRoot !== PRODUCTION_ISSUER_ROOT) {
    throw new Error(`production issuer root ${prodRoot} != PRODUCTION_ISSUER_ROOT ${PRODUCTION_ISSUER_ROOT}`);
  }
  const testIndex = leaves.length - 1;
  const testTree = merkle(leaves, testIndex);

  for (const i of issuances) {
    console.log(`real issuance ${i.txHash}`);
    console.log(`  chain ${i.chainId} via ${i.verifier}, issuer ${i.issuer} == issuer() on chain`);
    console.log(`  score ${i.head.score} scorer ${i.head.scorerId} threshold ${i.head.threshold}, data ${i.dataLen} bytes (cap ${MAX_DATA}), expires ${i.req.expirationTime}`);
  }
  console.log('issuer list root:', merkle(leaves, 0).root, `(${leaves.length} leaves)`);
  console.log('production issuer root:', prodRoot, `(${prodLeaves.length} leaves; real issuances prove against it)`);

  fs.mkdirSync(VECTORS, { recursive: true });
  fs.mkdirSync(REAL_VECTORS, { recursive: true });

  // ---- real issuer half: each real issuance accepted, and two one-field
  //      derivations of the first refused.
  const realCases = [];
  issuances.forEach((i, n) => {
    const leafIndex = PRODUCTION_VERIFIERS.findIndex(p => p.chainId === i.chainId && p.verifier.toLowerCase() === i.verifier.toLowerCase());
    const real = {
      sourceTx: i.txHash, domain: i.domain, req: i.req, issuerSig: i.issuerSig, issuerPub: i.issuerPub,
      tree: merkle(prodLeaves, leafIndex), leafIndex, minScore: i.head.score, scorerId: i.head.scorerId,
      now: i.req.expirationTime - 90n * DAY + DAY,
    };
    const name = `real_${n}_chain${i.chainId}_${i.dataLen}b`;
    fs.writeFileSync(path.join(REAL_VECTORS, `${name}.toml`), realToml(real, 'real issuance, must be ACCEPTED'));
    realCases.push(`${name}\tACCEPT`);
    if (n === 0) {
      fs.writeFileSync(path.join(REAL_VECTORS, 'real_tampered_score.toml'),
        realToml({ ...real, req: { ...i.req, data: setWord(i.req.data, 3, i.head.score + 1n) } }, 'score word +1, must be REFUSED'));
      realCases.push('real_tampered_score\tInvalid issuer signature');
      fs.writeFileSync(path.join(REAL_VECTORS, 'real_below_threshold.toml'),
        realToml({ ...real, minScore: i.head.score + 1n }, 'min_score = score + 1, must be REFUSED'));
      realCases.push('real_below_threshold\tScore below threshold');
      fs.writeFileSync(path.join(REAL_VECTORS, 'real_other_recipient.toml'),
        realToml({ ...real, req: { ...i.req, recipient: wallet.address } }, 'recipient replaced, must be REFUSED'));
      realCases.push('real_other_recipient\tInvalid issuer signature');
    }
  });
  fs.writeFileSync(path.join(REAL_VECTORS, 'cases.tsv'), realCases.join('\n') + '\n');

  // ---- full circuit, synthetic issuer over the real data
  const scope = ethers.keccak256(ethers.toUtf8Bytes('human-passport-score-fixture-scope'));
  const nullifierOf = addr => ethers.keccak256(ethers.concat([
    ethers.keccak256(ethers.concat([addr, CIRCUIT_TAG])), scope]));

  const action = {
    domain: { name: 'ZKProofport Human Passport Fixture', version: '1', chainId: 8453, verifyingContract: '0x000000000000000000000000000000000000dEaD' },
    types: { ScoreGate: [{ name: 'action', type: 'string' }, { name: 'expiresAt', type: 'uint256' }] },
    primaryType: 'ScoreGate',
    message: { action: 'enter', expiresAt: 4102444800n },
  };
  const signalHash = ethers.keccak256(ethers.toUtf8Bytes('human-passport-score-fixture-signal'));

  function build(o = {}) {
    const userKey = o.userKey ?? wallet;
    const recipient = o.recipient ?? wallet.address;
    const issuerKey = o.issuerKey ?? testIssuer;
    const req = { ...realReq, recipient, ...(o.req || {}) };
    const issuerSig = issuerKey.sign(passportDigest(domain, req));
    const withAction = o.mode !== 'signal';
    let userDigest, actionDomain = ZERO32, actionHash = ZERO32, sh = ZERO32;
    if (withAction) {
      actionDomain = ethers.TypedDataEncoder.hashDomain(action.domain);
      actionHash = ethers.TypedDataEncoder.hashStruct(action.primaryType, action.types, action.message);
      userDigest = ethers.TypedDataEncoder.hash(action.domain, action.types, action.message);
    } else {
      sh = signalHash;
      userDigest = ethers.hashMessage(ethers.getBytes(signalHash));
    }
    const f = {
      sourceTx: txHash, domain, req, issuerSig: sig64(issuerSig), issuerPub: pubXY(issuerKey),
      tree: testTree, leafIndex: testIndex,
      signalHash: sh, actionDomain, actionHash, scope,
      nullifier: nullifierOf(userKey.address),
      minScore: head.score, scorerId: head.scorerId, now: issuedAt + DAY,
      userAddress: userKey.address, userSig: sig64(userKey.signingKey.sign(userDigest)), userPub: pubXY(userKey.signingKey),
    };
    return Object.assign(f, o.after ? o.after(f) : {});
  }

  const base = build();
  const write = (file, f, note) => fs.writeFileSync(file, fullToml(f, note));
  write(path.join(CIRCUIT_DIR, 'Prover.toml'), base, 'action mode, must be ACCEPTED');
  // Not 'Prover.no-action.toml': nargo (beta.19) treats '.no-action' as a file
  // extension and swaps it for '.toml', so --prover-name Prover.no-action
  // silently reads Prover.toml. Every fixture name here is dot-free.
  write(path.join(VECTORS, 'no_action.toml'), build({ mode: 'signal' }), 'signal mode, must be ACCEPTED');

  const baseText = fullToml(base, '');
  const cases = {
    // accepted edges
    accept_min_score_zero: [{ after: () => ({ minScore: 0n }) }],
    accept_just_before_expiry: [{ after: () => ({ now: realReq.expirationTime - 1n }) }],
    accept_lower_threshold: [{ after: () => ({ minScore: head.score - 1n }) }],
    // refusals
    below_threshold: [{ after: () => ({ minScore: head.score + 1n }) }, 'Score below threshold'],
    expired_at_boundary: [{ after: () => ({ now: realReq.expirationTime }) }, 'Attestation expired'],
    expired_later: [{ after: () => ({ now: realReq.expirationTime + DAY }) }, 'Attestation expired'],
    no_expiration: [{ req: { expirationTime: 0n } }, 'Attestation expired'],
    tampered_score: [{ after: f => ({ req: { ...f.req, data: setWord(f.req.data, 3, head.score + 1n) } }) }, 'Invalid issuer signature'],
    tampered_stamp_byte: [{ after: f => { const b = ethers.getBytes(f.req.data).slice(); b[b.length - 1] ^= 1; return { req: { ...f.req, data: ethers.hexlify(b) } }; } }, 'Invalid issuer signature'],
    data_len_plus_one: [{ after: () => ({ dataLen: dataLen + 1 }) }, 'Invalid issuer signature'],
    data_len_over_cap: [{ after: () => ({ dataLen: MAX_DATA + 1 }) }, 'score data longer than the circuit allows'],
    data_len_under_head: [{ after: () => ({ dataLen: 191 }) }, 'score data shorter than its head'],
    tampered_expiration: [{ after: f => ({ req: { ...f.req, expirationTime: f.req.expirationTime + DAY } }) }, 'Invalid issuer signature'],
    wrong_attester_key: [{ issuerKey: attacker }, 'Issuer not in valid list'],
    wrong_signer_root: [{ after: () => ({ root: ethers.keccak256(ethers.toUtf8Bytes('another list')) }) }, 'Issuer not in valid list'],
    wrong_leaf_index: [{ after: () => ({ leafIndex: 0 }) }, 'Issuer not in valid list'],
    other_schema: [{ req: { schema: BASE.oldScoreSchema } }, 'Issuer not in valid list'],
    other_chain_domain: [{ after: f => ({ domain: passportDomainSeparator(10, BASE.verifiers[0]) }) }, 'Invalid issuer signature'],
    wrong_scorer_id: [{ after: () => ({ scorerId: head.scorerId + 1n }) }, 'Scorer id mismatch'],
    other_decimals: [{ req: { data: setWord(realReq.data, 1, 2n) } }, 'score data: decimals is not 4'],
    dirty_score_padding: [{ req: { data: setWord(realReq.data, 3, (1n << 40n) + head.score) } }, 'score data: score has non-zero padding'],
    wrong_wallet: [{ userKey: other }, 'Invalid issuer signature'],
    pubkey_of_other_wallet: [{ after: () => ({ userPub: pubXY(other.signingKey) }) }, 'User pubkey does not match address'],
    signature_from_other_message: [{ after: () => ({ userSig: sig64(wallet.signingKey.sign(ethers.hashMessage('something else'))) }) }, 'Invalid user signature'],
    wrong_nullifier: [{ after: () => ({ nullifier: ethers.keccak256(ethers.toUtf8Bytes('not the nullifier')) }) }, 'Nullifier mismatch'],
    nullifier_other_scope: [{ after: () => ({ scope: ethers.keccak256(ethers.toUtf8Bytes('other scope')) }) }, 'Nullifier mismatch'],
    both_modes: [{ after: () => ({ signalHash }) }, 'signal_hash must be empty in action mode'],
    half_action_no_hash: [{ after: () => ({ actionHash: ZERO32 }) }, 'action mode needs an action hash'],
    half_action_no_domain: [{ after: () => ({ actionDomain: ZERO32 }) }, 'action mode needs a domain separator'],
    nothing_signed: [{ mode: 'signal', after: () => ({ signalHash: ZERO32 }) }, 'signal_hash is required when no action is bound'],
  };

  const manifest = [];
  for (const [name, [opts, reason]] of Object.entries(cases)) {
    const f = build(opts);
    const text = fullToml(f, reason ? `must be REFUSED: ${reason}` : 'must be ACCEPTED');
    if (text.split('\n').slice(1).join('\n') === baseText.split('\n').slice(1).join('\n') && opts.mode !== 'signal') {
      throw new Error(`case ${name} changed nothing relative to the accepted fixture`);
    }
    fs.writeFileSync(path.join(VECTORS, `${name}.toml`), text);
    manifest.push(`${name}\t${reason || 'ACCEPT'}`);
  }
  fs.writeFileSync(path.join(VECTORS, 'cases.tsv'), manifest.join('\n') + '\n');
  console.log(`wrote 2 accepted fixtures, ${manifest.length} full-circuit cases, ${realCases.length} real-issuer cases`);
}

main().catch(err => { console.error(err.stack || err); process.exit(1); });
