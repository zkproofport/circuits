#!/usr/bin/env node
/**
 * Fixtures for coinbase_attestation v2's ANDROID package: a REAL Coinbase
 * attestation, and statements signed by a SYNTHETIC Android key attestation
 * device (scripts/statement-signer/android.js).
 *
 *   node generate-prover-toml.js --coinbase <coinbase-attestation Prover.toml> \
 *        --synthetic-dir <synthetic-anchors copy> --real-dir <coinbase-attestation-v2-android>
 *
 * Needs ATTESTED_WALLET_KEY (make-fixtures.sh reads it from
 * proofport-ai/.env.test and never prints it).
 *
 * The Coinbase half and the 225-byte statement are exactly
 * ../coinbase-attestation-v2/generate-prover-toml.js's (one shared circuit
 * library, ../../coinbase-v2-libs). The iOS package's acceptance run walks
 * every statement-content refusal; this one repeats the ones a different
 * signer could plausibly break and adds every Android chain refusal.
 *
 *   --synthetic-dir  the synthetic-anchors copy: Google's root replaced by the
 *                    synthetic root (anchors.js). Writes Prover.toml (EIP-712
 *                    action), Prover.no-action.toml and test-vectors/*.toml.
 *   --real-dir       the real circuit, Google's Key Attestation CA1 pinned.
 *                    Writes test-vectors/real_*.toml: the synthetic chain
 *                    (refused at the root) and a REAL Google chain (tegu,
 *                    Google's test app), which must pass every link and stop
 *                    at the package.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('../node_modules/ethers');
const A = require('../statement-signer/android');
const chainJs = require('../android-key-attestation/chain');

const opt = name => {
  const args = process.argv.slice(2);
  const i = args.indexOf(name);
  if (i === -1 || !args[i + 1]) throw new Error(`${name} is required`);
  return args[i + 1];
};

const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase_attestation')));
const MAGIC = Buffer.from('ZKProofport/AA/1');
const KYC_SCHEMA = ethers.getBytes('0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9');
const COINBASE_ATTESTER = ethers.getBytes('0x357458739F90461b99789350868CD7CF330Dd7EE');
const SCOPE_STRING = 'proofport';
const N_P256 = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const N_P384 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973');
const DAY = 86400;

function parseToml(text) {
  const out = {};
  const re = /^(\w+)\s*=\s*/gm;
  let m;
  while ((m = re.exec(text))) {
    const i = re.lastIndex;
    if (text[i] === '[') {
      let depth = 0;
      let j = i;
      for (; j < text.length; j++) {
        if (text[j] === '[') depth++;
        if (text[j] === ']' && --depth === 0) break;
      }
      out[m[1]] = JSON.parse(text.slice(i, j + 1).replace(/,\s*\]/g, ']'));
      re.lastIndex = j + 1;
    } else {
      out[m[1]] = text.slice(i).split('\n')[0].trim();
    }
  }
  return out;
}
const arr = bytes => {
  const a = Array.from(bytes).map(b => `0x${b.toString(16).padStart(2, '0')}`);
  const rows = [];
  for (let i = 0; i < a.length; i += 16) rows.push('    ' + a.slice(i, i + 16).join(', '));
  return '[\n' + rows.join(',\n') + '\n]';
};
function highS(sig, n, size) {
  const s = BigInt('0x' + sig.subarray(size).toString('hex'));
  return Buffer.concat([sig.subarray(0, size), Buffer.from((n - s).toString(16).padStart(size * 2, '0'), 'hex')]);
}

function main() {
  const COINBASE_TOML = path.resolve(opt('--coinbase'));
  const SYN_DIR = path.resolve(opt('--synthetic-dir'));
  const REAL_DIR = path.resolve(opt('--real-dir'));
  if (!process.env.ATTESTED_WALLET_KEY) throw new Error('ATTESTED_WALLET_KEY is required');
  const wallet = new ethers.Wallet(process.env.ATTESTED_WALLET_KEY);
  const cb = parseToml(fs.readFileSync(COINBASE_TOML, 'utf8'));
  const userAddress = Buffer.from(cb.user_address);
  if (ethers.getAddress(ethers.hexlify(userAddress)) !== wallet.address) {
    throw new Error(`${COINBASE_TOML} is for ${ethers.hexlify(userAddress)}, the key is for ${wallet.address}`);
  }
  const pub = ethers.getBytes(wallet.signingKey.publicKey);
  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(SCOPE_STRING)));
  const secret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  const nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([secret, scope])));
  const ZERO32 = new Uint8Array(32);
  const signalHash = ethers.getBytes(ethers.solidityPackedKeccak256(
    ['address', 'string', 'string'], [wallet.address, SCOPE_STRING, 'coinbase_attestation']));
  const domain = { name: 'ZKProofport Coinbase KYC v2 fixture', version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' };
  const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
  const message = { member: wallet.address, nonce: 'coinbase-attestation-v2-android-1' };
  const requests = {
    action: {
      signal: ZERO32,
      domainSeparator: ethers.getBytes(ethers.TypedDataEncoder.hashDomain(domain)),
      actionHash: ethers.getBytes(ethers.TypedDataEncoder.hashStruct('Join', types, message)),
      digest: ethers.getBytes(ethers.TypedDataEncoder.hash(domain, types, message)),
    },
    noAction: {
      signal: signalHash,
      domainSeparator: ZERO32,
      actionHash: ZERO32,
      digest: ethers.getBytes(ethers.hashMessage(signalHash)),
    },
  };
  for (const r of Object.values(requests)) {
    const sig = wallet.signingKey.sign(r.digest);
    r.userSignature = ethers.getBytes(ethers.concat([sig.r, sig.s]));
  }

  const attestedAt = Math.floor(Date.now() / 1000);
  const easUid = crypto.randomBytes(32);
  function clientData(req, o = {}) {
    const t = Buffer.alloc(8);
    t.writeBigUInt64BE(BigInt(o.timestamp ?? attestedAt));
    const cd = Buffer.concat([
      MAGIC, Buffer.from(CIRCUIT_TAG), Buffer.from(o.wallet ?? userAddress), t,
      Buffer.from(o.schema ?? KYC_SCHEMA), Buffer.from(COINBASE_ATTESTER), easUid,
      Buffer.from([o.revoked ?? 0]), Buffer.from(o.digest ?? req.digest), Buffer.from(o.scope ?? scope),
    ]);
    if (cd.length !== 225) throw new Error(`clientData is ${cd.length} bytes`);
    return cd;
  }

  /** One Prover TOML; `o.dev` are androidDevice options, `o.chainInputs` a ready chain. */
  function toml(req, o = {}) {
    const at = o.attestedAt ?? attestedAt;
    const cd = o.clientData ?? clientData(req, { timestamp: o.statementTime ?? at });
    let chain;
    let sig;
    if (o.chainInputs) {
      chain = { ...o.chainInputs };
      sig = Buffer.alloc(64);
      sig[31] = 1;
      sig[63] = 1;
    } else {
      const dev = A.androidDevice({ now: o.chainTime ?? at, ...(o.dev || {}) });
      chain = { ...dev.inputs };
      sig = o.statementSig ?? A.androidSign(o.signed ?? cd, o.otherSigner ? A.ecKey('prime256v1') : dev.leaf);
      if (o.highS) sig = highS(sig, N_P256, 32);
    }
    if (o.mutateChain) o.mutateChain(chain);
    return `# Generated by scripts/coinbase-attestation-v2-android/generate-prover-toml.js
# Coinbase part: real (from ${path.basename(path.dirname(COINBASE_TOML))}/Prover.toml).
# Statement: SYNTHETIC Android key attestation device (or a real Google chain for real_*).
# Case: ${o.label ?? 'accepted'}

signal_hash = ${arr(req.signal)}
domain_separator = ${arr(req.domainSeparator)}
action_hash = ${arr(req.actionHash)}
signer_list_merkle_root = ${arr(cb.signer_list_merkle_root)}
scope = ${arr(scope)}
nullifier = ${arr(nullifier)}
attested_at = ${at}

user_address = ${arr(userAddress)}
user_signature = ${arr(req.userSignature)}
user_pubkey_x = ${arr(pub.slice(1, 33))}
user_pubkey_y = ${arr(pub.slice(33, 65))}
raw_transaction = ${arr(cb.raw_transaction)}
tx_length = ${cb.tx_length}
coinbase_attester_pubkey_x = ${arr(cb.coinbase_attester_pubkey_x)}
coinbase_attester_pubkey_y = ${arr(cb.coinbase_attester_pubkey_y)}
coinbase_signer_merkle_proof = [
${cb.coinbase_signer_merkle_proof.map(row => arr(row)).join(',\n')}
]
coinbase_signer_leaf_index = ${cb.coinbase_signer_leaf_index}
merkle_proof_depth = ${cb.merkle_proof_depth}

client_data = ${arr(cd)}
statement_sig = ${arr(sig)}

ca2_tbs = ${arr(chain.ca2_tbs)}
ca2_tbs_len = ${chain.ca2_tbs_len}
ca2_sig = ${arr(chain.ca2_sig)}
ca3_tbs = ${arr(chain.ca3_tbs)}
ca3_tbs_len = ${chain.ca3_tbs_len}
ca3_sig = ${arr(chain.ca3_sig)}
att_tbs = ${arr(chain.att_tbs)}
att_tbs_len = ${chain.att_tbs_len}
att_sig = ${arr(chain.att_sig)}
leaf_tbs = ${arr(chain.leaf_tbs)}
leaf_tbs_len = ${chain.leaf_tbs_len}
leaf_sig = ${arr(chain.leaf_sig)}
`;
  }

  const writer = dir => (file, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), text);
    console.log('wrote', path.relative(path.dirname(dir), path.join(dir, file)));
  };
  const syn = writer(SYN_DIR);
  const ACT = requests.action;
  syn('Prover.toml', toml(ACT));
  syn('Prover.no-action.toml', toml(requests.noAction));

  // oidc_domain_attestation's provider-key statement, signed by the same kind of key.
  const oidcNow = Buffer.alloc(8);
  oidcNow.writeBigUInt64BE(BigInt(attestedAt));
  const oidcStatement = Buffer.concat([
    Buffer.from('ZKProofport/PK/1'), ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('oidc_domain_attestation'))),
    Buffer.from([0]), oidcNow, Buffer.concat([Buffer.from([0x80]), crypto.randomBytes(255)]),
  ]);
  const otherWallet = ethers.getBytes(ethers.Wallet.createRandom().address);
  const cases = {
    strongbox: { dev: { level: 2 } },
    client_revoked: { clientData: clientData(ACT, { revoked: 1 }) },
    client_wallet_mismatch: { clientData: clientData(ACT, { wallet: otherWallet }) },
    client_other_request: { clientData: clientData(ACT, { digest: requests.noAction.digest }) },
    client_other_scope: { clientData: clientData(ACT, { scope: ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('another-scope'))) }) },
    timestamp_changed: { statementTime: attestedAt + 1 },
    oidc_statement_replay: { clientData: oidcStatement.subarray(0, 225), signed: oidcStatement },
    stmt_signed_by_other_key: { otherSigner: true },
    stmt_high_s: { highS: true },
    other_package: { dev: { packages: ['com.masselabs.zkproofport.debug'] } },
    debug_signing_certificate: { dev: { digests: [crypto.createHash('sha256').update('debug.keystore').digest()] } },
    bootloader_unlocked: { dev: { lockedByte: 0 } },
    boot_unverified: { dev: { bootState: 2 } },
    software_key: { dev: { level: 0 } },
    imported_key: { dev: { origin: 2 } },
    att_expired_at_attested_at: { dev: { validity: { att: [attestedAt - 15 * DAY, attestedAt - 1] } } },
    other_root: { dev: { root: A.ecKey('secp384r1') } },
    leaf_signed_by_other_key: { dev: { leafSigner: A.ecKey('prime256v1') } },
    ca2_sig_high_s: { mutateChain: c => { c.ca2_sig = highS(c.ca2_sig, N_P384, 48); } },
  };
  for (const [name, o] of Object.entries(cases)) {
    syn(path.join('test-vectors', `${name}.toml`), toml(ACT, { ...o, label: name }));
  }

  // ---- the real circuit (Google's Key Attestation CA1 pinned) -----------------
  const real = writer(REAL_DIR);
  real(path.join('test-vectors', 'real_synthetic_root.toml'), toml(ACT, { label: 'real_synthetic_root' }));
  const pem = fs.readFileSync(path.join(__dirname, '../../android-key-attestation/test-vectors/tegu-sdk36-tee-ec-2026-root.pem'), 'utf8');
  const tegu = chainJs.chainInputs(chainJs.pemChain(pem), chainJs.GOOGLE_KEY_ATTESTATION_CA1);
  real(path.join('test-vectors', 'real_google_chain_other_app.toml'), toml(ACT, {
    label: 'real_google_chain_other_app: Google-signed tegu chain, Google\'s test app',
    chainInputs: tegu,
    attestedAt: 1772323200, // 2026-03-01T00:00:00Z, inside that chain's validity
  }));
  console.log('wallet:      ', wallet.address);
  console.log('attested_at: ', attestedAt);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
}
