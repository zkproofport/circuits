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
 *   --signer rkp|factory  coinbase-attestation-v2-android (Remote Key
 *                    Provisioning chain) or coinbase-attestation-v2-android-factory
 *                    (factory chain under Google's RSA root + Play Integrity verdict).
 *   --real-dir       the real circuit, Google's anchors pinned.
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
const anchors = require('../statement-signer/anchors');
const chainJs = require('../android-key-attestation/chain');

const opt = name => {
  const args = process.argv.slice(2);
  const i = args.indexOf(name);
  if (i === -1 || !args[i + 1]) throw new Error(`${name} is required`);
  return args[i + 1];
};

const MAGIC = Buffer.from('ZKProofport/AA/1');
const KYC_SCHEMA = ethers.getBytes('0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9');
const COUNTRY_SCHEMA = ethers.getBytes('0x1801901fabd0e6189356b4fb52bb0ab855276d84f7ec140839fbd1f6801ca065');
const tagOf = id => ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(id)));
// --circuit coinbase_attestation (default) | coinbase_country_attestation:
// the same Android signers for the Country v2 packages (227-byte statement with
// the attestation's country, the country list; --kyc-coinbase for the KYC
// statement replay). An unknown id is an error, never the KYC row.
const PROFILES = {
  coinbase_attestation: { schema: KYC_SCHEMA, clientDataLen: 225, country: false, label: 'Coinbase KYC v2' },
  coinbase_country_attestation: { schema: COUNTRY_SCHEMA, clientDataLen: 227, country: true, label: 'Coinbase Country v2' },
};
const flagOr = (name, fallback) => {
  const args = process.argv.slice(2);
  const i = args.indexOf(name);
  return i === -1 ? fallback : args[i + 1];
};
const CIRCUIT_ID = flagOr('--circuit', 'coinbase_attestation');
if (!Object.prototype.hasOwnProperty.call(PROFILES, CIRCUIT_ID)) {
  throw new Error(`Unknown --circuit ${CIRCUIT_ID}. Known: ${Object.keys(PROFILES).join(', ')}.`);
}
const PROFILE = PROFILES[CIRCUIT_ID];
const CIRCUIT_TAG = tagOf(CIRCUIT_ID);
function txCountry(cb) {
  const raw = ethers.hexlify(Uint8Array.from(cb.raw_transaction.slice(0, Number(cb.tx_length))));
  return Buffer.from(ethers.getBytes(ethers.Transaction.from(raw).data).subarray(14, 16));
}
const countryRows = list => {
  const rows = list.map(c => (typeof c === 'string' ? Array.from(Buffer.from(c, 'ascii')) : Array.from(c)));
  while (rows.length < 10) rows.push([0, 0]);
  return rows;
};
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
  const SIGNER = opt('--signer');
  if (!['rkp', 'factory'].includes(SIGNER)) throw new Error(`Unknown --signer ${SIGNER}. Known: rkp, factory.`);
  const syntheticRsa = chainJs.rsa4096Params(anchors.syntheticAndroidRsaRoot().modulusHex);
  const realRsa = chainJs.rsa4096Params(chainJs.GOOGLE_RSA_ROOT_MODULUS_HEX);
  const testPlay = anchors.testPlayKey();
  const decArr = v => '[' + v.map(x => `"${x.toString()}"`).join(', ') + ']';
  if (!process.env.ATTESTED_WALLET_KEY) throw new Error('ATTESTED_WALLET_KEY is required');
  const wallet = new ethers.Wallet(process.env.ATTESTED_WALLET_KEY);
  const cb = parseToml(fs.readFileSync(COINBASE_TOML, 'utf8'));
  const userAddress = Buffer.from(cb.user_address);
  if (ethers.getAddress(ethers.hexlify(userAddress)) !== wallet.address) {
    throw new Error(`${COINBASE_TOML} is for ${ethers.hexlify(userAddress)}, the key is for ${wallet.address}`);
  }
  const country = PROFILE.country ? txCountry(cb) : null;
  if (PROFILE.country && !/^[A-Z]{2}$/.test(country.toString('ascii'))) throw new Error(`the transaction attests '${country.toString('hex')}'`);
  const otherCountry = PROFILE.country ? (country.toString('ascii') === 'US' ? 'JP' : 'US') : null;
  const LIST = PROFILE.country ? { list: [otherCountry, country.toString('ascii')], length: 2, included: true } : null;
  const pub = ethers.getBytes(wallet.signingKey.publicKey);
  const scope = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(SCOPE_STRING)));
  const secret = ethers.getBytes(ethers.keccak256(ethers.concat([userAddress, CIRCUIT_TAG])));
  const nullifier = ethers.getBytes(ethers.keccak256(ethers.concat([secret, scope])));
  const ZERO32 = new Uint8Array(32);
  const signalHash = ethers.getBytes(ethers.solidityPackedKeccak256(
    ['address', 'string', 'string'], [wallet.address, SCOPE_STRING, CIRCUIT_ID]));
  const domain = { name: `ZKProofport ${PROFILE.label} fixture`, version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' };
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
      MAGIC, Buffer.from(o.tag ?? CIRCUIT_TAG), Buffer.from(o.wallet ?? userAddress), t,
      Buffer.from(o.schema ?? PROFILE.schema), Buffer.from(COINBASE_ATTESTER), easUid,
      Buffer.from([o.revoked ?? 0]), Buffer.from(o.digest ?? req.digest), Buffer.from(o.scope ?? scope),
      ...(PROFILE.country ? [Buffer.from(o.country ?? country)] : []),
    ]);
    if (cd.length !== PROFILE.clientDataLen) throw new Error(`clientData is ${cd.length} bytes`);
    return cd;
  }

  /** One Prover TOML; `o.dev` are androidDevice options, `o.chainInputs` a ready chain. */
  function toml(req, o = {}) {
    const list = o.list ?? LIST;
    const countryToml = list
      ? `country_list = [\n${countryRows(list.list).map(r => '  ' + JSON.stringify(r).replace(/,/g, ', ')).join(',\n')},\n]
country_list_length = ${list.length}
is_included = ${list.included}
`
      : '';
    const at = o.attestedAt ?? attestedAt;
    const cd = o.clientData ?? clientData(req, { timestamp: o.statementTime ?? at });
    let chain;
    let sig;
    if (o.chainInputs) {
      chain = { ...o.chainInputs };
      sig = o.statementSig ?? Buffer.alloc(64);
      if (!o.statementSig) {
        sig[31] = 1;
        sig[63] = 1;
      }
    } else {
      const dev = SIGNER === 'rkp'
        ? A.androidDevice({ now: o.chainTime ?? at, ...(o.dev || {}) })
        : A.factoryDevice(o.dev || {});
      chain = { ...dev.inputs };
      sig = o.statementSig ?? A.androidSign(o.signed ?? cd, o.otherSigner ? A.ecKey('prime256v1') : dev.leaf);
      if (o.highS) sig = highS(sig, N_P256, 32);
    }
    if (o.mutateChain) o.mutateChain(chain);
    let signerToml;
    if (SIGNER === 'rkp') {
      signerToml = `ca2_tbs = ${arr(chain.ca2_tbs)}
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
leaf_sig = ${arr(chain.leaf_sig)}`;
    } else {
      const nonce = o.verdictNonce ?? A.playIntegrityNonce(o.signed ?? cd, sig);
      const t = o.integrity ?? A.playToken(nonce, o.verdictKey ?? testPlay, o.verdict || {});
      const rsa = o.rsa ?? syntheticRsa;
      const playKey = o.playKey ?? Buffer.concat([testPlay.x, testPlay.y]);
      signerToml = `ik_tbs = ${arr(chain.ik_tbs)}
ik_tbs_len = ${chain.ik_tbs_len}
ik_sig = ${decArr(chain.ik_sig)}
batch_tbs = ${arr(chain.batch_tbs)}
batch_tbs_len = ${chain.batch_tbs_len}
batch_sig = ${arr(chain.batch_sig)}
leaf_tbs = ${arr(chain.leaf_tbs)}
leaf_tbs_len = ${chain.leaf_tbs_len}
leaf_sig = ${arr(chain.leaf_sig)}
integrity_payload_b64 = ${arr(t.payload_b64)}
integrity_payload_b64_len = ${t.payload_b64_len}
integrity_signature = ${arr(t.signature)}
rsa_root_modulus = ${decArr(rsa.modulus)}
rsa_root_redc = ${decArr(rsa.redc)}
play_integrity_key = ${arr(playKey)}`;
    }
    return `# Generated by scripts/coinbase-attestation-v2-android/generate-prover-toml.js
# Coinbase part: real (from ${path.basename(path.dirname(COINBASE_TOML))}/Prover.toml).
# Circuit: ${CIRCUIT_ID} (${PROFILE.label}).
# Statement: SYNTHETIC Android key attestation device (or a real Google chain for real_*).
# Case: ${o.label ?? 'accepted'}

signal_hash = ${arr(req.signal)}
domain_separator = ${arr(req.domainSeparator)}
action_hash = ${arr(req.actionHash)}
signer_list_merkle_root = ${arr(cb.signer_list_merkle_root)}
${countryToml}scope = ${arr(scope)}
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

${signerToml}
`;
  }

  const writer = dir => (file, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), text);
    console.log('wrote', path.relative(path.dirname(dir), path.join(dir, file)));
  };
  const syn = writer(SYN_DIR);
  const ACT = requests.action;

  // ---- a REAL phone (factory signer only) ----------------------------------
  // --device-statement <dir>: write the statement for the phone to sign
  //   (statement.bin, attested_at.txt), then stop. The phone signs it with
  //   proofport-app scripts/capture-android-attestation.sh <serial> <dir>/statement.bin <dir>.
  // --device-capture <dir>: with the capture there, write real_device.toml
  //   (Play-installed build: must be accepted and proved) or
  //   real_device_debug_build.toml (refused at the signing certificate) into
  //   the REAL circuit's test-vectors, besides the other cases.
  const argv = process.argv.slice(2);
  const flag = name => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined);
  const deviceStatementDir = flag('--device-statement');
  if (deviceStatementDir) {
    if (SIGNER !== 'factory') throw new Error('--device-statement is for --signer factory');
    fs.mkdirSync(deviceStatementDir, { recursive: true });
    fs.writeFileSync(path.join(deviceStatementDir, 'statement.bin'), clientData(ACT));
    fs.writeFileSync(path.join(deviceStatementDir, 'attested_at.txt'), String(attestedAt));
    console.log(`device statement for attested_at=${attestedAt} written to ${deviceStatementDir}`);
    return;
  }
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
    oidc_statement_replay: { clientData: oidcStatement.subarray(0, PROFILE.clientDataLen), signed: oidcStatement },
    stmt_signed_by_other_key: { otherSigner: true },
    stmt_high_s: { highS: true },
    other_package: { dev: { packages: ['com.masselabs.zkproofport.debug'] } },
    debug_signing_certificate: { dev: { digests: [crypto.createHash('sha256').update('debug.keystore').digest()] } },
    bootloader_unlocked: { dev: { lockedByte: 0 } },
    boot_unverified: { dev: { bootState: 2 } },
    software_key: { dev: { level: 0 } },
    imported_key: { dev: { origin: 2 } },
  };
  if (SIGNER === 'rkp') {
    Object.assign(cases, {
      att_expired_at_attested_at: { dev: { validity: { att: [attestedAt - 15 * DAY, attestedAt - 1] } } },
      other_root: { dev: { root: A.ecKey('secp384r1') } },
      leaf_signed_by_other_key: { dev: { leafSigner: A.ecKey('prime256v1') } },
      ca2_sig_high_s: { mutateChain: c => { c.ca2_sig = highS(c.ca2_sig, N_P384, 48); } },
    });
  } else {
    Object.assign(cases, {
      leaf_signed_by_other_key: { dev: { leafSigner: A.ecKey('prime256v1') } },
      batch_signed_by_other_key: { dev: { batchSigner: A.ecKey('secp384r1') } },
      other_rsa_root_inputs: { rsa: realRsa },
      other_play_key_input: { playKey: Buffer.concat([A.ecKey('prime256v1').x, A.ecKey('prime256v1').y]) },
      verdict_basic_only: { verdict: { verdicts: ['MEETS_BASIC_INTEGRITY'] } },
      verdict_unrecognized: { verdict: { recognition: 'UNRECOGNIZED_VERSION' } },
      verdict_for_other_statement: { verdictNonce: crypto.randomBytes(32) },
      verdict_signed_by_other_key: { verdictKey: A.ecKey('prime256v1') },
    });
  }
  if (PROFILE.country) {
    const kycTomlPath = flagOr('--kyc-coinbase', null);
    if (!kycTomlPath) throw new Error('--kyc-coinbase <coinbase-attestation Prover.toml> is required for coinbase_country_attestation');
    const kyc = parseToml(fs.readFileSync(path.resolve(kycTomlPath), 'utf8'));
    if (Buffer.compare(Buffer.from(kyc.user_address), userAddress) !== 0) throw new Error(`${kycTomlPath} is for another wallet`);
    const kycTag = tagOf('coinbase_attestation');
    const kycStatement = Buffer.concat([clientData(ACT, { tag: kycTag, schema: KYC_SCHEMA }).subarray(0, 225), country]);
    Object.assign(cases, {
      exclusion_accepted: { list: { list: [otherCountry], length: 1, included: false } },
      client_other_country: { clientData: clientData(ACT, { country: Buffer.from(otherCountry, 'ascii') }) },
      kyc_statement_replay: { clientData: kycStatement },
      not_in_inclusion_list: { list: { list: [otherCountry, 'ZZ'], length: 2, included: true } },
    });
  }
  for (const [name, o] of Object.entries(cases)) {
    syn(path.join('test-vectors', `${name}.toml`), toml(ACT, { ...o, label: name }));
  }

  // ---- the real circuit (Google's Key Attestation CA1 pinned) -----------------
  const real = writer(REAL_DIR);
  if (SIGNER === 'rkp') {
    real(path.join('test-vectors', 'real_synthetic_root.toml'), toml(ACT, { label: 'real_synthetic_root' }));
    const pem = fs.readFileSync(path.join(__dirname, '../../android-key-attestation/test-vectors/tegu-sdk36-tee-ec-2026-root.pem'), 'utf8');
    real(path.join('test-vectors', 'real_google_chain_other_app.toml'), toml(ACT, {
      label: 'real_google_chain_other_app: Google-signed tegu chain, Google\'s test app',
      chainInputs: chainJs.chainInputs(chainJs.pemChain(pem), chainJs.GOOGLE_KEY_ATTESTATION_CA1),
      attestedAt: 1772323200, // 2026-03-01T00:00:00Z, inside that chain's validity
    }));
  } else {
    real(path.join('test-vectors', 'real_synthetic_root.toml'), toml(ACT, { label: 'real_synthetic_root', playKey: anchors.readPlayKey() }));
    const pem = fs.readFileSync(path.join(__dirname, '../../android-key-attestation/test-vectors/sony-xperia10iii-sdk33-factory.pem'), 'utf8');
    real(path.join('test-vectors', 'real_google_factory_chain_other_app.toml'), toml(ACT, {
      label: 'real_google_factory_chain_other_app: Google-signed Sony chain, the Play Store\'s key',
      chainInputs: chainJs.factoryChainInputs(chainJs.pemChain(pem), chainJs.GOOGLE_RSA_ROOT_MODULUS_HEX),
      rsa: realRsa,
      playKey: anchors.readPlayKey(),
    }));
  }
  const deviceCapture = flag('--device-capture');
  if (deviceCapture) {
    if (SIGNER !== 'factory') throw new Error('--device-capture is for --signer factory');
    const att = JSON.parse(fs.readFileSync(path.join(deviceCapture, 'attest.json'), 'utf8'));
    const verdict = JSON.parse(fs.readFileSync(path.join(deviceCapture, 'verdict.json'), 'utf8'));
    const cd = fs.readFileSync(path.join(deviceCapture, 'statement.bin'));
    const at = Number(fs.readFileSync(path.join(deviceCapture, 'attested_at.txt'), 'utf8').trim());
    if (Buffer.from(verdict.protectedHeader, 'ascii').toString() !== 'eyJhbGciOiJFUzI1NiJ9') throw new Error('the verdict header is not {"alg":"ES256"}');
    const raw = Buffer.from(verdict.signature, 'base64url');
    let vs = BigInt('0x' + raw.subarray(32).toString('hex'));
    if (vs > N_P256 / 2n) vs = N_P256 - vs;
    const payload = Buffer.from(verdict.payload, 'ascii');
    const recognized = verdict.verdict?.appIntegrity?.appRecognitionVerdict === 'PLAY_RECOGNIZED';
    const name = recognized ? 'real_device' : 'real_device_debug_build';
    real(path.join('test-vectors', `${name}.toml`), toml(ACT, {
      label: `${name}: REAL phone, ${att.chain.length} certificates, verdict ${verdict.verdict?.appIntegrity?.appRecognitionVerdict}`,
      clientData: cd,
      attestedAt: at,
      chainInputs: chainJs.factoryChainInputs(att.chain.map(c => Buffer.from(c, 'base64')), chainJs.GOOGLE_RSA_ROOT_MODULUS_HEX),
      statementSig: chainJs.rawLowS(Buffer.from(att.signature, 'base64'), 32, N_P256),
      integrity: {
        payload_b64: Buffer.concat([payload, Buffer.alloc(1368 - payload.length)]),
        payload_b64_len: payload.length,
        signature: Buffer.concat([raw.subarray(0, 32), Buffer.from(vs.toString(16).padStart(64, '0'), 'hex')]),
      },
      rsa: realRsa,
      playKey: anchors.readPlayKey(),
    }));
  }
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
