#!/usr/bin/env node
/**
 * Fixtures for coinbase_attestation_v2: a REAL Coinbase attestation, and
 * statements signed by SYNTHETIC App Attest material or by the server test key.
 *
 *   node generate-prover-toml.js --coinbase <coinbase-attestation Prover.toml> \
 *        --synthetic-dir <synthetic-anchors copy> --real-dir <coinbase-attestation-v2>
 *
 * Needs ATTESTED_WALLET_KEY in the environment: the key of the wallet the
 * Coinbase fixture is for (make-fixtures.sh reads it from proofport-ai/.env.test
 * and never prints it).
 *
 * TWO TARGETS.
 *   --synthetic-dir  the synthetic-anchors copy of the circuit (make-fixtures.sh
 *                    makes it): Apple's CA 1 replaced by the SYNTHETIC CA
 *                    (anchors.js), the server key by the test key. Every
 *                    acceptance and refusal case runs here, because no fixture
 *                    can carry an Apple-signed credential certificate for our
 *                    App ID together with that device's private key.
 *                    Writes Prover.toml (app kind, EIP-712 action),
 *                    Prover.no-action.toml, and test-vectors/*.toml.
 *   --real-dir       the real circuit, Apple's CA 1 pinned. Writes
 *                    test-vectors/real_*.toml: a server-kind statement (accepted
 *                    while the test key is pinned, refused after the swap), the
 *                    synthetic chain (refused: not signed by Apple's CA 1), and
 *                    a REAL credential certificate CA 1 signed (zkPassport's
 *                    vector), which must pass the P-384 check and stop at the
 *                    App ID.
 *
 * WHAT IS REAL. raw_transaction, the attester key, the signer Merkle proof
 * and root come from coinbase-attestation/Prover.toml, which
 * proofport-ai/scripts/gen-prover-toml.ts builds from Base. apple-vector.json
 * is a real Apple chain. The wallet signs a fresh request here.
 *
 * HOW THE SYNTHETIC CHAIN DIFFERS FROM APPLE'S. The intermediate is only a
 * key (anchors.js syntheticCa, pinned in the copy as CA 1 is in the circuit).
 * The credential certificate copies the real
 * one's structure (field order, attribute types, extensions and OIDs; the 8.5
 * items with our App ID; the 8.7 extension verbatim; the nonce computed).
 * Assertion flags are 0x00; no CBOR extensions in either authData.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('../node_modules/ethers');
const anchors = require('../statement-signer/anchors');
const {
  APP_ID, KIND_APP, KIND_SERVER, TBS_MAX, ATT_AUTH_MAX, ASSERT_AUTH_MAX, AAGUID_PROD, AAGUID_DEV,
  N_P256, N_P384, SIG_ALG_SHA256, sha256, tlv, seq, credentialTbs, ecKey, toLowS, signLowS, highS,
  p1363ToDer, certDer, attestationAuthData, assertionAuthData, serverSign, arr, pad,
} = require('../statement-signer/signers');

const opt = name => {
  const args = process.argv.slice(2);
  const i = args.indexOf(name);
  if (i === -1 || !args[i + 1]) throw new Error(`${name} is required`);
  return args[i + 1];
};

// ---- constants that must match the circuit ---------------------------------
const CIRCUIT_TAG = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('coinbase_attestation')));
const MAGIC = Buffer.from('ZKProofport/AA/1');
const KYC_SCHEMA = ethers.getBytes('0xf8b05c79f090979bf4a80270aba232dff11a10d9ca55c4f88de95317970f0de9');
const COINBASE_ATTESTER = ethers.getBytes('0x357458739F90461b99789350868CD7CF330Dd7EE');
const SCOPE_STRING = 'proofport';

// ---- the Coinbase half ------------------------------------------------------
function parseToml(text) {
  const out = {};
  const re = /^(\w+)\s*=\s*/gm;
  let m;
  while ((m = re.exec(text))) {
    let i = re.lastIndex;
    if (text[i] === '[') {
      let depth = 0;
      let j = i;
      for (; j < text.length; j++) {
        if (text[j] === '[') depth++;
        if (text[j] === ']' && --depth === 0) break;
      }
      const body = text.slice(i, j + 1);
      out[m[1]] = JSON.parse(body.replace(/,\s*\]/g, ']'));
      re.lastIndex = j + 1;
    } else {
      out[m[1]] = text.slice(i).split('\n')[0].trim();
    }
  }
  return out;
}

// ---- TOML -------------------------------------------------------------------
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

  // The two requests a wallet can sign.
  const signalHash = ethers.getBytes(ethers.solidityPackedKeccak256(
    ['address', 'string', 'string'], [wallet.address, SCOPE_STRING, 'coinbase_attestation']));
  const domain = { name: 'ZKProofport Coinbase KYC v2 fixture', version: '1', chainId: 8453, verifyingContract: '0x0000000000000000000000000000000000000001' };
  const types = { Join: [{ name: 'member', type: 'address' }, { name: 'nonce', type: 'string' }] };
  const message = { member: wallet.address, nonce: 'coinbase-attestation-v2-1' };
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

  // ---- anchors: the synthetic CA and the server test key ---------------------
  const inter = anchors.syntheticCa();
  const otherInter = ecKey('secp384r1');
  const server = anchors.testServerKey();
  const otherServer = ecKey('prime256v1');
  const syntheticCaXY = Buffer.concat([inter.x, inter.y]);
  // The real circuit must pin Apple's CA 1, never the synthetic one.
  if (anchors.readAppleCa().equals(syntheticCaXY)) throw new Error('the real circuit pins the synthetic CA');

  // ---- one synthetic device ---------------------------------------------------
  const cred = ecKey('prime256v1');
  const otherCred = ecKey('prime256v1');

  const keyId = sha256(Buffer.from([4]), cred.x, cred.y);
  const serial = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(5)]);
  const attCdh = sha256(crypto.randomBytes(32));
  const device = (aaguid = AAGUID_PROD, appId = APP_ID) => {
    const attAuth = attestationAuthData(cred, APP_ID, aaguid);
    const nonce = sha256(attAuth, attCdh);
    const tbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce, appId, serial });
    const sig = signLowS('sha256', tbs, inter, N_P384, 48);
    return { attAuth, tbs, sig };
  };
  const dev = device();
  const x509 = new crypto.X509Certificate(certDer(dev.tbs, SIG_ALG_SHA256, dev.sig, 48));
  if (!x509.verify(crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-384', x: inter.x.toString('base64url'), y: inter.y.toString('base64url') }, format: 'jwk' }))) {
    throw new Error('synthetic credential certificate does not verify');
  }
  if (dev.tbs.length > TBS_MAX) throw new Error(`TBS is ${dev.tbs.length} bytes`);

  const attestedAt = Math.floor(Date.now() / 1000);
  const easUid = crypto.randomBytes(32); // what the signer found; not checked in-circuit

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
  function assertion(cd, o = {}) {
    const auth = assertionAuthData(o.rpId ?? APP_ID, o.counter ?? 1);
    const nonce = sha256(auth, sha256(cd));
    const sig = signLowS('sha256', nonce, o.key ?? cred, N_P256, 32);
    if (!crypto.verify('sha256', nonce, { key: (o.key ?? cred).publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
      throw new Error('synthetic assertion does not verify');
    }
    return { auth, sig };
  }

  const EMPTY_CHAIN = {
    tbs: Buffer.alloc(0), certSig: Buffer.alloc(96),
    attAuth: Buffer.alloc(0), attCdh: Buffer.alloc(32), assertAuth: Buffer.alloc(0),
  };

  /** One Prover TOML. kind 'app' builds the chain unless overridden; 'server'
   *  passes zeros for every App Attest input, exactly as README.md says. */
  function toml(req, o = {}) {
    const kindName = o.kind ?? 'app';
    const cd = o.clientData ?? clientData(req);
    let chain;
    let statementSig;
    if (kindName === 'app') {
      const as = o.assertion ?? assertion(cd);
      chain = {
        tbs: o.tbs ?? dev.tbs, certSig: o.certSig ?? dev.sig,
        attAuth: o.attAuth ?? dev.attAuth, attCdh: o.attCdh ?? attCdh, assertAuth: as.auth,
      };
      statementSig = o.statementSig ?? as.sig;
    } else if (kindName === 'server') {
      chain = o.chain ?? EMPTY_CHAIN;
      statementSig = o.statementSig ?? serverSign(cd, o.serverKey ?? server);
    } else {
      throw new Error(`Unknown fixture kind ${kindName}. Known: app, server.`);
    }
    const kindByte = o.kindByte ?? { app: KIND_APP, server: KIND_SERVER }[kindName];
    return `# Generated by scripts/coinbase-attestation-v2/generate-prover-toml.js
# Coinbase part: real (from ${path.basename(path.dirname(COINBASE_TOML))}/Prover.toml).
# Statement: ${kindName} kind${kindName === 'app' ? ', SYNTHETIC App Attest chain' : ', INSECURE test server key'}.
# Case: ${o.label ?? 'accepted'}

signal_hash = ${arr(req.signal)}
domain_separator = ${arr(req.domainSeparator)}
action_hash = ${arr(req.actionHash)}
signer_list_merkle_root = ${arr(cb.signer_list_merkle_root)}
scope = ${arr(scope)}
nullifier = ${arr(nullifier)}
attested_at = ${o.attestedAt ?? attestedAt}

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
signer_kind = ${kindByte}
statement_sig = ${arr(statementSig)}

credential_tbs = ${arr(pad(chain.tbs, TBS_MAX, 'TBS'))}
credential_tbs_len = ${chain.tbs.length}
credential_sig = ${arr(chain.certSig)}
att_auth_data = ${arr(pad(chain.attAuth, ATT_AUTH_MAX, 'attestation authData'))}
att_auth_data_len = ${chain.attAuth.length}
att_client_data_hash = ${arr(chain.attCdh)}
assertion_auth_data = ${arr(pad(chain.assertAuth, ASSERT_AUTH_MAX, 'assertion authData'))}
assertion_auth_data_len = ${chain.assertAuth.length}
`;
  }

  const A = requests.action;
  const writer = dir => (file, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), text);
    console.log('wrote', path.relative(path.dirname(dir), path.join(dir, file)));
  };
  const syn = writer(SYN_DIR);
  syn('Prover.toml', toml(A));
  syn('Prover.no-action.toml', toml(requests.noAction));

  // ---- the synthetic-anchors cases. Each changes ONE thing. ------------------
  const otherAppId = APP_ID.slice(0, -1) + 's'; // same length, so only the comparison can refuse
  const otherWallet = ethers.getBytes(ethers.Wallet.createRandom().address);
  const reSignCred = tbs => signLowS('sha256', tbs, inter, N_P384, 48);
  const otherCredTbs = credentialTbs({ x: cred.x, y: cred.y, keyId, nonce: sha256(dev.attAuth, attCdh), appId: APP_ID, serial: Buffer.from('02aabbccddee', 'hex') });
  const appCd = clientData(A);
  const devEnv = device(AAGUID_DEV);
  const otherApp = device(AAGUID_PROD, otherAppId);

  // oidc_domain_attestation's provider-key statement (oidc-domain-attestation/
  // src/provider_key.nr): "ZKProofport/PK/1" || keccak256(id) || provider ||
  // now || 256-byte modulus.
  const oidcNow = Buffer.alloc(8);
  oidcNow.writeBigUInt64BE(BigInt(attestedAt));
  const oidcStatement = Buffer.concat([
    Buffer.from('ZKProofport/PK/1'), ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('oidc_domain_attestation'))),
    Buffer.from([0]), oidcNow, Buffer.concat([Buffer.from([0x80]), crypto.randomBytes(255)]),
  ]);
  if (oidcStatement.length !== 313) throw new Error(`OIDC statement is ${oidcStatement.length} bytes`);

  const cases = {
    // ---- server kind
    server_action: { kind: 'server' },
    server_ignores_chain_fields: {
      kind: 'server',
      chain: { tbs: dev.tbs, certSig: dev.sig, attAuth: dev.attAuth, attCdh, assertAuth: assertion(appCd).auth },
    },
    server_other_key: { kind: 'server', serverKey: otherServer },
    server_client_revoked: { kind: 'server', clientData: clientData(A, { revoked: 1 }) },
    server_high_s: { kind: 'server', statementSig: highS(serverSign(appCd, server), N_P256, 32) },
    // ---- the private kind byte
    kind_flipped_app_to_server: { kindByte: KIND_SERVER },
    kind_flipped_server_to_app: { kind: 'server', kindByte: KIND_APP },
    // Server-signed with an unknown kind byte: without the kind assert these
    // would take the server path and be ACCEPTED, so the assert is what refuses.
    kind_zero: { kind: 'server', kindByte: 0 },
    kind_unknown: { kind: 'server', kindByte: 3 },
    app_chain_with_server_signature: { statementSig: serverSign(appCd, server) },
    // ---- intermediate -> credential
    cert_bad_signature: { certSig: reSignCred(otherCredTbs) },
    cert_other_ca: { certSig: signLowS('sha256', dev.tbs, otherInter, N_P384, 48) },
    cert_other_app: { tbs: otherApp.tbs, certSig: otherApp.sig, attAuth: otherApp.attAuth },
    cert_high_s: { certSig: highS(dev.sig, N_P384, 48) },
    attestation_not_certified: { attCdh: sha256(Buffer.from('another challenge')) },
    env_development: { tbs: devEnv.tbs, certSig: devEnv.sig, attAuth: devEnv.attAuth },
    // ---- the assertion
    assertion_other_key: { assertion: assertion(appCd, { key: otherCred }) },
    assertion_wrong_rpid: { assertion: assertion(appCd, { rpId: otherAppId }) },
    assertion_counter_zero: { assertion: assertion(appCd, { counter: 0 }) },
    assertion_high_s: (() => {
      const as = assertion(appCd);
      return { assertion: { auth: as.auth, sig: highS(as.sig, N_P256, 32) } };
    })(),
    // ---- the statement
    client_wallet_mismatch: { clientData: clientData(A, { wallet: otherWallet }) },
    client_revoked: { clientData: clientData(A, { revoked: 1 }) },
    client_other_schema: { clientData: clientData(A, { schema: sha256(Buffer.from('another schema')) }) },
    client_other_request: { clientData: clientData(A, { digest: requests.noAction.digest }) },
    client_other_scope: { clientData: clientData(A, { scope: ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('another-scope'))) }) },
    timestamp_changed: { attestedAt: attestedAt + 1 },
    stale_timestamp_resigned: { clientData: clientData(A, { timestamp: attestedAt - 3600 }) },
    // ---- another circuit's statement, signed by the same server key
    // (statement-signer serves oidc_domain_attestation too). The server's
    // signature is over the whole 313-byte provider-key statement; the
    // clientData is what a replayer can make of it in 225 bytes.
    oidc_statement_replay: { kind: 'server', clientData: oidcStatement.subarray(0, 225), statementSig: serverSign(oidcStatement, server) },
    oidc_statement_magic_swapped: {
      kind: 'server',
      clientData: Buffer.concat([MAGIC, oidcStatement.subarray(16, 225)]),
      statementSig: serverSign(oidcStatement, server),
    },
  };
  for (const [name, o] of Object.entries(cases)) {
    syn(path.join('test-vectors', `${name}.toml`), toml(A, { ...o, label: name }));
  }
  syn(path.join('test-vectors', 'server_no_action.toml'), toml(requests.noAction, { kind: 'server', label: 'server_no_action' }));

  // ---- the real circuit (Apple's CA 1 pinned) ---------------------------------
  const real = writer(REAL_DIR);
  real(path.join('test-vectors', 'real_server_action.toml'), toml(A, { kind: 'server', label: 'real_server_action' }));
  real(path.join('test-vectors', 'real_synthetic_ca.toml'), toml(A, { label: 'real_synthetic_ca' }));
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'apple-vector.json'), 'utf8'));
  const hex = h => Buffer.from(h, 'hex');
  if (!anchors.readAppleCa().equals(hex(v.intermediate_key_xy))) throw new Error('the real circuit does not pin apple-vector.json\'s intermediate (CA 1)');
  real(path.join('test-vectors', 'real_apple_chain.toml'), toml(A, {
    label: 'real_apple_chain: CA 1 -> zkPassport credential (another App ID)',
    tbs: hex(v.credential_tbs),
    certSig: toLowS(hex(v.credential_sig), N_P384, 48),
  }));

  console.log('wallet:            ', wallet.address);
  console.log('App ID:            ', APP_ID);
  console.log('synthetic CA:      ', syntheticCaXY.toString('hex'));
  console.log('server test key:   ', Buffer.concat([server.x, server.y]).toString('hex'));
  console.log('credential TBS:    ', dev.tbs.length, 'bytes; attestation authData', dev.attAuth.length, 'bytes');
  console.log('attested_at:       ', attestedAt);
}

// The certificate builder and signing helpers are shared with
// ../coinbase-app-attest-poc/generate-trust-anchor-fixtures.js.
module.exports = {
  APP_ID, N_P256, N_P384, TBS_MAX, sha256, seq, tlv, credentialTbs, ecKey, signLowS, p1363ToDer, arr, pad,
};

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
}
