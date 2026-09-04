#!/usr/bin/env node
/**
 * Register an address with the GIWA KYC stand-in attester, and list who is
 * already registered.
 *
 *   node scripts/giwa-poc/attest-account.js list
 *   node scripts/giwa-poc/attest-account.js attest 0x<address>
 *
 * WHY THIS EXISTS. The one attestation that was on chain before today was made
 * by hand, so nothing in the repository could add a second one or even say who
 * held the first. `.env.development` records the contract and the deploy tx and
 * then stops; `generate-prover-toml.js` takes an attest tx hash as an argument
 * and never says where that hash came from. This is where it comes from.
 *
 * WHAT IT TALKS TO. `MockGiwaAttester` (circuits/src/MockGiwaAttester.sol) on
 * GIWA Sepolia. It stands in for Coinbase's StaticAttester on a chain that has
 * no such service yet, and deliberately mirrors its selector — 0x56feed5e,
 * attestAccount(address) — so one Noir circuit verifies either. Internally it
 * calls GIWA's EAS predeploy at 0x4200000000000000000000000000000000000021 with
 * a `bool verifiedAccount` schema.
 *
 * ONLY THE ATTESTER MAY CALL IT. The contract reverts NotAttester for anyone
 * else, so this needs GIWA_MOCK_UPBIT_ATTESTER_PRIVATE_KEY, not the deployer.
 *
 * DO NOT LIST BY SCANNING LOGS. That was the first attempt here and it was
 * wrong twice over. `sepolia-rpc.giwa.io` answers a log range wider than ~100k
 * blocks with an EMPTY LIST instead of an error — measured 2026-09-04, on a
 * range that provably contained an event — so one wide query reports zero
 * attestations on a contract that has one. Walking it in 100k chunks instead
 * took minutes, died partway on ranges the RPC would not serve at all, and was
 * answering a question the attester's nonce answers in one call. See
 * `attestationsViaExplorer` below.
 */
const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');

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

function need(name) {
  if (!env[name]) throw new Error(`${name} is missing from circuits/.env.development`);
  return env[name];
}

const RPC = need('GIWA_SEPOLIA_RPC_URL');
const CONTRACT = need('GIWA_MOCK_ATTESTER_CONTRACT');
const EXPLORER = need('GIWA_SEPOLIA_EXPLORER_URL');

const ABI = [
  'function attestAccount(address recipient) external returns (bytes32)',
  'function attester() external view returns (address)',
  'function verifiedAccountSchema() external view returns (bytes32)',
  'event AttestationCreated(address indexed recipient, bytes32 attestationUid)',
];

const provider = new ethers.JsonRpcProvider(RPC);

/**
 * THE CHEAP WAY, AND WHY IT IS ALSO THE COMPLETE ONE.
 *
 * Only the attester EOA can call `attestAccount` — everyone else reverts
 * NotAttester. So every attestation this contract ever made is an outgoing
 * transaction from that one account, and its NONCE is the total number of
 * transactions it has ever sent. Read the nonce and you have an upper bound on
 * the whole history in one call.
 *
 * This replaced a walk over every block since deployment. That walk took
 * minutes, kept dying on ranges the RPC would not serve, and was answering a
 * question the nonce answers instantly. Measured 2026-09-04: nonce 1, one
 * attestation, ten million blocks of scanning to learn it.
 *
 * The explorer's `txlist` gives the transactions themselves. If it is ever
 * unreachable the nonce still bounds the answer, so a disagreement between the
 * two is reported rather than smoothed over.
 */
async function attestationsViaExplorer() {
  const attesterAddr = await new ethers.Contract(CONTRACT, ABI, provider).attester();
  const nonce = await provider.getTransactionCount(attesterAddr);

  const url = `${EXPLORER}/api?module=account&action=txlist&address=${attesterAddr}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`explorer ${url} answered ${res.status}`);
  const body = await res.json();
  const rows = Array.isArray(body.result) ? body.result : [];

  const calls = rows.filter(t =>
    t.from.toLowerCase() === attesterAddr.toLowerCase() &&
    t.to.toLowerCase() === CONTRACT.toLowerCase() &&
    (t.methodId || '').toLowerCase() === ATTEST_SELECTOR);

  const found = calls.map(t => ({
    // The recipient is the single address argument, right-aligned in the word
    // after the 4-byte selector.
    recipient: ethers.getAddress('0x' + t.input.slice(10 + 24, 10 + 64)),
    block: Number(t.blockNumber),
    tx: t.hash,
    failed: t.txreceipt_status !== '1',
  }));

  return { attesterAddr, nonce, found, sentTotal: rows.filter(
    t => t.from.toLowerCase() === attesterAddr.toLowerCase()).length };
}

const ATTEST_SELECTOR = '0x56feed5e';

async function main() {
  const command = process.argv[2];
  const contract = new ethers.Contract(CONTRACT, ABI, provider);

  if (command === 'list') {
    const { attesterAddr, nonce, found, sentTotal } = await attestationsViaExplorer();
    console.log(`MockGiwaAttester ${CONTRACT}`);
    console.log(`  attester : ${attesterAddr}  (nonce ${nonce} — every attestation it ever made)`);
    console.log(`  schema   : ${await contract.verifiedAccountSchema()}\n`);
    if (!found.length) console.log('No address is registered.');
    for (const a of found) {
      console.log(`${a.recipient}${a.failed ? '  [TRANSACTION FAILED]' : ''}`);
      console.log(`  block ${a.block}  tx ${a.tx}`);
      if (EXPLORER) console.log(`  ${EXPLORER}/tx/${a.tx}`);
    }
    if (sentTotal !== nonce) {
      console.log(`\nWARNING: the explorer listed ${sentTotal} outgoing transaction(s) but the ` +
                  `chain says the nonce is ${nonce}. The explorer's list is incomplete, so ` +
                  `treat the addresses above as a floor, not the whole set.`);
    }
    return;
  }

  if (command === 'attest') {
    const target = process.argv[3];
    if (!target) throw new Error('usage: attest-account.js attest 0x<address>');
    const recipient = ethers.getAddress(target); // throws on a bad checksum

    const { nonce, found, sentTotal } = await attestationsViaExplorer();
    if (sentTotal !== nonce) {
      console.log(`WARNING: explorer listed ${sentTotal} transaction(s), chain nonce is ${nonce}. ` +
                  `The "already registered?" check below may miss one.`);
    }
    const already = found.filter(a => a.recipient.toLowerCase() === recipient.toLowerCase());
    if (already.length) {
      console.log(`${recipient} already has ${already.length} attestation(s) from this contract:`);
      for (const a of already) console.log(`  block ${a.block}  tx ${a.tx}`);
      console.log('Nothing sent. Delete this check only if a second attestation is wanted on purpose.');
      return;
    }

    const signer = new ethers.Wallet(need('GIWA_MOCK_UPBIT_ATTESTER_PRIVATE_KEY'), provider);
    const onChainAttester = await contract.attester();
    if (signer.address.toLowerCase() !== onChainAttester.toLowerCase()) {
      throw new Error(`the key in .env.development is ${signer.address}, but the contract only ` +
                      `accepts ${onChainAttester} — attestAccount would revert NotAttester`);
    }
    const balance = await provider.getBalance(signer.address);
    if (balance === 0n) throw new Error(`attester ${signer.address} has no GIWA Sepolia ETH for gas`);

    console.log(`Attesting ${recipient} as ${signer.address} ...`);
    const tx = await contract.connect(signer).attestAccount(recipient);
    console.log(`  tx ${tx.hash}`);
    const receipt = await tx.wait();
    if (receipt.status !== 1) throw new Error(`transaction reverted: ${tx.hash}`);

    // Read the uid back out of the event rather than trusting the return value,
    // which a transaction cannot hand back.
    const event = receipt.logs
      .map(l => { try { return contract.interface.parseLog(l); } catch { return null; } })
      .find(e => e && e.name === 'AttestationCreated');
    console.log(`  block ${receipt.blockNumber}`);
    console.log(`  attestation uid ${event ? event.args.attestationUid : '(event not found)'}`);
    if (EXPLORER) console.log(`  ${EXPLORER}/tx/${tx.hash}`);
    console.log('\nFeed this tx hash to generate-prover-toml.js to build a proof from it.');
    return;
  }

  throw new Error('usage: attest-account.js list | attest 0x<address>');
}

main().catch(err => {
  console.error(err.message || err);
  process.exit(1);
});
