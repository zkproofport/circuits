#!/usr/bin/env node
/**
 * Build the Coinbase KYC snapshot tree for one Base block.
 *
 *   node scripts/coinbase-snapshot/build-snapshot.js [--block <n>] [--out-dir <dir>]
 *
 * Needs circuits/.env.production (BASE_RPC_URL; a full node is enough, the
 * basis block is recent).
 *
 * THE RULE (what any rebuild must reproduce)
 *
 *   At block B, an address is in the set when EAS.getAttestation(uid), read AT
 *   B, returns an attestation with schema = config.schema, attester =
 *   config.attester, revocationTime = 0, and expirationTime 0 or later than
 *   B's timestamp, whose recipient is that address. The tree is tree.js.
 *
 *   B is chosen on a fixed schedule: the latest `basisBlockTag` block rounded
 *   DOWN to a multiple of `intervalBlocks`. Two people running this in the same
 *   window get the same B and therefore the same root.
 *
 * WHERE THE CANDIDATES COME FROM, AND WHY THAT IS SAFE
 *
 *   Every inclusion decision is an eth_call at B. The list of uids to ask
 *   about comes from the EAS explorer, because no free RPC serves this
 *   schema's full event history (tried 2026-10-22: Alchemy free allows 10
 *   blocks per eth_getLogs, drpc free refused every range, publicnode wants
 *   an archive token, 1rpc caps at 50). So the explorer can only cause an
 *   OMISSION -- a revoked or invented uid still fails the on-chain read. An
 *   auditor with a full log index can rebuild the candidate list from
 *   Attested events and compare.
 */
const { ethers } = require('../node_modules/ethers');
const fs = require('fs');
const path = require('path');
const { sortAddresses, buildLevels } = require('./tree');

const CIRCUITS_ROOT = path.resolve(__dirname, '../..');
const CONFIG = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const EXPLORER = 'https://base.easscan.org/graphql';
const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11';
const BATCH = 250;
const PARALLEL = 4;

const args = process.argv.slice(2);
const opt = name => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
};
const OUT_DIR = path.resolve(opt('--out-dir') || path.join(CIRCUITS_ROOT, 'coinbase-snapshot-poc/snapshots'));
const CANDIDATE_CACHE = path.join(OUT_DIR, 'candidates.json');

const EAS_IFACE = new ethers.Interface([
  'function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))',
]);
const MC_IFACE = new ethers.Interface([
  'function aggregate3(tuple(address target, bool allowFailure, bytes callData)[] calls) view returns (tuple(bool success, bytes returnData)[])',
]);

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

async function explorer(query) {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(EXPLORER, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query }) });
    if (res.ok) {
      const body = await res.json();
      if (body.errors) throw new Error('explorer: ' + JSON.stringify(body.errors).slice(0, 300));
      return body.data;
    }
    if (attempt === 5) throw new Error(`explorer answered ${res.status} five times`);
    await new Promise(r => setTimeout(r, 2000 * attempt));
  }
}

/**
 * Unrevoked candidates, newest cached time onwards. Revocation is final in
 * EAS, so a uid the explorer reports revoked can be dropped without asking the
 * chain; anything it reports live is asked.
 */
async function candidates() {
  const cache = fs.existsSync(CANDIDATE_CACHE) ? JSON.parse(fs.readFileSync(CANDIDATE_CACHE, 'utf8')) : { since: 0, uids: {} };
  let since = cache.since;
  for (;;) {
    const data = await explorer(`{ attestations(take: 5000, orderBy: [{time: asc}, {id: asc}], where: {schemaId: {equals: "${CONFIG.schema}"}, attester: {equals: "${CONFIG.attester}"}, time: {gte: ${since}}}) { id recipient time revoked } }`);
    const page = data.attestations;
    for (const a of page) {
      if (a.revoked) delete cache.uids[a.id];
      else cache.uids[a.id] = a.recipient;
    }
    const last = page.length ? page[page.length - 1].time : since;
    process.stdout.write(`\r  candidates: ${Object.keys(cache.uids).length} live after time ${last}   `);
    if (page.length < 5000) { since = last; break; }
    if (last === since) throw new Error(`more than 5000 attestations share time ${since}; page by id`);
    since = last;
  }
  process.stdout.write('\n');
  cache.since = since;
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(CANDIDATE_CACHE, JSON.stringify(cache));
  return Object.keys(cache.uids);
}

async function verifyAt(provider, uids, block) {
  const live = [];
  const rejected = { notFound: 0, revoked: 0, expired: 0, otherSchemaOrAttester: 0 };
  const batches = [];
  for (let i = 0; i < uids.length; i += BATCH) batches.push(uids.slice(i, i + BATCH));
  let done = 0;
  const run = async batch => {
    const calls = batch.map(uid => ({ target: CONFIG.eas, allowFailure: false, callData: EAS_IFACE.encodeFunctionData('getAttestation', [uid]) }));
    const raw = await provider.call({ to: MULTICALL3, data: MC_IFACE.encodeFunctionData('aggregate3', [calls]), blockTag: block.number });
    const [results] = MC_IFACE.decodeFunctionResult('aggregate3', raw);
    results.forEach((r, k) => {
      const [a] = EAS_IFACE.decodeFunctionResult('getAttestation', r.returnData);
      if (a.uid !== batch[k]) rejected.notFound++;
      else if (a.schema !== CONFIG.schema || a.attester !== CONFIG.attester) rejected.otherSchemaOrAttester++;
      else if (a.revocationTime !== 0n) rejected.revoked++;
      else if (a.expirationTime !== 0n && a.expirationTime <= BigInt(block.timestamp)) rejected.expired++;
      else live.push(a.recipient);
    });
    done += batch.length;
    process.stdout.write(`\r  checked at block ${block.number}: ${done}/${uids.length}   `);
  };
  for (let i = 0; i < batches.length; i += PARALLEL) {
    await Promise.all(batches.slice(i, i + PARALLEL).map(b => withRetry(() => run(b))));
  }
  process.stdout.write('\n');
  return { live, rejected };
}

async function withRetry(fn) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (attempt === 5) throw e;
      await new Promise(r => setTimeout(r, 1500 * attempt));
    }
  }
}

async function main() {
  const provider = new ethers.JsonRpcProvider(loadEnv().BASE_RPC_URL);
  const net = await provider.getNetwork();
  if (net.chainId !== BigInt(CONFIG.chainId)) throw new Error(`RPC is chain ${net.chainId}, config says ${CONFIG.chainId}`);

  let number = opt('--block') ? Number(opt('--block')) : null;
  if (number === null) {
    const basis = await provider.getBlock(CONFIG.basisBlockTag);
    number = Math.floor(basis.number / CONFIG.intervalBlocks) * CONFIG.intervalBlocks;
  }
  const block = await provider.getBlock(number);
  console.log(`basis block ${block.number} (${new Date(block.timestamp * 1000).toISOString()}), every ${CONFIG.intervalBlocks} blocks`);

  const t0 = Date.now();
  const uids = await candidates();
  const t1 = Date.now();
  const { live, rejected } = await verifyAt(provider, uids, block);
  const t2 = Date.now();
  const sorted = sortAddresses(live);
  const tree = buildLevels(sorted, CONFIG.treeDepth);
  const t3 = Date.now();

  const root = ethers.toBeHex(tree.root, 32);
  const snapshot = {
    rule: { chainId: CONFIG.chainId, eas: CONFIG.eas, schema: CONFIG.schema, attester: CONFIG.attester, treeDepth: CONFIG.treeDepth },
    block: { number: block.number, hash: block.hash, timestamp: block.timestamp },
    root,
    count: sorted.length,
    addresses: sorted.map(a => ethers.toBeHex(a, 20)),
  };
  const file = path.join(OUT_DIR, `${block.number}.json`);
  fs.writeFileSync(file, JSON.stringify(snapshot));

  console.log(`live attestations ${live.length}, distinct addresses ${sorted.length}`);
  console.log('rejected at the basis block:', rejected);
  console.log(`root ${root}`);
  console.log(`timing: candidates ${((t1 - t0) / 1000).toFixed(1)}s, on-chain check ${((t2 - t1) / 1000).toFixed(1)}s, tree ${((t3 - t2) / 1000).toFixed(1)}s`);
  console.log(`wrote ${path.relative(CIRCUITS_ROOT, file)} (${(fs.statSync(file).size / 1e6).toFixed(1)} MB)`);
}

main().catch(e => {
  console.error('\n' + (e.message || e));
  process.exit(1);
});
