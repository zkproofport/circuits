#!/usr/bin/env node
/**
 * Issue a Dojang Playground attestation to the fixture wallet, the same call
 * the GIWA Playground's "Dojang 발급" button makes: payAndIssueEAS() on the
 * testnet faucet, paying its fee.
 *
 * The fixtures need one issuance of each transaction shape a wallet sends, so
 * the shape is chosen here:
 *
 *   node issue.js --type 0   # legacy, EIP-155
 *   node issue.js --type 2   # EIP-1559
 *
 * Needs circuits/.env.development (PRIVATE_KEY, GIWA_SEPOLIA_RPC_URL) and a
 * little GIWA Sepolia ETH: the fee is read from the contract, 0.001 ETH when
 * this was written.
 */
const { ethers } = require('../node_modules/ethers');
const { loadEnv, FAUCET } = require('./common');

async function main() {
  const i = process.argv.indexOf('--type');
  const type = i === -1 ? null : Number(process.argv[i + 1]);
  if (type !== 0 && type !== 2) throw new Error('Pass --type 0 (legacy) or --type 2 (EIP-1559).');

  const env = loadEnv();
  const provider = new ethers.JsonRpcProvider(env.GIWA_SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(env.PRIVATE_KEY, provider);
  const faucet = new ethers.Contract(FAUCET, ['function fee() view returns (uint256)', 'function payAndIssueEAS() payable returns (bytes32)'], wallet);
  const fee = await faucet.fee();

  const overrides = { value: fee, type };
  if (type === 0) overrides.gasPrice = (await provider.getFeeData()).gasPrice;
  const tx = await faucet.payAndIssueEAS(overrides);
  console.log('sent', tx.hash, 'type', tx.type, 'from', wallet.address);
  const receipt = await tx.wait();
  if (receipt.status !== 1) throw new Error('issuance reverted: ' + tx.hash);
  console.log('mined in block', receipt.blockNumber);
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
