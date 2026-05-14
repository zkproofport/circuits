#!/usr/bin/env node
/**
 * Submits the GiwaAttestation proof to the deployed HonkVerifier
 *  1) cast call equivalent — dry-run, returns true/false
 *  2) eth_sendTransaction — leaves an on-chain tx receipt for the PoC demo
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

const VERIFIER = '0xEb9eb5452790Cfe549fF83CEB3Dbe1C432231492';
const RPC = env.GIWA_SEPOLIA_RPC_URL;
const PK = env.PRIVATE_KEY;

(async () => {
  const proofPath = path.resolve(__dirname, '../../giwa-attestation/target/proof/proof');
  const pubInpPath = path.resolve(__dirname, '../../giwa-attestation/target/proof/public_inputs');

  const proofBytes = fs.readFileSync(proofPath);
  const proofHex = '0x' + proofBytes.toString('hex');

  const pubInpRaw = fs.readFileSync(pubInpPath);
  const publicInputs = [];
  for (let i = 0; i < pubInpRaw.length; i += 32) {
    publicInputs.push('0x' + pubInpRaw.subarray(i, i + 32).toString('hex'));
  }

  console.log('proof bytes:    ', proofBytes.length);
  console.log('public inputs:  ', publicInputs.length, 'x 32 bytes');

  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PK, provider);
  const iface = new ethers.Interface([
    'function verify(bytes proof, bytes32[] publicInputs) view returns (bool)'
  ]);

  // 1) Dry-run via eth_call
  const callData = iface.encodeFunctionData('verify', [proofHex, publicInputs]);
  const callRes = await provider.call({ to: VERIFIER, data: callData });
  const [okCall] = iface.decodeFunctionResult('verify', callRes);
  console.log('');
  console.log('=== Dry-run (eth_call) ===');
  console.log('verify() returned:', okCall);

  if (!okCall) {
    console.error('Proof rejected by verifier; aborting tx submission.');
    process.exit(1);
  }

  // 2) Real tx — view function, but still produces a receipt on chain.
  console.log('');
  console.log('=== Sending on-chain tx ===');
  const gasEstimate = await provider.estimateGas({ to: VERIFIER, data: callData, from: wallet.address });
  console.log('gas estimate:', gasEstimate.toString());

  const tx = await wallet.sendTransaction({
    to: VERIFIER,
    data: callData,
    gasLimit: gasEstimate * 12n / 10n,
  });
  console.log('tx hash:', tx.hash);
  const receipt = await tx.wait();
  console.log('block:', receipt.blockNumber);
  console.log('status:', receipt.status, '(1 = success)');
  console.log('gas used:', receipt.gasUsed.toString());
  console.log('');
  console.log('Explorer:', `${env.GIWA_SEPOLIA_EXPLORER_URL}/tx/${tx.hash}`);
})();
