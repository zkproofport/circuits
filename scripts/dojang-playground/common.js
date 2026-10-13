const fs = require('fs');
const path = require('path');

const CIRCUITS_ROOT = path.resolve(__dirname, '../..');

/** GIWAFaucetExtension on GIWA Sepolia: the Playground's issuing contract. */
const FAUCET = '0x63CCe2b569A7bC35895ee24306c1512fefc06121';
const GIWA_SEPOLIA_CHAIN_ID = 91342n;

function loadEnv() {
  const file = path.join(CIRCUITS_ROOT, '.env.development');
  if (!fs.existsSync(file)) throw new Error(`${file} is required (PRIVATE_KEY, GIWA_SEPOLIA_RPC_URL)`);
  const env = Object.fromEntries(
    fs.readFileSync(file, 'utf8').split('\n')
      .filter(l => l.trim() && !l.startsWith('#') && l.includes('='))
      .map(l => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]),
  );
  for (const k of ['PRIVATE_KEY', 'GIWA_SEPOLIA_RPC_URL']) {
    if (!env[k]) throw new Error(`${k} missing from ${file}`);
  }
  return env;
}

module.exports = { CIRCUITS_ROOT, FAUCET, GIWA_SEPOLIA_CHAIN_ID, loadEnv };
