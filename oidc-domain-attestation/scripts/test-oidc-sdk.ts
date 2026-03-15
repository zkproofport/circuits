#!/usr/bin/env npx tsx
/**
 * CLI test: Generate OIDC circuit inputs using the SDK, write Prover.toml,
 * and optionally run the circuit proof.
 *
 * Usage:
 *   npx tsx scripts/test-oidc-sdk.ts                    # uses gcloud JWT
 *   npx tsx scripts/test-oidc-sdk.ts --prove             # + run nargo/bb proof
 *   JWT=eyJ... npx tsx scripts/test-oidc-sdk.ts          # custom JWT
 */

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Import from SDK source directly (relative path)
import { prepareOidcInputs, buildOidcProverToml } from '../../../proofport-ai/packages/sdk/src/oidc-inputs.js';

const CIRCUIT_DIR = path.resolve(import.meta.dirname, '..');
const SCOPE = 'openstoa:topic:test';
const shouldProve = process.argv.includes('--prove');

async function main() {
  console.log('=== OIDC Domain Attestation — SDK Input Test ===\n');

  // 1. Get JWT
  let jwt = process.env.JWT;
  if (!jwt) {
    console.log('1. Getting Google identity token via gcloud...');
    jwt = execSync('gcloud auth print-identity-token', { encoding: 'utf-8' }).trim();
  } else {
    console.log('1. Using JWT from environment variable...');
  }

  // Quick decode to show info
  const payload = JSON.parse(
    Buffer.from(jwt.split('.')[1], 'base64url').toString(),
  );
  console.log(`   email: ${payload.email}`);
  console.log(`   iss: ${payload.iss}`);
  console.log(`   exp: ${new Date(payload.exp * 1000).toISOString()}\n`);

  // 2. Generate inputs using SDK
  console.log('2. Calling prepareOidcInputs()...');
  const startTime = Date.now();

  const inputs = await prepareOidcInputs({ jwt, scope: SCOPE });

  const elapsed = Date.now() - startTime;
  console.log(`   Done in ${elapsed}ms`);
  console.log(`   domain: ${Buffer.from(inputs.domain.storage.slice(0, inputs.domain.len)).toString()}`);
  console.log(`   partial_data.len: ${inputs.partial_data.len}`);
  console.log(`   full_data_length: ${inputs.full_data_length}`);
  console.log(`   base64_decode_offset: ${inputs.base64_decode_offset}`);
  console.log(`   partial_hash: [${inputs.partial_hash.map(v => (v >>> 0).toString()).join(', ')}]`);
  console.log(`   scope: [${inputs.scope.slice(0, 4).join(', ')}...] (32 bytes)`);
  console.log(`   nullifier: [${inputs.nullifier.slice(0, 4).join(', ')}...] (32 bytes)\n`);

  // 3. Build Prover.toml
  console.log('3. Building Prover.toml...');
  const toml = buildOidcProverToml(inputs);
  const tomlPath = path.join(CIRCUIT_DIR, 'Prover.toml');
  fs.writeFileSync(tomlPath, toml, 'utf-8');
  console.log(`   Written: ${tomlPath} (${fs.statSync(tomlPath).size} bytes)\n`);

  // 4. Optionally run proof
  if (shouldProve) {
    console.log('4. Running circuit proof pipeline...\n');

    const nargoPath = `${process.env.HOME}/.nargo/bin/nargo`;
    const bbPath = `${process.env.HOME}/.bb/bb`;

    // Compile
    console.log('   [compile] nargo compile...');
    execSync(`${nargoPath} compile`, { cwd: CIRCUIT_DIR, stdio: 'inherit' });

    // Write VK
    console.log('   [vk] bb write_vk...');
    execSync(
      `${bbPath} write_vk -b target/oidc_domain_attestation.json -o target/vk --oracle_hash keccak`,
      { cwd: CIRCUIT_DIR, stdio: 'inherit' },
    );

    // Execute witness
    console.log('   [witness] nargo execute...');
    execSync(`${nargoPath} execute witness`, { cwd: CIRCUIT_DIR, stdio: 'inherit' });

    // Move witness
    fs.mkdirSync(path.join(CIRCUIT_DIR, 'target/proof'), { recursive: true });
    fs.copyFileSync(
      path.join(CIRCUIT_DIR, 'target/witness.gz'),
      path.join(CIRCUIT_DIR, 'target/proof/witness.gz'),
    );

    // Prove
    console.log('   [prove] bb prove...');
    execSync(
      `${bbPath} prove -b target/oidc_domain_attestation.json -w target/proof/witness.gz -k target/vk/vk -o target/proof --oracle_hash keccak`,
      { cwd: CIRCUIT_DIR, stdio: 'inherit' },
    );

    // Verify
    console.log('   [verify] bb verify...');
    execSync(
      `${bbPath} verify -k target/vk/vk -p target/proof/proof -i target/proof/public_inputs --oracle_hash keccak`,
      { cwd: CIRCUIT_DIR, stdio: 'inherit' },
    );

    const proofSize = fs.statSync(path.join(CIRCUIT_DIR, 'target/proof/proof')).size;
    console.log(`\n   Proof verified! (${proofSize} bytes)\n`);
  }

  console.log('=== Done ===');
}

main().catch((err) => {
  console.error('Fatal:', err.message || err);
  process.exit(1);
});
