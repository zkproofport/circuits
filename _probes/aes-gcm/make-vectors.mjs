// Writes Prover.toml for each probe from a real AES-256-GCM encryption
// (node:crypto), and expected.json with the packed plaintext the circuit
// must return.
import { createCipheriv, randomBytes } from 'node:crypto';
import { writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const arr = (b) => `[${[...b].join(', ')}]`;
for (const dir of readdirSync(here)) {
  const m = /^(ctr|gcm)-(\d+)$/.exec(dir);
  if (!m || !existsSync(join(here, dir, 'Nargo.toml'))) continue;
  const n = Number(m[2]);
  const key = randomBytes(32), iv = randomBytes(12), pt = randomBytes(n);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  let toml = `key = ${arr(key)}\niv = ${arr(iv)}\nct = ${arr(ct)}\n`;
  if (m[1] === 'gcm') toml += `tag = ${arr(tag)}\n`;
  writeFileSync(join(here, dir, 'Prover.toml'), toml);
  const packed = [];
  for (let i = 0; i < n; i++) {
    const k = Math.floor(i / 31);
    packed[k] = (packed[k] ?? 0n) * 256n + BigInt(pt[i]);
  }
  writeFileSync(join(here, dir, 'expected.json'), JSON.stringify(packed.map(String)));
  // A copy with one tag byte flipped, for the refusal check.
  if (m[1] === 'gcm') {
    const bad = Buffer.from(tag); bad[0] ^= 1;
    writeFileSync(join(here, dir, 'Prover_badtag.toml'), toml.replace(/^tag = .*$/m, `tag = ${arr(bad)}`));
  }
}
