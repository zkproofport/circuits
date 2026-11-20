// Prover.toml for fields/: one key and IV, each field AES-256-GCM with the key
// as AAD (the format of toss/toss-cert-java-sdk AESCipher), plus a copy whose
// DI tag has one bit flipped.
import { createCipheriv, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const dir = join(dirname(fileURLToPath(import.meta.url)), 'fields');
const key = randomBytes(32), iv = randomBytes(12);
const enc = (s) => { const c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(key);
  const ct = Buffer.concat([c.update(Buffer.from(s, 'utf8')), c.final()]); return [ct, c.getAuthTag()]; };
const birthday = '19900101', name = '홍길동김철수', di = randomBytes(66).toString('base64');
const fields = { birthday, name, di };
const arr = (b) => `[${[...b].join(', ')}]`;
let toml = `key = ${arr(key)}\niv = ${arr(iv)}\n`;
for (const [k, v] of Object.entries(fields)) {
  const [ct, tag] = enc(v);
  toml += `${k} = ${arr(ct)}\n${k}_tag = ${arr(tag)}\n`;
}
writeFileSync(join(dir, 'Prover.toml'), toml);
const bad = toml.replace(/^di_tag = \[(\d+)/m, (m, d) => `di_tag = [${Number(d) ^ 1}`);
writeFileSync(join(dir, 'Prover_badtag.toml'), bad);
const pack = (b) => { const out = []; b.forEach((x, i) => { const k = Math.floor(i / 31); out[k] = (out[k] ?? 0n) * 256n + BigInt(x); }); return out; };
const d = pack([...Buffer.from(di)]), t = pack([...Buffer.from(birthday), ...Buffer.from(name)]);
writeFileSync(join(dir, 'expected.json'), JSON.stringify([...d, ...t].map(String)));
console.log('lengths', Buffer.from(birthday).length, Buffer.from(name).length, di.length);
