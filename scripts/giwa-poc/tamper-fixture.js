#!/usr/bin/env node
/**
 * Derive a DELIBERATELY BROKEN fixture from a good one, by rewriting one
 * 32-byte array in a Prover.toml.
 *
 * Why not generate these from the chain like the good fixtures: a build must
 * not need the network to prove that the circuit refuses things. Every refusal
 * case is one field away from a committed fixture, so it is produced here with
 * no RPC and no keys.
 *
 * Usage:
 *   tamper-fixture.js <in.toml> <out.toml> zero <field>
 *   tamper-fixture.js <in.toml> <out.toml> fill <field>
 *   tamper-fixture.js <in.toml> <out.toml> copy <field> <other.toml>
 */
const fs = require('fs');

const [, , IN, OUT, OP, FIELD, OTHER] = process.argv;
if (!IN || !OUT || !OP || !FIELD) {
  console.error('Usage: tamper-fixture.js <in.toml> <out.toml> zero|fill|copy <field> [other.toml]');
  process.exit(1);
}

/** The `name = [ ... ]` block for a one-dimensional byte array. */
function blockOf(text, field) {
  const re = new RegExp(`(^|\\n)${field}\\s*=\\s*\\[[^\\]]*\\]`, 'm');
  const m = text.match(re);
  if (!m) throw new Error(`field not found: ${field}`);
  return m[0].replace(/^\n/, '');
}

function rendered(field, bytes) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += 8) {
    rows.push('    ' + bytes.slice(i, i + 8).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', '));
  }
  return `${field} = [\n${rows.join(',\n')}\n]`;
}

const text = fs.readFileSync(IN, 'utf8');
const current = blockOf(text, FIELD);

let replacement;
if (OP === 'zero') {
  replacement = rendered(FIELD, new Array(32).fill(0));
} else if (OP === 'fill') {
  replacement = rendered(FIELD, new Array(32).fill(0xab));
} else if (OP === 'copy') {
  if (!OTHER) throw new Error('copy needs a source file');
  replacement = blockOf(fs.readFileSync(OTHER, 'utf8'), FIELD);
} else {
  throw new Error(`unknown operation: ${OP}`);
}

if (replacement.trim() === current.trim()) {
  // The check the mutation lesson demands: a "tamper" that changed nothing
  // would make the case pass for the wrong reason.
  throw new Error(`tamper changed nothing: ${FIELD} in ${IN} already holds that value`);
}

fs.writeFileSync(OUT, text.replace(current, replacement));
console.log(`${OP} ${FIELD} -> ${OUT}`);
