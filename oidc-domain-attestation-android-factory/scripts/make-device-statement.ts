/**
 * Prepare a REAL-device run of this circuit (the phone signs, this machine proves).
 *
 *   tsx make-device-statement.ts <capture dir>
 *
 * Writes <capture dir>/jwt-key.pem (a fresh RSA-2048 key standing in for the
 * provider's key), statement.bin (the 313-byte provider-key statement for that
 * key, Google, now) and now.txt. Then:
 *   proofport-app/scripts/capture-android-attestation.sh <serial> <dir>/statement.bin <dir>
 * and make-fixtures.ts with ANDROID_DEVICE_CAPTURE=<dir> writes real_device.toml.
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { providerKeyStatement } from "../../oidc-domain-attestation/scripts/oidc-inputs.ts";

const dir = process.argv[2];
if (!dir) throw new Error("usage: tsx make-device-statement.ts <capture dir>");
fs.mkdirSync(dir, { recursive: true });
const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
const n = (key.publicKey.export({ format: "jwk" }) as { n: string }).n;
const now = BigInt(Math.floor(Date.now() / 1000));
fs.writeFileSync(path.join(dir, "jwt-key.pem"), key.privateKey.export({ format: "pem", type: "pkcs8" }) as string, { mode: 0o600 });
fs.writeFileSync(path.join(dir, "statement.bin"), Buffer.from(providerKeyStatement(0, now, n)));
fs.writeFileSync(path.join(dir, "now.txt"), now.toString());
console.log(`statement for now=${now} written to ${dir}`);
