/* tamper.mjs: prove the verifier FAILS when it should.
 *
 * A verifier that has only ever been run on good input is not known to work. These
 * cases corrupt a real DigiCert token four different ways and assert that each
 * corruption is caught.
 *
 * The result table below is the empirical argument for why this tool shows an
 * itemised list of checks and never a single green badge. Each tamper is caught by
 * exactly ONE check, and the others keep passing, truthfully:
 *
 *   tamper                     imprint  nonce  messagedigest  signature
 *   wrong document             FAIL     pass   pass           PASS
 *   replayed (wrong nonce)     pass     FAIL   pass           PASS
 *   byte flipped in TSTInfo    pass     pass   FAIL           PASS
 *   byte flipped in signature  pass     pass   pass           FAIL
 *
 * Read the first row carefully. "Signature verified" is TRUE for a token that has
 * nothing to do with your document: DigiCert really did sign it. A tool that
 * collapsed these four checks into one tick would show green on a worthless token.
 *
 * Usage: node test/tamper.mjs <fixture-dir>
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as tsp from '../src/tsp.js';
import * as V from '../src/verify.js';
import { toHex } from '../src/sha256.js';

const dir = process.argv[2];
if (!dir) { console.error('usage: node test/tamper.mjs <fixture-dir>'); process.exit(2); }

const read = (f) => new Uint8Array(readFileSync(join(dir, f)));
const doc = read('probe.txt');
const docHash = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', doc)));
const raw = read('digicert.tsr');
const tsq = read('probe.tsq');

const imprintOff = tsq.indexOf(0x04, 20);
const afterImprint = imprintOff + 2 + 32;
const nonceHex = toHex(tsq.subarray(afterImprint + 2, afterImprint + 2 + tsq[afterImprint + 1]))
  .replace(/^0+(?=.)/, '');

const baseline = tsp.parseTimeStampResp(raw);

let pass = 0, fail = 0;
const expect = (name, checks, id, want) => {
  const got = checks.find((c) => c.id === id)?.result;
  if (got === want) { pass++; console.log(`  PASS  ${name}: ${id} is ${want}`); }
  else { fail++; console.log(`  FAIL  ${name}: ${id} is ${got}, expected ${want}`); }
};

const run = async (bytes, expected) =>
  (await V.verifyResponse(tsp.parseTimeStampResp(bytes), expected)).checks;

function indexOfSub(hay, needle) {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

console.log('\nControl: an untouched token must pass everything checkable');
{
  const c = await run(raw, { digestHex: docHash, nonceHex });
  expect('control', c, 'imprint', V.PASS);
  expect('control', c, 'nonce', V.PASS);
  expect('control', c, 'messagedigest', V.PASS);
  expect('control', c, 'signature', V.PASS);
  expect('control', c, 'chain', V.NOT_PERFORMED);
}

console.log('\nTamper 1: the token belongs to a different document');
{
  const c = await run(raw, { digestHex: '00'.repeat(32), nonceHex });
  expect('wrong document', c, 'imprint', V.FAIL);
  // Truthfully still valid. This is the row that justifies the whole design.
  expect('wrong document', c, 'signature', V.PASS);
}

console.log('\nTamper 2: a replayed response, answering a different request');
{
  const c = await run(raw, { digestHex: docHash, nonceHex: 'deadbeefdeadbeef' });
  expect('replayed', c, 'nonce', V.FAIL);
  expect('replayed', c, 'imprint', V.PASS);
}

console.log('\nTamper 3: one byte altered inside the signed TSTInfo');
{
  const t = raw.slice();
  const at = indexOfSub(t, baseline.token.tstInfoBytes);
  t[at + baseline.token.tstInfoBytes.length - 5] ^= 0x01;
  const c = await run(t, { digestHex: docHash, nonceHex });
  expect('tstinfo byte flip', c, 'messagedigest', V.FAIL);
}

console.log('\nTamper 4: one byte altered inside the signature');
{
  const s = raw.slice();
  const at = indexOfSub(s, baseline.token.signer.signature);
  s[at + 10] ^= 0x01;
  const c = await run(s, { digestHex: docHash, nonceHex });
  expect('signature byte flip', c, 'signature', V.FAIL);
  expect('signature byte flip', c, 'messagedigest', V.PASS);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
