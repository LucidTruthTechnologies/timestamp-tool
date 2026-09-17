/* roundtrip.mjs: assert our DER against artifacts openssl produced.
 *
 * These are not unit tests over our own assumptions. Every expected value comes
 * from a real openssl invocation or a real authority response, so a green run means
 * our encoder agrees with the reference implementation, not with itself.
 *
 * Usage: node test/roundtrip.mjs <fixture-dir>
 * The fixture dir must contain probe.tsq and {freetsa,digicert,sectigo}.tsr
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import * as tsp from '../src/tsp.js';
import { toHex, fromHex, sha256 } from '../src/sha256.js';

const dir = process.argv[2];
if (!dir) { console.error('usage: node test/roundtrip.mjs <fixture-dir>'); process.exit(2); }

let pass = 0, fail = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? `\n        ${detail}` : ''}`); }
};

const read = (f) => new Uint8Array(readFileSync(join(dir, f)));

/* ---- 1. TimeStampReq must be byte-identical to openssl's ------------------ */
console.log('\nTimeStampReq encoder vs openssl ts -query');

const refTsq = read('probe.tsq');
const refParsed = parseRefTsq(refTsq);
const mine = tsp.buildTimeStampReq({
  digest: refParsed.imprint,
  hashOid: tsp.OID.sha256,
  nonce: refParsed.nonceMagnitude,
  certReq: true,
});

ok('byte-identical to openssl output', eqBytes(mine, refTsq),
   `openssl: ${toHex(refTsq)}\n        ours:    ${toHex(mine)}`);
ok('same length as openssl output', mine.length === refTsq.length,
   `openssl ${refTsq.length} B, ours ${mine.length} B`);

/* Minimal independent reader so the comparison does not lean on our own parser. */
function parseRefTsq(b) {
  // SEQUENCE { INTEGER 1, SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }, INTEGER nonce, BOOLEAN }
  const imprintStart = b.indexOf(0x04, 20);
  const imprint = b.subarray(imprintStart + 2, imprintStart + 2 + 32);
  const afterImprint = imprintStart + 2 + 32;
  if (b[afterImprint] !== 0x02) throw new Error('fixture: expected INTEGER nonce');
  const nonceLen = b[afterImprint + 1];
  const nonceMagnitude = b.subarray(afterImprint + 2, afterImprint + 2 + nonceLen);
  return { imprint, nonceMagnitude };
}

/* ---- 2. Parse every real response ---------------------------------------- */
const authorities = ['freetsa', 'digicert', 'sectigo', 'sigstore'];
const expectedImprint = toHex(refParsed.imprint);

for (const name of authorities) {
  const file = `${name}.tsr`;
  if (!existsSync(join(dir, file))) { console.log(`\n${name}: no fixture, skipped`); continue; }

  console.log(`\n${name}.tsr`);
  const resp = tsp.parseTimeStampResp(read(file));

  ok('status is granted', resp.granted, `status=${resp.statusName}`);
  if (!resp.token) { ok('token present', false); continue; }

  const t = resp.token.tstInfo;
  ok('messageImprint matches the document hash', t.imprintHex === expectedImprint,
     `token ${t.imprintHex}\n        doc   ${expectedImprint}`);
  ok('nonce echoed back', t.nonceHex === toHex(refParsed.nonceMagnitude).replace(/^0+(?=..)/, ''),
     `token ${t.nonceHex}, sent ${toHex(refParsed.nonceMagnitude)}`);
  ok('genTime parsed to a real date', t.genTime instanceof Date && !isNaN(t.genTime),
     `raw=${t.genTimeRaw}`);
  ok('at least one certificate embedded', resp.token.certificates.length > 0,
     `count=${resp.token.certificates.length}`);

  const signerCert = tsp.findSignerCertificate(resp.token);
  ok('signer certificate located in the token', signerCert !== null);

  const sa = resp.token.signer.signedAttrs;
  ok('signedAttrs present', sa !== null);
  if (sa) {
    ok('signedAttrs contentType is id-ct-TSTInfo', sa.contentType === tsp.OID.ctTSTInfo,
       `got ${sa.contentType}`);
    /* The digest algorithm is READ FROM THE SIGNER, never assumed. Across the four
     * authorities this tool talks to it is SHA-512, SHA-256, SHA-384 and SHA-256
     * respectively. An earlier version of this test hardcoded SHA-256 and reported
     * two false failures, which is the cheapest possible reminder that a probe
     * shaped like the familiar case lies about the unfamiliar one. */
    const alg = resp.token.signer.digestAlgorithm;
    const digest = await digestBy(alg, resp.token.tstInfoBytes);
    const eq = sa.messageDigest && eqBytes(sa.messageDigest, digest);
    ok(`signedAttrs messageDigest matches ${alg} of TSTInfo`, !!eq);
  }

  console.log(`        policy      ${t.policy}`);
  console.log(`        serial      0x${t.serialHex.toUpperCase()}`);
  console.log(`        genTime     ${t.genTimeRaw}  (${t.genTime.toISOString()})`);
  console.log(`        accuracy    ${t.accuracy ? JSON.stringify(t.accuracy) : 'ABSENT'}`);
  console.log(`        ordering    ${t.ordering}`);
  console.log(`        TSA field   ${t.tsaName ? t.tsaName.value : 'ABSENT'}`);
  console.log(`        certs       ${resp.token.certificates.length}`);
  if (signerCert) {
    console.log(`        signer      ${signerCert.subject}`);
    console.log(`        notAfter    ${signerCert.notAfter.toISOString()}`);
    console.log(`        key         ${signerCert.keyBits ? signerCert.keyBits + '-bit RSA' : signerCert.curveOid ?? signerCert.keyAlgOid}`);
    console.log(`        sigAlg      ${resp.token.signer.sigAlgOid}`);
  }
}

async function digestBy(alg, bytes) {
  return new Uint8Array(await crypto.subtle.digest(alg, bytes));
}

function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
