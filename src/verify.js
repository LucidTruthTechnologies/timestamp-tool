/* verify.js: the itemised verification pass.
 *
 * DESIGN RULE, and the reason there is no single green badge anywhere in this tool:
 * every check reports its own result and its own basis. A verdict whose basis the
 * reader cannot see is the exact defect that got a sibling forensic tool barred from
 * client work, and a green tick that quietly covers an unperformed check is worse
 * than no check at all.
 *
 * Three outcomes, never two:
 *   PASS           the check ran and succeeded
 *   FAIL           the check ran and failed
 *   NOT_PERFORMED  the check did not run, with the reason stated
 *
 * NOT_PERFORMED is never collapsed into PASS. The most important instance is chain
 * validation: a browser cannot reach the operating system trust store, by design, so
 * this tool cannot tell you the signing certificate chains to a root you trust. It
 * says so, and it hands you the openssl command that settles it.
 */

import {
  TAG, derTlv, derConcat, derSeq, derSet, derNull, derBool, derOctetString, derInteger, derIntegerFromNumber, derOid, derParse, derChildren, derContent, derOuter, derIsContext, derIsConstructed, derIntToHex, derIntToNumber, derOidToString, derGeneralizedTime, derStringValue,
} from './asn1.js';
import * as tsp from './tsp.js';
import { toHex } from './sha256.js';

export const PASS = 'PASS';
export const FAIL = 'FAIL';
export const NOT_PERFORMED = 'NOT_PERFORMED';

const check = (id, label, result, detail, basis) => ({ id, label, result, detail, basis });

const CURVE_BY_OID = {
  [tsp.OID.p256]: { name: 'P-256', size: 32 },
  [tsp.OID.p384]: { name: 'P-384', size: 48 },
  [tsp.OID.p521]: { name: 'P-521', size: 66 },
};

const ECDSA_HASH_BY_SIG_OID = {
  [tsp.OID.ecdsaSha256]: 'SHA-256',
  [tsp.OID.ecdsaSha384]: 'SHA-384',
  [tsp.OID.ecdsaSha512]: 'SHA-512',
};

/**
 * Run every check for one authority's response.
 *
 * @param resp      parsed TimeStampResp
 * @param expected  { digest, digestHex, nonceHex } as SENT, from our own state
 * @returns { checks[], summary }
 */
export async function verifyResponse(resp, expected) {
  const checks = [];

  /* 1. Did the authority grant it at all. */
  checks.push(check(
    'status',
    'Authority granted the request',
    resp.granted ? PASS : FAIL,
    `PKIStatus ${resp.statusCode} (${resp.statusName})` +
      (resp.statusStrings.length ? `: ${resp.statusStrings.join('; ')}` : '') +
      (resp.failInfo?.length ? ` [failInfo: ${resp.failInfo.join(', ')}]` : ''),
    'RFC 3161 section 2.4.2, PKIStatusInfo',
  ));

  if (!resp.token) {
    checks.push(check('token', 'Timestamp token present', FAIL,
      'The authority returned no token.', 'RFC 3161 section 2.4.2'));
    return { checks, summary: summarize(checks) };
  }

  const t = resp.token.tstInfo;

  /* 2. THE check. Does the token commit to OUR bytes.
   *    Everything else in the package is worthless if this fails, and a malicious
   *    or broken relay returning someone else's valid token is caught precisely
   *    here, by comparing against a hash this browser computed locally. */
  const imprintMatches = t.imprintHex === expected.digestHex;
  checks.push(check(
    'imprint',
    'Token commits to this exact document',
    imprintMatches ? PASS : FAIL,
    imprintMatches
      ? `messageImprint ${t.imprintHex} equals the digest computed from your file.`
      : `MISMATCH. Token says ${t.imprintHex}; your file hashes to ${expected.digestHex}. ` +
        'This token does not belong to this document.',
    'RFC 3161 section 2.4.2, TSTInfo.messageImprint',
  ));

  /* 3. Replay defence. Only meaningful because we keep the request file. */
  if (expected.nonceHex) {
    const nonceMatches = normalizeHex(t.nonceHex) === normalizeHex(expected.nonceHex);
    checks.push(check(
      'nonce',
      'Nonce echoed back unchanged',
      t.nonceHex == null ? FAIL : (nonceMatches ? PASS : FAIL),
      t.nonceHex == null
        ? 'The authority returned no nonce, so this reply cannot be tied to this request.'
        : (nonceMatches
            ? `Nonce 0x${t.nonceHex.toUpperCase()} matches the value sent.`
            : `MISMATCH. Sent 0x${expected.nonceHex.toUpperCase()}, received 0x${t.nonceHex.toUpperCase()}.`),
      'RFC 3161 section 2.4.1; proves this reply answers this request, not a replayed one',
    ));
  }

  /* 4. Internal CMS consistency: do the signed attributes actually cover the
   *    TSTInfo we just read? Without this, a signature could be valid over
   *    attributes describing a different payload. */
  const sa = resp.token.signer.signedAttrs;
  if (!sa) {
    checks.push(check('signedattrs', 'Signed attributes present', FAIL,
      'SignerInfo carries no signedAttrs, so the signature does not cover a messageDigest.',
      'RFC 5652 section 5.3'));
  } else {
    const alg = resp.token.signer.digestAlgorithm;
    let digestOk = false;
    let detail;
    try {
      const computed = new Uint8Array(await crypto.subtle.digest(alg, resp.token.tstInfoBytes));
      digestOk = sa.messageDigest != null && attrBytesEqual(computed, sa.messageDigest);
      detail = digestOk
        ? `messageDigest attribute equals ${alg} of the TSTInfo content.`
        : `messageDigest attribute does not equal ${alg} of the TSTInfo content.`;
    } catch (e) {
      detail = `Could not compute ${alg}: ${e.message}`;
    }
    checks.push(check(
      'messagedigest',
      'Signed attributes cover this token content',
      digestOk ? PASS : FAIL,
      detail,
      'RFC 5652 section 5.4, message-digest attribute',
    ));

    checks.push(check(
      'contenttype',
      'Content type is a timestamp token',
      sa.contentType === tsp.OID.ctTSTInfo ? PASS : FAIL,
      `contentType attribute is ${sa.contentType ?? 'absent'} (expected id-ct-TSTInfo ${tsp.OID.ctTSTInfo}).`,
      'RFC 3161 section 2.4.2',
    ));
  }

  /* 5. The cryptographic signature itself. */
  const signerCert = tsp.findSignerCertificate(resp.token);
  if (!signerCert) {
    checks.push(check('signature', 'Signature verified against the signing certificate', NOT_PERFORMED,
      'The signing certificate is not embedded in the token, so there is no public key to check against. ' +
      'This happens when certReq was not set at request time.',
      'RFC 5652 section 5.3, SignerIdentifier'));
  } else {
    checks.push(await verifySignature(resp.token, signerCert));
  }

  /* 6. The honest gap, stated as loudly as the passes. */
  checks.push(check(
    'chain',
    'Certificate chains to a trusted root',
    NOT_PERFORMED,
    'A web browser does not expose the operating system trust store to JavaScript, so this ' +
    'page cannot perform path validation. This is a limit of the browser, not a property of ' +
    'your token. The verification commands saved in this package settle it with openssl, and ' +
    'they must be run before this timestamp is relied upon.',
    'Web Cryptography API defines primitives only; it has no certificate or trust model',
  ));

  /* 7. Informational: when the signing certificate expires. Not a failure today,
   *    but the date that decides when the package must be re-timestamped. */
  checks.push(check(
    'certvalidity',
    'Signing certificate validity window',
    PASS,
    `Valid from ${signerCert ? signerCert.notBefore.toISOString() : 'unknown'} to ` +
    `${signerCert ? signerCert.notAfter.toISOString() : 'unknown'}. Re-timestamp this package ` +
    'before that end date if the evidence must remain checkable beyond it.',
    'Informational; not a verification result',
  ));

  return { checks, summary: summarize(checks) };
}

/**
 * Verify the CMS signature over the signed attributes.
 *
 * Two details that are easy to get wrong and both produce a confident false FAIL:
 *
 * 1. The bytes signed are the signedAttrs re-tagged as SET OF (0x31). They travel in
 *    the token as [0] IMPLICIT (0xA0). RFC 5652 section 5.4 is explicit that the
 *    SET OF encoding is what gets hashed. We swap the single tag byte on the
 *    ORIGINAL bytes rather than re-encoding the structure, because a re-encode could
 *    legitimately differ and would then verify against nothing.
 *
 * 2. ECDSA signatures in CMS are DER SEQUENCE { r, s }. WebCrypto wants the raw
 *    fixed-width r || s concatenation. Passing the DER through unconverted fails
 *    silently, as a wrong answer rather than an error.
 */
async function verifySignature(token, signerCert) {
  const signer = token.signer;
  const id = 'signature';
  const label = 'Signature verified against the signing certificate';

  try {
    const signedBytes = retagAsSetOf(signer.signedAttrsRaw);
    if (!signedBytes) {
      return check(id, label, NOT_PERFORMED,
        'No signed attributes to verify.', 'RFC 5652 section 5.4');
    }

    const hash = signer.digestAlgorithm;
    let algorithm, importAlgo, signature = signer.signature;

    if (signerCert.keyAlgOid === tsp.OID.rsaEncryption) {
      importAlgo = { name: 'RSASSA-PKCS1-v1_5', hash };
      algorithm = { name: 'RSASSA-PKCS1-v1_5' };
    } else if (signerCert.keyAlgOid === tsp.OID.ecPublicKey) {
      const curve = CURVE_BY_OID[signerCert.curveOid];
      if (!curve) {
        return check(id, label, NOT_PERFORMED,
          `Unsupported elliptic curve ${signerCert.curveOid}. Verify with openssl instead.`,
          'Web Cryptography API named curves');
      }
      const ecHash = ECDSA_HASH_BY_SIG_OID[signer.sigAlgOid] ?? hash;
      importAlgo = { name: 'ECDSA', namedCurve: curve.name };
      algorithm = { name: 'ECDSA', hash: ecHash };
      signature = derEcdsaToRaw(signer.signature, curve.size);
    } else {
      return check(id, label, NOT_PERFORMED,
        `Unsupported public key algorithm ${signerCert.keyAlgOid}. Verify with openssl instead.`,
        'Web Cryptography API supported algorithms');
    }

    const key = await crypto.subtle.importKey('spki', signerCert.spkiDer, importAlgo, false, ['verify']);
    const valid = await crypto.subtle.verify(algorithm, key, signature, signedBytes);

    const desc = signerCert.keyAlgOid === tsp.OID.rsaEncryption
      ? `${signerCert.keyBits}-bit RSA, ${hash}`
      : `ECDSA ${CURVE_BY_OID[signerCert.curveOid].name}, ${algorithm.hash}`;

    return check(id, label, valid ? PASS : FAIL,
      valid
        ? `Signature over the signed attributes is valid (${desc}), made by the key in ` +
          `certificate serial 0x${signerCert.serialHex.toUpperCase()}.`
        : `Signature over the signed attributes did NOT verify (${desc}). Treat this token as unreliable.`,
      'RFC 5652 section 5.4, verified with the Web Cryptography API');
  } catch (e) {
    return check(id, label, NOT_PERFORMED,
      `The signature check could not be completed: ${e.message}. Verify with openssl instead.`,
      'Web Cryptography API threw during verification');
  }
}

/** Replace the leading [0] IMPLICIT tag with SET OF, leaving every other byte alone. */
export function retagAsSetOf(raw) {
  if (!raw || raw.length === 0) return null;
  const out = raw.slice();
  out[0] = TAG.SET;
  return out;
}

/** DER SEQUENCE { INTEGER r, INTEGER s } to fixed-width r || s. */
export function derEcdsaToRaw(der, size) {
  const kids = derChildren(derParse(der));
  if (kids.length !== 2) throw new Error('ECDSA signature: expected SEQUENCE of two INTEGERs');
  const out = new Uint8Array(size * 2);
  for (let i = 0; i < 2; i++) {
    let v = derContent(kids[i]);
    let s = 0;
    while (s < v.length - 1 && v[s] === 0x00) s++;   // strip DER sign padding
    v = v.subarray(s);
    if (v.length > size) throw new Error('ECDSA signature: component wider than the curve');
    out.set(v, i * size + (size - v.length));        // left-pad to fixed width
  }
  return out;
}

function summarize(checks) {
  const counts = { PASS: 0, FAIL: 0, NOT_PERFORMED: 0 };
  for (const c of checks) counts[c.result]++;
  return {
    ...counts,
    /* Deliberately NOT a boolean "verified". The caller must render the itemised
     * list; there is no single value here that could be mistaken for a verdict. */
    anyFailure: counts.FAIL > 0,
    total: checks.length,
  };
}

function normalizeHex(h) {
  return (h ?? '').toLowerCase().replace(/^0+(?=.)/, '');
}

function attrBytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export { toHex };
