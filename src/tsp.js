/* tsp.js: RFC 3161 request construction and response parsing, plus the slice of
 * CMS and X.509 needed to read a timestamp token.
 *
 * Every structure here is read from the token itself. Nothing is assumed from the
 * request, because a response that merely echoes what we sent proves nothing: the
 * point of parsing is to find out what the authority actually said.
 */

import {
  TAG, derTlv, derConcat, derSeq, derSet, derNull, derBool, derOctetString, derInteger, derIntegerFromNumber, derOid, derParse, derChildren, derContent, derOuter, derIsContext, derIsConstructed, derIntToHex, derIntToNumber, derOidToString, derGeneralizedTime, derStringValue,
} from './asn1.js';
import { sha256, toHex } from './sha256.js';

export const OID = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  signedData: '1.2.840.113549.1.7.2',
  ctTSTInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
};

const HASH_BY_OID = {
  [OID.sha256]: 'SHA-256',
  [OID.sha384]: 'SHA-384',
  [OID.sha512]: 'SHA-512',
};

/** Human names for the attribute OIDs that appear in an X.509 Name. */
const NAME_OID = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
  '2.5.4.13': 'description', '1.2.840.113549.1.9.1': 'emailAddress',
};

/* ------------------------------------------------------- request building -- */

/**
 * Build a DER TimeStampReq.
 *
 * Produces bytes identical to:
 *   openssl ts -query -data FILE -sha256 -cert -out request.tsq
 * which the test suite asserts against a real openssl artifact. Byte identity is
 * not vanity: it means an examiner can regenerate our request with the standard
 * tool and get the same file, so the request is reproducible rather than trusted.
 *
 * certReq defaults to true. Omitting it yields a smaller token and a future
 * problem, because the signing certificate needed in year six is the one that was
 * current in year one.
 */
export function buildTimeStampReq({ digest, hashOid = OID.sha256, nonce, certReq = true }) {
  const messageImprint = derSeq(
    derSeq(derOid(hashOid), derNull()),
    derOctetString(digest),
  );

  const parts = [derIntegerFromNumber(1), messageImprint];
  if (nonce) parts.push(derInteger(nonce));
  if (certReq) parts.push(derBool(true));
  return derSeq(...parts);
}

/** 64 bits from the platform CSPRNG. Fresh for every submission, never reused. */
export function generateNonce() {
  const n = new Uint8Array(8);
  crypto.getRandomValues(n);
  // Guarantee a non-zero high byte so the nonce is always a full 8 significant
  // bytes after DER minimal-length encoding. Purely cosmetic for matching openssl.
  if (n[0] === 0) n[0] = 1;
  return n;
}

/* ------------------------------------------------------ response parsing --- */

const PKI_STATUS = {
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification',
};

const FAIL_INFO_BITS = {
  0: 'badAlg', 2: 'badRequest', 5: 'badDataFormat', 14: 'timeNotAvailable',
  15: 'unacceptedPolicy', 16: 'unacceptedExtension', 17: 'addInfoNotAvailable',
  25: 'systemFailure',
};

/**
 * Parse a TimeStampResp.
 *
 * Returns { statusCode, statusName, statusStrings, failInfo, granted, token }.
 * `token` is null when the authority refused. A refusal is a result, not an error:
 * the caller reports it and packages it, and never silently drops the authority.
 */
export function parseTimeStampResp(bytes) {
  const root = derParse(bytes);
  if (root.tag !== TAG.SEQUENCE) throw new Error('TimeStampResp: expected a SEQUENCE at the root');
  const kids = derChildren(root);
  if (kids.length < 1) throw new Error('TimeStampResp: empty');

  const statusInfo = derChildren(kids[0]);
  const statusCode = derIntToNumber(statusInfo[0]);
  const statusName = PKI_STATUS[statusCode] ?? `unknown(${statusCode})`;

  const statusStrings = [];
  let failInfo = null;
  for (let i = 1; i < statusInfo.length; i++) {
    const n = statusInfo[i];
    if (n.tag === TAG.SEQUENCE) {
      for (const s of derChildren(n)) statusStrings.push(derStringValue(s));
    } else if (n.tag === TAG.BIT_STRING) {
      failInfo = decodeFailInfo(n);
    }
  }

  const granted = statusCode === 0 || statusCode === 1;
  const tokenNode = kids.length > 1 ? kids[1] : null;

  return {
    statusCode,
    statusName,
    statusStrings,
    failInfo,
    granted,
    token: tokenNode ? parseTimeStampToken(derOuter(tokenNode)) : null,
    tokenBytes: tokenNode ? derOuter(tokenNode).slice() : null,
  };
}

function decodeFailInfo(node) {
  const c = derContent(node);
  if (c.length < 2) return [];
  const unused = c[0];
  const names = [];
  const totalBits = (c.length - 1) * 8 - unused;
  for (let bit = 0; bit < totalBits; bit++) {
    const byte = c[1 + (bit >> 3)];
    if (byte & (0x80 >> (bit & 7))) names.push(FAIL_INFO_BITS[bit] ?? `bit${bit}`);
  }
  return names;
}

/**
 * Parse a TimeStampToken, which is a CMS ContentInfo wrapping SignedData whose
 * encapsulated content is a TSTInfo.
 */
export function parseTimeStampToken(bytes) {
  const ci = derParse(bytes);
  const ciKids = derChildren(ci);
  const contentType = derOidToString(ciKids[0]);
  if (contentType !== OID.signedData) {
    throw new Error(`TimeStampToken: expected CMS SignedData, found OID ${contentType}`);
  }

  const explicit = ciKids[1];
  if (!derIsContext(explicit, 0)) throw new Error('TimeStampToken: missing [0] content');
  const sd = derChildren(explicit)[0];
  const sdKids = derChildren(sd);

  // version, digestAlgorithms, encapContentInfo, then optional [0] certs, [1] crls, then signerInfos.
  const encap = sdKids[2];
  const encapKids = derChildren(encap);
  const eContentType = derOidToString(encapKids[0]);
  if (eContentType !== OID.ctTSTInfo) {
    throw new Error(`TimeStampToken: encapsulated content is ${eContentType}, not id-ct-TSTInfo`);
  }
  const eContentOctets = derChildren(encapKids[1])[0];
  const tstInfoBytes = derContent(eContentOctets);

  let certs = [];
  let signerInfos = null;
  for (let i = 3; i < sdKids.length; i++) {
    const n = sdKids[i];
    if (derIsContext(n, 0)) {
      certs = derChildren(n)
        .filter((c) => c.tag === TAG.SEQUENCE) // skip [1]/[2] attribute-certificate forms
        .map((c) => parseCertificate(derOuter(c).slice()));
    } else if (n.tag === TAG.SET) {
      signerInfos = derChildren(n);
    }
  }
  if (!signerInfos || signerInfos.length === 0) throw new Error('TimeStampToken: no SignerInfo present');

  return {
    tstInfo: parseTSTInfo(tstInfoBytes),
    tstInfoBytes: tstInfoBytes.slice(),
    certificates: certs,
    signer: parseSignerInfo(signerInfos[0]),
    signerCount: signerInfos.length,
  };
}

/**
 * TSTInfo ::= SEQUENCE {
 *   version, policy, messageImprint, serialNumber, genTime,
 *   accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL,
 *   tsa [0] OPTIONAL, extensions [1] OPTIONAL }
 *
 * Optional fields are reported as null, never as a blank or a default. The
 * difference between "DigiCert omitted the TSA field" and "the TSA field was empty"
 * is the whole subject of the post this tool comes from.
 */
export function parseTSTInfo(bytes) {
  const kids = derChildren(derParse(bytes));
  let i = 0;

  const version = derIntToNumber(kids[i++]);
  const policy = derOidToString(kids[i++]);

  const miKids = derChildren(kids[i++]);
  const hashOid = derOidToString(derChildren(miKids[0])[0]);
  const imprint = derContent(miKids[1]).slice();

  const serialHex = derIntToHex(kids[i++]);
  const gt = derGeneralizedTime(kids[i++]);

  let accuracy = null;
  let ordering = false;
  let nonceHex = null;
  let tsaName = null;

  for (; i < kids.length; i++) {
    const n = kids[i];
    if (n.tag === TAG.SEQUENCE) accuracy = parseAccuracy(n);
    else if (n.tag === TAG.BOOLEAN) ordering = derContent(n)[0] !== 0;
    else if (n.tag === TAG.INTEGER) nonceHex = derIntToHex(n);
    else if (derIsContext(n, 0)) tsaName = parseGeneralName(derChildren(n)[0]);
  }

  return {
    version,
    policy,
    hashOid,
    hashAlgorithm: HASH_BY_OID[hashOid] ?? hashOid,
    imprint,
    imprintHex: toHex(imprint),
    serialHex,
    genTime: gt.date,
    genTimeRaw: gt.raw,
    accuracy,
    ordering,
    nonceHex,
    tsaName,
  };
}

function parseAccuracy(node) {
  const out = { seconds: null, millis: null, micros: null };
  for (const k of derChildren(node)) {
    if (k.tag === TAG.INTEGER) out.seconds = derIntToNumber(k);
    else if (derIsContext(k, 0)) out.millis = beToNumber(derContent(k));
    else if (derIsContext(k, 1)) out.micros = beToNumber(derContent(k));
  }
  return out;
}

function beToNumber(bytes) {
  let v = 0;
  for (const b of bytes) v = v * 256 + b;
  return v;
}

/** GeneralName, of which only directoryName [4] appears in practice for a TSA field. */
function parseGeneralName(node) {
  if (derIsContext(node, 4)) {
    const inner = derChildren(node)[0];
    return { type: 'directoryName', value: parseName(inner) };
  }
  if (derIsContext(node, 1) || derIsContext(node, 2) || derIsContext(node, 6)) {
    return { type: 'name', value: new TextDecoder().decode(derContent(node)) };
  }
  return { type: `context-${node.tag & 0x1f}`, value: '(unparsed form)' };
}

function parseSignerInfo(node) {
  const kids = derChildren(node);
  let i = 0;
  const version = derIntToNumber(kids[i++]);

  let issuerAndSerial = null;
  let subjectKeyId = null;
  const sid = kids[i++];
  if (sid.tag === TAG.SEQUENCE) {
    const sk = derChildren(sid);
    issuerAndSerial = { issuer: parseName(sk[0]), serialHex: derIntToHex(sk[1]) };
  } else if (derIsContext(sid, 0)) {
    subjectKeyId = toHex(derContent(sid));
  }

  const digestAlgOid = derOidToString(derChildren(kids[i++])[0]);

  let signedAttrsNode = null;
  if (derIsContext(kids[i], 0)) signedAttrsNode = kids[i++];

  const sigAlgOid = derOidToString(derChildren(kids[i++])[0]);
  const signature = derContent(kids[i++]).slice();

  return {
    version,
    issuerAndSerial,
    subjectKeyId,
    digestAlgOid,
    digestAlgorithm: HASH_BY_OID[digestAlgOid] ?? digestAlgOid,
    sigAlgOid,
    signature,
    signedAttrs: signedAttrsNode ? readSignedAttrs(signedAttrsNode) : null,
    /* The exact original bytes of the [0] IMPLICIT signedAttrs, tag included.
     * Kept because verification must re-tag these as SET OF (0x31) per RFC 5652
     * section 5.4 and hash the result; re-encoding the contents instead would
     * produce different bytes and verify against nothing. */
    signedAttrsRaw: signedAttrsNode ? derOuter(signedAttrsNode).slice() : null,
  };
}

function readSignedAttrs(node) {
  const out = { contentType: null, messageDigest: null, hasSigningCertificate: false, all: [] };
  for (const attr of derChildren(node)) {
    const ak = derChildren(attr);
    const type = derOidToString(ak[0]);
    const values = derChildren(ak[1]);
    out.all.push(type);
    if (type === OID.contentType && values.length) out.contentType = derOidToString(values[0]);
    else if (type === OID.messageDigest && values.length) out.messageDigest = derContent(values[0]).slice();
    else if (type === OID.signingCertificate || type === OID.signingCertificateV2) out.hasSigningCertificate = true;
  }
  return out;
}

/* ------------------------------------------------------------- X.509 ------- */

/**
 * Parse enough of a certificate to describe it and to verify a signature with it.
 * Extensions are not parsed: this tool makes no path-validation claim, so reading
 * basicConstraints or EKU would only invite one.
 */
export function parseCertificate(der) {
  const cert = derParse(der);
  const ck = derChildren(cert);
  const tbs = ck[0];
  const tk = derChildren(tbs);

  let i = 0;
  let version = 1;
  if (derIsContext(tk[0], 0)) {
    version = derIntToNumber(derChildren(tk[0])[0]) + 1;
    i = 1;
  }

  const serialHex = derIntToHex(tk[i++]);
  const innerSigAlg = derOidToString(derChildren(tk[i++])[0]);
  const issuer = parseName(tk[i++]);

  const validityKids = derChildren(tk[i++]);
  const notBefore = parseTime(validityKids[0]);
  const notAfter = parseTime(validityKids[1]);

  const subject = parseName(tk[i++]);
  const spkiNode = tk[i++];

  const spkiKids = derChildren(spkiNode);
  const keyAlgOid = derOidToString(derChildren(spkiKids[0])[0]);
  let curveOid = null;
  if (keyAlgOid === OID.ecPublicKey) {
    const params = derChildren(spkiKids[0])[1];
    if (params && params.tag === TAG.OID) curveOid = derOidToString(params);
  }
  // RSA modulus size, for the report. The BIT STRING has a leading unused-bits byte.
  let keyBits = null;
  if (keyAlgOid === OID.rsaEncryption) {
    const bs = derContent(spkiKids[1]).subarray(1);
    const rsaKey = derChildren(derParse(bs))[0];
    let m = derContent(rsaKey);
    let z = 0;
    while (z < m.length && m[z] === 0) z++;
    keyBits = (m.length - z) * 8;
  }

  return {
    version,
    serialHex,
    innerSigAlg,
    issuer,
    subject,
    notBefore,
    notAfter,
    keyAlgOid,
    curveOid,
    keyBits,
    spkiDer: derOuter(spkiNode).slice(),
    der: der instanceof Uint8Array ? der : new Uint8Array(der),
  };
}

function parseTime(node) {
  if (node.tag === TAG.GeneralizedTime) return derGeneralizedTime(node).date;
  const raw = new TextDecoder('ascii').decode(derContent(node));
  const m = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) throw new Error(`X.509: unsupported UTCTime form: ${raw}`);
  const yy = +m[1];
  const year = yy >= 50 ? 1900 + yy : 2000 + yy;
  return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

/** Render an X.509 Name as an RFC 4514 style string, outermost RDN last. */
export function parseName(node) {
  const parts = [];
  for (const rdn of derChildren(node)) {
    for (const atv of derChildren(rdn)) {
      const ak = derChildren(atv);
      const oidStr = derOidToString(ak[0]);
      const label = NAME_OID[oidStr] ?? oidStr;
      parts.push(`${label}=${derStringValue(ak[1])}`);
    }
  }
  return parts.join(', ');
}

/** Find the certificate a SignerInfo points at, by issuer+serial or by SKI. */
export function findSignerCertificate(token) {
  const { signer, certificates } = token;
  if (signer.issuerAndSerial) {
    const wantSerial = signer.issuerAndSerial.serialHex.toLowerCase();
    const wantIssuer = signer.issuerAndSerial.issuer;
    const hit = certificates.find(
      (c) => c.serialHex.toLowerCase() === wantSerial && c.issuer === wantIssuer,
    );
    if (hit) return hit;
  }
  return null;
}

/** DER to PEM. Used for the chain files inside the package. */
export function toPem(der, label = 'CERTIFICATE') {
  let b64 = '';
  const chunk = 0x8000;
  let bin = '';
  for (let i = 0; i < der.length; i += chunk) {
    bin += String.fromCharCode.apply(null, der.subarray(i, i + chunk));
  }
  b64 = btoa(bin);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export { sha256, toHex };
