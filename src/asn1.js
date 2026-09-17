/* asn1.js: minimal DER encoder and decoder.
 *
 * Scope is deliberately narrow. This handles exactly the DER that RFC 3161
 * timestamping needs and nothing else. It is not a general ASN.1 library and should
 * not grow into one: every construct it does not implement is a construct that
 * cannot silently misparse.
 *
 * DER, not BER. Definite lengths only. An indefinite length (0x80) is rejected
 * rather than tolerated, because accepting it would mean accepting two different
 * encodings of the same value, and a signature is computed over bytes.
 */

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8String: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PrintableString: 0x13,
  IA5String: 0x16,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
  BMPString: 0x1e,
};

/* ---------------------------------------------------------------- encoding -- */

/** Encode a length in DER short or long form. */
function encodeLength(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** Wrap a payload in tag + length. */
export function derTlv(tag, payload) {
  const body = payload instanceof Uint8Array ? payload : derConcat(payload);
  const len = encodeLength(body.length);
  const out = new Uint8Array(1 + len.length + body.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(body, 1 + len.length);
  return out;
}

export function derConcat(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

export const derSeq = (...items) => derTlv(TAG.SEQUENCE, derConcat(items));
export const derSet = (...items) => derTlv(TAG.SET, derConcat(items));
export const derNull = () => Uint8Array.of(TAG.NULL, 0x00);
export const derBool = (b) => Uint8Array.of(TAG.BOOLEAN, 0x01, b ? 0xff : 0x00);
export const derOctetString = (bytes) => derTlv(TAG.OCTET_STRING, bytes);

/**
 * DER INTEGER from raw big-endian magnitude bytes, non-negative.
 *
 * Two rules that are easy to get wrong and produce a request no TSA will accept:
 * leading zero bytes are stripped, and a leading byte with the high bit set gets a
 * 0x00 prefix so the value is not read as negative.
 */
export function derInteger(magnitude) {
  let i = 0;
  while (i < magnitude.length - 1 && magnitude[i] === 0x00) i++;
  let body = magnitude.subarray(i);
  if (body.length === 0) body = Uint8Array.of(0x00);
  if (body[0] & 0x80) body = derConcat([Uint8Array.of(0x00), body]);
  return derTlv(TAG.INTEGER, body);
}

export function derIntegerFromNumber(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('integerFromNumber: non-negative safe integer required');
  if (n === 0) return derTlv(TAG.INTEGER, Uint8Array.of(0));
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return derInteger(Uint8Array.from(bytes));
}

/** Encode a dotted OID string, for example '2.16.840.1.101.3.4.2.1'. */
export function derOid(dotted) {
  const parts = dotted.split('.').map(Number);
  if (parts.length < 2) throw new Error('oid: need at least two arcs');
  const body = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [v & 0x7f];
    v = Math.floor(v / 128);
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    body.push(...stack);
  }
  return derTlv(TAG.OID, Uint8Array.from(body));
}

/* ---------------------------------------------------------------- decoding -- */

/**
 * A parsed TLV.
 *   tag        the raw tag byte
 *   header     byte length of tag + length octets
 *   length     byte length of the content
 *   start,end  offsets of the CONTENT within the original buffer
 *   outerStart,outerEnd  offsets of tag + length + content
 *
 * Offsets are kept against the ORIGINAL buffer rather than copying, because
 * signature verification needs the exact original bytes of a substructure, and any
 * re-encoding risks producing a different, equally valid DER that verifies against
 * nothing.
 */
export function derParse(buf, offset = 0) {
  if (offset >= buf.length) throw new Error('DER: read past end of buffer');
  const tag = buf[offset];
  let p = offset + 1;
  if (p >= buf.length) throw new Error('DER: truncated after tag');

  let length = buf[p++];
  if (length === 0x80) throw new Error('DER: indefinite length is BER, not DER, and is refused');
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count > 6) throw new Error('DER: length field too large');
    if (p + count > buf.length) throw new Error('DER: truncated length field');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[p++];
  }

  const start = p;
  const end = start + length;
  if (end > buf.length) throw new Error(`DER: content runs past end of buffer (need ${end}, have ${buf.length})`);

  return { tag, header: start - offset, length, start, end, outerStart: offset, outerEnd: end, buf };
}

/** Parse every TLV directly inside a constructed node. */
export function derChildren(node) {
  const out = [];
  let p = node.start;
  while (p < node.end) {
    const child = derParse(node.buf, p);
    out.push(child);
    p = child.outerEnd;
  }
  return out;
}

/** Content bytes of a node, as a view onto the original buffer. */
export const derContent = (node) => node.buf.subarray(node.start, node.end);

/** Full tag + length + content bytes, as a view onto the original buffer. */
export const derOuter = (node) => node.buf.subarray(node.outerStart, node.outerEnd);

export function derIsContext(node, number) {
  return (node.tag & 0xc0) === 0x80 && (node.tag & 0x1f) === number;
}

export function derIsConstructed(node) {
  return (node.tag & 0x20) !== 0;
}

/** Decode an INTEGER node to a hex string. Serial numbers exceed Number range. */
export function derIntToHex(node) {
  const c = derContent(node);
  let i = 0;
  while (i < c.length - 1 && c[i] === 0x00) i++;
  let s = '';
  for (; i < c.length; i++) s += c[i].toString(16).padStart(2, '0');
  return s.length ? s : '00';
}

/** Decode a small INTEGER node to a Number. Throws if it will not fit safely. */
export function derIntToNumber(node) {
  const c = derContent(node);
  if (c.length > 6) throw new Error('DER: integer too large for a safe Number');
  let v = 0;
  for (let i = 0; i < c.length; i++) v = v * 256 + c[i];
  return v;
}

/** Decode an OID node to its dotted string. */
export function derOidToString(node) {
  const c = derContent(node);
  if (c.length === 0) return '';
  const first = Math.floor(c[0] / 40);
  const second = c[0] % 40;
  const arcs = [first, second];
  let v = 0;
  for (let i = 1; i < c.length; i++) {
    v = v * 128 + (c[i] & 0x7f);
    if ((c[i] & 0x80) === 0) { arcs.push(v); v = 0; }
  }
  return arcs.join('.');
}

/**
 * Decode a GeneralizedTime node to a JS Date, plus the literal string as it appeared.
 *
 * The literal is kept and reported alongside the Date because the token's own text is
 * the evidence and a Date is an interpretation of it. Fractional seconds are
 * preserved in the literal even where the Date rounds them.
 */
export function derGeneralizedTime(node) {
  const raw = new TextDecoder('ascii').decode(derContent(node));
  const m = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/);
  if (!m) throw new Error(`DER: unsupported GeneralizedTime form: ${raw}`);
  const [, y, mo, d, h, mi, s, frac] = m;
  const ms = frac ? Math.round(parseFloat(frac) * 1000) : 0;
  const date = new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s, ms));
  return { date, raw };
}

/** Decode a string node, covering the string types that appear in X.509 names. */
export function derStringValue(node) {
  const c = derContent(node);
  if (node.tag === TAG.BMPString) {
    let s = '';
    for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
    return s;
  }
  return new TextDecoder('utf-8').decode(c);
}
