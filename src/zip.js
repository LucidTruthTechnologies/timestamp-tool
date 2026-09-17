/* zip.js: a ZIP writer built for ASiC conformance and for large files.
 *
 * WHY HAND-ROLLED rather than a library:
 *
 * ETSI EN 319 162-1 Annex A.1 requires, normatively, that the `mimetype` entry is
 * the FIRST file in the container, is STORED rather than deflated, and carries a
 * ZERO-LENGTH extra field (the extra field length at offset 28 must be zero). Most
 * JavaScript zip libraries add an extra field to every entry by default, commonly a
 * timestamp field. That produces a container that opens perfectly in every unzip
 * tool on earth and is silently NON-CONFORMANT, so an ASiC validator rejects it.
 * A failure that looks exactly like success is the kind this project cannot afford,
 * and controlling the bytes is the only way to be sure.
 *
 * Everything is STORED, never deflated. Compression would save little on tokens and
 * certificates, and it costs byte-fidelity of the document, which is the one thing
 * this container exists to preserve.
 *
 * ZIP64 is emitted when any entry or the archive as a whole crosses 4 GiB. A writer
 * that ignores this produces a corrupt archive at the boundary with no error, which
 * is the second failure-shaped-like-success in this file.
 */

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;

const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;
const CRC_CHUNK = 4 * 1024 * 1024;

/* ---------------------------------------------------------------- CRC-32 --- */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export class Crc32 {
  constructor() { this.c = 0xffffffff; }
  update(bytes) {
    let c = this.c;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    this.c = c;
    return this;
  }
  digest() { return (this.c ^ 0xffffffff) >>> 0; }
}

export function crc32(bytes) { return new Crc32().update(bytes).digest(); }

/* ------------------------------------------------------------- writing ---- */

function u16(v) { return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff); }
function u32(v) { return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff); }

/** 64-bit little-endian, built from a JS number (safe to 2^53, far beyond need). */
function u64(v) {
  const out = new Uint8Array(8);
  let n = v;
  for (let i = 0; i < 8; i++) { out[i] = n & 0xff; n = Math.floor(n / 256); }
  return out;
}

function cat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** MS-DOS date and time. Second resolution is 2s; this is metadata, never evidence. */
function dosDateTime(date) {
  const y = Math.max(1980, date.getUTCFullYear());
  const time = ((date.getUTCHours() & 0x1f) << 11) | ((date.getUTCMinutes() & 0x3f) << 5) | ((date.getUTCSeconds() / 2) & 0x1f);
  const day = (((y - 1980) & 0x7f) << 9) | (((date.getUTCMonth() + 1) & 0x0f) << 5) | (date.getUTCDate() & 0x1f);
  return { time, day };
}

export class ZipWriter {
  /**
   * @param fixedDate  Date stamped into every entry. Callers pass the authority's
   *                   genTime or a stated UTC instant, never the local clock, so the
   *                   container carries no machine-clock value that a reader could
   *                   mistake for evidence.
   */
  constructor(fixedDate = new Date(Date.UTC(1980, 0, 1, 0, 0, 0))) {
    this.parts = [];
    this.entries = [];
    this.offset = 0;
    this.date = fixedDate;
    this.finished = false;
  }

  get size() { return this.offset; }

  /**
   * Append one entry.
   *
   * @param name       published path inside the archive, UTF-8
   * @param data       Uint8Array, string, or Blob/File (Blob is streamed, never
   *                   materialized, so a multi-gigabyte document does not have to
   *                   fit in memory)
   * @param opts.noExtraField  refuse to emit any extra field for this entry. Set on
   *                   `mimetype`; the writer THROWS rather than silently emitting
   *                   one, because a silent extra field here is exactly the
   *                   conformance bug this class exists to prevent.
   */
  async add(name, data, opts = {}) {
    if (this.finished) throw new Error('ZipWriter: add() after finish()');

    const nameBytes = new TextEncoder().encode(name);
    if (nameBytes.length > U16_MAX) throw new Error('ZipWriter: entry name too long');

    let size, crc, payload;
    if (typeof data === 'string') {
      payload = new TextEncoder().encode(data);
      size = payload.length;
      crc = crc32(payload);
    } else if (data instanceof Uint8Array) {
      payload = data;
      size = data.length;
      crc = crc32(data);
    } else if (typeof Blob !== 'undefined' && data instanceof Blob) {
      payload = data;
      size = data.size;
      const h = new Crc32();
      for (let pos = 0; pos < data.size; pos += CRC_CHUNK) {
        const slice = data.slice(pos, Math.min(pos + CRC_CHUNK, data.size));
        h.update(new Uint8Array(await slice.arrayBuffer()));
      }
      crc = h.digest();
    } else {
      throw new Error('ZipWriter: unsupported data type');
    }

    const needsZip64 = size > U32_MAX || this.offset > U32_MAX;
    if (needsZip64 && opts.noExtraField) {
      throw new Error(`ZipWriter: ${name} needs a ZIP64 extra field but was declared extra-field-free`);
    }

    const { time, day } = dosDateTime(this.date);
    const localExtra = needsZip64 ? zip64LocalExtra(size) : new Uint8Array(0);

    const header = cat([
      u32(LOCAL_SIG),
      u16(needsZip64 ? 45 : 20),          // version needed
      u16(0x0800),                        // flags: UTF-8 names
      u16(0),                             // method 0, STORED
      u16(time), u16(day),
      u32(crc),
      u32(needsZip64 ? U32_MAX : size),   // compressed size
      u32(needsZip64 ? U32_MAX : size),   // uncompressed size
      u16(nameBytes.length),
      u16(localExtra.length),
      nameBytes,
      localExtra,
    ]);

    // Belt and braces on the rule that matters. Offset 28 in a local header is the
    // extra-field length; ASiC requires it to be zero for `mimetype`.
    if (opts.noExtraField) {
      const extraLen = header[28] | (header[29] << 8);
      if (extraLen !== 0) throw new Error(`ZipWriter: ${name} emitted a non-zero extra field length`);
    }

    const localOffset = this.offset;
    this.parts.push(header);
    this.offset += header.length;
    this.parts.push(payload);
    this.offset += size;

    this.entries.push({ nameBytes, crc, size, localOffset, time, day, needsZip64 });
    return this;
  }

  /** Finish and return a Blob of the whole archive. */
  finish(mimeType = 'application/zip') {
    if (this.finished) throw new Error('ZipWriter: finish() called twice');
    this.finished = true;

    const centralStart = this.offset;
    const central = [];

    for (const e of this.entries) {
      const bigOffset = e.localOffset > U32_MAX;
      const bigSize = e.size > U32_MAX;
      const extra = bigOffset || bigSize ? zip64CentralExtra(e.size, e.localOffset, bigSize, bigOffset) : new Uint8Array(0);

      central.push(cat([
        u32(CENTRAL_SIG),
        u16(45), u16(bigOffset || bigSize ? 45 : 20),
        u16(0x0800), u16(0),
        u16(e.time), u16(e.day),
        u32(e.crc),
        u32(bigSize ? U32_MAX : e.size),
        u32(bigSize ? U32_MAX : e.size),
        u16(e.nameBytes.length),
        u16(extra.length),
        u16(0), u16(0), u16(0),
        u32(0),
        u32(bigOffset ? U32_MAX : e.localOffset),
        e.nameBytes,
        extra,
      ]));
    }

    const centralBytes = cat(central);
    this.parts.push(centralBytes);
    this.offset += centralBytes.length;

    const count = this.entries.length;
    const needsZip64 = count > U16_MAX || centralStart > U32_MAX || centralBytes.length > U32_MAX;

    if (needsZip64) {
      const z64 = cat([
        u32(ZIP64_EOCD_SIG),
        u64(44),                    // size of this record minus 12
        u16(45), u16(45),
        u32(0), u32(0),
        u64(count), u64(count),
        u64(centralBytes.length),
        u64(centralStart),
      ]);
      const locator = cat([
        u32(ZIP64_LOCATOR_SIG),
        u32(0),
        u64(this.offset),
        u32(1),
      ]);
      this.parts.push(z64, locator);
      this.offset += z64.length + locator.length;
    }

    this.parts.push(cat([
      u32(EOCD_SIG),
      u16(0), u16(0),
      u16(needsZip64 ? U16_MAX : count),
      u16(needsZip64 ? U16_MAX : count),
      u32(needsZip64 ? U32_MAX : centralBytes.length),
      u32(needsZip64 ? U32_MAX : centralStart),
      u16(0),
    ]));

    return new Blob(this.parts, { type: mimeType });
  }
}

function zip64LocalExtra(size) {
  return cat([u16(0x0001), u16(16), u64(size), u64(size)]);
}

function zip64CentralExtra(size, offset, bigSize, bigOffset) {
  const fields = [];
  if (bigSize) fields.push(u64(size), u64(size));
  if (bigOffset) fields.push(u64(offset));
  const body = cat(fields);
  return cat([u16(0x0001), u16(body.length), body]);
}

/* ---------------------------------------------------------------- ASiC ----- */

export const ASIC_S_MIMETYPE = 'application/vnd.etsi.asic-s+zip';
export const ASIC_E_MIMETYPE = 'application/vnd.etsi.asic-e+zip';

/**
 * Build one ASiC-S container: a single data file plus a single RFC 3161 token that
 * applies to it, per ETSI EN 319 162-1 clause 4.3.3.
 *
 * Deliberately one container PER AUTHORITY. ASiC-S permits exactly one time
 * assertion, and the alternative (a single ASiC-E holding all three) makes each
 * token cover an intermediate manifest rather than the document itself. "The token
 * covers a manifest which records a digest of your file" is a sentence no
 * non-technical holder should ever have to defend. Here the token covers the
 * document's own hash, directly, and each container validates on its own in any
 * ASiC validator.
 *
 * Baseline conformance forbids extra files at the container root, which is why the
 * narrative report lives in the OUTER archive and never in here.
 */
export async function buildAsicS({ documentName, documentData, tokenBytes, date }) {
  const zip = new ZipWriter(date);
  // First, stored, no extra field. All three properties are normative.
  await zip.add('mimetype', ASIC_S_MIMETYPE, { noExtraField: true });
  await zip.add(documentName, documentData);
  await zip.add('META-INF/timestamp.tst', tokenBytes);
  return zip.finish(ASIC_S_MIMETYPE);
}

/**
 * Structural self-check on a finished ASiC container.
 *
 * Reads the bytes back and asserts the three normative properties rather than
 * trusting that the writer did what it meant to. The tool runs this on its own
 * output before handing the package over; a container that fails is not shipped.
 */
export async function checkAsicStructure(blob) {
  const head = new Uint8Array(await blob.slice(0, 256).arrayBuffer());
  const findings = [];

  const sigOk = head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
  findings.push({ rule: 'first 4 octets are 50 4B 03 04', ok: sigOk });

  const method = head[8] | (head[9] << 8);
  findings.push({ rule: 'mimetype is STORED (method 0)', ok: method === 0 });

  const nameLen = head[26] | (head[27] << 8);
  const extraLen = head[28] | (head[29] << 8);
  findings.push({ rule: 'mimetype extra field length is zero', ok: extraLen === 0 });

  const name = new TextDecoder().decode(head.subarray(30, 30 + nameLen));
  findings.push({ rule: 'first entry is named mimetype', ok: name === 'mimetype' });

  const value = new TextDecoder().decode(head.subarray(30 + nameLen, 30 + nameLen + 31));
  findings.push({
    rule: 'media type string begins at offset 38',
    ok: value.startsWith('application/vnd.etsi.asic-'),
    detail: value,
  });

  return { ok: findings.every((f) => f.ok), findings };
}
