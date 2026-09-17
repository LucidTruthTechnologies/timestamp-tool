/* sha256.js: streaming SHA-256.
 *
 * WHY THIS EXISTS AT ALL, given WebCrypto ships SHA-256:
 * crypto.subtle.digest() takes ONE ArrayBuffer. There is no streaming/incremental
 * form in the Web Crypto API. Hashing a multi-gigabyte evidence ZIP therefore means
 * holding the whole file in memory, which fails on exactly the large case that
 * matters. This is a chunk-at-a-time implementation so file size is bounded by disk,
 * not by RAM.
 *
 * It is NOT a replacement for WebCrypto. Below LARGE_FILE_THRESHOLD the caller
 * computes BOTH and asserts they agree (see hashFile). Two independent
 * implementations returning the same digest is a real integrity check on the one
 * number the whole package hangs from; a single implementation is a single point of
 * silent failure.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export class Sha256 {
  constructor() {
    this.h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this.buf = new Uint8Array(64);
    this.bufLen = 0;
    this.byteCount = 0;
    this.w = new Uint32Array(64);
    this.done = false;
  }

  /** Absorb a chunk. Call as many times as you like, then digest(). */
  update(bytes) {
    if (this.done) throw new Error('Sha256: update() after digest()');
    let off = 0;
    this.byteCount += bytes.length;

    if (this.bufLen > 0) {
      const need = 64 - this.bufLen;
      const take = Math.min(need, bytes.length);
      this.buf.set(bytes.subarray(0, take), this.bufLen);
      this.bufLen += take;
      off = take;
      if (this.bufLen === 64) {
        this._block(this.buf, 0);
        this.bufLen = 0;
      }
    }

    while (off + 64 <= bytes.length) {
      this._block(bytes, off);
      off += 64;
    }

    if (off < bytes.length) {
      this.buf.set(bytes.subarray(off), 0);
      this.bufLen = bytes.length - off;
    }
    return this;
  }

  /** Finalize. Returns a 32-byte Uint8Array. */
  digest() {
    if (this.done) throw new Error('Sha256: digest() called twice');
    const bitLenHi = Math.floor(this.byteCount / 0x20000000);
    const bitLenLo = (this.byteCount << 3) >>> 0;

    // Padding: 0x80, then zeros, then 8-byte big-endian bit length.
    const pad = new Uint8Array(this.bufLen < 56 ? 64 : 128);
    pad.set(this.buf.subarray(0, this.bufLen), 0);
    pad[this.bufLen] = 0x80;
    const dv = new DataView(pad.buffer);
    dv.setUint32(pad.length - 8, bitLenHi, false);
    dv.setUint32(pad.length - 4, bitLenLo, false);
    for (let i = 0; i < pad.length; i += 64) this._block(pad, i);

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, this.h[i], false);
    this.done = true;
    return out;
  }

  _block(p, off) {
    const w = this.w;
    const dv = new DataView(p.buffer, p.byteOffset + off, 64);
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      const s0 = (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) >>> 0;
      const s1 = (((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }

    const H = this.h;
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
}

/** One-shot convenience over the streaming core. */
export function sha256(bytes) {
  return new Sha256().update(bytes).digest();
}

/* Above this size we do not attempt the WebCrypto cross-check, because it would
 * require materializing the whole file as one ArrayBuffer, which is the very thing the
 * streaming path exists to avoid. 256 MiB is comfortably inside what a browser
 * tab will allocate without the allocation itself becoming the failure. */
export const LARGE_FILE_THRESHOLD = 256 * 1024 * 1024;
const CHUNK = 4 * 1024 * 1024;

/**
 * Hash a File/Blob by streaming it off disk.
 *
 * Returns { digest, method, crossChecked }.
 *   method       'webcrypto+js' when both ran and agreed, 'js-streaming' otherwise
 *   crossChecked true only when two independent implementations produced the same
 *                32 bytes. Reported verbatim in the package; never asserted when false.
 *
 * Throws on cross-check disagreement rather than picking a winner. If two
 * implementations disagree about the document's hash, every downstream claim in the
 * package is void, and guessing which one is right is the worst available move.
 */
export async function hashFile(file, onProgress) {
  const hasher = new Sha256();
  let read = 0;

  for (let pos = 0; pos < file.size; pos += CHUNK) {
    const slice = file.slice(pos, Math.min(pos + CHUNK, file.size));
    const buf = new Uint8Array(await slice.arrayBuffer());
    hasher.update(buf);
    read += buf.length;
    if (onProgress) onProgress(read, file.size);
  }

  const digest = hasher.digest();

  if (file.size <= LARGE_FILE_THRESHOLD && globalThis.crypto?.subtle) {
    const whole = new Uint8Array(await file.arrayBuffer());
    const ref = new Uint8Array(await crypto.subtle.digest('SHA-256', whole));
    if (!bytesEqual(digest, ref)) {
      throw new Error(
        'SHA-256 cross-check FAILED: the streaming implementation and the browser\'s ' +
        'WebCrypto disagree about this file\'s digest. No package will be produced. ' +
        'Please report this; it is a defect, not a problem with your file.'
      );
    }
    return { digest, method: 'webcrypto+js', crossChecked: true };
  }

  return { digest, method: 'js-streaming', crossChecked: false };
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex) {
  const clean = hex.replace(/[\s:]/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('not hexadecimal');
  if (clean.length % 2 !== 0) throw new Error('odd number of hex digits');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}
