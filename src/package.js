/* package.js: assemble the evidence archive.
 *
 * Layout, and why it is this shape:
 *
 *   README-FIRST.txt        plain text, opens first, leads with "re-hash and compare"
 *   REPORT.md               the full record, plain text so it outlives HTML renderers
 *   REPORT.html             the same content, readable in any browser, offline
 *   MANIFEST.txt            sha256sum -c format, so completeness is checkable
 *   document/<name>         the original bytes, STORED, byte-identical on extraction
 *   request/request.tsq     mandatory: the nonce lives here and cannot be checked without it
 *   authorities/<id>/       response.tsr, token.tst, chain.pem, per authority
 *   <id>.asics              ASiC-S containers, one per authority, for third-party validators
 *
 * Two files carry the same content in two formats on purpose. REPORT.html is what a
 * person will actually read; REPORT.md is what will still be readable when no browser
 * of this era exists. Longevity is the whole point of the exercise.
 */

import { ZipWriter, buildAsicS, checkAsicStructure } from './zip.js';
import { buildReport, buildReadme, buildManifest, reportToHtml } from './report.js';
import { toHex } from './sha256.js';
import * as tsp from './tsp.js';

/**
 * @returns { blob, filename, manifest, asicChecks }
 */
export async function buildPackage(ctx) {
  const enc = new TextEncoder();
  const withTokens = ctx.results.filter((r) => r.ok && r.resp?.token);

  /* Stamp every archive entry with an authority-signed instant rather than the local
   * clock, so the container itself contains no machine-clock value a reader could
   * mistake for evidence. Falls back to the ZIP epoch when nothing was granted. */
  const stampDate = withTokens.length
    ? new Date(Math.min(...withTokens.map((r) => r.resp.token.tstInfo.genTime.getTime())))
    : new Date(Date.UTC(1980, 0, 1));

  const files = [];
  const addFile = (path, data) => { files.push({ path, data }); };

  const markdown = buildReport(ctx);
  addFile('README-FIRST.txt', buildReadme(ctx));
  addFile('REPORT.md', markdown);
  addFile('REPORT.html', reportToHtml(markdown, 'Timestamp evidence record'));

  if (ctx.mode !== 'hash-only' && ctx.documentBlob) {
    addFile(`document/${sanitize(ctx.document.name)}`, ctx.documentBlob);
  }
  addFile('request/request.tsq', ctx.requestBytes);

  for (const r of ctx.results) {
    const base = `authorities/${r.id}`;
    addFile(`${base}/endpoint.txt`,
      `${r.name}\n${r.endpoint}\n\n` +
      (r.ok ? `status: ${r.resp?.statusName ?? 'unknown'}\n` : `NOT OBTAINED: ${r.error ?? 'unknown error'}\n`));
    if (!r.ok || !r.resp?.token) continue;

    addFile(`${base}/response.tsr`, r.responseBytes);
    addFile(`${base}/token.tst`, r.resp.tokenBytes);

    const pem = r.resp.token.certificates.map((c) => tsp.toPem(c.der)).join('');
    addFile(`${base}/chain.pem`, pem);

    const detail = r.resp.token.certificates
      .map((c, i) => `# ${i + 1}\nsubject: ${c.subject}\nissuer:  ${c.issuer}\nserial:  0x${c.serialHex.toUpperCase()}\nvalid:   ${c.notBefore.toISOString()} .. ${c.notAfter.toISOString()}\n`)
      .join('\n');
    addFile(`${base}/chain.txt`,
      `Certificates embedded in the ${r.name} token (${r.resp.token.certificates.length}).\n\n` +
      `A root may be absent: an authority is not required to embed one.\n\n${detail}`);
  }

  /* ASiC-S containers. Only possible with the document present, because the standard
   * requires the data file to be inside the container. In hash-only mode we say so
   * rather than shipping something that looks conformant and is not. */
  const asicChecks = [];
  if (ctx.mode !== 'hash-only' && ctx.documentBlob) {
    for (const r of withTokens) {
      const asic = await buildAsicS({
        documentName: sanitize(ctx.document.name),
        documentData: ctx.documentBlob,
        tokenBytes: r.resp.tokenBytes,
        date: r.resp.token.tstInfo.genTime,
      });
      const check = await checkAsicStructure(asic);
      asicChecks.push({ id: r.id, ...check });
      /* Refuse to ship a container that fails its own structural check. A
       * non-conformant ASiC opens fine in every unzip tool and is rejected by every
       * validator, which is the worst combination available. */
      if (check.ok) addFile(`${r.id}.asics`, asic);
    }
    addFile('asic/README.txt', asicReadme(asicChecks));
  } else {
    addFile('asic/README.txt',
      'No ASiC containers were produced.\n\n' +
      'ASiC-S requires the data file to sit inside the container, and this package was\n' +
      'made in hash-only mode, so there is no document to place in one.\n');
  }

  /* Manifest last: it digests everything else, and cannot digest itself. */
  const manifestEntries = [];
  for (const f of files) {
    manifestEntries.push({ path: f.path, digestHex: await digestOf(f.data, enc) });
  }
  addFile('MANIFEST.txt', buildManifest(manifestEntries));

  const zip = new ZipWriter(stampDate);
  for (const f of files) await zip.add(f.path, f.data);
  const blob = zip.finish('application/zip');

  return {
    blob,
    filename: makeFilename(ctx, stampDate),
    manifest: manifestEntries,
    asicChecks,
  };
}

async function digestOf(data, enc) {
  let bytes;
  if (typeof data === 'string') bytes = enc.encode(data);
  else if (data instanceof Uint8Array) bytes = data;
  else if (typeof Blob !== 'undefined' && data instanceof Blob) bytes = new Uint8Array(await data.arrayBuffer());
  else throw new Error('digestOf: unsupported type');
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

function asicReadme(checks) {
  return `ASiC CONTAINERS
${'='.repeat(52)}

Each .asics file in the parent directory is an ASiC-S container as defined by
ETSI EN 319 162-1. Each one holds:

    mimetype                  application/vnd.etsi.asic-s+zip
    <your document>           the data file
    META-INF/timestamp.tst    one RFC 3161 timestamp token over that file

There is one container per authority because ASiC-S permits exactly one time
assertion per container. That shape was chosen deliberately: here each token
covers your document's own hash directly. The alternative single-container
form (ASiC-E) has each token cover an intermediate manifest instead, which is
harder to explain and harder to defend.

These are standard files. Validators that have never heard of the tool that
made this package can read them, including the European Commission's DSS
demonstration validator.

Structural self-check performed at packaging time:

${checks.map((c) => `  ${c.id}: ${c.ok ? 'PASS' : 'FAIL'}\n${c.findings.map((f) => `      ${f.ok ? 'ok  ' : 'FAIL'} ${f.rule}`).join('\n')}`).join('\n\n')}
`;
}

/** Strip path separators and control characters from a user-supplied filename. */
function sanitize(name) {
  return (name || 'document')
    .replace(/[/\\]/g, '_')
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/^\.+/, '')
    .slice(0, 180) || 'document';
}

function makeFilename(ctx, stampDate) {
  const stamp = stampDate.toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z');
  const base = ctx.mode === 'hash-only'
    ? 'hash'
    : sanitize(ctx.document.name).replace(/\.[^.]+$/, '').slice(0, 40).replace(/[^A-Za-z0-9._-]/g, '-');
  return `timestamp-evidence-${base}-${stamp}.zip`;
}
