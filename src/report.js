/* report.js: the narrative record that travels inside the package.
 *
 * This file carries the project's evidentiary discipline, so the rules it follows
 * are written down here rather than left to whoever edits it next.
 *
 * 1. "No later than", never "proves", never "on that date". A token establishes that
 *    a hash was presented to an authority no later than an instant. Everything else
 *    a reader might want to conclude lives somewhere else.
 *
 * 2. MEASURED and NOT ESTABLISHED are separate, headed sections. A report that
 *    asserts a conclusion without disclosing its basis is the defect that got a
 *    sibling forensic tool barred from client work here.
 *
 * 3. The report is NARRATIVE. The tokens are the evidence. Anyone can retype this
 *    file; nobody can forge a token. The package says so in both documents, because
 *    a reader who relies on the wrong artifact has been misled by our layout.
 *
 * 4. Instructions LEAD with re-hashing the document. Substituting a different file
 *    into the archive is trivial and is detected only by someone who recomputes the
 *    hash. Ordering is the mitigation.
 *
 * 5. No local machine time is ever printed except under an explicit label saying it
 *    is the operator's clock and is not evidence. The only authoritative times in
 *    this package are the genTime values inside the tokens.
 *
 * 6. Every number is durable or carries its own timestamp.
 */

import { toHex } from './sha256.js';
import * as tsp from './tsp.js';
import { PASS, FAIL, NOT_PERFORMED } from './verify.js';

export const TOOL_NAME = 'LTT Timestamp Tool';

/* The repository's LICENSE, substituted by build.sh so the copy that ships inside every
 * evidence archive cannot drift from the copy in the repo. In an unbuilt source tree this
 * is still the literal placeholder; packageLicenseText() below says so rather than writing
 * a confusing token into an archive. */
export const LICENSE_TEXT = "__LICENSE_TEXT__";

export function packageLicenseText() {
  if (LICENSE_TEXT.startsWith('__LICENSE')) {
    return 'The license text was not substituted at build time.\n\n' +
      'This archive was produced from an unbuilt source tree. The canonical terms are the\n' +
      'MIT License at https://github.com/LucidTruthTechnologies/timestamp-tool/blob/master/LICENSE\n';
  }
  return LICENSE_TEXT;
}

/* The liability statement, kept beside the not-validated statement everywhere it appears.
 *
 * Two things this wording is careful about, and the reason it is a constant rather than
 * prose typed three times:
 *
 * 1. THE ENTITY. "Lucid Truth Technologies" is a DBA brand and never carries an entity
 *    suffix. The legal entity is Kenneth G. Hartman Consulting Services LLC. The
 *    construction below is taken verbatim from the firm's own site footer rather than
 *    invented, because a disclaimer naming a party that does not exist is worse than none.
 *
 * 2. IT DISCLAIMS THE TOOL, NOT THE TIMESTAMPS. A liability clause that reads as "this
 *    evidence is unreliable" would defeat the package it travels in. The tokens are signed
 *    by third parties whose signatures hold whatever anyone says here, so the last
 *    paragraph draws that line explicitly.
 */
export const LIABILITY_PARAGRAPHS = [
  'This tool is provided as is, without warranty of any kind, express or implied. ' +
  'Lucid Truth Technologies, a registered trademark of Kenneth G. Hartman Consulting ' +
  'Services LLC, accepts no liability for any use of, or any reliance on, this tool or ' +
  'anything it produces.',

  'Using it creates no professional, examiner or client relationship, and nothing it ' +
  'produces is legal advice. Whether the evidence in this package supports any particular ' +
  'conclusion is a judgment for you and your advisors to make, not for this tool.',

  'This disclaims the TOOL, not the timestamps. The tokens in this package were signed by ' +
  'the timestamp authorities named in it, and those signatures can be checked with standard ' +
  'software using the commands in this document, independently of this tool, its author, ' +
  'and this disclaimer.',
];


const RESULT_WORD = {
  [PASS]: 'PASS',
  [FAIL]: 'FAIL',
  [NOT_PERFORMED]: 'NOT PERFORMED',
};

/**
 * @param ctx.version       tool version string, baked at build time
 * @param ctx.toolSha256    published digest of the page that produced this, or null
 * @param ctx.mode          'file' or 'hash-only'
 * @param ctx.transport     'relay' | 'offline' | 'direct'
 * @param ctx.transportNote human-readable description of the path taken
 * @param ctx.document      { name, size, digestHex, hashMethod, crossChecked } or null
 * @param ctx.nonceHex      nonce as sent
 * @param ctx.requestBytes  the DER TimeStampReq
 * @param ctx.results       [{ id, name, endpoint, ok, error, resp, checks, summary }]
 * @param ctx.localClock    Date, printed only under its warning label
 */
export function buildReport(ctx) {
  const L = [];
  const p = (s = '') => L.push(s);

  p(`# Timestamp evidence record`);
  p();
  p(`This file describes what was done to produce this package. It is a **narrative**.`);
  p(`The evidence is the timestamp tokens stored alongside it. Anyone can edit this`);
  p(`document; nobody can forge a token. Where this document and a token disagree,`);
  p(`the token is right.`);
  p();

  /* ---------------------------------------------------- the one-line claim -- */
  p(`## What this package establishes`);
  p();
  if (ctx.mode === 'hash-only') {
    p(`A fingerprint (SHA-256 digest) was presented to the timestamp authorities listed`);
    p(`below, and each authority that granted the request signed a statement that it saw`);
    p(`that fingerprint **no later than** the instant recorded in its token.`);
    p();
    p(`**This package does not contain the document.** It was produced in hash-only mode,`);
    p(`from a fingerprint supplied by the operator. On its own it binds to nothing. It`);
    p(`acquires meaning only when placed beside a file that hashes to exactly:`);
    p();
    p('```');
    p(ctx.document?.digestHex ?? '(no digest recorded)');
    p('```');
    p();
    p(`This tool did not see that file, could not observe what was hashed, and cannot`);
    p(`confirm the fingerprint was computed correctly. Preserve the file yourself.`);
  } else {
    p(`The document stored in this package hashes to a value that was presented to the`);
    p(`timestamp authorities listed below. Each authority that granted the request signed`);
    p(`a statement that it saw that value **no later than** the instant recorded in its`);
    p(`token, and each token has not been altered since.`);
  }
  p();

  /* ------------------------------------------------- re-hash comes first ---- */
  p(`## Check this yourself, first`);
  p();
  p(`Do this before reading anything else. A ZIP file can be edited, and a substituted`);
  p(`document is detected only by someone who recomputes the hash.`);
  p();
  if (ctx.mode === 'hash-only') {
    p('```');
    p(`sha256sum <your-preserved-file>`);
    p('```');
    p(`That must print, exactly:`);
  } else {
    p('```');
    p(`sha256sum "document/${ctx.document.name}"`);
    p('```');
    p(`That must print, exactly:`);
  }
  p();
  p('```');
  p(ctx.document?.digestHex ?? '(no digest recorded)');
  p('```');
  p();
  p(`If it prints anything else, the document in this package is not the document that`);
  p(`was timestamped, and nothing else in here applies to it.`);
  p();

  /* ------------------------------------------------------------ the facts -- */
  p(`## MEASURED`);
  p();
  p(`Everything in this section was observed directly and can be re-derived from the`);
  p(`files in this package using the commands given later.`);
  p();

  if (ctx.mode !== 'hash-only') {
    p(`### The document`);
    p();
    p(`- **Name as supplied:** \`${ctx.document.name}\``);
    p(`- **Size:** ${ctx.document.size} bytes`);
    p(`- **SHA-256:** \`${ctx.document.digestHex}\``);
    p(`- **How it was hashed:** ${describeHashMethod(ctx.document)}`);
    p();
    p(`The file was hashed inside the operator's web browser. Its contents were never`);
    p(`transmitted. Only the 32-byte digest above left the machine.`);
    p();
  }

  p(`### The request`);
  p();
  p(`- **Nonce:** \`0x${(ctx.nonceHex ?? '').toUpperCase()}\``);
  p(`- **Request size:** ${ctx.requestBytes.length} bytes`);
  p(`- **Certificates requested:** yes (certReq set, so each token carries its signing chain)`);
  p();
  p(`The nonce is a random value generated for this request alone. An authority copies`);
  p(`it back verbatim, which is what ties a reply to *this* request rather than to a`);
  p(`reply replayed from some earlier one. The request file \`request/request.tsq\` is`);
  p(`preserved in this package because the nonce cannot be checked without it.`);
  p();

  p(`### What each authority returned`);
  p();
  p(`| Authority | Status | Time stamped (UTC) | Policy | Serial |`);
  p(`|---|---|---|---|---|`);
  for (const r of ctx.results) {
    if (!r.ok || !r.resp?.token) {
      p(`| ${r.name} | **${r.ok ? r.resp?.statusName ?? 'no token' : 'NOT OBTAINED'}** | not applicable | not applicable | not applicable |`);
      continue;
    }
    const t = r.resp.token.tstInfo;
    p(`| ${r.name} | ${r.resp.statusName} | ${t.genTimeRaw} | \`${t.policy}\` | \`0x${t.serialHex.toUpperCase()}\` |`);
  }
  p();

  const failures = ctx.results.filter((r) => !r.ok || !r.resp?.token);
  if (failures.length) {
    p(`**${failures.length} of ${ctx.results.length} authorities did not produce a token.**`);
    p(`They are listed here rather than omitted, because a package that quietly ships`);
    p(`two tokens where three were requested misrepresents what was attempted.`);
    p();
    for (const f of failures) {
      p(`- **${f.name}** (\`${f.endpoint}\`): ${f.error ?? f.resp?.statusName ?? 'no token returned'}`);
    }
    p();
  }

  p(`### Field-by-field, per authority`);
  p();
  for (const r of ctx.results) {
    p(`#### ${r.name}`);
    p();
    p(`- **Endpoint:** \`${r.endpoint}\``);
    if (!r.ok || !r.resp?.token) {
      p(`- **Result:** no token obtained. ${r.error ?? ''}`);
      p();
      continue;
    }
    const t = r.resp.token.tstInfo;
    const signerCert = tsp.findSignerCertificate(r.resp.token);
    p(`- **Status:** ${r.resp.statusName} (PKIStatus ${r.resp.statusCode})`);
    p(`- **genTime:** \`${t.genTimeRaw}\``);
    p(`- **Message imprint:** \`${t.imprintHex}\``);
    p(`- **Hash algorithm:** ${t.hashAlgorithm}`);
    p(`- **Policy OID:** \`${t.policy}\``);
    p(`- **Serial number:** \`0x${t.serialHex.toUpperCase()}\``);
    p(`- **Nonce returned:** ${t.nonceHex ? `\`0x${t.nonceHex.toUpperCase()}\`` : '**ABSENT**'}`);
    p(`- **Accuracy:** ${formatAccuracy(t.accuracy)}`);
    p(`- **Ordering:** ${t.ordering}`);
    p(`- **TSA field:** ${t.tsaName ? `\`${t.tsaName.value}\`` : '**ABSENT** (optional in RFC 3161; the binding identification is the signing certificate)'}`);
    p(`- **Certificates embedded:** ${r.resp.token.certificates.length}`);
    p(`- **Self-signed root included in the token:** ${chainHasSelfSignedRoot(r.resp.token) ? 'yes' : '**no**'}` +
      ` (decides which trust source verifies this token; see the commands below)`);
    if (signerCert) {
      p(`- **Signing certificate:** \`${signerCert.subject}\``);
      p(`- **Issued by:** \`${signerCert.issuer}\``);
      p(`- **Valid:** ${signerCert.notBefore.toISOString()} to **${signerCert.notAfter.toISOString()}**`);
      p(`- **Key:** ${signerCert.keyBits ? `${signerCert.keyBits}-bit RSA` : `EC ${signerCert.curveOid}`}`);
      p(`- **Signature digest:** ${r.resp.token.signer.digestAlgorithm}`);
    }
    p();
    p(`Verification checks run by this tool:`);
    p();
    p(`| Check | Result | Basis |`);
    p(`|---|---|---|`);
    for (const c of r.checks) {
      p(`| ${c.label} | **${RESULT_WORD[c.result]}** | ${c.basis} |`);
    }
    p();
    for (const c of r.checks) {
      if (c.result !== PASS) p(`- **${c.label} (${RESULT_WORD[c.result]}):** ${c.detail}`);
    }
    p();
  }

  /* ----------------------------------------------- the disagreement table -- */
  const withTokens = ctx.results.filter((r) => r.ok && r.resp?.token);
  if (withTokens.length > 1) {
    p(`### Do the authorities agree`);
    p();
    const times = withTokens.map((r) => r.resp.token.tstInfo.genTime.getTime());
    const spread = Math.max(...times) - Math.min(...times);
    p(`The recorded times span **${spread} milliseconds** across ${withTokens.length} authorities.`);
    p();
    p(`These values are reported exactly as each authority returned them. They are not`);
    p(`averaged, reconciled or adjusted. Where authorities disagree, the disagreement is`);
    p(`itself information and belongs in front of the reader.`);
    p();
    const noAccuracy = withTokens.filter((r) => !r.resp.token.tstInfo.accuracy);
    if (noAccuracy.length) {
      p(`${noAccuracy.length} of ${withTokens.length} authorities returned **no accuracy field**.`);
      p(`That field is optional in RFC 3161. Where it is absent, the recorded time carries`);
      p(`no stated bound on how far off it might be, so these tokens do not support an`);
      p(`argument about sub-second ordering between authorities.`);
      p();
    }
  }

  /* ---------------------------------------------------- the honest limits -- */
  p(`## NOT ESTABLISHED`);
  p();
  p(`Each item below is something this package does **not** show. They are listed with`);
  p(`the same prominence as the findings above, deliberately.`);
  p();
  p(`- **Who wrote the document, or who held it.** A timestamp authority never saw the`);
  p(`  document and takes no position on its origin.`);
  p(`- **Whether anything in the document is true.** The authority signed a fingerprint,`);
  p(`  not a claim about content.`);
  p(`- **That the document is older than the timestamp.** The document may have been`);
  p(`  created moments before it was submitted. A timestamp fixes the LATEST moment the`);
  p(`  content can have existed, never the earliest.`);
  p(`- **Anything about the past.** A file timestamped today says nothing about last year.`);
  p(`- **That the signing certificates chain to a root you trust.** A web browser does`);
  p(`  not expose the operating system trust store to JavaScript, so this was NOT checked`);
  p(`  by the tool. Run the openssl commands below; that is the step that settles it.`);
  p(`- **That the operator is who they say they are.** Nothing here authenticates a person.`);
  p();

  /* ------------------------------------------------------ the recipe -------- */
  p(`## Verify this package independently`);
  p();
  p(`These commands re-derive every claim above using standard tools. Nothing in this`);
  p(`section depends on trusting ${TOOL_NAME} or its author. Run them from the`);
  p(`directory where you extracted this package.`);
  p();
  p(`Note the \`-CAfile\` argument. \`openssl ts -verify\` consults no trust store by`);
  p(`default and requires one of \`-CAfile\`, \`-CApath\` or \`-CAstore\` to be named`);
  p(`explicitly. Omitting it produces a confusing failure about a missing local issuer`);
  p(`even when the issuer is present on your system.`);
  p();
  if (ctx.mode !== 'hash-only') {
    p(`**1. Confirm the document is the one that was timestamped.**`);
    p();
    p('```');
    p(`sha256sum "document/${ctx.document.name}"`);
    p(`# expect: ${ctx.document.digestHex}`);
    p('```');
    p();
  }
  p(`**2. Read each token back.**`);
  p();
  p('```');
  for (const r of withTokens) {
    p(`openssl ts -reply -in "authorities/${r.id}/response.tsr" -text`);
  }
  p('```');
  p();
  p(`**3. Verify each token.** The correct trust source is NOT the same for every`);
  p(`authority, and using the wrong one produces a confident FAILED on a perfectly good`);
  p(`token. What decides it is whether the authority embedded its own self-signed root`);
  p(`in the token it sent.`);
  p();
  p(`Each command below is written for the authority it names, based on what that`);
  p(`authority actually returned here. They are not interchangeable.`);
  p();
  for (const r of withTokens) {
    const trust = trustSourceFor(r);
    p(`*${r.name}* ${trust.why}`);
    p();
    p('```');
    if (trust.note) { p(trust.note); p(trust.note2); }
    p(`openssl ts -verify -in "authorities/${r.id}/response.tsr" \\`);
    p(`  -queryfile "request/request.tsq" \\`);
    if (trust.untrusted) {
      p(`  -untrusted "authorities/${r.id}/chain.pem" \\`);
    }
    p(`  -CAfile ${trust.caFile}`);
    p('```');
    p();
    if (trust.caution) { p(trust.caution); p(); }
  }
  p(`On macOS the system bundle is usually \`/etc/ssl/cert.pem\`; on Debian and Ubuntu`);
  p(`\`/etc/ssl/certs/ca-certificates.crt\`; on Red Hat derivatives`);
  p(`\`/etc/pki/tls/certs/ca-bundle.crt\`. If your build supports it, \`-CAstore\` can`);
  p(`reference the operating system store directly.`);
  p();
  p(`**Why the flag is required at all.** \`openssl ts -verify\` consults no trust store`);
  p(`by default and will not go looking for one. The manual page states that at least`);
  p(`one of \`-CAfile\`, \`-CApath\` or \`-CAstore\` must be given. Omit it and you get an`);
  p(`error about a missing local issuer even when the issuer is sitting in your system`);
  p(`bundle, which reads like a broken token and is not.`);
  p();
  if (ctx.mode !== 'hash-only') {
    p(`**4. Or verify against the document directly.** Use this when the request file is`);
    p(`long gone. It does not check the nonce, which is worth knowing you are skipping.`);
    p(`The same per-authority trust source applies.`);
    p();
    p('```');
    for (const r of withTokens) {
      const trust = trustSourceFor(r);
      p(`openssl ts -verify -data "document/${ctx.document.name}" \\`);
      p(`  -in "authorities/${r.id}/response.tsr" \\`);
      if (trust.untrusted) p(`  -untrusted "authorities/${r.id}/chain.pem" \\`);
      p(`  -CAfile ${trust.caFile}`);
      p('');
    }
    p('```');
    p();
  }
  p(`**5. What \`chain.pem\` is, and what it is not.** Each \`chain.pem\` holds the`);
  p(`certificates the authority embedded in its own token, and nothing else. Verifying`);
  p(`against it shows the token is internally consistent. It shows that the authority`);
  p(`is one *you* trust only when the authority chose to include its own root, which`);
  p(`some do and most do not. The table above says which is which for this package.`);
  p();
  p(`**6. Validate the ASiC containers.** Each \`.asics\` file in this package is an`);
  p(`ASiC-S container per ETSI EN 319 162-1, holding the document and one timestamp`);
  p(`token. Third-party validators read this format, including the European`);
  p(`Commission's DSS demonstration validator. They have never heard of this tool.`);
  p();

  /* --------------------------------------------------------- provenance ----- */
  p(`## How this package was produced`);
  p();
  p(`- **Tool:** ${TOOL_NAME} version ${ctx.version}`);
  if (ctx.toolSha256) {
    p(`- **SHA-256 of the page that produced this:** \`${ctx.toolSha256}\``);
    p(`  Compare this against the published digest for that version to confirm the tool`);
    p(`  had not been modified. The tool is a single HTML file and anyone can edit one.`);
  } else {
    p(`- **SHA-256 of the page that produced this:** not recorded.`);
  }
  p(`- **Transport:** ${ctx.transportNote}`);
  p();
  p(`The transport is recorded because packages made by different routes have different`);
  p(`custody stories, and a reader should not have to discover which one this was.`);
  p();
  if (ctx.transport === 'relay') {
    p(`A relay forwards the 32-byte fingerprint to each authority and returns the reply.`);
    p(`It holds no authority's signing key, so it cannot forge a token or alter one: any`);
    p(`change breaks a signature that only the authority can make. The most a relay could`);
    p(`do is learn the fingerprint, delay a request, or return a token for a *different*`);
    p(`fingerprint, and that last case is caught by the "Token commits to this exact`);
    p(`document" check above, which compares against a hash computed locally in the`);
    p(`browser. The relay is untrusted by construction.`);
    p();
  }
  p(`### Operator's clock (NOT evidence)`);
  p();
  p(`- The computer that produced this package reported its own local time as`);
  p(`  \`${ctx.localClock.toISOString()}\` when the package was assembled.`);
  p();
  p(`That value is recorded for completeness and is **not evidence of anything**. It`);
  p(`came from a clock the operator controls and can set to any value. The only`);
  p(`authoritative times in this package are the genTime values inside the tokens,`);
  p(`listed above, which were signed by parties who do not know the operator.`);
  p();
  p(`Likewise, the file modification dates on the files in this archive describe when`);
  p(`this package was written, never when the document was created.`);
  p();

  /* --------------------------------------------------------- tool status ---- */
  p(`## Status of this tool`);
  p();
  p(`${TOOL_NAME} is **not a validated forensic instrument**. It has not been through`);
  p(`formal validation, and its listing anywhere is a description of what exists, not a`);
  p(`warrant of fitness for any particular purpose.`);
  p();
  p(`This does not weaken the package. The evidence here is not this tool's output; it`);
  p(`is a set of cryptographic tokens signed by independent third parties, checkable`);
  p(`with standard software using the commands in this document. The tool's job was to`);
  p(`collect those tokens and keep them together with the document. Verify the tokens,`);
  p(`not the tool.`);
  p();
  p(`### No warranty, and no liability`);
  p();
  for (const para of LIABILITY_PARAGRAPHS) { p(para); p(); }
  p(`The complete terms are in \`LICENSE.txt\`, included in this package.`);
  p();
  p(`Source code: https://github.com/LucidTruthTechnologies/timestamp-tool`);
  p();

  /* ----------------------------------------------------------- preserve ----- */
  p(`## Preserving this package`);
  p();
  p(`1. **Keep this ZIP file exactly as it is.** Do not open it and re-save it, do not`);
  p(`   add files to it, do not rename anything inside it.`);
  p(`2. **To work with the document, extract a COPY** and work on the copy. Leave this`);
  p(`   archive untouched.`);
  p(`3. **Store at least two copies** in places that fail independently.`);
  p(`4. Copying this archive changes the file dates your operating system shows for it.`);
  p(`   That is normal and harmless. The evidence is inside the file, not in its`);
  p(`   filesystem metadata.`);
  p(`5. **Re-timestamp before the signing certificates expire.** The earliest expiry`);
  p(`   among the tokens here is **${earliestExpiry(ctx.results)}**. Before then, take a`);
  p(`   fresh timestamp over this whole archive so the proof carries forward.`);
  p();

  return L.join('\n');
}

/** The short plain-text file a non-technical holder opens first. */
export function buildReadme(ctx) {
  const digest = ctx.document?.digestHex ?? '(none)';
  const ok = ctx.results.filter((r) => r.ok && r.resp?.token);
  return `WHAT THIS IS, AND WHAT TO DO WITH IT
${'='.repeat(52)}

This archive is a record that a fingerprint of your document was shown to
${ok.length} independent timestamp ${ok.length === 1 ? 'authority' : 'authorities'} on the date recorded inside.

Those authorities never saw your document. They only saw a fingerprint, which
cannot be turned back into the document.


THE ONE THING TO DO FIRST
${'-'.repeat(52)}

Check that the document in here is the one that was timestamped.

${ctx.mode === 'hash-only'
  ? `  This package does NOT contain your document. You supplied only a
  fingerprint. Find the file you preserved and run:

      sha256sum <your-file>`
  : `      sha256sum "document/${ctx.document.name}"`}

It must print exactly this:

      ${digest}

If it prints something else, the document does not match and nothing else
in this archive applies to it.


WHAT IT SHOWS, IN ONE SENTENCE
${'-'.repeat(52)}

That the contents of your document existed NO LATER THAN the moment recorded
in the tokens.

It does NOT show who wrote it, who held it, whether any of it is true, or
that the document is any older than that moment. It does not reach backwards:
a file stamped today says nothing about last year.


HOW TO LOOK AFTER IT
${'-'.repeat(52)}

  KEEP this ZIP file exactly as it is. Do not add to it, rename things inside
  it, or open and re-save it.

  To USE the document, extract a COPY and work on the copy. The original
  archive stays untouched.

  Keep more than one copy, in places that would not be lost together.

  Copying the archive changes the dates your computer shows for the file
  itself. That is normal. The evidence is inside the archive.


WHAT ELSE IS IN HERE
${'-'.repeat(52)}

  REPORT.md / REPORT.html   The full record, including commands anyone can
                            run to check all of this independently.
  MANIFEST.txt              Every file in this archive and its fingerprint.
  LICENSE.txt               The terms this tool is provided under.
  ${ctx.mode === 'hash-only' ? 'request/' : 'document/'}                 ${ctx.mode === 'hash-only' ? 'The request that was sent.' : 'Your original document, unchanged.'}
  authorities/              What each authority sent back, with certificates.
  *.asics                   Standard-format containers (ETSI EN 319 162)
                            that third-party validators can read.


NO WARRANTY, AND NO LIABILITY
${'-'.repeat(52)}

This tool is provided as is, with no warranty of any kind. Lucid Truth
Technologies, a registered trademark of Kenneth G. Hartman Consulting Services
LLC, accepts no liability for any use of, or any reliance on, this tool or
anything it produces. Using it creates no professional or client relationship,
and nothing here is legal advice.

That disclaims the TOOL, not the timestamps. The tokens in this archive were
signed by the timestamp authorities, and those signatures hold independently of
this tool and of anything said here.

The full terms are in LICENSE.txt.


IF SOMEONE CHALLENGES THIS
${'-'.repeat(52)}

Give them the whole archive and point them at REPORT.md. It contains the
exact commands to verify everything using standard, freely available
software. They do not have to trust the tool that made this, and they should
not be asked to. The tokens are signed by the authorities, not by us.

Source code: https://github.com/LucidTruthTechnologies/timestamp-tool
`;
}

/** Manifest of every packaged file with its own digest. */
export function buildManifest(entries) {
  const L = [
    'MANIFEST',
    '',
    'SHA-256 of every file in this archive, so the archive can be checked for',
    'completeness without relying on the report.',
    '',
    'Verify with:   sha256sum -c MANIFEST.txt',
    '(run from the directory where you extracted this archive)',
    '',
  ];
  for (const e of entries) L.push(`${e.digestHex}  ${e.path}`);
  L.push('');
  return L.join('\n');
}

/**
 * Does this authority's token embed its own self-signed root?
 *
 * This single property decides which trust source verifies the token, and getting it
 * wrong sends a reader to a FAILED verification on good evidence. Measured across the
 * four authorities this tool uses: FreeTSA embeds a self-signed root (2 certificates),
 * DigiCert and Sectigo embed signer plus intermediates and no root (3 each), and
 * Sigstore embeds the signer alone (1).
 *
 * The widely repeated advice "keep the authority's chain and verify against it" is
 * therefore correct for exactly one of them.
 */
export function chainHasSelfSignedRoot(token) {
  return token.certificates.some((c) => c.subject === c.issuer);
}

const PUBLICLY_TRUSTED_ROOT = new Set(['digicert', 'sectigo']);

function trustSourceFor(r) {
  const selfSigned = chainHasSelfSignedRoot(r.resp.token);
  const n = r.resp.token.certificates.length;

  if (selfSigned) {
    return {
      caFile: `"authorities/${r.id}/chain.pem"`,
      untrusted: false,
      why: `embedded its own self-signed root in the token (${n} certificates), so the ` +
        `bundled chain is a complete trust source on its own.`,
      caution:
        'Note what this does and does not show. It confirms the token is consistent with ' +
        'a root the authority itself supplied. It is not an independent check that anyone ' +
        'else trusts that root, because the same party provided both the signature and the ' +
        'anchor. Treat this as a self-consistency check unless you have obtained this ' +
        'authority\'s root from its published location by some other route.',
    };
  }

  if (PUBLICLY_TRUSTED_ROOT.has(r.id)) {
    return {
      caFile: '/etc/ssl/certs/ca-certificates.crt',
      untrusted: false,
      why: `embedded its signing certificate and intermediates but NOT a root ` +
        `(${n} certificates), so the trust anchor must come from your own system bundle. ` +
        `This is the stronger result of the two: the anchor is one your operating system ` +
        `vendor put there, not one the authority handed you.`,
      caution: null,
    };
  }

  /* The placeholder is shell-safe on purpose. An earlier version wrote
   * "<path to this authority's published root certificate>", whose apostrophe breaks
   * shell quoting, so a reader pasting the block got a syntax error rather than a
   * clear prompt to supply a file. A placeholder a reader will paste has to survive
   * being pasted. */
  return {
    caFile: `/path/to/${r.id}-root.pem`,
    note: `# ${r.name} does not ship a root in its token and its root is not in system`,
    note2: `# trust stores. Replace the path below with its published root certificate.`,
    untrusted: true,
    why: `embedded ${n} certificate${n === 1 ? '' : 's'} and no self-signed root, and its ` +
      `root is not normally present in operating system trust stores.`,
    caution:
      'This authority cannot be verified against a stock system bundle. You must obtain ' +
      'its root certificate from its own published location and name that file. Until you ' +
      'do, treat this token as corroboration that sits alongside the others rather than as ' +
      'independently anchored evidence.',
  };
}

function describeHashMethod(doc) {
  if (doc.crossChecked) {
    return 'computed twice, by the browser\'s Web Crypto implementation and by an ' +
      'independent implementation in this tool, and the two agreed';
  }
  return 'computed by a streaming implementation in this tool (the file was too large ' +
    'for the second, cross-checking implementation to run)';
}

function formatAccuracy(a) {
  if (!a) return '**ABSENT** (optional in RFC 3161; no stated bound on error)';
  const parts = [];
  if (a.seconds != null) parts.push(`${a.seconds}s`);
  if (a.millis != null) parts.push(`${a.millis}ms`);
  if (a.micros != null) parts.push(`${a.micros}us`);
  return parts.length ? parts.join(' ') : 'present but empty';
}

function earliestExpiry(results) {
  const dates = results
    .filter((r) => r.ok && r.resp?.token)
    .map((r) => tsp.findSignerCertificate(r.resp.token))
    .filter(Boolean)
    .map((c) => c.notAfter);
  if (!dates.length) return 'not determined';
  return new Date(Math.min(...dates.map((d) => d.getTime()))).toISOString().slice(0, 10);
}

/** Wrap the markdown report in a self-contained, printable HTML file. */
export function reportToHtml(markdown, title) {
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; --ink:#12161c; --paper:#fff; --rule:#d7dde5; --quiet:#5b6675; --fail:#a3271e; --gap:#8a5a00; }
  @media (prefers-color-scheme: dark) { :root { --ink:#e6eaf0; --paper:#12161c; --rule:#2b323c; --quiet:#9aa5b4; --fail:#ff9c92; --gap:#e0b25a; } }
  body { background:var(--paper); color:var(--ink); font:16px/1.65 Georgia,"Times New Roman",serif; max-width:46rem; margin:0 auto; padding:2rem 1rem 6rem; }
  h1,h2,h3,h4 { font-family:system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.25; }
  h1 { font-size:1.6rem; border-bottom:2px solid var(--rule); padding-bottom:.4rem; }
  h2 { font-size:1.25rem; margin-top:2.5rem; border-bottom:1px solid var(--rule); padding-bottom:.3rem; }
  h3 { font-size:1.05rem; margin-top:1.8rem; } h4 { font-size:.95rem; color:var(--quiet); }
  pre { background:rgba(127,127,127,.1); padding:.8rem 1rem; overflow-x:auto; border-left:3px solid var(--rule); }
  code,pre { font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:.85em; }
  table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.9rem; }
  th,td { border:1px solid var(--rule); padding:.4rem .6rem; text-align:left; vertical-align:top; }
  th { background:rgba(127,127,127,.08); font-family:system-ui,sans-serif; }
  strong { font-weight:700; }
  li { margin:.3rem 0; }
</style></head><body>
${mdToHtml(markdown, esc)}
</body></html>`;
}

/* A deliberately small markdown renderer. It covers only what buildReport emits.
 * Anything it does not understand is escaped and shown verbatim, so an unhandled
 * construct degrades to visible text rather than to silently dropped content. */
function mdToHtml(md, esc) {
  const out = [];
  const lines = md.split('\n');
  let inCode = false, inTable = false, inList = false;

  const closeList = () => { if (inList) { out.push('</ul>'); inList = false; } };
  const closeTable = () => { if (inTable) { out.push('</table>'); inTable = false; } };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.trim() === '```') {
      closeList(); closeTable();
      out.push(inCode ? '</pre>' : '<pre>');
      inCode = !inCode;
      continue;
    }
    if (inCode) { out.push(esc(line)); continue; }

    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { closeList(); closeTable(); out.push(`<h${h[1].length}>${inline(h[2], esc)}</h${h[1].length}>`); continue; }

    if (/^\|/.test(line)) {
      if (/^\|[\s:|-]+\|$/.test(line)) continue;   // separator row
      closeList();
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (!inTable) { out.push('<table>'); inTable = true; out.push('<tr>' + cells.map((c) => `<th>${inline(c, esc)}</th>`).join('') + '</tr>'); }
      else out.push('<tr>' + cells.map((c) => `<td>${inline(c, esc)}</td>`).join('') + '</tr>');
      continue;
    }
    closeTable();

    const li = line.match(/^(\s*)[-*]\s+(.*)$/);
    if (li) { if (!inList) { out.push('<ul>'); inList = true; } out.push(`<li>${inline(li[2], esc)}</li>`); continue; }
    const ol = line.match(/^\s*\d+\.\s+(.*)$/);
    if (ol) { if (!inList) { out.push('<ul>'); inList = true; } out.push(`<li>${inline(ol[1], esc)}</li>`); continue; }
    closeList();

    if (line.trim() === '') continue;
    out.push(`<p>${inline(line, esc)}</p>`);
  }
  closeList(); closeTable();
  if (inCode) out.push('</pre>');
  return out.join('\n');
}

function inline(s, esc) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}
