# Timestamp Tool

A single HTML page that gets independent, third-party evidence that a document existed no
later than a given moment, and packages that evidence so it is still checkable years later
by someone who has never heard of this tool.

Your file is never uploaded. It is hashed in the browser, and only the 32-byte fingerprint
is ever sent.

- **Page:** `dist/index.html`, one self-contained file, no CDN, no fonts, no analytics
- **Relay:** `relay/`, a Cloudflare Worker you can run yourself
- **License:** MIT

## Why a relay is needed at all

A browser cannot submit an RFC 3161 request to the public timestamp authorities. This is not
a limitation of the page; it is the browser security model meeting infrastructure built
before that model existed.

Measured 2026-09-17:

| Endpoint | CORS preflight | `Access-Control-Allow-Origin` | HTTPS |
|---|---|---|---|
| `freetsa.org/tsr` | 403 Forbidden | absent | yes |
| `timestamp.digicert.com` | 501 Not Implemented | absent | **no listener at all** |
| `timestamp.sectigo.com` | 200, `Allow: POST,OPTIONS,HEAD,GET` | **absent** | 302, not a TSA |
| `timestamp.sigstore.dev/api/v1/timestamp` | 204 | **`*`** | yes |

RFC 3161 requires `Content-Type: application/timestamp-query`, which is not a CORS-safelisted
value, so every such POST is forced into a preflight that these authorities were never built
to answer. DigiCert additionally has no HTTPS listener, so a page served over HTTPS cannot
reach it under any header policy anyone could add.

Sigstore is the exception and the page talks to it **directly**, with no relay. That matters:
the page still produces a genuine RFC 3161 token when every relay on earth is down.

## What the relay can and cannot do

The relay holds no authority's signing key. It therefore **cannot forge a timestamp token or
alter one**: any change breaks a signature only the authority can produce. The complete list
of what a malicious or compromised relay could do is:

1. Learn the 32-byte fingerprint. It never sees your document.
2. Delay, drop, or refuse a request.
3. Return a token for a **different** fingerprint.

Case 3 is caught by the page, which compares the returned `messageImprint` against a digest it
computed locally and reports a failure if they differ. **The relay is untrusted by
construction**, which is what makes it safe to use someone else's, and why running your own is
a supported first-class option rather than an afterthought.

The only record the relay keeps is a count of requests relayed, published at `/count`. No
fingerprints, addresses, origins or per-request timestamps.

## What the tool produces

```
timestamp-evidence-<name>-<UTC>.zip
├── README-FIRST.txt      plain English; leads with "re-hash and compare"
├── REPORT.md             the full record, plain text, outlives HTML renderers
├── REPORT.html           the same content, readable offline in any browser
├── MANIFEST.txt          sha256sum -c format, so completeness is checkable
├── document/<file>       your original bytes, STORED, byte-identical on extraction
├── request/request.tsq   mandatory: the nonce lives here and cannot be checked without it
├── authorities/<id>/     response.tsr, token.tst, chain.pem, chain.txt, endpoint.txt
└── <id>.asics            ASiC-S containers, one per authority
```

The `.asics` files are standard containers under **ETSI EN 319 162-1**. Third-party validators
read them, including the European Commission's DSS demonstration validator. That is the point:
the package is checkable by software neither you nor we wrote.

One container per authority, rather than a single ASiC-E, is deliberate. ASiC-S permits exactly
one time assertion per container, and in that form **the token covers your document's own hash
directly**. In ASiC-E each token instead covers an intermediate manifest that records the
document's digest, and "the token covers a manifest which records a digest of your file" is a
sentence no non-technical holder should have to defend.

## Design rules

These are enforced in the code and the tests, not just described here.

**No single green tick.** Every check reports its own result and its own basis, and there are
three outcomes rather than two: `PASS`, `FAIL`, `NOT_PERFORMED`. The reason is empirical, and
`test/tamper.mjs` demonstrates it against a real token:

| tamper | imprint | nonce | messagedigest | signature |
|---|---|---|---|---|
| wrong document | **FAIL** | pass | pass | **PASS** |
| replayed (wrong nonce) | pass | **FAIL** | pass | **PASS** |
| byte flipped in TSTInfo | pass | pass | **FAIL** | **PASS** |
| byte flipped in signature | pass | pass | pass | **FAIL** |

Read the first row. "Signature verified" is *true* for a token that has nothing to do with
your document, because the authority really did sign it. A tool that collapsed these into one
tick would show green on a worthless token.

**Chain validation is `NOT_PERFORMED`, and says so.** A browser does not expose the operating
system trust store to JavaScript. The tool cannot do path validation, does not pretend to, and
prints the openssl command that settles it.

**The report is narrative; the tokens are the evidence.** Anyone can retype the report. Nobody
can forge a token. The package says so in both documents.

**No local clock value is presented as evidence.** The only authoritative times are the
`genTime` values inside the tokens. The operator's clock appears once, under a heading saying
it is the operator's clock and is not evidence.

**The trust source differs per authority, and the report gets it right per authority.** FreeTSA
embeds its own self-signed root, so its bundled chain verifies it. DigiCert and Sectigo embed
intermediates only, so they need your system bundle. Sigstore embeds neither and its root is in
no system store. Generic advice to "keep the authority's chain" is correct for exactly one of
the four.

## Status

**This is not a validated forensic instrument.** It has not been through formal validation.
That does not weaken what it produces: the evidence is a set of tokens signed by independent
third parties, checkable with standard software using commands included in every archive.
Verify the tokens, not the tool.

## Build

```sh
./build.sh [version]                 # writes dist/index.html and dist/index.html.sha256
RELAY_URL=https://your-relay ./build.sh
```

The bundle is a plain concatenation of `src/*.js` in dependency order, with import lines and
the `export` keyword stripped. There is no bundler, so anyone can diff `dist/index.html`
against the sources by eye. Two consequences the build enforces rather than documents:

- **Top-level names must be unique across modules**, because concatenation removes module
  scope. The build refuses to produce output if two files declare the same name. This exists
  because the first build hit it (`eq`, in two files).
- **Namespace imports are synthesized.** `import * as tsp from './tsp.js'` has no meaning after
  concatenation, so the build generates the namespace object from that module's actual exports.
  A real browser caught this; running the same sources under Node never would, because there
  the imports are real.

The build also refuses to publish a page that references any external resource, or that still
contains an unsubstituted placeholder.

`dist/index.html.sha256` is published so anyone can confirm the page they used was the
published one. A single HTML file is trivially editable, and "the report said version 0.1.0"
is not evidence that it *was* version 0.1.0.

## Tests

```sh
node test/roundtrip.mjs <fixture-dir>   # our DER against real openssl artifacts
node test/tamper.mjs    <fixture-dir>   # the verifier must FAIL when it should
node test/browser.mjs <url> <file> [expected-sha256]   # the built page in real Chrome
```

`roundtrip` asserts that our `TimeStampReq` is **byte-identical** to
`openssl ts -query -data FILE -sha256 -cert`, and parses real responses from all four
authorities. `browser.mjs` drives `dist/index.html` in headless Chrome over CDP using Node's
built-in WebSocket, with no test framework and no Playwright.

A fixture directory needs `probe.txt`, `probe.tsq` and `{freetsa,digicert,sectigo,sigstore}.tsr`.
Generate them with:

```sh
printf 'fixture\n' > probe.txt
openssl ts -query -data probe.txt -sha256 -cert -out probe.tsq
curl -sS -H "Content-Type: application/timestamp-query" --data-binary @probe.tsq \
  https://freetsa.org/tsr -o freetsa.tsr
# and the same for the other three endpoints
```

## Relay: run your own

See [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md). It is a single Cloudflare Worker with no
required bindings and it deploys in about two minutes.

## Background

- [One Hash, Three Timestamp Authorities](https://kennethghartman.com/blog/one-hash-three-timestamp-authorities/), the measurements this tool is built on
- [How to prove a document existed on a given date](https://lucidtruthtechnologies.com/prove-when-a-document-existed/), the same subject for the person holding the document
