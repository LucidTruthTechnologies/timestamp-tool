/* app.js: the interface and the transport.
 *
 * The page does the hashing, builds the request, checks the replies and assembles
 * the archive. The only thing it cannot do by itself is reach three of the four
 * authorities, because browsers refuse cross-origin POSTs that those authorities
 * will not answer a preflight for. Hence two paths, and the archive records which
 * one produced it.
 */

import { hashFile, sha256, toHex, fromHex, LARGE_FILE_THRESHOLD } from './sha256.js';
import * as tsp from './tsp.js';
import { verifyResponse, PASS, FAIL, NOT_PERFORMED } from './verify.js';
import { buildPackage } from './package.js';

export const VERSION = '__VERSION__';
const DEFAULT_RELAY = '__RELAY_URL__';

/* Sigstore is reachable DIRECTLY from a browser: it is the one authority in this set
 * that sends Access-Control-Allow-Origin. That matters more than it looks. It means
 * this page still produces a genuine RFC 3161 token when every relay on earth is
 * down. Its root is self-signed and in no operating system trust store, so it is
 * recorded as a corroborant rather than a primary, and the report says so. */
const AUTHORITIES = [
  { id: 'freetsa',  name: 'FreeTSA',  direct: 'https://freetsa.org/tsr',        relayPath: '/tsa/freetsa',  kind: 'primary' },
  { id: 'digicert', name: 'DigiCert', direct: 'http://timestamp.digicert.com',  relayPath: '/tsa/digicert', kind: 'primary' },
  { id: 'sectigo',  name: 'Sectigo',  direct: 'http://timestamp.sectigo.com',   relayPath: '/tsa/sectigo',  kind: 'primary' },
  { id: 'sigstore', name: 'Sigstore', direct: 'https://timestamp.sigstore.dev/api/v1/timestamp', relayPath: null, kind: 'corroborant', browserReachable: true },
];

const TSQ_TYPE = 'application/timestamp-query';
const PER_AUTHORITY_TIMEOUT_MS = 25000;

const state = {
  mode: null,            // 'file' | 'hash-only'
  file: null,
  documentBlob: null,
  digest: null,
  digestHex: null,
  hashMethod: null,
  crossChecked: false,
  nonce: null,
  nonceHex: null,
  requestBytes: null,
  transport: null,       // 'relay' | 'offline'
  results: [],
  relayBase: DEFAULT_RELAY,
};

const $ = (sel) => document.querySelector(sel);
const show = (sel) => $(sel).classList.remove('hidden');
const hide = (sel) => $(sel).classList.add('hidden');

/* ------------------------------------------------------------- wiring ------ */

export function init() {
  $('#tool-version').textContent = VERSION;
  $('#relay-url').value = state.relayBase;

  const drop = $('#drop');
  const picker = $('#file-input');

  drop.addEventListener('click', () => picker.click());
  drop.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); picker.click(); }
  });
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    if (e.dataTransfer.files.length) onFile(e.dataTransfer.files[0]);
  });
  picker.addEventListener('change', () => { if (picker.files.length) onFile(picker.files[0]); });

  $('#use-hash').addEventListener('click', () => { hide('#step-input'); show('#step-hash-entry'); $('#hash-input').focus(); });
  $('#hash-back').addEventListener('click', () => { show('#step-input'); hide('#step-hash-entry'); });
  $('#hash-accept').addEventListener('click', onHashEntered);

  $('#btn-relay').addEventListener('click', () => submitViaRelay());
  $('#btn-offline').addEventListener('click', () => prepareOffline());
  $('#btn-restart').addEventListener('click', () => location.reload());
  $('#btn-download').addEventListener('click', onDownload);

  $('#relay-url').addEventListener('change', (e) => {
    state.relayBase = e.target.value.trim().replace(/\/$/, '');
  });

  const resp = $('#resp-drop');
  resp.addEventListener('click', () => $('#resp-input').click());
  resp.addEventListener('dragover', (e) => { e.preventDefault(); resp.classList.add('over'); });
  resp.addEventListener('dragleave', () => resp.classList.remove('over'));
  resp.addEventListener('drop', (e) => {
    e.preventDefault(); resp.classList.remove('over');
    onResponseFiles([...e.dataTransfer.files]);
  });
  $('#resp-input').addEventListener('change', (e) => onResponseFiles([...e.target.files]));
}

/* ------------------------------------------------------------- input ------- */

async function onFile(file) {
  state.mode = 'file';
  state.file = file;
  state.documentBlob = file;

  hide('#step-input');
  show('#step-hashing');
  $('#hashing-name').textContent = file.name;
  $('#hashing-size').textContent = formatBytes(file.size);

  if (file.size > LARGE_FILE_THRESHOLD) {
    $('#hashing-note').textContent =
      'This file is large enough that it is read in pieces. The second, cross-checking ' +
      'hash implementation cannot run on a file this size, and the record will say so.';
    show('#hashing-note');
  }

  try {
    const { digest, method, crossChecked } = await hashFile(file, (read, total) => {
      $('#hash-bar').style.width = `${Math.round((read / total) * 100)}%`;
      $('#hash-status').textContent = `Reading ${formatBytes(read)} of ${formatBytes(total)}`;
    });
    state.digest = digest;
    state.digestHex = toHex(digest);
    state.hashMethod = method;
    state.crossChecked = crossChecked;
    toReview();
  } catch (e) {
    hide('#step-hashing');
    show('#step-input');
    $('#input-error').textContent = e.message;
    show('#input-error');
  }
}

function onHashEntered() {
  const raw = $('#hash-input').value.trim();
  const errEl = $('#hash-error');
  try {
    const bytes = fromHex(raw);
    if (bytes.length !== 32) {
      throw new Error(`a SHA-256 digest is 32 bytes, which is 64 hex characters; you gave ${bytes.length} bytes`);
    }
    state.mode = 'hash-only';
    state.digest = bytes;
    state.digestHex = toHex(bytes);
    state.hashMethod = 'supplied by the operator';
    state.crossChecked = false;
    state.documentBlob = null;
    errEl.classList.add('hidden');
    hide('#step-hash-entry');
    toReview();
  } catch (e) {
    errEl.textContent = `That is not a SHA-256 digest: ${e.message}.`;
    errEl.classList.remove('hidden');
  }
}

function toReview() {
  state.nonce = tsp.generateNonce();
  state.nonceHex = toHex(state.nonce).replace(/^0+(?=.)/, '');
  state.requestBytes = tsp.buildTimeStampReq({
    digest: state.digest,
    hashOid: tsp.OID.sha256,
    nonce: state.nonce,
    certReq: true,
  });

  hide('#step-hashing');
  $('#rev-mode').textContent = state.mode === 'file' ? 'A file you supplied' : 'A fingerprint you supplied (no document)';
  $('#rev-name').textContent = state.mode === 'file' ? state.file.name : 'not supplied';
  $('#rev-size').textContent = state.mode === 'file' ? formatBytes(state.file.size) : 'not applicable';
  $('#rev-hash').textContent = state.digestHex;
  $('#rev-req').textContent = `${state.requestBytes.length} bytes`;

  $('#hash-only-warning').classList.toggle('hidden', state.mode !== 'hash-only');
  show('#step-review');
}

/* ----------------------------------------------------------- transport ----- */

async function submitViaRelay() {
  state.transport = 'relay';
  hide('#step-review');
  show('#step-submitting');
  renderPending();

  const jobs = AUTHORITIES.map(async (a) => {
    const useDirect = a.browserReachable;
    const endpoint = useDirect ? a.direct : `${state.relayBase}${a.relayPath}`;
    try {
      const responseBytes = await postRequest(endpoint, state.requestBytes);
      return await evaluate(a, endpoint, responseBytes, useDirect ? 'direct' : 'relay');
    } catch (e) {
      markRow(a.id, 'fail', e.message);
      return { id: a.id, name: a.name, endpoint, ok: false, error: e.message, checks: [], summary: {} };
    }
  });

  state.results = await Promise.all(jobs);
  toResults();
}

async function postRequest(endpoint, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PER_AUTHORITY_TIMEOUT_MS);
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': TSQ_TYPE },
      body,
      signal: controller.signal,
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} from the endpoint`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.length === 0) throw new Error('the endpoint returned an empty reply');
    return bytes;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`no reply within ${PER_AUTHORITY_TIMEOUT_MS / 1000} seconds`);
    /* A CORS rejection surfaces as an opaque TypeError with the real reason confined
     * to the devtools console. Saying so is more useful than repeating "Failed to
     * fetch" at someone who cannot open devtools. */
    if (e instanceof TypeError) {
      throw new Error('the browser blocked or could not complete this request (often a CORS or network failure)');
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function evaluate(a, endpoint, responseBytes, via) {
  let resp;
  try {
    resp = tsp.parseTimeStampResp(responseBytes);
  } catch (e) {
    markRow(a.id, 'fail', `reply could not be parsed: ${e.message}`);
    return { id: a.id, name: a.name, endpoint, ok: false, error: `unparseable reply: ${e.message}`, checks: [], summary: {} };
  }

  const { checks, summary } = await verifyResponse(resp, {
    digest: state.digest, digestHex: state.digestHex, nonceHex: state.nonceHex,
  });

  const ok = resp.granted && !!resp.token && !summary.anyFailure;
  markRow(a.id, ok ? 'ok' : 'fail',
    resp.token ? `${resp.statusName}, ${resp.token.tstInfo.genTimeRaw}` : resp.statusName);

  return { id: a.id, name: a.name, endpoint, via, ok: resp.granted && !!resp.token, resp, responseBytes, checks, summary };
}

/* ------------------------------------------------------------ offline ------ */

function prepareOffline() {
  state.transport = 'offline';
  hide('#step-review');
  show('#step-offline');

  download('request.tsq', new Blob([state.requestBytes], { type: TSQ_TYPE }));
  $('#offline-sh').textContent = shellScript();
  $('#offline-bat').textContent = batchScript();

  $('#dl-sh').onclick = () => download('stamp.sh', new Blob([shellScript()], { type: 'text/x-shellscript' }));
  $('#dl-bat').onclick = () => download('stamp.bat', new Blob([batchScript()], { type: 'text/plain' }));
  $('#dl-tsq').onclick = () => download('request.tsq', new Blob([state.requestBytes], { type: TSQ_TYPE }));
}

function shellScript() {
  const lines = AUTHORITIES.filter((a) => a.kind === 'primary' || a.browserReachable).map((a) =>
    `curl -sS -H "Content-Type: ${TSQ_TYPE}" --data-binary @request.tsq \\\n  "${a.direct}" -o "${a.id}.tsr" && echo "  ${a.name}: $(wc -c < "${a.id}.tsr") bytes" || echo "  ${a.name}: FAILED"`);
  return `#!/bin/sh
# Timestamp request helper, generated by LTT Timestamp Tool ${VERSION}.
#
# Run this in the same folder as request.tsq. It sends the request to each
# authority and saves the replies beside it. Then drag the .tsr files back onto
# the tool page.
#
# It sends only request.tsq, which contains a fingerprint and nothing else.
# Your document is not read by this script and never leaves this machine.
set -u
cd "$(dirname "$0")"
if [ ! -f request.tsq ]; then echo "request.tsq not found; put this script beside it."; exit 1; fi
echo "Sending the request to each authority:"
${lines.join('\n')}
echo
echo "Done. Drag the .tsr files back onto the tool page."
`;
}

function batchScript() {
  const lines = AUTHORITIES.filter((a) => a.kind === 'primary' || a.browserReachable).map((a) =>
    `curl -sS -H "Content-Type: ${TSQ_TYPE}" --data-binary @request.tsq "${a.direct}" -o "${a.id}.tsr"\r\nif exist "${a.id}.tsr" (echo   ${a.name}: saved) else (echo   ${a.name}: FAILED)`);
  return `@echo off\r
REM Timestamp request helper, generated by LTT Timestamp Tool ${VERSION}.\r
REM Run this in the same folder as request.tsq. curl ships with Windows 10 and later.\r
REM It sends only request.tsq, which contains a fingerprint and nothing else.\r
cd /d "%~dp0"\r
if not exist request.tsq (echo request.tsq not found; put this file beside it. & pause & exit /b 1)\r
echo Sending the request to each authority:\r
${lines.join('\r\n')}\r
echo.\r
echo Done. Drag the .tsr files back onto the tool page.\r
pause\r
`;
}

async function onResponseFiles(files) {
  const found = [];
  for (const f of files) {
    const id = AUTHORITIES.find((a) => f.name.toLowerCase().startsWith(a.id))?.id;
    if (!id) continue;
    const a = AUTHORITIES.find((x) => x.id === id);
    const bytes = new Uint8Array(await f.arrayBuffer());
    found.push(await evaluate(a, a.direct, bytes, 'offline'));
  }
  if (!found.length) {
    $('#resp-error').textContent =
      'None of those files matched an expected name. They should be called freetsa.tsr, ' +
      'digicert.tsr, sectigo.tsr or sigstore.tsr, exactly as the helper script saved them.';
    show('#resp-error');
    return;
  }
  hide('#resp-error');

  const byId = new Map(state.results.map((r) => [r.id, r]));
  for (const r of found) byId.set(r.id, r);
  for (const a of AUTHORITIES) {
    if (!byId.has(a.id)) {
      byId.set(a.id, { id: a.id, name: a.name, endpoint: a.direct, ok: false, error: 'no reply file was supplied', checks: [], summary: {} });
    }
  }
  state.results = AUTHORITIES.map((a) => byId.get(a.id));
  hide('#step-offline');
  toResults();
}

/* ----------------------------------------------------------- rendering ----- */

function renderPending() {
  const host = $('#submit-rows');
  host.innerHTML = '';
  for (const a of AUTHORITIES) {
    const row = document.createElement('div');
    row.className = 'status';
    row.id = `row-${a.id}`;
    row.textContent = `${a.name}: contacting...`;
    host.appendChild(row);
  }
}

function markRow(id, kind, text) {
  const row = document.getElementById(`row-${id}`);
  if (!row) return;
  const a = AUTHORITIES.find((x) => x.id === id);
  row.textContent = `${a.name}: ${kind === 'ok' ? 'replied' : 'no usable reply'} (${text})`;
}

function toResults() {
  hide('#step-submitting');
  show('#step-results');

  const got = state.results.filter((r) => r.ok && r.resp?.token);
  const lost = state.results.filter((r) => !r.ok || !r.resp?.token);

  $('#result-headline').textContent =
    `${got.length} of ${state.results.length} authorities returned a usable timestamp.`;

  if (lost.length) {
    $('#result-missing').innerHTML =
      `<strong>Not obtained:</strong> ${lost.map((r) => `${r.name} (${escapeHtml(r.error ?? r.resp?.statusName ?? 'no token')})`).join('; ')}. ` +
      'These are recorded in the archive as missing rather than left out, so the record ' +
      'shows what was attempted.';
    show('#result-missing');
  } else {
    hide('#result-missing');
  }

  const host = $('#result-authorities');
  host.innerHTML = '';
  for (const r of state.results) host.appendChild(renderAuthority(r));

  if (got.length > 1) {
    const times = got.map((r) => r.resp.token.tstInfo.genTime.getTime());
    const spread = Math.max(...times) - Math.min(...times);
    $('#spread').textContent =
      `The recorded times span ${spread} milliseconds across ${got.length} authorities. ` +
      'They are shown exactly as returned and are never averaged or reconciled.';
    show('#spread-note');
  } else {
    hide('#spread-note');
  }

  $('#btn-download').disabled = false;
}

function renderAuthority(r) {
  const el = document.createElement('details');
  el.className = 'auth';
  if (!r.ok) el.open = true;

  const counts = { PASS: 0, FAIL: 0, NOT_PERFORMED: 0 };
  for (const c of r.checks) counts[c.result]++;

  const summary = document.createElement('summary');
  const t = r.resp?.token?.tstInfo;
  summary.innerHTML =
    `<span>${escapeHtml(r.name)}${t ? ` <span class="tally">${escapeHtml(t.genTimeRaw)}</span>` : ''}</span>` +
    `<span class="tally">${r.ok ? `${counts.PASS} pass / ${counts.FAIL} fail / ${counts.NOT_PERFORMED} not performed` : 'no timestamp'}</span>`;
  el.appendChild(summary);

  const body = document.createElement('div');
  body.className = 'body';

  if (!r.ok) {
    body.innerHTML = `<p class="err">${escapeHtml(r.error ?? r.resp?.statusName ?? 'No token returned.')}</p>
      <p class="hint">Endpoint: <code>${escapeHtml(r.endpoint)}</code></p>`;
    el.appendChild(body);
    return el;
  }

  const cert = tsp.findSignerCertificate(r.resp.token);
  body.innerHTML = `
    <dl class="kv">
      <dt>Time stamped</dt><dd>${escapeHtml(t.genTimeRaw)}</dd>
      <dt>Policy</dt><dd>${escapeHtml(t.policy)}</dd>
      <dt>Serial</dt><dd class="hash">0x${escapeHtml(t.serialHex.toUpperCase())}</dd>
      <dt>Accuracy</dt><dd>${t.accuracy ? 'stated' : 'ABSENT (optional in RFC 3161)'}</dd>
      <dt>TSA field</dt><dd>${t.tsaName ? escapeHtml(t.tsaName.value) : 'ABSENT (optional; identity is the certificate)'}</dd>
      <dt>Certificates</dt><dd>${r.resp.token.certificates.length}</dd>
      ${cert ? `<dt>Signed by</dt><dd>${escapeHtml(cert.subject)}</dd>
      <dt>Expires</dt><dd>${cert.notAfter.toISOString().slice(0, 10)}</dd>` : ''}
    </dl>`;

  const ul = document.createElement('ul');
  ul.className = 'checks';
  for (const c of r.checks) {
    const li = document.createElement('li');
    const cls = c.result === PASS ? 'pass' : c.result === FAIL ? 'fail' : 'gap';
    const word = c.result === NOT_PERFORMED ? 'NOT RUN' : c.result;
    li.innerHTML = `<span class="tag ${cls}">${word}</span>` +
      `<span>${escapeHtml(c.label)}<span class="check-detail">${escapeHtml(c.detail)}</span></span>`;
    ul.appendChild(li);
  }
  body.appendChild(ul);
  el.appendChild(body);
  return el;
}

/* ------------------------------------------------------------ download ----- */

async function onDownload() {
  const btn = $('#btn-download');
  btn.disabled = true;
  btn.textContent = 'Building the archive...';
  try {
    const out = await buildPackage({
      version: VERSION,
      toolSha256: null,
      mode: state.mode,
      transport: state.transport,
      transportNote: describeTransport(),
      document: {
        name: state.mode === 'file' ? state.file.name : '(not supplied)',
        size: state.mode === 'file' ? state.file.size : 0,
        digestHex: state.digestHex,
        hashMethod: state.hashMethod,
        crossChecked: state.crossChecked,
      },
      documentBlob: state.documentBlob,
      nonceHex: state.nonceHex,
      requestBytes: state.requestBytes,
      results: state.results,
      localClock: new Date(),
    });
    download(out.filename, out.blob);
    $('#download-name').textContent = out.filename;
    show('#download-done');
    btn.textContent = 'Download again';
  } catch (e) {
    btn.textContent = 'Download the evidence archive';
    $('#result-error').textContent = `The archive could not be built: ${e.message}`;
    show('#result-error');
  } finally {
    btn.disabled = false;
  }
}

function describeTransport() {
  if (state.transport === 'offline') {
    return 'offline. The request was saved to disk and sent by a helper script run by the ' +
      'operator, using their own network connection. No relay was involved.';
  }
  const relayed = state.results.filter((r) => r.via === 'relay').map((r) => r.name);
  const direct = state.results.filter((r) => r.via === 'direct').map((r) => r.name);
  const bits = [];
  if (relayed.length) bits.push(`${relayed.join(', ')} via the relay at ${state.relayBase}`);
  if (direct.length) bits.push(`${direct.join(', ')} contacted directly from the browser`);
  return `${bits.join('; ')}. A relay forwards the fingerprint only; it holds no signing key.`;
}

function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

/* -------------------------------------------------------------- utils ----- */

function formatBytes(n) {
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}
