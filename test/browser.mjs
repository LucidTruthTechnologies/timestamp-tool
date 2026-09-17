/* browser.mjs: drive the built page in a real browser over CDP.
 *
 * No test framework and no Playwright: Node's built-in WebSocket is enough to speak
 * the Chrome DevTools Protocol, and the point here is to exercise dist/index.html
 * exactly as a visitor's browser would, including WebCrypto, File objects, Blob
 * assembly and the real network stack.
 *
 * Usage: node test/browser.mjs <url> <file-to-timestamp> [expected-sha256]
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const URL_UNDER_TEST = process.argv[2] ?? 'http://127.0.0.1:8731/';
const FILE = resolve(process.argv[3] ?? 'VERSION');
const EXPECTED = process.argv[4] ?? null;
const PORT = 9222 + Math.floor(Math.random() * 400);

let pass = 0, fail = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? `\n        ${detail}` : ''}`); }
};

const profile = mkdtempSync(join(tmpdir(), 'tstool-'));
const chrome = spawn('/usr/bin/google-chrome', [
  '--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  '--no-sandbox', '--disable-gpu', '--no-first-run', '--disable-dev-shm-usage',
  'about:blank',
], { stdio: 'ignore' });

const cleanup = () => { try { chrome.kill('SIGKILL'); } catch {} rmSync(profile, { recursive: true, force: true }); };
process.on('exit', cleanup);

/* ------------------------------------------------------------- CDP glue --- */

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const pageErrors = [];

function send(method, params = {}, sessionId) {
  const id = nextId++;
  return new Promise((res, rej) => {
    pending.set(id, { res, rej });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}

async function waitForChrome() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      if (r.ok) return (await r.json()).webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('chrome did not expose a debugging port');
}

async function evaluate(sessionId, expression) {
  const r = await send('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  }, sessionId);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? 'evaluate threw');
  return r.result.value;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(sessionId, expr, timeoutMs = 30000, label = expr) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(sessionId, `!!(${expr})`)) return true;
    await sleep(150);
  }
  throw new Error(`timed out waiting for: ${label}`);
}

/* ---------------------------------------------------------------- run ----- */

const browserWs = await waitForChrome();
ws = new WebSocket(browserWs);
await new Promise((res) => { ws.onopen = res; });

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { res, rej } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
    return;
  }
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description).join(' '));
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails.exception?.description
      ?? msg.params.exceptionDetails.text);
  }
};

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });

await send('Runtime.enable', {}, sessionId);
await send('Page.enable', {}, sessionId);
await send('DOM.enable', {}, sessionId);

console.log(`\nLoading ${URL_UNDER_TEST}`);
await send('Page.navigate', { url: URL_UNDER_TEST }, sessionId);
await until(sessionId, 'document.readyState === "complete"', 15000, 'document ready');
await sleep(300);

ok('page loads with no uncaught exception', pageErrors.length === 0, pageErrors.join('\n        '));
ok('page loads with no console error', consoleErrors.length === 0, consoleErrors.join('\n        '));

const title = await evaluate(sessionId, 'document.title');
ok('title is set', title === 'Timestamp a Document', `got "${title}"`);

const version = await evaluate(sessionId, 'document.getElementById("tool-version").textContent');
ok('version was substituted at build time', /^\d+\.\d+\.\d+$/.test(version), `got "${version}"`);

/* The FILE must reference nothing external. A HOST may still inject something as it
 * serves the page, and the canonical deployment's host does (Cloudflare Web Analytics,
 * enabled zone-wide; see "What the host adds" in README.md). Failing on that would make
 * this guard cry wolf on every hosted run and it would stop being read, so host
 * injections are reported separately and by name. Anything NOT on that list still fails,
 * which is what the guard is for. test/external-resources.mjs is the unconditional
 * census of what a browser actually requests. */
const HOST_INJECTED = [/^https:\/\/static\.cloudflareinsights\.com\//, /\/cdn-cgi\//];
const externalRefs = await evaluate(sessionId, `
  JSON.stringify([...document.querySelectorAll('script[src],link[href],img[src]')]
    .map(e => e.getAttribute('src') || e.getAttribute('href') || '')
    .filter(u => /^https?:/.test(u)))`);
const refs = JSON.parse(externalRefs);
const injected = refs.filter((u) => HOST_INJECTED.some((re) => re.test(u)));
const unexpected = refs.filter((u) => !HOST_INJECTED.some((re) => re.test(u)));

ok('the file itself references no external resource', unexpected.length === 0,
  unexpected.join('\n        '));
if (injected.length) {
  console.log(`  NOTE  ${injected.length} host-injected resource(s), documented in README:`);
  for (const u of injected) console.log(`        ${u.slice(0, 100)}`);
}

/* ---- brand mark: embedded, and exactly one visible per theme ----
 * The two marks are different artwork, shown by CSS. `.brand img` is specificity (0,1,1)
 * and a bare `.brand-dark` is (0,1,0), so the obvious stylesheet renders BOTH, stacked.
 * That is invisible in the CSS and obvious in getComputedStyle, so it is checked here. */
console.log('\nBrand mark');
const brandInfo = async () => JSON.parse(await evaluate(sessionId,
  `JSON.stringify([...document.querySelectorAll('.brand img')].map(i => ({
     cls: i.className, natural: i.naturalWidth + 'x' + i.naturalHeight,
     complete: i.complete, shown: getComputedStyle(i).display })))`));

ok('both marks are embedded, not linked',
  await evaluate(sessionId,
    `[...document.querySelectorAll('.brand img')].every(i => i.src.startsWith('data:image/'))`));

{
  const marks = await brandInfo();
  ok('both marks decoded', marks.length === 2 && marks.every((m) => m.complete && m.natural !== '0x0'),
    JSON.stringify(marks));
  const visible = marks.filter((m) => m.shown !== 'none');
  ok('exactly one mark is visible in light mode', visible.length === 1,
    `visible: ${visible.map((m) => m.cls).join(', ') || 'none'}`);
  ok('the light mark is the visible one', visible[0]?.cls === 'brand-light', JSON.stringify(marks));
}

await send('Emulation.setEmulatedMedia',
  { features: [{ name: 'prefers-color-scheme', value: 'dark' }] }, sessionId);
await sleep(250);
{
  const marks = await brandInfo();
  const visible = marks.filter((m) => m.shown !== 'none');
  ok('exactly one mark is visible in dark mode', visible.length === 1,
    `visible: ${visible.map((m) => m.cls).join(', ') || 'none'}`);
  ok('the dark mark is the visible one', visible[0]?.cls === 'brand-dark', JSON.stringify(marks));
}
await send('Emulation.setEmulatedMedia', { features: [] }, sessionId);

/* ---- the liability statement must sit beside the not-validated statement ---- */
ok('page carries the liability disclaimer',
  await evaluate(sessionId, `document.body.innerText.includes('accepts no liability for any use of')`));
ok('disclaimer names the legal entity, not an LLC-suffixed brand',
  await evaluate(sessionId, `
    document.body.innerText.includes('Kenneth G. Hartman Consulting Services LLC')
    && !/Lucid Truth Technologies,? LLC/.test(document.body.innerText)`));

/* ---- drive a real file through the hashing path ---- */
console.log(`\nHashing ${FILE} through the page`);
const { root } = await send('DOM.getDocument', {}, sessionId);
const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector: '#file-input' }, sessionId);
await send('DOM.setFileInputFiles', { files: [FILE], nodeId }, sessionId);

await until(sessionId, '!document.getElementById("step-review").classList.contains("hidden")', 30000, 'review step');
ok('page advanced to the review step', true);

const shown = await evaluate(sessionId, 'document.getElementById("rev-hash").textContent.trim()');
ok('digest is 64 hex characters', /^[0-9a-f]{64}$/.test(shown), `got "${shown}"`);
if (EXPECTED) {
  ok('digest matches sha256sum on the same file', shown === EXPECTED,
    `page     ${shown}\n        sha256sum ${EXPECTED}`);
}

const reqSize = await evaluate(sessionId, 'document.getElementById("rev-req").textContent');
ok('request was built', /^\d+ bytes$/.test(reqSize), `got "${reqSize}"`);

/* ---- offline path renders a runnable script ---- */
console.log('\nOffline path');
await evaluate(sessionId, 'document.getElementById("btn-offline").click()');
await until(sessionId, '!document.getElementById("step-offline").classList.contains("hidden")', 10000, 'offline step');
const sh = await evaluate(sessionId, 'document.getElementById("offline-sh").textContent');
ok('shell helper mentions every authority',
  ['freetsa', 'digicert', 'sectigo', 'sigstore'].every((a) => sh.includes(a)));
ok('shell helper sends only request.tsq', sh.includes('--data-binary @request.tsq'));
ok('shell helper does not reference the document', !sh.includes(FILE));

/* ---- full relay run, when a relay is reachable ---- */
if (process.env.RELAY_TEST_DIR) {
  console.log('\nRelay path, end to end');
  await send('Browser.setDownloadBehavior',
    { behavior: 'allow', downloadPath: process.env.RELAY_TEST_DIR, eventsEnabled: true });

  await evaluate(sessionId, 'location.reload()');
  await until(sessionId, 'document.readyState === "complete"', 15000, 'reload');
  await sleep(300);

  const doc2 = await send('DOM.getDocument', {}, sessionId);
  const inp = await send('DOM.querySelector', { nodeId: doc2.root.nodeId, selector: '#file-input' }, sessionId);
  await send('DOM.setFileInputFiles', { files: [FILE], nodeId: inp.nodeId }, sessionId);
  await until(sessionId, '!document.getElementById("step-review").classList.contains("hidden")', 30000, 'review');

  await evaluate(sessionId, 'document.getElementById("btn-relay").click()');
  await until(sessionId, '!document.getElementById("step-results").classList.contains("hidden")', 90000, 'results');

  const headline = await evaluate(sessionId, 'document.getElementById("result-headline").textContent');
  console.log(`        ${headline}`);
  ok('every authority returned a usable timestamp', /^4 of 4/.test(headline), headline);

  const tags = await evaluate(sessionId,
    'JSON.stringify([...document.querySelectorAll("#result-authorities .tag")].reduce((a,e)=>{a[e.textContent]=(a[e.textContent]||0)+1;return a;},{}))');
  console.log(`        check tally: ${tags}`);
  const tally = JSON.parse(tags);
  ok('no check reported FAIL', !tally.FAIL, tags);
  ok('chain check is NOT RUN on every authority', tally['NOT RUN'] >= 4, tags);
  ok('there is no single aggregate verdict element',
    await evaluate(sessionId, 'document.querySelectorAll(".verdict,.overall-pass,#verified-badge").length === 0'));

  await evaluate(sessionId, 'document.getElementById("btn-download").click()');
  await until(sessionId, '!document.getElementById("download-done").classList.contains("hidden")', 60000, 'download');
  const name = await evaluate(sessionId, 'document.getElementById("download-name").textContent');
  console.log(`        archive: ${name}`);
  ok('archive filename was produced', /^timestamp-evidence-.*\.zip$/.test(name), name);
  await sleep(1500);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (consoleErrors.length) console.log('console errors:\n  ' + consoleErrors.join('\n  '));
cleanup();
process.exit(fail === 0 ? 0 : 1);
