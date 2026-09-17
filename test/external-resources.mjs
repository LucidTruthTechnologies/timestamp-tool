/* external-resources.mjs: list every network request a real browser makes when
 * loading the page.
 *
 * The page's central claim is that your document never leaves your computer. A
 * self-contained HTML file is necessary for that but not sufficient: a CDN or host
 * can inject script tags server-side, or a browser extension can, and the delivered
 * bytes matching the built bytes does not by itself prove the browser made no other
 * request. This measures the requests rather than inferring them from the markup.
 *
 * Usage: node test/external-resources.mjs <url>
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const URL_UNDER_TEST = process.argv[2] ?? 'http://127.0.0.1:8731/';
const PORT = 9700 + Math.floor(Math.random() * 300);

const profile = mkdtempSync(join(tmpdir(), 'tsx-'));
const chrome = spawn('/usr/bin/google-chrome', [
  '--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  '--no-sandbox', '--disable-gpu', '--no-first-run', '--disable-dev-shm-usage',
  'about:blank',
], { stdio: 'ignore' });
const cleanup = () => { try { chrome.kill('SIGKILL'); } catch {} rmSync(profile, { recursive: true, force: true }); };
process.on('exit', cleanup);

let ws, nextId = 1;
const pending = new Map();
const requests = [];

const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const id = nextId++;
  pending.set(id, { res, rej });
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});

async function waitForChrome() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      if (r.ok) return (await r.json()).webSocketDebuggerUrl;
    } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('chrome did not start');
}

ws = new WebSocket(await waitForChrome());
await new Promise((res) => { ws.onopen = res; });
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { res, rej } = pending.get(m.id);
    pending.delete(m.id);
    m.error ? rej(new Error(m.error.message)) : res(m.result);
    return;
  }
  if (m.method === 'Network.requestWillBeSent') {
    requests.push({ url: m.params.request.url, type: m.params.type, initiator: m.params.initiator?.type });
  }
};

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Network.enable', {}, sessionId);
await send('Page.enable', {}, sessionId);
await send('Page.navigate', { url: URL_UNDER_TEST }, sessionId);
await new Promise((r) => setTimeout(r, 4000));

const origin = new URL(URL_UNDER_TEST).origin;
console.log(`\nEvery request made while loading ${URL_UNDER_TEST}\n`);
for (const r of requests) {
  const external = r.url.startsWith('http') && !r.url.startsWith(origin);
  console.log(`  ${external ? 'EXTERNAL' : 'same-origin'}  ${r.type.padEnd(10)} ${r.url.slice(0, 110)}`);
}

const externals = requests.filter((r) => r.url.startsWith('http') && !r.url.startsWith(origin));
const sameOriginExtra = requests.filter((r) => r.url.startsWith(origin) && new URL(r.url).pathname !== '/'
  && new URL(r.url).pathname !== '/index.html');

console.log(`\n  total requests      ${requests.length}`);
console.log(`  cross-origin        ${externals.length}`);
console.log(`  extra same-origin   ${sameOriginExtra.length}`);
for (const r of sameOriginExtra) console.log(`      ${new URL(r.url).pathname}`);

cleanup();
process.exit(externals.length === 0 ? 0 : 1);
