/**
 * timestamp-relay: a CORS shim in front of public RFC 3161 timestamp authorities.
 *
 * WHY THIS EXISTS
 *
 * Browsers cannot POST to the public timestamp authorities. Measured 2026-09-17:
 * FreeTSA answers a CORS preflight with 403, DigiCert with 501, and Sectigo answers
 * 200 while omitting Access-Control-Allow-Origin entirely. DigiCert additionally has
 * no HTTPS listener at all, so a page served over HTTPS cannot reach it under any
 * header policy. RFC 3161 mandates Content-Type: application/timestamp-query, which
 * is not a CORS-safelisted value, so every such POST is forced into a preflight that
 * these authorities were never built to answer.
 *
 * WHAT THIS RELAY CAN AND CANNOT DO, which is the whole security argument
 *
 * It holds no authority's signing key. It therefore CANNOT forge a timestamp token
 * or alter one: any modification breaks a signature only the authority can produce.
 * The complete list of what a malicious or compromised relay could do is:
 *
 *   1. Learn the 32-byte fingerprint. It never sees the document.
 *   2. Delay, drop, or refuse a request.
 *   3. Return a token for a DIFFERENT fingerprint.
 *
 * Case 3 is detected by the client, which compares the returned messageImprint
 * against a digest it computed locally and fails the package if they differ. The
 * relay is untrusted by construction, which is why it is safe to run someone else's.
 *
 * It is also why this code is published: run your own. See docs/SELF-HOSTING.md.
 *
 * LOGGING
 *
 * The only record this relay keeps is a count of requests relayed. No fingerprints,
 * no IP addresses, no origins, no user agents, no per-request timestamps. The count
 * is approximate by design, because making it exact would require per-request
 * durable state, which is the thing being avoided.
 */

export interface Env {
  COUNTER?: KVNamespace;
  /** Optional comma-separated origin allowlist. Unset means allow any origin. */
  ALLOWED_ORIGINS?: string;
}

/** The authorities this relay will forward to. An allowlist, never a free-form URL,
 *  so the relay cannot be used as a general-purpose open proxy. */
const AUTHORITIES: Record<string, { name: string; url: string }> = {
  freetsa: { name: 'FreeTSA', url: 'https://freetsa.org/tsr' },
  digicert: { name: 'DigiCert', url: 'http://timestamp.digicert.com' },
  sectigo: { name: 'Sectigo', url: 'http://timestamp.sectigo.com' },
};

const TSQ_CONTENT_TYPE = 'application/timestamp-query';
const TSR_CONTENT_TYPE = 'application/timestamp-reply';

/* An RFC 3161 request carrying one SHA-512 imprint, a nonce and a policy OID is
 * comfortably under 200 bytes. This ceiling exists so the relay cannot be used to
 * push bulk data at a third party. */
const MAX_REQUEST_BYTES = 4096;
const UPSTREAM_TIMEOUT_MS = 20000;
const COUNTER_KEY = 'requests-relayed';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const cors = corsHeaders(origin, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    if (url.pathname === '/' || url.pathname === '/authorities') {
      return json({
        service: 'timestamp-relay',
        purpose: 'CORS shim for RFC 3161 timestamp authorities. Holds no signing key.',
        authorities: Object.entries(AUTHORITIES).map(([id, a]) => ({ id, name: a.name, url: a.url })),
        logging: 'A count of requests relayed. Nothing else is recorded.',
        source: 'https://github.com/LucidTruthTechnologies/timestamp-tool',
      }, 200, cors);
    }

    if (url.pathname === '/health') {
      return json({ ok: true }, 200, cors);
    }

    /* The counter is published rather than kept private. A log nobody can inspect is
     * a promise; a log anyone can read is a fact. */
    if (url.pathname === '/count') {
      const raw = env.COUNTER ? await env.COUNTER.get(COUNTER_KEY) : null;
      return json({
        requestsRelayed: raw ? Number(raw) : 0,
        approximate: true,
        note: 'The only record this relay keeps. No fingerprints, addresses or origins are stored.',
      }, 200, cors);
    }

    const match = url.pathname.match(/^\/tsa\/([a-z0-9-]+)$/);
    if (!match) {
      return json({ error: 'not found' }, 404, cors);
    }

    const authority = AUTHORITIES[match[1]];
    if (!authority) {
      return json({ error: 'unknown authority', known: Object.keys(AUTHORITIES) }, 404, cors);
    }

    if (request.method !== 'POST') {
      return json({ error: 'method not allowed' }, 405, { ...cors, Allow: 'POST, OPTIONS' });
    }

    const contentType = (request.headers.get('Content-Type') ?? '').split(';')[0].trim();
    if (contentType !== TSQ_CONTENT_TYPE) {
      return json({ error: `expected Content-Type: ${TSQ_CONTENT_TYPE}` }, 415, cors);
    }

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length === 0) return json({ error: 'empty request body' }, 400, cors);
    if (body.length > MAX_REQUEST_BYTES) {
      return json({ error: `request body exceeds ${MAX_REQUEST_BYTES} bytes` }, 413, cors);
    }
    /* Shallow shape check: a TimeStampReq is a DER SEQUENCE. This is not validation,
     * it is a refusal to forward obviously non-RFC-3161 payloads. */
    if (body[0] !== 0x30) {
      return json({ error: 'body is not a DER SEQUENCE; this is not a TimeStampReq' }, 400, cors);
    }

    let upstream: Response;
    try {
      upstream = await fetch(authority.url, {
        method: 'POST',
        headers: { 'Content-Type': TSQ_CONTENT_TYPE, 'Content-Length': String(body.length) },
        body,
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
    } catch (e) {
      /* The authority's name is safe to echo; the request body is never touched. */
      return json({ error: 'upstream authority unreachable', authority: authority.name }, 502, cors);
    }

    const replyBytes = new Uint8Array(await upstream.arrayBuffer());

    if (env.COUNTER) ctx.waitUntil(bumpCounter(env.COUNTER));

    return new Response(replyBytes, {
      status: upstream.status,
      headers: {
        ...cors,
        'Content-Type': upstream.headers.get('Content-Type') ?? TSR_CONTENT_TYPE,
        'Cache-Control': 'no-store',
        'X-Relay-Authority': authority.name,
      },
    });
  },
};

/**
 * Best-effort counter.
 *
 * Read-modify-write on eventually-consistent storage undercounts under concurrency,
 * and that is accepted deliberately: the alternative is per-request durable state,
 * which is exactly the kind of record this relay promises not to keep. The /count
 * endpoint says the figure is approximate rather than implying a precision it does
 * not have.
 */
async function bumpCounter(kv: KVNamespace): Promise<void> {
  try {
    const current = Number((await kv.get(COUNTER_KEY)) ?? '0');
    await kv.put(COUNTER_KEY, String(current + 1));
  } catch {
    /* A counter is not worth failing a timestamp over. */
  }
}

function corsHeaders(origin: string | null, env: Env): Record<string, string> {
  const base: Record<string, string> = {
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };

  const allowList = (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (allowList.length === 0) {
    /* No allowlist configured: this is public infrastructure and a wildcard is
     * honest about that. Credentials are never accepted, so a wildcard costs
     * nothing here. */
    base['Access-Control-Allow-Origin'] = '*';
    return base;
  }
  if (origin && allowList.includes(origin)) {
    base['Access-Control-Allow-Origin'] = origin;
    return base;
  }
  base['Access-Control-Allow-Origin'] = allowList[0];
  return base;
}

function json(data: unknown, status: number, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' },
  });
}
