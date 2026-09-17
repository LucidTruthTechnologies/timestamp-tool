# Run your own relay

The relay exists only because browsers cannot POST to the public timestamp authorities. It
holds no signing key and can neither forge nor alter a timestamp. Running your own is
supported because a relay you control answers the one question a relay you do not control
cannot: *whose server was that?*

## What you get

A single Cloudflare Worker, no required bindings, deployable in about two minutes. It has no
database, no per-request state, and one optional counter.

## Deploy

```sh
git clone https://github.com/LucidTruthTechnologies/timestamp-tool
cd timestamp-tool/relay
npm install
npx wrangler login
npx wrangler deploy
```

That prints a `*.workers.dev` URL. Test it:

```sh
curl https://YOUR-WORKER.workers.dev/health
curl https://YOUR-WORKER.workers.dev/            # lists the authorities it will forward to
```

Then point a page at it. Either paste the URL into the tool's "Use a different relay" box, or
bake it in at build time:

```sh
cd ..
RELAY_URL=https://YOUR-WORKER.workers.dev ./build.sh
```

## Optional: the counter

The relay keeps no log. If you want a count of how many requests it has forwarded, create a
KV namespace and uncomment the binding in `wrangler.toml`:

```sh
npx wrangler kv namespace create COUNTER
```

Paste the returned id into `wrangler.toml`, redeploy, and the count is readable at `/count`.

The figure is approximate, and `/count` says so. It is a read-modify-write against
eventually-consistent storage, so concurrent requests undercount. That is the deliberate
trade: making it exact would require per-request durable state, which is the thing this relay
promises not to keep.

Without the binding the relay works normally and `/count` reports zero.

## Optional: restrict who can use it

By default the relay sends `Access-Control-Allow-Origin: *`, which is honest for public
infrastructure since it never accepts credentials. To restrict it to your own pages, set an
allowlist in `wrangler.toml`:

```toml
[vars]
ALLOWED_ORIGINS = "https://your-site.example,https://staging.your-site.example"
```

This is a convenience, not a security control. Origin headers are set by browsers and can be
forged by anything that is not a browser. Since the relay holds no key and keeps no data,
there is very little to protect.

## What it refuses

Verified against the running worker:

| Request | Response |
|---|---|
| Wrong `Content-Type` | 415 |
| Body that is not a DER SEQUENCE | 400 |
| Authority not in the allowlist | 404 |
| `GET` on `/tsa/<id>` | 405 |
| Body over 4096 bytes | 413 |
| Upstream authority unreachable | 502 |

The authority list is a fixed allowlist in the source, not a free-form URL parameter, so the
relay cannot be turned into a general-purpose open proxy.

## Verify it is behaving

The relay's honesty is checkable rather than promised. Send the same request through your
relay and directly with `curl`, and compare the tokens:

```sh
openssl ts -query -data somefile -sha256 -cert -out r.tsq

curl -sS -H "Content-Type: application/timestamp-query" --data-binary @r.tsq \
  https://YOUR-WORKER.workers.dev/tsa/digicert -o via-relay.tsr

curl -sS -H "Content-Type: application/timestamp-query" --data-binary @r.tsq \
  http://timestamp.digicert.com -o direct.tsr

openssl ts -reply -in via-relay.tsr -text | head -20
openssl ts -reply -in direct.tsr    -text | head -20
```

The two tokens differ (different serial, different instant, and the nonce ties each to its own
request), but both carry DigiCert's signature and both name your imprint. A relay that had
tampered with the imprint would be caught by the tool itself, which compares what came back
against the digest it computed locally before it will build an archive.

## Costs

At any plausible volume for this tool, a Cloudflare Worker sits inside the free tier. The
relay does no compute beyond forwarding a few hundred bytes.

## If your relay goes away

Nothing breaks. **A relay is needed only to CREATE a package, never to verify one.** Every
archive already produced stays self-contained and checkable forever with `openssl`. And the
page can still reach Sigstore directly with no relay at all, so it continues to produce a
genuine RFC 3161 token even with every relay offline.
