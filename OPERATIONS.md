# Operations: cors.marinerdigitalagency.com

A fork of [Rob--W/cors-anywhere](https://github.com/Rob--W/cors-anywhere) running on Railway (project `cors-proxy-mda`, service `cors-proxy-mda`). The upstream README describes the library; this file records how this deployment is run and why.

## What uses it

Only the **Site Structure Navigator** extension (`Projects/ChromeExtensions/WebsiteNavigator`), to reach the mailer's `/welcomeMessage`. The Mariner websites and the YPF landing page call the mailer directly. A 30-day log review (2026-09-22 to 2026-10-22, 35,733 requests) showed zero calls to our own endpoints from anything.

The Navigator has `host_permissions: <all_urls>`, so it does not technically need a CORS proxy; it could call the mailer function directly. The proxy is **kept on purpose** because the owner plans to use it for future projects. If it is ever retired: ship a Navigator update that calls the function directly, wait for adoption, then delete the service (old installs only lose welcome emails).

## Deployment

- The service is **not connected to GitHub**. Deploy with `railway up --service cors-proxy-mda --detach` from this folder (it is linked to the `cors-proxy-mda` project). Merging a PR records the state; it does not deploy.
- A variable change redeploys the existing build. After the 2026-10 Railway incident a redeploy failed once with no log output; `railway redeploy --service cors-proxy-mda --yes` succeeded on retry.
- Always pass `--service`; `railway variable delete` has no `--skip-deploys`.
- Node >= 20. Run `npm ci` (not just `npm audit fix --omit=dev`, which prunes dev dependencies and breaks `npm test`).

## Configuration (Railway variables, none are secrets)

| Variable | Value | Meaning |
|---|---|---|
| `CORSANYWHERE_WHITELIST` | `chrome-extension://jcidaogiecfddcmhcnplfagahimdmied` | Exact `Origin` match, comma separated, no spaces. No Origin = refused. |
| `CORSANYWHERE_ALLOWED_TARGETS` | `us-central1-mdamailer313.cloudfunctions.net` | The only destination host it will forward to, including redirect hops. |
| `CORSANYWHERE_RATELIMIT` | `30 5` | 30 requests per 5 minutes per origin. |

`server.js` **refuses to start** without both of the first two (`CORSANYWHERE_ALLOW_OPEN=1` is the explicit opt-out). Do not set it in production.

To add a consumer: add its exact Origin to `CORSANYWHERE_WHITELIST` and its destination host to `CORSANYWHERE_ALLOWED_TARGETS`, then redeploy.

## What happened (October 2026) and the decisions

**Finding.** The Heroku deployment had an origin whitelist. It was never recreated after the move to Railway, so the Railway proxy was a free open relay (commit `599f399` even says "Open-CORS behavior unchanged"). From 2026-10-10 a single client IP (a `QtEmbedded` user agent, IPTV-box style) sent about 3,000 requests a day through it to `mag.trexlive.me` and two raw IPs: 88% of all traffic. The other 300 or so source IPs were scanners probing for `.env`, `.git/config` and `wp-login.php`, all answered 404.

**Decisions.**

1. **Destination allowlist is the real control.** An origin check can be forged by any non-browser client (the Navigator's extension id is public). Restricting where the proxy can send traffic removes the thing being abused, whatever Origin is claimed. It is checked first in `checkTargetAllowed`, so it covers the initial request and every redirect hop.
2. **Keep the origin whitelist and a rate limit** as cheap extra layers, set via config only.
3. **Fail closed.** The proxy ran open for months because variables were simply never set. It now refuses to start instead.
4. **A client-IP block was tried and removed.** An end-to-end test using the tester's own IP showed it never matched: behind Railway's edge the proxy does not receive the client address in `X-Forwarded-For`. It was redundant with the allowlist, and a control that silently does nothing is worse than none.
5. **Railway's WAF was not used.** The CLI offers only "Under Attack Mode" (a browser check), which would also break the Navigator's non-browser requests.
6. **Patched `follow-redirects`** (transitive via `http-proxy`, two high-severity advisories). Production audit: 0 vulnerabilities.

**Verified live** after the final deploy: no Origin, wrong Origin, right Origin to the abuser's targets, raw IPs, the cloud-metadata address, arbitrary sites, a look-alike host and an `allowed-host@evil` userinfo URL are all refused; the mailer host and the pre-flight for the Navigator's POST work; the full Navigator request (POST to `/welcomeMessage`) succeeds end to end.

## Tests

`npm test`: 88 passing, 8 failing. The 8 failures are identical on `master` before this work (old `http-proxy` stream-teardown tests on Node 22: "Content-Encoding invalid body", "Content-Length mismatch", "Invalid HTTP status code", rate-limit/memory/rewrite examples). They are not caused by the abuse controls. `test/test-abuse-controls.js` adds 7 tests for the destination allowlist.

## Probes (safe: they send no email)

```bash
U=https://cors.marinerdigitalagency.com; NAV="chrome-extension://jcidaogiecfddcmhcnplfagahimdmied"
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Requested-With: x" "$U/https://example.com/"      # 403 no Origin
curl -s -o /dev/null -w "%{http_code}\n" -H "Origin: $NAV" "$U/https://example.com/"            # 403 unapproved target
curl -s -o /dev/null -w "%{http_code}\n" -H "Origin: $NAV" "$U/http://169.254.169.254/"         # 403 metadata
```

Do not POST a valid recipient to `/welcomeMessage` unless you intend to send an email; see `CORE/MDAmailer/OPERATIONS.md`.

## Logs

`railway logs --http --service cors-proxy-mda` returns at most 5,000 rows per call; page backwards with `--until <timestamp>`. The HTTP log has the client IP and path but not the Origin header.
