# Contributor guidance (cors-anywhere, Mariner deployment)

Read `OPERATIONS.md` first: it records how this proxy is deployed and why it is locked down.

- This is a security-sensitive public endpoint. Never run it as an open proxy in production: `server.js` fails closed unless `CORSANYWHERE_WHITELIST` and `CORSANYWHERE_ALLOWED_TARGETS` are set. Do not set `CORSANYWHERE_ALLOW_OPEN`.
- The destination allowlist is the real control; the Origin whitelist can be forged. Do not weaken or bypass the allowlist to make something work, add the exact host instead.
- Deploy with `railway up --service cors-proxy-mda --detach` from this folder. The service is not connected to GitHub, so merging does not deploy. Always pass `--service`.
- Config lives in Railway variables, not the repo. Record any change in `OPERATIONS.md`.
- Use Node >= 20. After `npm audit fix --omit=dev` run `npm ci`, or dev dependencies (mocha, eslint) are gone.
- `npm test` has 8 known failures that also fail on `master` (old http-proxy teardown tests on Node 22). Do not weaken tests to hide them; report them. New behaviour needs tests.
- Do not test by POSTing to the mailer through the proxy with a real recipient: it sends email.
