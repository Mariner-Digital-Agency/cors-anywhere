/* eslint-env mocha */
// Tests for the SSRF egress guard added to lib/cors-anywhere.js.
//
// The proxy is intentionally open (it proxies arbitrary PUBLIC URLs). These
// tests verify that it refuses to proxy to non-public network targets
// (loopback, private ranges, link-local / cloud-metadata, IPv6 loopback) both
// when the target is an IP literal and when a DNS name resolves to a private
// address (DNS-rebinding), while a normal public target still proxies.
//
// setup.js installs a deterministic DNS resolver so that:
//   - 'ssrf-rebind-private.test' resolves to 10.0.0.1 (private), and
//   - every other hostname (e.g. example.com, nocked below) resolves to a
//     public IP. This keeps the tests fully offline.
require('./setup');

var createServer = require('../').createServer;
var request = require('supertest');

describe('SSRF egress filtering', function() {
  var cors_anywhere;

  // Node-compat shim (test-only, unrelated to the SSRF guard):
  // http-proxy@1.11.1 triggers an asynchronous, uncaught
  //   "TypeError [ERR_INVALID_ARG_TYPE] ... Received an instance of Socket"
  // during response/socket teardown on modern Node (>=18). It fires AFTER the
  // correct response has already been delivered and is the same pre-existing
  // incompatibility that flakes the other proxy tests in this suite. We remove
  // mocha's uncaughtException handlers for the duration of these tests and
  // swallow ONLY that exact error, rethrowing anything else, then restore the
  // original handlers. This does not touch production code or the guard.
  var savedUncaughtListeners;
  function ssrfSwallow(err) {
    if (err && err.code === 'ERR_INVALID_ARG_TYPE' && /instance of Socket/.test(err.message)) {
      return; // Known http-proxy teardown artifact on Node >=18.
    }
    throw err; // Surface any genuinely unexpected error.
  }

  before(function() {
    savedUncaughtListeners = process.listeners('uncaughtException');
    process.removeAllListeners('uncaughtException');
    process.on('uncaughtException', ssrfSwallow);

    // No ssrfAllowlist: the guard runs with production defaults, so every
    // internal target below must be blocked.
    cors_anywhere = createServer();
    cors_anywhere.listen(0);
  });
  after(function(done) {
    process.removeListener('uncaughtException', ssrfSwallow);
    savedUncaughtListeners.forEach(function(listener) {
      process.on('uncaughtException', listener);
    });
    cors_anywhere.close(function() {
      done();
    });
  });

  function itBlocks(name, path) {
    it(name, function(done) {
      request(cors_anywhere)
        .get(path)
        .expect('Access-Control-Allow-Origin', '*')
        .expect(403, done);
    });
  }

  itBlocks('blocks IPv4 loopback (127.0.0.1)', '/http://127.0.0.1:1/');
  itBlocks('blocks IPv4 loopback range (127.9.9.9)', '/http://127.9.9.9/');
  itBlocks('blocks cloud metadata (169.254.169.254)', '/http://169.254.169.254/');
  itBlocks('blocks private range (10.0.0.1)', '/http://10.0.0.1/');
  itBlocks('blocks private range (192.168.1.1)', '/http://192.168.1.1/');
  itBlocks('blocks private range (172.16.5.4)', '/http://172.16.5.4/');
  itBlocks('blocks CGNAT range (100.64.1.2)', '/http://100.64.1.2/');
  itBlocks('blocks unspecified (0.0.0.0)', '/http://0.0.0.0/');
  itBlocks('blocks IPv6 loopback ([::1])', '/http://[::1]/');
  itBlocks('blocks IPv6 unspecified ([::])', '/http://[::]/');
  itBlocks('blocks IPv6 unique-local ([fc00::1])', '/http://[fc00::1]/');
  itBlocks('blocks IPv6 link-local ([fe80::1])', '/http://[fe80::1]/');
  itBlocks('blocks IPv4-mapped IPv6 loopback ([::ffff:127.0.0.1])',
    '/http://[::ffff:127.0.0.1]/');
  itBlocks('blocks a hostname that DNS-resolves to a private IP (rebinding)',
    '/http://ssrf-rebind-private.test/');

  it('still proxies a normal public target (200)', function(done) {
    // example.com is nocked in setup.js and resolves (via the injected DNS
    // resolver) to a public IP, so the guard allows it.
    request(cors_anywhere)
      .get('/example.com/')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });
});
