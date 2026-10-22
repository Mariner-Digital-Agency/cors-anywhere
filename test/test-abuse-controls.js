/* eslint-env mocha */
// Tests for the operator abuse control: the target allowlist.
//
// Background: the proxy was found being used as a free open relay (one client
// IP, ~3k requests/day, to unrelated hosts and raw IPs). An Origin check alone
// cannot stop that because any non-browser client can send any Origin. The
// target allowlist removes the thing being abused (arbitrary destinations).
// (A client-IP block was tried and removed: behind Railway's edge the proxy does
// not receive the client address in X-Forwarded-For, so it never matched.)
require('./setup');

var nock = require('nock');
var createServer = require('../').createServer;
var request = require('supertest');

describe('Abuse controls', function() {
  // Same http-proxy teardown shim as test-ssrf.js (Node >=18 artifact that
  // fires after a correct response has been delivered; unrelated to these rules).
  var savedUncaughtListeners;
  function swallowKnownTeardownError(err) {
    if (err && err.code === 'ERR_INVALID_ARG_TYPE' && /instance of Socket/.test(err.message)) {
      return;
    }
    throw err;
  }
  before(function() {
    savedUncaughtListeners = process.listeners('uncaughtException');
    process.removeAllListeners('uncaughtException');
    process.on('uncaughtException', swallowKnownTeardownError);

    // An approved host that bounces to an unapproved one, and a canary on the
    // unapproved host that must never be reached.
    nock('http://example.com')
      .persist()
      .get('/bounce-to-unapproved')
      .reply(302, '', {Location: 'http://unapproved.test/steal'});
    nock('http://unapproved.test')
      .persist()
      .get('/steal')
      .reply(200, 'LEAKED FROM UNAPPROVED HOST');
    nock('http://unapproved.test')
      .persist()
      .get('/')
      .reply(200, 'Response from unapproved.test');
  });
  after(function() {
    process.removeListener('uncaughtException', swallowKnownTeardownError);
    savedUncaughtListeners.forEach(function(listener) {
      process.on('uncaughtException', listener);
    });
  });

  describe('targetAllowlist', function() {
    var cors_anywhere;
    before(function() {
      cors_anywhere = createServer({targetAllowlist: ['example.com']});
      cors_anywhere.listen(0);
    });
    after(function(done) {
      cors_anywhere.close(done);
    });

    it('proxies an approved host', function(done) {
      request(cors_anywhere)
        .get('/example.com/')
        .expect('Access-Control-Allow-Origin', '*')
        .expect(200, 'Response from example.com', done);
    });

    it('matches the approved host case-insensitively', function(done) {
      request(cors_anywhere)
        .get('/http://EXAMPLE.com/')
        .expect(200, 'Response from example.com', done);
    });

    it('refuses an unapproved host without contacting it', function(done) {
      request(cors_anywhere)
        .get('/http://unapproved.test/')
        .expect('Access-Control-Allow-Origin', '*')
        .expect(403, 'This proxy only forwards requests to approved hosts.', done);
    });

    it('refuses raw public IP targets (the observed abuse pattern)', function(done) {
      request(cors_anywhere)
        .get('/http://89.42.231.11/')
        .expect(403, 'This proxy only forwards requests to approved hosts.', done);
    });

    it('does not let a look-alike hostname through', function(done) {
      request(cors_anywhere)
        .get('/example.com.com/')
        .expect(403, done);
    });

    it('refuses a redirect from an approved host to an unapproved one', function(done) {
      request(cors_anywhere)
        .get('/example.com/bounce-to-unapproved')
        .expect(403)
        .end(function(err, res) {
          if (err) {
            done(err);
            return;
          }
          if (/LEAKED/.test(res.text)) {
            done(new Error('redirect target on an unapproved host was fetched'));
            return;
          }
          done();
        });
    });
  });

  describe('empty targetAllowlist', function() {
    var cors_anywhere;
    before(function() {
      cors_anywhere = createServer({targetAllowlist: []});
      cors_anywhere.listen(0);
    });
    after(function(done) {
      cors_anywhere.close(done);
    });

    it('keeps the default open behaviour (no restriction)', function(done) {
      request(cors_anywhere)
        .get('/http://unapproved.test/')
        .expect(200, 'Response from unapproved.test', done);
    });
  });
});
