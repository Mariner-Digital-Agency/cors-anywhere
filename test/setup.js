var nock = require('nock');
var net = require('net');

// --- SSRF egress guard: deterministic DNS resolver for tests --------------
// The proxy's SSRF guard resolves DNS names to verify they are not internal.
// nock does NOT intercept dns.lookup, so without this override the guard would
// perform real network DNS (flaky/offline-unsafe, e.g. `robots.txt` -> ENOTFOUND
// would fail closed and break existing tests). We inject a fake resolver that:
//   - maps a designated hostname to a PRIVATE IP, to exercise DNS-rebinding
//     blocking (see test/test-ssrf.js), and
//   - resolves every other hostname to a fixed PUBLIC IP.
// This only affects the module loaded in-process by the test suite; production
// code (and the forked memory-test child, which never requires this file) keeps
// Node's real resolver.
var corsAnywhere = require('../');
corsAnywhere.dnsLookup = function(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  var privateHosts = {
    // Simulates a host whose DNS record points at an internal address.
    'ssrf-rebind-private.test': '10.0.0.1',
  };
  var address = privateHosts[hostname] || '93.184.216.34'; // default: public
  var result = {address: address, family: net.isIPv6(address) ? 6 : 4};
  process.nextTick(function() {
    if (options && options.all) {
      callback(null, [result]);
    } else {
      callback(null, result.address, result.family);
    }
  });
};
// --------------------------------------------------------------------------

if (parseInt(process.versions.node, 10) >= 8) {
  // See DEP0066 at https://nodejs.org/api/deprecations.html.
  // _headers and _headerNames have been removed from Node v8, which causes
  // nock <= 9.0.13 to fail. The snippet below monkey-patches the library, see
  // https://github.com/node-nock/nock/pull/929/commits/f6369d0edd2a172024124f
  // for the equivalent logic without proxies.
  Object.defineProperty(require('http').ClientRequest.prototype, '_headers', {
    get: function() {
      var request = this;
      // eslint-disable-next-line no-undef
      return new Proxy(request.getHeaders(), {
        set: function(target, property, value) {
          request.setHeader(property, value);
          return true;
        },
      });
    },
    set: function() {
      // Ignore.
    },
  });
}

nock.enableNetConnect('127.0.0.1');

function echoheaders(origin) {
  nock(origin)
    .persist()
    .get('/echoheaders')
    .reply(function() {
      var headers = this.req.headers;
      var excluded_headers = [
        'accept-encoding',
        'user-agent',
        'connection',
        // Remove these headers since their values are platform-specific
        // (host/port bound at runtime). http-proxy >=1.18 adds x-forwarded-host
        // in addition to x-forwarded-for when xfwd is enabled.
        'x-forwarded-for',
        'x-forwarded-host',
        'test-include-xfwd',
      ];
      if (!('test-include-xfwd' in headers)) {
        excluded_headers.push('x-forwarded-port');
        excluded_headers.push('x-forwarded-proto');
      }
      var response = {};
      Object.keys(headers).forEach(function(name) {
        if (excluded_headers.indexOf(name) === -1) {
          response[name] = headers[name];
        }
      });
      return response;
    });
}

nock('http://example.com')
  .persist()
  .get('/')
  .reply(200, 'Response from example.com')

  .post('/echopost')
  .reply(200, function(uri, requestBody) {
    return requestBody;
  })

  .get('/setcookie')
  .reply(200, '', {
    'Set-Cookie': 'x',
    'Set-Cookie2': 'y',
    'Set-Cookie3': 'z', // This is not a special cookie setting header.
  })

  .get('/redirecttarget')
  .reply(200, 'redirect target', {
    'Some-header': 'value',
  })

  .head('/redirect')
  .reply(302, '', {
    Location: '/redirecttarget',
  })

  .get('/redirect')
  .reply(302, 'redirecting...', {
    'header at redirect': 'should not be here',
    Location: '/redirecttarget',
  })

  .get('/redirectposttarget')
  .reply(200, 'post target')

  .post('/redirectposttarget')
  .reply(200, 'post target (POST)')

  .post('/redirectpost')
  .reply(302, 'redirecting...', {
    Location: '/redirectposttarget',
  })

  .post('/redirect307')
  .reply(307, 'redirecting...', {
    Location: '/redirectposttarget',
  })

  .get('/redirect2redirect')
  .reply(302, 'redirecting to redirect...', {
    Location: '/redirect',
  })

  .get('/redirectloop')
  .reply(302, 'redirecting ad infinitum...', {
    Location: '/redirectloop',
  })

  .get('/redirectwithoutlocation')
  .reply(302, 'maybe found')

  .get('/redirectinvalidlocation')
  .reply(302, 'redirecting to junk...', {
    Location: 'http:///',
  })

  .get('/proxyerror')
  .replyWithError('throw node')
;

nock('https://example.com')
  .persist()
  .get('/')
  .reply(200, 'Response from https://example.com')
;

nock('http://example.com.com')
  .persist()
  .get('/')
  .reply(200, 'Response from example.com.com')
;

nock('http://example.com:1234')
  .persist()
  .get('/')
  .reply(200, 'Response from example.com:1234')
;

nock('http://prefix.example.com')
  .persist()
  .get('/')
  .reply(200, 'Response from prefix.example.com')
;

echoheaders('http://example.com');
echoheaders('http://example.com:1337');
echoheaders('https://example.com');
echoheaders('https://example.com:1337');

nock('http://robots.txt')
  .get('/')
  .reply(200, 'this is http://robots.txt');
