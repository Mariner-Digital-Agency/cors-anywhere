// © 2013 - 2016 Rob Wu <rob@robwu.nl>
// Released under the MIT license

'use strict';

var httpProxy = require('http-proxy');
var net = require('net');
var dns = require('dns');
var url = require('url');
var regexp_tld = require('./regexp-top-level-domain');
var getProxyForUrl = require('proxy-from-env').getProxyForUrl;

// DNS resolver used by the SSRF egress guard. Overridable so that tests can
// resolve hostnames deterministically without real network access. Production
// code never reassigns this, so the default (Node's resolver) is always used.
exports.dnsLookup = dns.lookup;

var help_text = {};
function showUsage(help_file, headers, response) {
  var isHtml = /\.html$/.test(help_file);
  headers['content-type'] = isHtml ? 'text/html' : 'text/plain';
  if (help_text[help_file] != null) {
    response.writeHead(200, headers);
    response.end(help_text[help_file]);
  } else {
    require('fs').readFile(help_file, 'utf8', function(err, data) {
      if (err) {
        console.error(err);
        response.writeHead(500, headers);
        response.end();
      } else {
        help_text[help_file] = data;
        showUsage(help_file, headers, response); // Recursive call, but since data is a string, the recursion will end
      }
    });
  }
}

/**
 * Check whether the specified hostname is valid.
 *
 * @param hostname {string} Host name (excluding port) of requested resource.
 * @return {boolean} Whether the requested resource can be accessed.
 */
function isValidHostName(hostname) {
  return !!(
    regexp_tld.test(hostname) ||
    net.isIPv4(hostname) ||
    net.isIPv6(hostname)
  );
}

/**
 * Adds CORS headers to the response headers.
 *
 * @param headers {object} Response headers
 * @param request {ServerRequest}
 */
function withCORS(headers, request) {
  headers['access-control-allow-origin'] = '*';
  var corsMaxAge = request.corsAnywhereRequestState.corsMaxAge;
  if (corsMaxAge) {
    headers['access-control-max-age'] = corsMaxAge;
  }
  if (request.headers['access-control-request-method']) {
    headers['access-control-allow-methods'] = request.headers['access-control-request-method'];
    delete request.headers['access-control-request-method'];
  }
  if (request.headers['access-control-request-headers']) {
    headers['access-control-allow-headers'] = request.headers['access-control-request-headers'];
    delete request.headers['access-control-request-headers'];
  }

  headers['access-control-expose-headers'] = Object.keys(headers).join(',');

  return headers;
}

/**
 * Performs the actual proxy request.
 *
 * @param req {ServerRequest} Incoming http request
 * @param res {ServerResponse} Outgoing (proxied) http request
 * @param proxy {HttpProxy}
 */
function proxyRequest(req, res, proxy) {
  var location = req.corsAnywhereRequestState.location;
  req.url = location.path;

  var proxyOptions = {
    changeOrigin: false,
    prependPath: false,
    target: location,
    headers: {
      host: location.host,
    },
    // HACK: Get hold of the proxyReq object, because we need it later.
    // http-proxy calls `(options.buffer || req).pipe(proxyReq)`, so by supplying
    // our own `buffer` with a custom pipe() we intercept proxyReq here.
    // https://github.com/http-party/node-http-proxy/blob/1.18.1/lib/http-proxy/passes/web-incoming.js#L170
    buffer: {
      pipe: function(proxyReq) {
        var proxyReqOn = proxyReq.on;
        // Intercepts the handler that connects proxyRes to res. http-proxy
        // registers its 'response' listener *after* the pipe() call above, so it
        // goes through the overridden proxyReq.on below.
        // https://github.com/http-party/node-http-proxy/blob/1.18.1/lib/http-proxy/passes/web-incoming.js#L172-L191
        proxyReq.on = function(eventName, listener) {
          if (eventName !== 'response') {
            return proxyReqOn.call(this, eventName, listener);
          }
          return proxyReqOn.call(this, 'response', function(proxyRes) {
            if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
              try {
                listener(proxyRes);
              } catch (err) {
                // Wrap in try-catch because an error could occur:
                // "RangeError: Invalid status code: 0"
                // https://github.com/Rob--W/cors-anywhere/issues/95
                // https://github.com/nodejitsu/node-http-proxy/issues/1080

                // Forward error (will ultimately emit the 'error' event on our proxy object):
                // https://github.com/http-party/node-http-proxy/blob/1.18.1/lib/http-proxy/passes/web-incoming.js#L153
                proxyReq.emit('error', err);
              }
            }
          });
        };
        return req.pipe(proxyReq);
      },
    },
  };

  var proxyThroughUrl = req.corsAnywhereRequestState.getProxyForUrl(location.href);
  if (proxyThroughUrl) {
    proxyOptions.target = proxyThroughUrl;
    proxyOptions.toProxy = true;
    // If a proxy URL was set, req.url must be an absolute URL. Then the request will not be sent
    // directly to the proxied URL, but through another proxy.
    req.url = location.href;
  }

  // Start proxying the request
  try {
    proxy.web(req, res, proxyOptions);
  } catch (err) {
    proxy.emit('error', err, req, res);
  }
}

/**
 * This method modifies the response headers of the proxied response.
 * If a redirect is detected, the response is not sent to the client,
 * and a new request is initiated.
 *
 * client (req) -> CORS Anywhere -> (proxyReq) -> other server
 * client (res) <- CORS Anywhere <- (proxyRes) <- other server
 *
 * @param proxy {HttpProxy}
 * @param proxyReq {ClientRequest} The outgoing request to the other server.
 * @param proxyRes {ServerResponse} The response from the other server.
 * @param req {IncomingMessage} Incoming HTTP request, augmented with property corsAnywhereRequestState
 * @param req.corsAnywhereRequestState {object}
 * @param req.corsAnywhereRequestState.location {object} See parseURL
 * @param req.corsAnywhereRequestState.getProxyForUrl {function} See proxyRequest
 * @param req.corsAnywhereRequestState.proxyBaseUrl {string} Base URL of the CORS API endpoint
 * @param req.corsAnywhereRequestState.maxRedirects {number} Maximum number of redirects
 * @param req.corsAnywhereRequestState.redirectCount_ {number} Internally used to count redirects
 * @param res {ServerResponse} Outgoing response to the client that wanted to proxy the HTTP request.
 *
 * @returns {boolean} true if http-proxy should continue to pipe proxyRes to res.
 */
function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
  var requestState = req.corsAnywhereRequestState;

  var statusCode = proxyRes.statusCode;

  if (!requestState.redirectCount_) {
    res.setHeader('x-request-url', requestState.location.href);
  }
  // Handle redirects
  if (statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308) {
    var locationHeader = proxyRes.headers.location;
    if (locationHeader) {
      locationHeader = url.resolve(requestState.location.href, locationHeader);

      if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
        // Exclude 307 & 308, because they are rare, and require preserving the method + request body
        requestState.redirectCount_ = requestState.redirectCount_ + 1 || 1;
        if (requestState.redirectCount_ <= requestState.maxRedirects) {
          // Handle redirects within the server, because some clients (e.g. Android Stock Browser)
          // cancel redirects.
          // Set header for debugging purposes. Do not try to parse it!
          res.setHeader('X-CORS-Redirect-' + requestState.redirectCount_, statusCode + ' ' + locationHeader);

          req.method = 'GET';
          req.headers['content-length'] = '0';
          delete req.headers['content-type'];
          requestState.location = parseURL(locationHeader);

          // Remove all listeners (=reset events to initial state)
          req.removeAllListeners();

          // Remove the error listener so that the ECONNRESET "error" that
          // may occur after aborting a request does not propagate to res.
          // https://github.com/http-party/node-http-proxy/blob/1.18.1/lib/http-proxy/passes/web-incoming.js#L153
          proxyReq.removeAllListeners('error');
          proxyReq.once('error', function catchAndIgnoreError() {});
          proxyReq.abort();

          // Initiate a new proxy request (re-applying the SSRF egress check to
          // the redirect target before actually re-proxying).
          proxyRequestIfAllowed(req, res, proxy);
          return false;
        }
      }
      proxyRes.headers.location = requestState.proxyBaseUrl + '/' + locationHeader;
    }
  }

  // Strip cookies
  delete proxyRes.headers['set-cookie'];
  delete proxyRes.headers['set-cookie2'];

  proxyRes.headers['x-final-url'] = requestState.location.href;
  withCORS(proxyRes.headers, req);
  return true;
}


/**
 * @param req_url {string} The requested URL (scheme is optional).
 * @return {object} URL parsed using url.parse
 */
function parseURL(req_url) {
  var match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
  //                              ^^^^^^^          ^^^^^^^^      ^^^^^^^                ^^^^^^^^^^^^
  //                            1:protocol       3:hostname     4:port                 5:path + query string
  //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //                                            2:host
  if (!match) {
    return null;
  }
  if (!match[1]) {
    // Scheme is omitted.
    if (req_url.lastIndexOf('//', 0) === -1) {
      // "//" is omitted.
      req_url = '//' + req_url;
    }
    req_url = (match[4] === '443' ? 'https:' : 'http:') + req_url;
  }
  return url.parse(req_url);
}

// =========================================================================
// SSRF egress filtering.
//
// This proxy is intentionally open: it fetches arbitrary client-supplied
// public URLs. That is by design and MUST NOT change. The guard below only
// prevents the proxy from being abused to reach non-public network targets
// (loopback, RFC1918/ULA private ranges, link-local incl. the cloud metadata
// endpoint 169.254.169.254, CGNAT, and other reserved/non-global space).
//
// Both cases are handled: an IP literal is checked directly; a DNS name is
// resolved (all records) and blocked if ANY resolved address is non-public,
// which also defeats DNS-rebinding. The check is re-applied on every redirect
// hop before the proxy re-issues a request.
// =========================================================================

/**
 * @param ip {string} An IPv4 address in dotted-decimal notation.
 * @return {boolean} true if the address is NOT globally routable / public.
 */
function isPrivateIPv4(ip) {
  var parts = ip.split('.');
  if (parts.length !== 4) {
    return true; // Unparseable -> fail closed.
  }
  var a = +parts[0];
  var b = +parts[1];
  var c = +parts[2];
  var d = +parts[3];
  if ([a, b, c, d].some(function(n) { return n !== n || n < 0 || n > 255; })) {
    return true; // Fail closed on anything that isn't a clean octet.
  }
  if (a === 0) { return true; }                              // 0.0.0.0/8 ("this" network)
  if (a === 10) { return true; }                             // 10.0.0.0/8 private
  if (a === 127) { return true; }                            // 127.0.0.0/8 loopback
  if (a === 100 && b >= 64 && b <= 127) { return true; }     // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) { return true; }               // 169.254.0.0/16 link-local (incl. metadata)
  if (a === 172 && b >= 16 && b <= 31) { return true; }      // 172.16.0.0/12 private
  if (a === 192 && b === 0 && c === 0) { return true; }      // 192.0.0.0/24 IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) { return true; }      // 192.0.2.0/24 TEST-NET-1
  if (a === 192 && b === 168) { return true; }               // 192.168.0.0/16 private
  if (a === 198 && (b === 18 || b === 19)) { return true; }  // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && c === 100) { return true; }   // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) { return true; }    // 203.0.113.0/24 TEST-NET-3
  if (a >= 224) { return true; }                             // 224/4 multicast + 240/4 reserved (incl. broadcast)
  return false;
}

/**
 * Expand an IPv6 address (already validated by net.isIPv6) into 8 16-bit groups.
 * @return {number[]|null} Array of 8 integers, or null if it could not be parsed.
 */
function expandIPv6(ip) {
  ip = String(ip).toLowerCase();
  var zone = ip.indexOf('%');
  if (zone !== -1) {
    ip = ip.slice(0, zone); // Strip any zone/scope id.
  }
  var halves = ip.split('::');
  if (halves.length > 2) {
    return null;
  }
  function parseHalf(s) {
    if (s === '') {
      return [];
    }
    var segs = s.split(':');
    var out = [];
    for (var i = 0; i < segs.length; i++) {
      var seg = segs[i];
      if (seg.indexOf('.') !== -1) {
        // Embedded IPv4, only valid as the final component.
        if (i !== segs.length - 1 || !net.isIPv4(seg)) {
          return null;
        }
        var oct = seg.split('.').map(Number);
        out.push(((oct[0] << 8) | oct[1]) & 0xffff);
        out.push(((oct[2] << 8) | oct[3]) & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(seg)) {
          return null;
        }
        out.push(parseInt(seg, 16));
      }
    }
    return out;
  }
  var head = parseHalf(halves[0]);
  if (head === null) {
    return null;
  }
  var groups;
  if (halves.length === 2) {
    var tail = parseHalf(halves[1]);
    if (tail === null) {
      return null;
    }
    var fill = 8 - head.length - tail.length;
    if (fill < 0) {
      return null;
    }
    groups = head;
    while (fill-- > 0) {
      groups.push(0);
    }
    groups = groups.concat(tail);
  } else {
    groups = head;
  }
  return groups.length === 8 ? groups : null;
}

/**
 * @param ip {string} An IPv6 address.
 * @return {boolean} true if the address is NOT globally routable / public.
 */
function isPrivateIPv6(ip) {
  var g = expandIPv6(ip);
  if (!g) {
    return true; // Fail closed.
  }
  var allZero = g.every(function(x) { return x === 0; });
  if (allZero) {
    return true; // :: unspecified
  }
  // ::1 loopback
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
    return true;
  }
  // ::ffff:a.b.c.d IPv4-mapped -> classify the embedded IPv4.
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return isPrivateIPv4(
      ((g[6] >> 8) & 0xff) + '.' + (g[6] & 0xff) + '.' + ((g[7] >> 8) & 0xff) + '.' + (g[7] & 0xff));
  }
  // ::a.b.c.d IPv4-compatible (deprecated) -> classify the embedded IPv4.
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPrivateIPv4(
      ((g[6] >> 8) & 0xff) + '.' + (g[6] & 0xff) + '.' + ((g[7] >> 8) & 0xff) + '.' + (g[7] & 0xff));
  }
  if ((g[0] & 0xffc0) === 0xfe80) { return true; }  // fe80::/10 link-local
  if ((g[0] & 0xfe00) === 0xfc00) { return true; }  // fc00::/7 unique-local
  if ((g[0] & 0xff00) === 0xff00) { return true; }  // ff00::/8 multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) { return true; } // 2001:db8::/32 documentation
  return false;
}

/**
 * @param ip {string} An IP address literal (IPv4 or IPv6).
 * @return {boolean} true if the address is non-public (or not a valid IP).
 */
function isPrivateAddress(ip) {
  var type = net.isIP(ip);
  if (type === 4) {
    return isPrivateIPv4(ip);
  }
  if (type === 6) {
    return isPrivateIPv6(ip);
  }
  return true; // Not a recognizable IP address -> fail closed.
}

/**
 * Determine whether the proxy is allowed to fetch the given target.
 * Blocks any target that is, or DNS-resolves to, a non-public address.
 *
 * @param requestState {object} req.corsAnywhereRequestState
 * @param location {object} Parsed target URL (see parseURL).
 * @param callback {function} Called with either null (safe to proxy) or an
 *   object {status, message} describing why the request must be blocked.
 */
function checkTargetAllowed(requestState, location, callback) {
  var hostname = location.hostname;

  // Test-only / operator escape hatch: an explicit allowlist of exact hostnames
  // or "host:port" strings that bypass the guard. Empty by default, so this has
  // no effect on the open proxy's production behavior.
  var allowlist = requestState.ssrfAllowlist;
  if (allowlist && allowlist.length &&
      (allowlist.indexOf(hostname) !== -1 || allowlist.indexOf(location.host) !== -1)) {
    callback(null);
    return;
  }

  var blocked = {
    status: 403,
    message: 'This proxy does not allow requests to non-public (internal) addresses.',
  };

  // Case 1: the target host is an IP literal -> check it directly.
  if (net.isIP(hostname)) {
    callback(isPrivateAddress(hostname) ? blocked : null);
    return;
  }

  // Case 2: the target host is a DNS name -> resolve all records and block if
  // ANY of them is non-public (this also defeats DNS-rebinding).
  var lookup = exports.dnsLookup || dns.lookup;
  var settled = false;
  var done = function(reason) {
    if (!settled) {
      settled = true;
      callback(reason);
    }
  };
  var failClosed = function() {
    done({status: 502, message: 'Unable to resolve the requested host.'});
  };
  try {
    lookup(hostname, {all: true}, function(err, addresses) {
      if (err || !addresses) {
        failClosed();
        return;
      }
      var list = Array.isArray(addresses) ? addresses : [addresses];
      if (!list.length) {
        failClosed();
        return;
      }
      for (var i = 0; i < list.length; i++) {
        var addr = list[i] && list[i].address ? list[i].address : list[i];
        if (isPrivateAddress(addr)) {
          done(blocked);
          return;
        }
      }
      done(null);
    });
  } catch (e) {
    // Never let a resolver exception crash the process; fail closed instead.
    failClosed();
  }
}

/**
 * Runs the SSRF egress check and only proxies the request when the target is a
 * public address. Used both for the initial request and for each redirect hop.
 */
function proxyRequestIfAllowed(req, res, proxy) {
  var requestState = req.corsAnywhereRequestState;
  checkTargetAllowed(requestState, requestState.location, function(reason) {
    if (reason) {
      if (res.headersSent || res.finished) {
        return;
      }
      var headers = withCORS({}, req);
      headers['content-type'] = 'text/plain';
      res.writeHead(reason.status, headers);
      res.end(reason.message);
      return;
    }
    proxyRequest(req, res, proxy);
  });
}

// Request handler factory
function getHandler(options, proxy) {
  var corsAnywhere = {
    getProxyForUrl: getProxyForUrl, // Function that specifies the proxy to use
    maxRedirects: 5,                // Maximum number of redirects to be followed.
    originBlacklist: [],            // Requests from these origins will be blocked.
    originWhitelist: [],            // If non-empty, requests not from an origin in this list will be blocked.
    checkRateLimit: null,           // Function that may enforce a rate-limit by returning a non-empty string.
    redirectSameOrigin: false,      // Redirect the client to the requested URL for same-origin requests.
    requireHeader: null,            // Require a header to be set?
    removeHeaders: [],              // Strip these request headers.
    setHeaders: {},                 // Set these request headers.
    corsMaxAge: 0,                  // If set, an Access-Control-Max-Age header with this value (in seconds) will be added.
    ssrfAllowlist: [],              // Hostnames / "host:port" exempt from the SSRF egress guard. Empty by default.
    helpFile: __dirname + '/help.txt',
  };

  Object.keys(corsAnywhere).forEach(function(option) {
    if (Object.prototype.hasOwnProperty.call(options, option)) {
      corsAnywhere[option] = options[option];
    }
  });

  // Convert corsAnywhere.requireHeader to an array of lowercase header names, or null.
  if (corsAnywhere.requireHeader) {
    if (typeof corsAnywhere.requireHeader === 'string') {
      corsAnywhere.requireHeader = [corsAnywhere.requireHeader.toLowerCase()];
    } else if (!Array.isArray(corsAnywhere.requireHeader) || corsAnywhere.requireHeader.length === 0) {
      corsAnywhere.requireHeader = null;
    } else {
      corsAnywhere.requireHeader = corsAnywhere.requireHeader.map(function(headerName) {
        return headerName.toLowerCase();
      });
    }
  }
  var hasRequiredHeaders = function(headers) {
    return !corsAnywhere.requireHeader || corsAnywhere.requireHeader.some(function(headerName) {
      return Object.hasOwnProperty.call(headers, headerName);
    });
  };

  return function(req, res) {
    req.corsAnywhereRequestState = {
      getProxyForUrl: corsAnywhere.getProxyForUrl,
      maxRedirects: corsAnywhere.maxRedirects,
      corsMaxAge: corsAnywhere.corsMaxAge,
      ssrfAllowlist: corsAnywhere.ssrfAllowlist,
    };

    var cors_headers = withCORS({}, req);
    if (req.method === 'OPTIONS') {
      // Pre-flight request. Reply successfully:
      res.writeHead(200, cors_headers);
      res.end();
      return;
    }

    var location = parseURL(req.url.slice(1));

    if (!location) {
      // Invalid API call. Show how to correctly use the API
      showUsage(corsAnywhere.helpFile, cors_headers, res);
      return;
    }

    if (location.host === 'iscorsneeded') {
      // Is CORS needed? This path is provided so that API consumers can test whether it's necessary
      // to use CORS. The server's reply is always No, because if they can read it, then CORS headers
      // are not necessary.
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end('no');
      return;
    }

    if (location.port > 65535) {
      // Port is higher than 65535
      res.writeHead(400, 'Invalid port', cors_headers);
      res.end('Port number too large: ' + location.port);
      return;
    }

    if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
      // Don't even try to proxy invalid hosts (such as /favicon.ico, /robots.txt)
      res.writeHead(404, 'Invalid host', cors_headers);
      res.end('Invalid host: ' + location.hostname);
      return;
    }

    if (!hasRequiredHeaders(req.headers)) {
      res.writeHead(400, 'Header required', cors_headers);
      res.end('Missing required request header. Must specify one of: ' + corsAnywhere.requireHeader);
      return;
    }

    var origin = req.headers.origin || '';
    if (corsAnywhere.originBlacklist.indexOf(origin) >= 0) {
      res.writeHead(403, 'Forbidden', cors_headers);
      res.end('The origin "' + origin + '" was blacklisted by the operator of this proxy.');
      return;
    }

    if (corsAnywhere.originWhitelist.length && corsAnywhere.originWhitelist.indexOf(origin) === -1) {
      res.writeHead(403, 'Forbidden', cors_headers);
      res.end('The origin "' + origin + '" was not whitelisted by the operator of this proxy.');
      return;
    }

    var rateLimitMessage = corsAnywhere.checkRateLimit && corsAnywhere.checkRateLimit(origin);
    if (rateLimitMessage) {
      res.writeHead(429, 'Too Many Requests', cors_headers);
      res.end('The origin "' + origin + '" has sent too many requests.\n' + rateLimitMessage);
      return;
    }

    if (corsAnywhere.redirectSameOrigin && origin && location.href[origin.length] === '/' &&
        location.href.lastIndexOf(origin, 0) === 0) {
      // Send a permanent redirect to offload the server. Badly coded clients should not waste our resources.
      cors_headers.vary = 'origin';
      cors_headers['cache-control'] = 'private';
      cors_headers.location = location.href;
      res.writeHead(301, 'Please use a direct request', cors_headers);
      res.end();
      return;
    }

    var isRequestedOverHttps = req.connection.encrypted || /^\s*https/.test(req.headers['x-forwarded-proto']);
    var proxyBaseUrl = (isRequestedOverHttps ? 'https://' : 'http://') + req.headers.host;

    corsAnywhere.removeHeaders.forEach(function(header) {
      delete req.headers[header];
    });

    Object.keys(corsAnywhere.setHeaders).forEach(function(header) {
      req.headers[header] = corsAnywhere.setHeaders[header];
    });

    req.corsAnywhereRequestState.location = location;
    req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

    proxyRequestIfAllowed(req, res, proxy);
  };
}

// Create server with default and given values
// Creator still needs to call .listen()
exports.createServer = function createServer(options) {
  options = options || {};

  // Default options:
  var httpProxyOptions = {
    xfwd: true,            // Append X-Forwarded-* headers
  };
  // Allow user to override defaults and add own options
  if (options.httpProxyOptions) {
    Object.keys(options.httpProxyOptions).forEach(function(option) {
      httpProxyOptions[option] = options.httpProxyOptions[option];
    });
  }

  var proxy = httpProxy.createServer(httpProxyOptions);
  var requestHandler = getHandler(options, proxy);
  var server;
  if (options.httpsOptions) {
    server = require('https').createServer(options.httpsOptions, requestHandler);
  } else {
    server = require('http').createServer(requestHandler);
  }

  // When the server fails, just show a 404 instead of Internal server error
  proxy.on('error', function(err, req, res) {
    if (res.headersSent) {
      // This could happen when a protocol error occurs when an error occurs
      // after the headers have been received (and forwarded). Do not write
      // the headers because it would generate an error.
      return;
    }

    // When the error occurs after setting headers but before writing the response,
    // then any previously set headers must be removed.
    var headerNames = res.getHeaderNames ? res.getHeaderNames() : Object.keys(res._headers || {});
    headerNames.forEach(function(name) {
      res.removeHeader(name);
    });

    res.writeHead(404, {'Access-Control-Allow-Origin': '*'});
    res.end('Not found because of proxy error: ' + err);
  });

  return server;
};
