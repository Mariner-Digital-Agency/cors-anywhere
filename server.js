// Listen on a specific host via the HOST environment variable
var host = process.env.HOST || '0.0.0.0';
// Listen on a specific port via the PORT environment variable
var port = process.env.PORT || 8080;

// Grab the blacklist from the command-line so that we can update the blacklist without deploying
// again. CORS Anywhere is open by design, and this blacklist is not used, except for countering
// immediate abuse (e.g. denial of service). If you want to block all origins except for some,
// use originWhitelist instead.
var originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
var originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
// Hostnames the proxy may forward to (lowercase, exact). Empty = no restriction.
var targetAllowlist = parseEnvHostList(process.env.CORSANYWHERE_ALLOWED_TARGETS, true);
// Client IPs refused outright.
var blockedClientIps = parseEnvHostList(process.env.CORSANYWHERE_BLOCKED_IPS, false);
function parseEnvList(env) {
  if (!env) {
    return [];
  }
  return env.split(',');
}

// Like parseEnvList, but tolerant of spaces and blank entries so a stray
// ", " in the Railway variable cannot silently disable a rule.
function parseEnvHostList(env, lowercase) {
  return parseEnvList(env).map(function(entry) {
    entry = entry.trim();
    return lowercase ? entry.toLowerCase() : entry;
  }).filter(Boolean);
}

// Set up rate-limiting to avoid abuse of the public CORS Anywhere server.
var checkRateLimit = require('./lib/rate-limit')(process.env.CORSANYWHERE_RATELIMIT);

var cors_proxy = require('./lib/cors-anywhere');
cors_proxy.createServer({
  originBlacklist: originBlacklist,
  originWhitelist: originWhitelist,
  targetAllowlist: targetAllowlist,
  blockedClientIps: blockedClientIps,
  requireHeader: ['origin', 'x-requested-with'],
  checkRateLimit: checkRateLimit,
  removeHeaders: [
    'cookie',
    'cookie2',
    // Strip Heroku-specific headers
    'x-heroku-queue-wait-time',
    'x-heroku-queue-depth',
    'x-heroku-dynos-in-use',
    'x-request-start',
  ],
  redirectSameOrigin: true,
  httpProxyOptions: {
    // Do not add X-Forwarded-For, etc. headers, because Heroku already adds it.
    xfwd: false,
  },
}).listen(port, host, function() {
  console.log('Running CORS Anywhere on ' + host + ':' + port);
});
