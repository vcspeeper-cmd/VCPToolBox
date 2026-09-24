/**
 * VCP Gateway — HTTPS reverse proxy with Bearer auth
 * Port 5000 (HTTPS) → vcp-main (127.0.0.1:6005)
 * Port 5001 (HTTPS) → vcp-admin (127.0.0.1:6006)
 *
 * TLS: Let's Encrypt cert for vcp.vcspeeper.ccwu.cc
 * Auth: Bearer token, Basic Auth, /pw=, /VCP_Key=, ?token=
 * Rate limit: 20 failed auth / 60s → 60s IP block.
 */
const http = require("http");
const https = require("https");
const net = require("net");
const fs = require("fs");
const path = require("path");

function loadToken() {
  if (process.env.VCP_GATEWAY_TOKEN) return process.env.VCP_GATEWAY_TOKEN;
  try {
    const env = fs.readFileSync(path.join(__dirname, "config.env"), "utf8");
    const m = env.match(/^Key=(.+)$/m);
    if (m) return m[1].trim();
  } catch {}
  return "vcspeepervcp";
}

const AUTH_TOKEN = loadToken();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 20;
const BLOCK_DURATION = 60000;
const failMap = new Map();
const blockMap = new Map();

// VCP WebSocket path patterns that need VCP_Key injection
const VCP_WS_PATHS = [
  "/VCPlog",
  "/vcpinfo",
  "/vcp-distributed-server",
  "/vcp-chrome-control",
  "/vcp-chrome-observer",
  "/vcp-admin-panel",
];

function checkAuth(req) {
  // 1. Standard Bearer header
  const authHeader = req.headers["authorization"] || "";
  if (authHeader === "Bearer " + AUTH_TOKEN) return true;
  // 2. Basic Auth (for admin API - VCPMobile uses this)
  if (authHeader.startsWith("Basic ")) {
    try {
      var decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
      var parts = decoded.split(":");
      if (parts.length >= 2 && parts[1] === AUTH_TOKEN) return true;
    } catch {}
  }
  // 3. VCP native: Key embedded in URL path /VCPlog/VCP_Key=xxx
  var keyInPath = req.url.match(/\/VCP_Key=([^\/&?\s]+)/);
  if (keyInPath && keyInPath[1] === AUTH_TOKEN) return true;
  // 4. VCP image/file service: /pw=xxx/images/... or /pw=xxx/files/...
  var pwMatch = req.url.match(/\/pw=([^\/]+)\//);
  if (pwMatch && pwMatch[1] === AUTH_TOKEN) return true;
  // 5. Query param ?token=
  try {
    const u = new URL(req.url, "http://localhost");
    if (u.searchParams.get("token") === AUTH_TOKEN) return true;
  } catch {}
  return false;
}

function isBlocked(ip) {
  const until = blockMap.get(ip);
  if (!until) return false;
  if (Date.now() > until) {
    blockMap.delete(ip);
    return false;
  }
  return true;
}

function recordFail(ip) {
  const now = Date.now();
  let entry = failMap.get(ip);
  if (!entry || now - entry.firstFail > RATE_LIMIT_WINDOW) {
    entry = { count: 0, firstFail: now };
  }
  entry.count++;
  failMap.set(ip, entry);
  if (entry.count >= RATE_LIMIT_MAX) {
    blockMap.set(ip, now + BLOCK_DURATION);
    failMap.delete(ip);
    console.log(
      "[Gateway] BLOCKED " + ip + " for " + BLOCK_DURATION / 1000 + "s"
    );
  }
}

/**
 * Rewrite WS URL: inject VCP_Key for backend auth.
 * Client sends:   ws://host:5000/VCPlog  (with Bearer header)
 * Backend needs:  /VCPlog/VCP_Key=xxx
 */
function rewriteWsUrl(url) {
  var qIdx = url.indexOf("?");
  var pathname = qIdx >= 0 ? url.slice(0, qIdx) : url;
  var query = qIdx >= 0 ? url.slice(qIdx) : "";
  var cleanPath = pathname.replace(/\/+$/, "");
  for (var i = 0; i < VCP_WS_PATHS.length; i++) {
    var prefix = VCP_WS_PATHS[i];
    if (cleanPath === prefix) {
      return cleanPath + "/VCP_Key=" + AUTH_TOKEN + query;
    }
    if (cleanPath.indexOf(prefix + "/VCP_Key=") === 0) {
      return prefix + "/VCP_Key=" + AUTH_TOKEN + query;
    }
  }
  return url;
}

function sanitizeHeaders(headers, targetPort, stripAuth) {
  var clean = Object.assign({}, headers, { host: "127.0.0.1:" + targetPort });
  if (stripAuth) delete clean["authorization"];
  return clean;
}

function createProxy(listenPort, targetPort, label, skipAuth) {
  // Load TLS certs
  var certDir = path.join(__dirname, "certs");
  var tlsOpts = null;
  try {
    tlsOpts = {
      key: fs.readFileSync(path.join(certDir, "privkey.pem")),
      cert: fs.readFileSync(path.join(certDir, "fullchain.pem")),
      // Match Caddy TLS compatibility for Android WebView/Xiaomi
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
      // Broad cipher list for compatibility
      ciphers: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
      ].join(":"),
      // ALPN: http/1.1 only (Node https.createServer doesn't support h2 frames)
      ALPNProtocols: ["http/1.1"],
    };
  } catch (e) {
    console.warn(
      "[Gateway] TLS certs not found, falling back to HTTP: " + e.message
    );
  }

  var createFn = tlsOpts
    ? https.createServer.bind(https, tlsOpts)
    : http.createServer.bind(http);
  var proto = tlsOpts ? "https" : "http";

  var server = createFn(function (req, res) {
    var clientIp =
      (req.socket.remoteAddress || "").replace("::ffff:", "") || "unknown";

    if (isBlocked(clientIp)) {
      res.writeHead(429, { "Content-Type": "application/json" });
      return res.end(
        JSON.stringify({ error: "Too many failed attempts. Try later." })
      );
    }

    if (!skipAuth && !checkAuth(req)) {
      recordFail(clientIp);
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end(
        JSON.stringify({ error: "Unauthorized. Bearer token required." })
      );
    }

    // Route /admin_api/ and /AdminPanel/ to admin port (6006)
    var actualPort = targetPort;
    if (
      req.url.startsWith("/admin_api/") ||
      req.url.startsWith("/AdminPanel")
    ) {
      actualPort = 6006;
    }

    var options = {
      hostname: "127.0.0.1",
      port: actualPort,
      path: req.url,
      method: req.method,
      headers: sanitizeHeaders(req.headers, actualPort),
    };

    var proxyReq = http.request(options, function (proxyRes) {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    });

    proxyReq.on("error", function (e) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Backend unavailable", detail: e.message })
      );
    });

    req.pipe(proxyReq, { end: true });
  });

  // WebSocket: auth via Bearer header or ?token=, then inject VCP_Key for backend
  server.on("upgrade", function (req, socket, head) {
    var clientIp =
      (req.socket.remoteAddress || "").replace("::ffff:", "") || "unknown";

    if (isBlocked(clientIp)) {
      socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
      socket.destroy();
      return;
    }

    if (!skipAuth && !checkAuth(req)) {
      recordFail(clientIp);
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    // Rewrite URL: inject VCP_Key, sanitize headers, strip ?token= from URL
    var backendUrl = rewriteWsUrl(req.url);
    var cleanHeaders = sanitizeHeaders(req.headers, targetPort, true);
    var finalUrl = backendUrl.replace(/[?&]token=[^&]+/, "").replace(/\?$/, "");

    var proxySocket = net.connect(targetPort, "127.0.0.1", function () {
      var reqLine = "GET " + finalUrl + " HTTP/1.1\r\n";
      var headerPairs = Object.entries(cleanHeaders);
      var headerStr = headerPairs
        .map(function (pair) {
          return pair[0] + ": " + pair[1];
        })
        .join("\r\n");
      proxySocket.write(reqLine + headerStr + "\r\n\r\n");
      if (head.length) proxySocket.write(head);
      socket.pipe(proxySocket).pipe(socket);
    });
    proxySocket.on("error", function () {
      socket.destroy();
    });
    socket.on("error", function () {
      proxySocket.destroy();
    });
  });

  server.on("error", function (e) {
    console.error(
      "[Gateway] " + label + " port " + listenPort + " error: " + e.message
    );
  });
  server.listen(listenPort, "0.0.0.0", function () {
    console.log(
      "[Gateway] " +
        label +
        ": " +
        proto +
        "://0.0.0.0:" +
        listenPort +
        " -> 127.0.0.1:" +
        targetPort
    );
  });
}

createProxy(5000, 6005, "vcp-main");
createProxy(5001, 6006, "vcp-admin", true);

// HTTP:5002 and HTTP:5080 removed — all traffic goes through HTTPS:5000/5001

console.log("[Gateway] Auth: Bearer token (" + AUTH_TOKEN.length + " chars)");
console.log(
  "[Gateway] WS: Bearer header or ?token= -> auto-inject VCP_Key to backend"
);
console.log(
  "[Gateway] Rate limit: " +
    RATE_LIMIT_MAX +
    " fails/" +
    RATE_LIMIT_WINDOW / 1000 +
    "s -> block " +
    BLOCK_DURATION / 1000 +
    "s"
);

setInterval(function () {
  var now = Date.now();
  for (var entry of failMap) {
    if (now - entry[1].firstFail > RATE_LIMIT_WINDOW) failMap.delete(entry[0]);
  }
  for (var entry of blockMap) {
    if (now > entry[1]) blockMap.delete(entry[0]);
  }
}, 300000);
