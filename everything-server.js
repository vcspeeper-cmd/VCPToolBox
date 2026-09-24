/**
 * Linux Everything-compatible HTTP file search server
 * Mimics Everything's HTTP JSON API on configurable port.
 * Uses `find` under the hood with result caching.
 *
 * API: GET /?s=<query>&json=1&n=<maxResults>&path_column=1
 * Returns: { results: [{ type: "file", name: "filename", path: "/dir/" }, ...] }
 */
const http = require("http");
const { execFile } = require("child_process");
const path = require("path");
const fs = require("fs");

// Config from env
const PORT = parseInt(process.env.EVERYTHING_PORT || "8025", 10);
const SEARCH_ROOTS = (process.env.EVERYTHING_SEARCH_ROOTS || "/root/VCPToolBox").split(",").map(function(s) { return s.trim(); });
const MAX_RESULTS_DEFAULT = 100;
const MAX_RESULTS_CAP = 500;
const CACHE_TTL = 60000; // 1 min
const DEBUG = (process.env.DEBUG_MODE || "false").toLowerCase() === "true";

// Simple LRU cache
var cache = new Map();
var cacheOrder = [];
var CACHE_MAX = 200;

function getCached(key) {
  var entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function setCache(key, data) {
  if (cache.size >= CACHE_MAX) {
    var oldest = cacheOrder.shift();
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, { data: data, ts: Date.now() });
  cacheOrder.push(key);
}

function searchFiles(query, maxResults, callback) {
  var cacheKey = query + "|" + maxResults;
  var cached = getCached(cacheKey);
  if (cached) return callback(null, cached);

  // Build find command: search filenames matching query (case insensitive)
  // Support basic glob: if query contains * or ?, use it as-is; otherwise wrap with *query*
  var namePattern = (query.indexOf("*") >= 0 || query.indexOf("?") >= 0) ? query : "*" + query + "*";

  var args = [];
  SEARCH_ROOTS.forEach(function(root) { args.push(root); });
  args.push("-maxdepth", "10", "-iname", namePattern, "-type", "f");

  execFile("find", args, { timeout: 10000, maxBuffer: 5 * 1024 * 1024 }, function(err, stdout) {
    if (err && err.killed) {
      return callback(new Error("Search timeout"));
    }
    // find may return exit code 1 for permission errors, still has partial results
    var lines = (stdout || "").trim().split("\n").filter(function(l) { return l.length > 0; });
    var results = lines.slice(0, maxResults).map(function(fullPath) {
      var dir = path.dirname(fullPath);
      var name = path.basename(fullPath);
      return { type: "file", name: name, path: dir + "/" };
    });

    setCache(cacheKey, results);
    callback(null, results);
  });
}

var server = http.createServer(function(req, res) {
  var url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch (e) {
    res.writeHead(400);
    return res.end("Bad request");
  }

  var query = url.searchParams.get("s") || "";
  var isJson = url.searchParams.get("json") === "1";
  var maxResults = Math.min(parseInt(url.searchParams.get("n") || MAX_RESULTS_DEFAULT, 10) || MAX_RESULTS_DEFAULT, MAX_RESULTS_CAP);

  if (!query) {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ results: [] }));
  }

  if (DEBUG) console.log("[Everything] Search: " + query + " (max: " + maxResults + ")");

  searchFiles(query, maxResults, function(err, results) {
    if (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: err.message }));
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ results: results }));
  });
});

server.listen(PORT, "127.0.0.1", function() {
  console.log("[Everything] Linux file search server on 127.0.0.1:" + PORT);
  console.log("[Everything] Search roots: " + SEARCH_ROOTS.join(", "));
  console.log("[Everything] Cache TTL: " + (CACHE_TTL / 1000) + "s, max entries: " + CACHE_MAX);
});
