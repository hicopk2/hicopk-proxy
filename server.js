const express = require("express");
const fetch = require("node-fetch");
const { URL } = require("url");

const app = express();

// Allowed protocols and host patterns
const ALLOWED_PROTOCOLS = ["http:", "https:"];

// Block common internal hosts and IP ranges
const BLOCKED_HOSTS = [
  "localhost",
  "127.0.0.1",
  "::1",
];

const BLOCKED_IP_PREFIXES = [
  "10.",        // 10.0.0.0/8
  "172.16.",    // 172.16.0.0 – 172.31.255.255 (simplified)
  "192.168.",   // 192.168.0.0/16
];

function isPrivateIp(host) {
  // Very simple check: only works when host is a plain IPv4 string.
  // For real production, resolve DNS and check CIDRs.
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;
  return BLOCKED_IP_PREFIXES.some(prefix => host.startsWith(prefix));
}

function validateAndNormalizeUrl(raw) {
  if (!raw) {
    throw new Error("Missing url parameter");
  }

  let urlStr = raw.trim();
  if (!urlStr) {
    throw new Error("Empty url");
  }

  // Add protocol if missing
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = "https://" + urlStr;
  }

  let u;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error("Invalid URL");
  }

  // Protocol check
  if (!ALLOWED_PROTOCOLS.includes(u.protocol)) {
    throw new Error("Disallowed protocol");
  }

  const host = u.hostname.toLowerCase();

  // Block obvious internal hostnames
  if (BLOCKED_HOSTS.includes(host)) {
    throw new Error("Disallowed host");
  }

  // Block obvious private IPs (if host is literal IP)
  if (isPrivateIp(host)) {
    throw new Error("Disallowed IP range");
  }

  return u.toString();
}

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Proxy endpoint with basic validation + SSRF guard
app.get("/proxy", async (req, res) => {
  let target;
  try {
    target = validateAndNormalizeUrl(req.query.url);
  } catch (err) {
    return res.status(400).send(`Bad url: ${err.message}`);
  }

  try {
    const upstream = await fetch(target, {
      // Only GET via this demo proxy
      method: "GET",
      redirect: "follow",
    });

    // Forward status and content-type
    res.status(upstream.status);
    const contentType = upstream.headers.get("content-type") || "text/html";
    res.set("Content-Type", contentType);

    const body = await upstream.text();
    res.send(body);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(502).send("Error fetching target URL");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy listening on http://localhost:${PORT}`);
});
