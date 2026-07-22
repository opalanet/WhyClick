const http  = require("http");
const https = require("https");
const tls   = require("tls");
const fs    = require("fs");
const path  = require("path");
const url   = require("url");

function httpsGet(requestUrl, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const req = https.get(requestUrl, { headers: { "Accept": "application/json" } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpsGet(res.headers.location, timeoutMs).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let data = "";
      res.on("data", chunk => (data += chunk));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error("Invalid JSON")); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("Timeout")); });
    req.on("error", reject);
  });
}

function formatDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d) ? str : d.toISOString().split("T")[0];
}

function extractRdapField(obj, ...keys) {
  for (const key of keys) {
    if (obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return null;
}

function parseRdapEvents(events = []) {
  const result = {};
  for (const ev of events) {
    const action = ev.eventAction;
    const date   = formatDate(ev.eventDate);
    if (action === "registration")   result.created  = date;
    if (action === "expiration")     result.expires  = date;
    if (action === "last changed")   result.updated  = date;
  }
  return result;
}

function parseRdapEntities(entities = []) {
  const registrar = { name: null, email: null };
  const registrant = { name: null, org: null, country: null };

  for (const entity of entities) {
    const roles = entity.roles || [];
    const vcard = entity.vcardArray ? entity.vcardArray[1] : [];

    const getName    = () => (vcard.find(f => f[0] === "fn")  || [])[3] || null;
    const getEmail   = () => (vcard.find(f => f[0] === "email") || [])[3] || null;
    const getOrg     = () => (vcard.find(f => f[0] === "org")   || [])[3] || null;
    const getCountry = () => {
      const adr = vcard.find(f => f[0] === "adr");
      if (!adr) return null;
      const parts = Array.isArray(adr[3]) ? adr[3] : [];
      return parts[6] || null;
    };

    if (roles.includes("registrar")) {
      registrar.name  = getName() || entity.publicIds?.[0]?.identifier || null;
      registrar.email = getEmail();
    }
    if (roles.includes("registrant") || roles.includes("administrative")) {
      registrant.name    = registrant.name    || getName();
      registrant.org     = registrant.org     || getOrg();
      registrant.country = registrant.country || getCountry();
    }
  }
  return { registrar, registrant };
}

async function rdapLookup(hostname) {
  const parts = hostname.split(".");
  const domain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;

  let rdapBase;
  try {
    const bootstrap = await httpsGet("https://data.iana.org/rdap/dns.json", 6000);
    const tld = "." + parts[parts.length - 1];
    const entry = bootstrap.services.find(([tlds]) => tlds.includes(tld.slice(1)));
    rdapBase = entry ? entry[1][0] : null;
  } catch {
    rdapBase = "https://rdap.org/";
  }

  if (!rdapBase) rdapBase = "https://rdap.org/";
  const rdapUrl = rdapBase.replace(/\/$/, "") + "/domain/" + domain;

  const data = await httpsGet(rdapUrl, 6000);

  const events = parseRdapEvents(data.events);
  const { registrar, registrant } = parseRdapEntities(data.entities || []);

  const nameservers = (data.nameservers || [])
    .map(ns => (ns.ldhName || ns.unicodeName || "").toLowerCase())
    .filter(Boolean);

  const status = (data.status || []).map(s => s.toLowerCase());

  let domainAgeDays = null;
  if (events.created) {
    domainAgeDays = Math.floor((Date.now() - new Date(events.created)) / 86400000);
  }

  return {
    domain,
    registrar:    registrar.name,
    registrant:   registrant.org || registrant.name,
    country:      registrant.country,
    created:      events.created  || null,
    updated:      events.updated  || null,
    expires:      events.expires  || null,
    domainAgeDays,
    nameservers:  nameservers.slice(0, 4),
    status,
    rdapUrl,
  };
}

function certLookup(hostname, port = 443, timeoutMs = 6000) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const authError  = socket.authorizationError || null;
        socket.destroy();

        if (!cert || !cert.subject) {
          return reject(new Error("No certificate returned"));
        }

        const issuerOrg   = cert.issuer?.O   || cert.issuer?.CN || null;
        const issuerCN    = cert.issuer?.CN   || null;
        const subjectCN   = cert.subject?.CN  || null;
        const subjectAlt  = cert.subjectaltname || null;
        const validFrom   = cert.valid_from ? new Date(cert.valid_from).toISOString().split("T")[0] : null;
        const validTo     = cert.valid_to   ? new Date(cert.valid_to).toISOString().split("T")[0]   : null;

        const now         = Date.now();
        const expiry      = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
        const isExpired   = expiry !== null && expiry < now;
        const daysLeft    = expiry !== null ? Math.floor((expiry - now) / 86400000) : null;
        const isExpiringSoon = daysLeft !== null && daysLeft >= 0 && daysLeft <= 14;

        const isSelfSigned = cert.issuer &&
          cert.subject &&
          JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

        const sans = subjectAlt
          ? subjectAlt.split(",").map(s => s.replace(/^DNS:/, "").trim()).filter(Boolean)
          : [];

        const hostnameMatches = authorized || (() => {
          const wild = sans.some(san => {
            if (san.startsWith("*.")) return hostname.endsWith(san.slice(1));
            return san === hostname;
          });
          return wild || (subjectCN && (subjectCN === hostname || (subjectCN.startsWith("*.") && hostname.endsWith(subjectCN.slice(1)))));
        })();

        resolve({
          issuerOrg,
          issuerCN,
          subjectCN,
          validFrom,
          validTo,
          daysLeft,
          isExpired,
          isExpiringSoon,
          isSelfSigned,
          hostnameMatches,
          authorized,
          authError,
          sans: sans.slice(0, 6),
        });
      }
    );

    socket.setTimeout(timeoutMs, () => { socket.destroy(); reject(new Error("Timeout")); });
    socket.on("error", reject);
  });
}

const loadHeuristic = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, "heuristics", `${name}.json`), "utf8"));
const suspiciousTLDs   = loadHeuristic("suspiciousTLDs");
const shorteners       = loadHeuristic("shorteners");
const brands           = loadHeuristic("brands");
const suspiciousParams = loadHeuristic("suspiciousParams");

const suspiciousParamsLower = new Set(suspiciousParams.map(p => p.toLowerCase()));

const PORT = 3000;

function checkHTTPS({ parsed }) {
  if (parsed.protocol !== "http:") return null;
  return { severity: "medium", label: "No HTTPS", score: 20,
    detail: "Connection is unencrypted. Data can be intercepted in transit." };
}

function checkIPHostname({ hostname }) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^\[([0-9a-fA-F:]+)\]$/;
  if (!ipv4.test(hostname) && !ipv6.test(hostname)) return null;
  const kind = ipv6.test(hostname) ? "IPv6" : "IPv4";
  return { severity: "high", label: `IP address hostname (${kind})`, score: 35,
    detail: "URLs using raw IPs instead of domain names are a common phishing tactic." };
}

function checkExcessiveSubdomains({ subdomainParts }) {
  if (subdomainParts.length <= 3) return null;
  return { severity: "medium", label: "Excessive subdomains", score: 20,
    detail: `${subdomainParts.length} domain levels detected. Deep nesting is often used to spoof trusted brands. (Note: multi-part TLDs like .co.uk or corporate subdomains may trigger this.)` };
}

function checkIDNHomograph({ hostname }) {
  const decodedHostname = url.domainToUnicode(hostname);
  const isPunycode = decodedHostname !== hostname && decodedHostname !== "";
  const hasNonASCII = /[^\x00-\x7F]/.test(hostname);
  if (!hasNonASCII && !isPunycode) return null;
  const display = isPunycode ? decodedHostname : hostname;
  return { severity: "high", label: "Non-ASCII / IDN homograph domain", score: 40,
    detail: `Domain decodes to "${display}". Unicode characters can visually mimic real domains (e.g. pаypal.com using a Cyrillic 'а').` };
}

function checkSuspiciousTLD({ hostname }) {
  const matched = suspiciousTLDs.find(tld => hostname.endsWith(tld));
  if (!matched) return null;
  return { severity: "medium", label: `Suspicious TLD (${matched})`, score: 20,
    detail: "This top-level domain is commonly associated with free/throwaway domains used in phishing campaigns." };
}

function checkURLShortener({ hostname }) {
  if (!shorteners.some(s => hostname === s || hostname.endsWith("." + s))) return null;
  return { severity: "medium", label: "URL shortener", score: 25,
    detail: "Destination is hidden. The link could redirect anywhere — including malicious sites." };
}

function checkBrandImpersonation({ hostname, subdomainParts }) {
  const domainWithoutTLD = subdomainParts.slice(0, -1).join(".");
  const decoded = url.domainToUnicode(domainWithoutTLD) || domainWithoutTLD;
  const matched = brands.find(b =>
    (domainWithoutTLD.includes(b) || decoded.includes(b)) && !hostname.startsWith(b + ".")
  );
  if (!matched) return null;
  return { severity: "high", label: `Brand impersonation (${matched})`, score: 45,
    detail: `"${matched}" appears in the URL path but is not the actual domain. Classic phishing pattern.` };
}

function checkRandomDomain({ subdomainParts }) {
  const registeredDomain = subdomainParts.slice(-2, -1)[0] || "";
  if (registeredDomain.length < 6) return null;

  const vowels = (registeredDomain.match(/[aeiou]/gi) || []).length;
  const vowelRatio = vowels / registeredDomain.length;
  const consonantClusters = (registeredDomain.match(/[^aeiou]{3,}/gi) || []).length;

  const freq = {};
  for (const c of registeredDomain) freq[c] = (freq[c] || 0) + 1;
  const entropy = -Object.values(freq).reduce((sum, count) => {
    const p = count / registeredDomain.length;
    return sum + p * Math.log2(p);
  }, 0);

  if (vowelRatio >= 0.2 && !(consonantClusters >= 2 && entropy > 3.2)) return null;
  return { severity: "medium", label: "Randomly generated domain name", score: 25,
    detail: `"${registeredDomain}" has unusually low vowel density (${Math.round(vowelRatio * 100)}%) or high character entropy — a common trait of algorithmically generated phishing domains (e.g. .biz.id, .id scams).` };
}

function checkLongURL({ fullURL }) {
  if (fullURL.length <= 200) return null;
  return { severity: "low", label: "Unusually long URL", score: 10,
    detail: `${fullURL.length} characters. Long URLs can obscure the real destination or hide injected parameters.` };
}

function checkOpenRedirect({ params }) {
  const found = params.find(([k]) => suspiciousParamsLower.has(k.toLowerCase()));
  if (!found) return null;
  return { severity: "medium", label: `Open redirect parameter (?${found[0]}=)`, score: 20,
    detail: "This parameter may redirect you to an unintended destination, bypassing domain trust." };
}

function checkHeavyEncoding({ pathname }) {
  const count = (pathname.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (count <= 5) return null;
  return { severity: "low", label: "Heavy URL encoding in path", score: 10,
    detail: `${count} encoded characters detected. Can be used to bypass filters or obscure intent.` };
}

function checkNonStandardPort({ parsed }) {
  if (!parsed.port || ["80", "443"].includes(parsed.port)) return null;
  return { severity: "medium", label: `Non-standard port (:${parsed.port})`, score: 25,
    detail: "Legitimate sites rarely use custom ports. This can indicate a rogue server." };
}

function checkAtSymbol({ rawURL }) {
  if (!rawURL.includes("@")) return null;
  return { severity: "high", label: "@ symbol in URL", score: 40,
    detail: "The @ character in a URL can be used to hide the real hostname. e.g. real.com@evil.com — evil.com is the actual destination." };
}

function checkPathTraversal({ pathname }) {
  if (!/\/\.\.\/|\/\//.test(pathname)) return null;
  return { severity: "medium", label: "Path traversal pattern", score: 15,
    detail: "Double slashes or ../ sequences in the path may indicate directory traversal or URL confusion." };
}

const CHECKS = [
  checkHTTPS,
  checkIPHostname,
  checkExcessiveSubdomains,
  checkIDNHomograph,
  checkSuspiciousTLD,
  checkURLShortener,
  checkBrandImpersonation,
  checkRandomDomain,
  checkLongURL,
  checkOpenRedirect,
  checkHeavyEncoding,
  checkNonStandardPort,
  checkAtSymbol,
  checkPathTraversal,
];

async function analyzeURL(rawURL) {
  let inputURL = rawURL.trim();
  if (!/^https?:\/\//i.test(inputURL)) inputURL = "http://" + inputURL;

  let parsed;
  try {
    parsed = new URL(inputURL);
  } catch {
    return { error: true, message: "Could not parse URL. Make sure it's a valid link." };
  }

  const hostname = parsed.hostname.toLowerCase();
  const subdomainParts = hostname.split(".");
  const context = {
    rawURL,
    parsed,
    hostname,
    fullURL: parsed.href,
    pathname: parsed.pathname,
    params: [...parsed.searchParams.entries()],
    subdomainParts,
  };

  const findings = [];
  let riskScore = 0;

  for (const check of CHECKS) {
    const result = check(context);
    if (result) {
      const { score, ...finding } = result;
      findings.push(finding);
      riskScore += score;
    }
  }

  let whois = null;
  const isIPHostname = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[([0-9a-fA-F:]+)\]$/.test(hostname);
  if (!isIPHostname && subdomainParts.length >= 2) {
    try {
      whois = await rdapLookup(hostname);
      if (whois.domainAgeDays !== null && whois.domainAgeDays < 90) {
        findings.push({
          severity: "high",
          label: `Newly registered domain (${whois.domainAgeDays} days old)`,
          detail: "Domains under 90 days old are disproportionately used in phishing. Treat with extra caution.",
        });
        riskScore += 35;
      }
    } catch {
      whois = { error: true };
    }
  }

  let cert = null;
  const isHTTPS = parsed.protocol === "https:";
  if (isHTTPS && !isIPHostname) {
    try {
      const port = parsed.port ? parseInt(parsed.port, 10) : 443;
      cert = await certLookup(hostname, port);

      if (cert.isSelfSigned) {
        findings.push({
          severity: "high",
          label: "Self-signed certificate",
          detail: "The certificate was not issued by a trusted authority. Anyone can create one — it provides no proof of identity.",
        });
        riskScore += 35;
      }

      if (cert.isExpired) {
        findings.push({
          severity: "high",
          label: "Expired TLS certificate",
          detail: `Certificate expired on ${cert.validTo}. Legitimate sites keep their certs current; an expired cert is a red flag.`,
        });
        riskScore += 30;
      } else if (cert.isExpiringSoon) {
        findings.push({
          severity: "medium",
          label: `Certificate expiring soon (${cert.daysLeft} days)`,
          detail: `The TLS certificate expires on ${cert.validTo}. This may indicate poor maintenance — or an abandoned site.`,
        });
        riskScore += 10;
      }

      if (!cert.hostnameMatches && !cert.isSelfSigned) {
        findings.push({
          severity: "high",
          label: "Certificate hostname mismatch",
          detail: `The certificate was not issued for "${hostname}". This could mean traffic is being intercepted or the domain was recently moved.`,
        });
        riskScore += 30;
      }
    } catch {
      cert = { error: true };
    }
  }

  riskScore = Math.min(riskScore, 100);

  let verdict, verdictCode;
  if (riskScore >= 60)       { verdict = "High Risk";   verdictCode = "danger"; }
  else if (riskScore >= 25)  { verdict = "Suspicious";  verdictCode = "warning"; }
  else                       { verdict = "Looks OK";    verdictCode = "safe"; }

  return {
    error: false,
    input: rawURL,
    parsed: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      params: Object.fromEntries(context.params),
    },
    riskScore,
    verdict,
    verdictCode,
    findings,
    whois,
    cert,
  };
}

const server = http.createServer((req, res) => {
  const parsedReq = new URL(req.url, "http://localhost");
  const pathname = parsedReq.pathname;

  const staticRoutes = {
    "/":          { file: "index.html",  type: "text/html" },
    "/style.css": { file: "style.css",   type: "text/css" },
    "/app.js":    { file: "app.js",      type: "application/javascript" },
  };

  if (req.method === "GET" && staticRoutes[pathname]) {
    const { file, type } = staticRoutes[pathname];
    fs.readFile(path.join(__dirname, "public", file), (err, data) => {
      if (err) { res.writeHead(err.code === "ENOENT" ? 404 : 500); return res.end("Not found"); }
      res.writeHead(200, { "Content-Type": type });
      res.end(data);
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/analyze") {
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", async () => {
      try {
        const { url: targetURL } = JSON.parse(body);
        if (!targetURL || typeof targetURL !== "string") {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: true, message: "No URL provided." }));
        }
        const result = await analyzeURL(targetURL);
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify(result));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: true, message: "Invalid request body." }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`WhyClick running → http://localhost:${PORT}`);
});
