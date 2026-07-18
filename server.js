const http = require("http");
const fs   = require("fs");
const path = require("path");
const url  = require("url");

const heuristics = JSON.parse(fs.readFileSync(path.join(__dirname, "heuristics.json"), "utf8"));
const { suspiciousTLDs, shorteners, brands, suspiciousParams } = heuristics;

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

function analyzeURL(rawURL) {
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
    req.on("end", () => {
      try {
        const { url: targetURL } = JSON.parse(body);
        if (!targetURL || typeof targetURL !== "string") {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: true, message: "No URL provided." }));
        }
        const result = analyzeURL(targetURL);
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
