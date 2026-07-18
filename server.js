const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const heuristics = JSON.parse(fs.readFileSync(path.join(__dirname, "heuristics.json"), "utf8"));
const { suspiciousTLDs, shorteners, brands, suspiciousParams } = heuristics;

const PORT = 3000;

function analyzeURL(rawURL) {
  const findings = [];
  let riskScore = 0;

  let inputURL = rawURL.trim();
  if (!/^https?:\/\//i.test(inputURL)) {
    inputURL = "http://" + inputURL;
  }

  let parsed;
  try {
    parsed = new URL(inputURL);
  } catch {
    return {
      error: true,
      message: "Could not parse URL. Make sure it's a valid link.",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullURL = parsed.href;
  const pathname = parsed.pathname;
  const params = [...parsed.searchParams.entries()];

  if (parsed.protocol === "http:") {
    findings.push({ severity: "medium", label: "No HTTPS", detail: "Connection is unencrypted. Data can be intercepted in transit." });
    riskScore += 20;
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^\[([0-9a-fA-F:]+)\]$/;
  if (ipv4Regex.test(hostname) || ipv6Regex.test(hostname)) {
    const isIPv6 = ipv6Regex.test(hostname);
    findings.push({
      severity: "high",
      label: `IP address hostname (${isIPv6 ? "IPv6" : "IPv4"})`,
      detail: "URLs using raw IPs instead of domain names are a common phishing tactic.",
    });
    riskScore += 35;
  }

  const subdomainParts = hostname.split(".");
  if (subdomainParts.length > 4) {
    findings.push({ severity: "medium", label: "Excessive subdomains", detail: `${subdomainParts.length} domain levels detected. Deep nesting is often used to spoof trusted brands.` });
    riskScore += 20;
  }

  const decodedHostname = url.domainToUnicode(hostname);
  const isPunycode = decodedHostname !== hostname && decodedHostname !== "";
  const lookalikes = /[^\x00-\x7F]/;
  if (lookalikes.test(hostname) || isPunycode) {
    const display = isPunycode ? decodedHostname : hostname;
    findings.push({
      severity: "high",
      label: "Non-ASCII / IDN homograph domain",
      detail: `Domain decodes to "${display}". Unicode characters can visually mimic real domains (e.g. pаypal.com using a Cyrillic 'а').`,
    });
    riskScore += 40;
  }


  const matchedTLD = suspiciousTLDs.find(tld => hostname.endsWith(tld));
  if (matchedTLD) {
    findings.push({ severity: "medium", label: `Suspicious TLD (${matchedTLD})`, detail: "This top-level domain is commonly associated with free/throwaway domains used in phishing campaigns." });
    riskScore += 20;
  }

  if (shorteners.some(s => hostname === s || hostname.endsWith("." + s))) {
    findings.push({ severity: "medium", label: "URL shortener", detail: "Destination is hidden. The link could redirect anywhere — including malicious sites." });
    riskScore += 25;
  }

  const domainWithoutTLD = subdomainParts.slice(0, -1).join(".");
  const decodedDomainWithoutTLD = url.domainToUnicode(domainWithoutTLD) || domainWithoutTLD;
  const impersonatedBrand = brands.find(b =>
    (domainWithoutTLD.includes(b) || decodedDomainWithoutTLD.includes(b)) &&
    !hostname.startsWith(b + ".")
  );
  if (impersonatedBrand) {
    findings.push({ severity: "high", label: `Brand impersonation (${impersonatedBrand})`, detail: `"${impersonatedBrand}" appears in the URL path but is not the actual domain. Classic phishing pattern.` });
    riskScore += 45;
  }

  const registeredDomain = subdomainParts.slice(-2, -1)[0] || "";
  if (registeredDomain.length >= 6) {
    const vowels = (registeredDomain.match(/[aeiou]/gi) || []).length;
    const vowelRatio = vowels / registeredDomain.length;

    const consonantClusters = (registeredDomain.match(/[^aeiou]{3,}/gi) || []).length;

    const freq = {};
    for (const c of registeredDomain) freq[c] = (freq[c] || 0) + 1;
    const entropy = -Object.values(freq).reduce((sum, count) => {
      const p = count / registeredDomain.length;
      return sum + p * Math.log2(p);
    }, 0);

    if (vowelRatio < 0.2 || (consonantClusters >= 2 && entropy > 3.2)) {
      findings.push({
        severity: "medium",
        label: "Randomly generated domain name",
        detail: `"${registeredDomain}" has unusually low vowel density (${Math.round(vowelRatio * 100)}%) or high character entropy — a common trait of algorithmically generated phishing domains (e.g. .biz.id, .id scams).`,
      });
      riskScore += 25;
    }
  }

  if (fullURL.length > 200) {
    findings.push({ severity: "low", label: "Unusually long URL", detail: `${fullURL.length} characters. Long URLs can obscure the real destination or hide injected parameters.` });
    riskScore += 10;
  }

  const foundRedirectParam = params.find(([k]) => suspiciousParams.map(p => p.toLowerCase()).includes(k.toLowerCase()));
  if (foundRedirectParam) {
    findings.push({ severity: "medium", label: `Open redirect parameter (?${foundRedirectParam[0]}=)`, detail: "This parameter may redirect you to an unintended destination, bypassing domain trust." });
    riskScore += 20;
  }

  const encodedCharsCount = (pathname.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encodedCharsCount > 5) {
    findings.push({ severity: "low", label: "Heavy URL encoding in path", detail: `${encodedCharsCount} encoded characters detected. Can be used to bypass filters or obscure intent.` });
    riskScore += 10;
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    findings.push({ severity: "medium", label: `Non-standard port (:${parsed.port})`, detail: "Legitimate sites rarely use custom ports. This can indicate a rogue server." });
    riskScore += 25;
  }

  if ((rawURL.match(/@/g) || []).length > 0) {
    findings.push({ severity: "high", label: "@ symbol in URL", detail: "The @ character in a URL can be used to hide the real hostname. e.g. real.com@evil.com — evil.com is the actual destination." });
    riskScore += 40;
  }

  if (/\/\.\.\/|\/\//.test(pathname)) {
    findings.push({ severity: "medium", label: "Path traversal pattern", detail: "Double slashes or ../ sequences in the path may indicate directory traversal or URL confusion." });
    riskScore += 15;
  }

  riskScore = Math.min(riskScore, 100);

  let verdict, verdictCode;
  if (riskScore >= 60) {
    verdict = "High Risk";
    verdictCode = "danger";
  } else if (riskScore >= 25) {
    verdict = "Suspicious";
    verdictCode = "warning";
  } else {
    verdict = "Looks OK";
    verdictCode = "safe";
  }

  return {
    error: false,
    input: rawURL,
    parsed: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      params: Object.fromEntries(params),
    },
    riskScore,
    verdict,
    verdictCode,
    findings,
  };
}

const server = http.createServer((req, res) => {
  const parsedReq = url.parse(req.url, true);
  const pathname = parsedReq.pathname;

  if (req.method === "GET" && pathname === "/") {
    const filePath = path.join(__dirname, "public", "index.html");
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(500); return res.end("Internal error"); }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(data);
    });
    return;
  }

  if (req.method === "GET" && pathname === "/style.css") {
    const filePath = path.join(__dirname, "public", "style.css");
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); return res.end("Not found"); }
      res.writeHead(200, { "Content-Type": "text/css" });
      res.end(data);
    });
    return;
  }

  if (req.method === "GET" && pathname === "/app.js") {
    const filePath = path.join(__dirname, "public", "app.js");
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); return res.end("Not found"); }
      res.writeHead(200, { "Content-Type": "application/javascript" });
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
