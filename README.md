# WhyClick

Paste any URL and get an instant security risk assessment before clicking.

## How to run

```bash
npm start
# http://localhost:3000
```

Or with live reload:
```bash
npm run dev
```

## What it checks

| Check                               | Severity |
|-------------------------------------|----------|
| No HTTPS                            | Medium   |
| IP address as hostname              | High     |
| Excessive subdomains                | Medium   |
| Non-ASCII / homograph characters    | High     |
| Suspicious TLD (.tk, .xyz, .click…) | Medium   |
| URL shortener (bit.ly, t.co…)       | Medium   |
| Brand impersonation in subdomain    | High     |
| Randomized domain names             | Medium   |
| Unusually long URL (>200 chars)     | Low      |
| Open redirect parameters            | Medium   |
| Heavy URL encoding in path          | Low      |
| Non-standard port                   | Medium   |
| @ symbol (credential spoofing)      | High     |
| Path traversal patterns             | Medium   |
| Newly registered domain (<90 days)  | High     |
| Self-signed certificate             | High     |
| Expired TLS certificate             | High     |
| Certificate hostname mismatch       | High     |
| Certificate expiring within 14 days | Medium   |

### WHOIS / RDAP lookup

Each analysis performs a live domain registration lookup using the [RDAP protocol](https://about.rdap.org/) — the modern, JSON-based successor to WHOIS. The server queries the IANA bootstrap registry to find the authoritative RDAP endpoint for each TLD, then fetches:

- Registrar name
- Registrant organisation / name and country
- Registration, last-updated, and expiry dates
- Nameservers
- Domain status flags

Domain age is surfaced as a colour-coded badge (red < 90 days, amber < 1 year, green otherwise). Domains under 90 days old are also raised as a High-severity finding, as newly registered domains are disproportionately used in phishing campaigns.

WHOIS data is fetched at analysis time and never cached. If the registry does not respond within 5 seconds, the lookup is skipped silently and the rest of the analysis still completes.

### TLS certificate analysis

For `https:` URLs, WhyClick opens a TLS connection to the host and inspects the server certificate. The following are surfaced in a dedicated **tls certificate** section:

- Issuer organisation and common name
- Subject common name
- Validity window (valid from / valid to)
- Subject Alternative Names (SANs) covered by the certificate

Four conditions are also raised as findings and contribute to the risk score:

| Condition                        | Severity | Score |
|----------------------------------|----------|-------|
| Self-signed certificate          | High     | +35   |
| Expired certificate              | High     | +30   |
| Hostname not covered by cert     | High     | +30   |
| Expiring within 14 days          | Medium   | +10   |

A colour-coded badge summarises the overall cert status at a glance: **valid** (green), **expires in N days** (amber), **expired** / **self-signed** / **hostname mismatch** (red).

Certificate inspection is skipped for plain `http:` URLs and non-hostname targets (raw IP addresses). If the TLS handshake times out or fails, the section reports unavailability and the rest of the analysis still completes.

### HTTP headers / origin detection

WhyClick fires a `HEAD` request to the target URL and inspects the response headers to identify the server software, hosting platform, and CDN in use — information that is often unintentionally exposed and useful for understanding where a site actually lives.

**Platform and CDN detection** works by recognising telltale headers that specific providers inject into every response:

| Header                  | Platform          | Kind    |
|-------------------------|-------------------|---------|
| `cf-ray`                | Cloudflare        | CDN     |
| `x-vercel-id`           | Vercel            | Hosting |
| `x-nf-request-id`       | Netlify           | Hosting |
| `x-github-request-id`   | GitHub Pages      | Hosting |
| `x-amz-cf-id`           | AWS CloudFront    | CDN     |
| `x-azure-ref`           | Azure             | Hosting |
| `fly-request-id`        | Fly.io            | Hosting |
| `x-fastly-request-id`   | Fastly            | CDN     |
| `x-sucuri-id`           | Sucuri WAF        | CDN     |
| *(+ 16 more)*           |                   |         |

Detected platforms are shown as colour-coded badges — blue for hosting providers, amber for CDN/proxy layers.

**Server software** is read from the `server` header and normalised to a clean display name (Nginx, Apache, Caddy, LiteSpeed, Microsoft IIS, Kestrel, etc.) with version numbers stripped.

**Runtime / framework** is read from `x-powered-by` and `via`, covering PHP, ASP.NET, Express, Next.js, Django, Ruby on Rails, WordPress, Shopify, and others.

All captured headers are also listed in a collapsible **revealing headers** section showing the raw header name and value, so it is clear exactly which header triggered each detection.

**Redirect chain tracking** follows up to 8 hops manually, recording each intermediate URL and its status code. The full chain is displayed in order — for example, `301 http://example.com → 302 https://example.com → 200 https://www.example.com` — so it is immediately clear whether a URL silently bounces through multiple domains before landing. Relative `Location` headers are resolved against the current base URL at each hop.

The headers probe runs in parallel with the TLS certificate check and does not add to the overall analysis time. If the host refuses `HEAD` requests or is unreachable, the section reports unavailability and the rest of the analysis still completes.

## Risk score

- **0–24** → Looks OK (green)
- **25–59** → Suspicious (amber)
- **60–100** → High Risk (red)

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).
