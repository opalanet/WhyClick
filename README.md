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

Each analysis also performs a live domain registration lookup using the [RDAP protocol](https://about.rdap.org/) — the modern, JSON-based successor to WHOIS. The server queries the IANA bootstrap registry to find the authoritative RDAP endpoint for each TLD, then fetches:

- Registrar name
- Registrant organisation / name and country
- Registration, last-updated, and expiry dates
- Nameservers
- Domain status flags

Domain age is surfaced as a colour-coded badge (red < 90 days, amber < 1 year, green otherwise). Domains under 90 days old are also added as a High-severity finding, as newly registered domains are disproportionately used in phishing campaigns.

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

## Risk score

- **0–24** → Looks OK (green)
- **25–59** → Suspicious (amber)
- **60–100** → High Risk (red)

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).
