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
| Unusually long URL (>200 chars)     | Low      |
| Open redirect parameters            | Medium   |
| Heavy URL encoding in path          | Low      |
| Non-standard port                   | Medium   |
| @ symbol (credential spoofing)      | High     |
| Path traversal patterns             | Medium   |

## Risk score

- **0–24** → Looks OK (green)
- **25–59** → Suspicious (amber)
- **60–100** → High Risk (red)

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).
