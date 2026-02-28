# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security concerns by emailing the maintainers directly (see
author contact in CITATION.cff). We will acknowledge receipt within 5 business
days and aim to resolve confirmed vulnerabilities within 90 days.

When reporting, include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested mitigations you have identified

## Public Data Guarantee

KEVGraph processes **only publicly available, officially published data**.
It does not:

- Generate, store, or distribute exploit code or attack payloads
- Access non-public vulnerability intelligence or private advisory databases
- Produce output that could serve as direct exploitation guidance
- Contact any endpoint outside the documented public data sources below

### Authorised Data Sources

| Source | Publisher | URL |
|--------|-----------|-----|
| CISA KEV Catalogue | US Cybersecurity and Infrastructure Security Agency | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| OSV Vulnerability Database | Google Open Source Security | https://osv.dev |
| EPSS Scores | FIRST (Forum of Incident Response and Security Teams) | https://www.first.org/epss |
| npm Registry | npm, Inc. | https://registry.npmjs.org |
| deps.dev Package Metadata | Google | https://deps.dev |
| GitHub Code Search | GitHub, Inc. | https://github.com |

No other external hosts are contacted at runtime. The codebase enforces this
with an explicit allowlist in `src/rate_limit.py`.

### Output Safety

KEVGraph's output is a **prioritised upgrade list**: an ordered sequence of
`npm upgrade <package>@<version>` actions. It identifies *which* packages to
upgrade and in *which order*, based on publicly known vulnerability data. It
does not recommend how to exploit those vulnerabilities.

Maintainers should verify recommended package versions through their normal
package-integrity workflow (e.g., `npm audit signatures`) before applying any
suggested upgrade.

## Scope

The following are **out of scope** for security reports:

- Dependency vulnerabilities in packages used by KEVGraph itself
  (please report these to the upstream package maintainers)
- Rate-limit bypass attempts against third-party APIs
- Issues that require a compromised GitHub token to exploit
