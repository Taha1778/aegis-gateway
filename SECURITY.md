# Security Policy

## Reporting Security Vulnerabilities

We take the security of Aegis Gateway seriously. If you discover a vulnerability or potential security weakness in this project, please report it responsibly.

### Disclosure Process

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or social media.

Instead, submit your report privately using GitHub Security Advisories:
1. Navigate to the repository's Security tab: [Security Advisories](https://github.com/Taha1778/aegis-gateway/security/advisories/new).
2. Click **"Report a vulnerability"**.
3. Provide a detailed description including:
   - A step-by-step reproduction guide or minimal proof-of-concept (PoC).
   - Affected versions and configurations.
   - Potential impact and threat severity.

Using GitHub Private Vulnerability Reporting ensures that the issue can be coordinated, investigated, and patched before public disclosure, without requiring an external unverified email address.

---

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No |

---

## Security Boundaries & Expectations

When reporting issues, please bear in mind the documented security boundaries of this project:
- **Heuristic Nature of Regex Filters**: As documented in [Threat Model](docs/threat-model.md), pattern matching is an initial defense-in-depth layer, not a universal guarantee against novel natural-language prompt injection or multi-language evasion. New bypass vectors that exploit the inherent limitations of regex are evaluated as feature enhancements and evaluation corpus additions rather than critical remote vulnerabilities unless they cause unhandled crashes, memory exhaustion, or secret leakage.
- **Tool Execution Boundary**: Aegis Gateway provides authorization decisions; the consuming application is responsible for executing tools. Failure of an application to respect gateway decisions is outside the gateway's boundary.
- **Experimental Notice**: Aegis Gateway is an inspectable portfolio reference implementation and research project. It is not currently certified as production-ready without dedicated architectural hardening and defense-in-depth surrounding it.
