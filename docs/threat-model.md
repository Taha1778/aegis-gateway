# Threat model

## Scope and trust

The server operator, environment configuration, application backend, and administrator are trusted. User text, retrieved document text, provider output, and proposed tool arguments are untrusted.

The proxy enforces input/output decisions. Tool endpoints return decisions which the application must honor. The gateway executes no tools. Callers sharing an application key share a principal; this is not a multi-tenant identity system.

## Boundaries

| Boundary | Control | Residual risk |
| --- | --- | --- |
| Client to gateway | Strict schemas, 128,000-byte body limit, 90 requests/minute/IP, separate admin key | Stolen keys, distributed denial of service, lack of per-user identity |
| Text to provider | Injection heuristics, pattern redaction, fixed HTTPS endpoint, no redirects | Novel attacks and unrecognized secrets pass |
| Provider to client | Bounded text, 15-second timeout, output inspection | No guarantee of semantic safety or factual correctness |
| Tool to execution | Default deny, argument binding, expiring single-use approval | Application must enforce decisions and handle crashes after consumption |
| Administrator to approval | Separate key and atomic state change | Redacted previews hide recipient details; review complete arguments in the trusted application |
| Database to operator | Metadata-only events, bounded retention | SQLite is not encrypted, signed, tamper-evident, or non-repudiable |

## Data retention

Events contain IDs, timestamps, stage, action, rule IDs, duration, and policy version, without prompt/response bodies. Approval records **contain redacted argument previews**, including subject/body text, a call digest, and a credential-derived principal. Unrecognized sensitive data can remain. Protect the database, WAL files, and backups.

Events retain the latest 1,000 records. Approvals expire after ten minutes and are physically deleted on a subsequent approval request, not on a timer. SQLite free pages and backups may retain historical data. The approval cap counts all unexpired statuses, not only pending requests.

## Detection limits

NFKC handles compatibility characters such as full-width Latin letters, not all cross-script lookalikes. Only selected zero-width characters are removed. Messages are inspected independently. Encoded, multilingual, paraphrased, split-message, indirect, and novel attacks can bypass the heuristics. Quoted attack strings and ordinary XML can cause false positives.

Redaction covers selected patterns, not all credentials, identifiers, or confidential documents. Binary malware scanning, OCR, PDF parsing, and archive inspection are absent. Applications may submit extracted text with `stage: "document"` and must enforce the resulting decision.

## Deployment assumptions

Demo mode binds to loopback, validates Host, and checks browser Origin. Protected mode requires distinct keys. Use TLS, a restricted reverse proxy, network access controls, and filesystem permissions. No forwarded-IP trust is configured, so clients behind a proxy may share a rate limit. Health/status endpoints expose limited operational metadata. Health checks process liveness, not provider readiness.

The argument hash binds a call to an approval; it is neither a signature nor a nonce. Approval IDs are random UUIDs. Consumption is atomic but is not an execution transaction: a client crash after consumption requires a new approval.

## References

- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

These inform the design; they do not establish compliance or certification.
