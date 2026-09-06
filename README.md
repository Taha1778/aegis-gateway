# Aegis Gateway

An AI security gateway for small teams integrating language models into applications. Inspect text, redact sensitive patterns, enforce tool permissions, and review decisions in a local dashboard.

Under active development. This repository will include a deterministic demonstration mode, a configurable upstream adapter, tests, and a documented threat model. Pattern detection is a heuristic mitigation, not a guarantee against prompt injection.

## Development

Requires Node.js 24 or newer. Run `npm ci`, then `npm run dev`.

## Scope

- Input and output text inspection with explainable findings
- Default-deny tool policy and separate administrator approval
- Metadata-only SQLite audit history
- Dashboard and a reproducible, explicitly limited evaluation corpus
- Optional non-streaming chat-completions integration

Binary malware scanning, arbitrary autonomous tool execution, and universal prompt-injection prevention are outside the first release.
