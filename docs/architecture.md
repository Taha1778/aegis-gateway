# Architecture

Aegis Gateway is an inspectable AI security gateway designed to sit between client applications and Large Language Model (LLM) providers. It provides heuristic input/output inspection, sensitive token redaction, default-deny tool policy authorization, human-in-the-loop approval management, and a privacy-preserving audit trail.

---

## 1. System Overview

```
                      +------------------------------------------+
                      |               Client App                 |
                      +------------------------------------------+
                                       |        ^
                   HTTP /v1/chat/...   |        |  Sanitized Output
                   HTTP /v1/inspect    v        |
                      +------------------------------------------+
                      |              Aegis Gateway               |
                      |                                          |
                      |  +------------------------------------+  |
                      |  |   Security Perimeter Middleware    |  |
                      |  |   - Rate Limiting (90 req/min)     |  |
                      |  |   - Helmet & Strict CSP            |  |
                      |  |   - Host / Origin Header Check     |  |
                      |  |   - Dual-Key Constant-Time Auth    |  |
                      |  +------------------------------------+  |
                      |                   |                      |
                      |  +------------------------------------+  |
                      |  |         Policy Engine              |  |
                      |  |   - NFKC & Zero-Width Normalize    |  |
                      |  |   - Prompt Injection Heuristics    |  |
                      |  |   - Sensitive Token Redaction      |  |
                      |  +------------------------------------+  |
                      |        |                     |           |
                      |        v                     v           |
                      |  +-------------+     +----------------+  |
                      |  | SQLite Store|     | Upstream / Demo|  |
                      |  | - Events    |     | Provider       |  |
                      |  | - Approvals |     +----------------+  |
                      |  +-------------+             |           |
                      +------------------------------|-----------+
                                                     v
                                       +-------------------------+
                                       | Upstream LLM (Optional) |
                                       +-------------------------+
```

---

## 2. Core Components

### 2.1 Security Perimeter Middleware (`src/app.ts`)
- **Fastify Framework**: Configured with a 128 KB body limit to prevent payload flooding.
- **Helmet**: Enforces a strict Content Security Policy (`default-src 'self'`, `script-src 'self'`, `style-src 'self'`).
- **Rate Limiting**: Uses `@fastify/rate-limit` allowing up to 90 requests per minute per IP.
- **Loopback Enforcement**: In local demo mode (when no API keys are configured), the server requires a loopback `Host` header (`localhost`, `127.0.0.1`, `[::1]`) and blocks foreign `Origin` headers to protect against DNS rebinding and cross-origin attacks from unauthorized browser tabs.
- **Dual Credential Architecture**: In protected mode, two distinct keys (each >= 24 characters) must be configured:
  - `GATEWAY_API_KEY`: Required for gateway consumers (`/v1/inspect`, `/v1/chat/completions`, `/v1/tools/*`).
  - `ADMIN_API_KEY`: Required for administrative operations (`/api/overview`, `/api/approvals/:id`).
  - Comparisons use `crypto.timingSafeEqual` with SHA-256 digests to prevent timing attacks.

### 2.2 Policy Engine (`src/policy.ts`)
- **Text Normalization**:
  - Normalizes Unicode using `NFKC` (including full-width compatibility characters, but not all cross-script lookalikes).
  - Strips zero-width characters (`\u200B-\u200D`, `\uFEFF`).
  - Collapses excessive whitespace sequences.
- **Injection Detection (Adversarial Heuristics)**:
  - `instruction-override`: Identifies attempts to override prior instructions (e.g. `ignore all previous instructions`).
  - `role-spoofing`: Detects delimiter injection such as `<|im_start|>`, `<|system|>`, `<|start_header_id|>`, `[INST]`, or `<system>`.
  - `prompt-extraction`: Blocks attempts to extract developer instructions or system prompts (e.g. `reveal system prompt`).
  - `data-exfiltration`: Detects commands attempting to transmit sensitive data or credentials to external URLs.
- **Sensitive Data Redaction**:
  - `api-token`: Detects OpenAI (`sk-*`), GitHub (`ghp_*`, `ghs_*`, `ghu_*`, `gho_*`, `ghr_*`), and AWS (`AKIA*`) credentials.
  - `private-key`: Detects PEM private keys (`BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, etc.).
  - `email`: Detects email addresses and masks them in place with `[REDACTED:email]`.
- **Finding Neutralization**:
  - Matched secret values are never included in finding objects or logs, preventing token leakage through error responses.

### 2.3 Store & Audit Subsystem (`src/store.ts`)
- **Storage Engine**: Node.js native `node:sqlite` in WAL (Write-Ahead Logging) mode with `PRAGMA busy_timeout = 5000`.
- **Privacy-First Audit Logging (`events` table)**:
  - Records event ID, timestamp, pipeline stage (`input`, `output`, `provider`, `tool`, `approval`), action taken (`allow`, `block`, `redact`), matched rule IDs, duration in milliseconds, and policy version.
  - **Event Content Minimization**: Events contain no prompt/response bodies. Approval rows separately retain redacted argument previews, which may still contain unrecognized sensitive information.
  - Auto-retention: Prunes to the last 1,000 events automatically upon insertion.
- **Approval Queue (`approvals` table)**:
  - Stores pending tool requests with human-readable preview (with sensitive parameters redacted).
  - Enforces a 10-minute expiration window (`Date.now() + 600_000`).
  - Limits all unexpired approval records to 1,000 entries. Expired records are pruned when another approval is requested.

### 2.4 Tool Authorization Lifecycle (`src/policy.ts` & `src/store.ts`)
The gateway enforces a default-deny policy for tool invocation:
1. `knowledge.search`:
   - Restricted strictly to single argument `{ query: string }`.
   - Query is inspected for prompt injection; allowed if clean, blocked if injection detected.
2. `email.send`:
   - Requires arguments `{ to: string, subject: string, body: string }`.
   - Validates email syntax via Zod.
   - Inspects subject and body; requires administrative approval if clean (`action: "require_approval"`).
3. Any other tool (`*`):
   - Blocked immediately (`action: "block"`).

#### Tool Approval Consumption Protocol
```
Client App                   Gateway API                   Admin / Dashboard
    |                             |                                |
    |-- 1. /v1/tools/authorize -->|                                |
    |   (email.send)              |-- 2. Store approval (pending)  |
    |<- Returns approvalId -------|                                |
    |   (action: require_approval)|                                |
    |                             |<-- 3. Review & Approve --------|
    |                             |    (POST /api/approvals/:id)   |
    |-- 4. POST /v1/tools/consume>|                                |
    |   { approvalId, call }      |-- 5. Verify callHash & caller  |
    |                             |      Transition to 'consumed'  |
    |<- 6. action: "allow" -------|                                |
    |                             |                                |
    v                             v                                v
(Caller executes tool)
```
- **Argument Binding**: The approval record stores a cryptographic hash (`callHash`) computed from `tool name + sorted argument key-values + policyVersion`. If the caller attempts to consume the approval with altered arguments, the request is rejected with `409 Conflict`.
- **Single-Use Enforcement**: State transitions from `pending` -> `approved` -> `consumed`. Replay attempts fail with `409 Conflict`.
- **Principal Binding**: Approvals are bound to the caller's authorization digest (`principal`); another caller cannot hijack or consume an approval.
- **Advisory Boundary**: The gateway *never executes tools directly*. The client application must verify approval consumption before executing tool code.

---

## 3. Data Persistence & Docker

- When running via Docker or systemd, persist the SQLite database directory:
  ```bash
  docker run -d \
    -p 4310:4310 \
    -v aegis-data:/app/data \
    -e GATEWAY_API_KEY="a-very-long-gateway-key-at-least-24-chars" \
    -e ADMIN_API_KEY="a-very-long-admin-key-at-least-24-chars" \
    aegis-gateway:latest
  ```
- The database is created at `data/aegis.sqlite` by default (configurable via `DATABASE_PATH`).
