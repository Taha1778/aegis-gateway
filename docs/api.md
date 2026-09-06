# API Reference

Aegis Gateway exposes RESTful endpoints for text inspection, chat completion proxying, tool authorization, and administrative oversight.

---

## 1. Authentication & Security Headers

### 1.1 Local Demo Mode
When running without API keys configured (`GATEWAY_API_KEY` and `ADMIN_API_KEY` unset):
- Requests must include a loopback `Host` header (`localhost`, `127.0.0.1`, or `[::1]`).
- Any supplied `Origin` must match the request Host (including port) and an accepted HTTP/HTTPS scheme. A different localhost port is also rejected.
- No `Authorization` header is required.

### 1.2 Protected Mode
When `GATEWAY_API_KEY` and `ADMIN_API_KEY` are configured:
- Both keys must be at least 24 characters and mutually distinct.
- Standard endpoints require: `Authorization: Bearer <GATEWAY_API_KEY>`
- Administrative endpoints (`/api/overview`, `/api/approvals/:id`) require: `Authorization: Bearer <ADMIN_API_KEY>`
- Constant-time verification (`crypto.timingSafeEqual`) prevents timing leaks.

---

## 2. Public / Health Endpoints

### `GET /health`
Process liveness probe; this does not check provider readiness.

#### Response `200 OK`
```json
{
  "status": "ok"
}
```

---

### `GET /api/status`
Returns gateway operational mode and policy configuration.

#### Response `200 OK`
```json
{
  "mode": "demo",
  "authentication": false,
  "policyVersion": "2026-09-06.1"
}
```

---

## 3. Inspection & Gateway Endpoints

### `POST /v1/inspect`
Inspects a single block of text for prompt injection patterns and sensitive data tokens.

#### Request Body
```json
{
  "text": "Please summarize our refund policy for customer alice@example.com",
  "stage": "input"
}
```
- `text` (string, required): 1 to 32,000 characters.
- `stage` (enum, optional): `'input' | 'output' | 'document'`. Defaults to `'input'`.

#### Response `200 OK` (Redacted)
```json
{
  "action": "redact",
  "text": "Please summarize our refund policy for customer [REDACTED:email]",
  "findings": [
    {
      "rule": "email",
      "category": "sensitive",
      "severity": "medium",
      "description": "Email address"
    }
  ],
  "policyVersion": "2026-09-06.1",
  "eventId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

#### Response `200 OK` (Blocked)
```json
{
  "action": "block",
  "text": null,
  "findings": [
    {
      "rule": "instruction-override",
      "category": "injection",
      "severity": "high",
      "description": "Attempt to override instruction hierarchy"
    }
  ],
  "policyVersion": "2026-09-06.1",
  "eventId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

---

### `POST /v1/chat/completions`
Proxies chat completions through the policy inspection boundary. In demo mode, uses a deterministic echo provider; in connected mode, forwards sanitized messages to the configured upstream LLM.

#### Request Body
```json
{
  "messages": [
    { "role": "user", "content": "What is the capital of France?" }
  ]
}
```
- `messages` (array, required): 1 to 16 messages. Each message must have `role: 'user' | 'assistant'` and `content` (1 to 32,000 chars).

#### Response `200 OK`
```json
{
  "id": "e6a2b8e4-8451-419b-9807-6b45012586e9",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Demo assistant: your request passed the gateway.\n\nReceived: What is the capital of France?\n\nThis is a deterministic demonstration, not a language-model response. Connect a provider to use a real model."
      },
      "finish_reason": "stop"
    }
  ],
  "gateway": {
    "inputRedacted": false,
    "outputRedacted": false,
    "policyVersion": "2026-09-06.1"
  }
}
```

#### Error Responses
- `400 Bad Request`: Validation failure (e.g. system role submitted, invalid types, oversized payload).
- `422 Unprocessable Entity`: Input or output blocked by security policy:
  ```json
  {
    "error": "Input blocked by policy",
    "eventId": "uuid-value",
    "rules": ["instruction-override"]
  }
  ```
- `502 Bad Gateway`: Upstream provider timed out, failed, or returned an unparseable response.

---

## 4. Tool Authorization Endpoints

### `POST /v1/tools/authorize`
Requests policy evaluation for a planned tool call.

#### Request Body (Allowed Tool)
```json
{
  "name": "knowledge.search",
  "arguments": {
    "query": "return policy guidelines"
  }
}
```

#### Response `200 OK` (Allowed)
```json
{
  "action": "allow",
  "eventId": "uuid-here",
  "policyVersion": "2026-09-06.1",
  "execution": "Caller must enforce this decision; gateway executes no tools."
}
```

#### Request Body (Approval Required Tool)
```json
{
  "name": "email.send",
  "arguments": {
    "to": "client@example.com",
    "subject": "Status Update",
    "body": "Project milestone completed."
  }
}
```

#### Response `200 OK` (Approval Required)
```json
{
  "action": "require_approval",
  "approvalId": "7b8d4f40-333e-4d0f-8c34-726ef30ef58a",
  "eventId": "uuid-here",
  "policyVersion": "2026-09-06.1",
  "execution": "Caller must enforce this decision; gateway executes no tools."
}
```

---

### `POST /v1/tools/consume`
Validates that an approved tool call is authentic, unexpired, and matches the exact arguments submitted.

#### Request Body
```json
{
  "approvalId": "7b8d4f40-333e-4d0f-8c34-726ef30ef58a",
  "call": {
    "name": "email.send",
    "arguments": {
      "to": "client@example.com",
      "subject": "Status Update",
      "body": "Project milestone completed."
    }
  }
}
```

#### Response `200 OK`
```json
{
  "action": "allow",
  "execution": "Authorization consumed once. Caller is responsible for execution."
}
```

#### Error Response `409 Conflict`
Returned when the approval is expired, not yet approved, already consumed, belonging to a different principal, or when the arguments were tampered with:
```json
{
  "error": "Approval unavailable, expired, already used, or arguments changed"
}
```

---

## 5. Administrative Endpoints

### `GET /api/overview`
Returns audit history, aggregate statistics, pending approvals, and active tool policies.
Requires `ADMIN_API_KEY`.

#### Response `200 OK`
```json
{
  "events": [
    {
      "id": "uuid",
      "created_at": "2026-09-06T19:40:50.000Z",
      "stage": "input",
      "action": "allow",
      "rules": "[]",
      "duration_ms": 0.42,
      "policy_version": "2026-09-06.1"
    }
  ],
  "stats": [
    { "action": "allow", "count": 14 },
    { "action": "block", "count": 3 },
    { "action": "redact", "count": 2 }
  ],
  "approvals": [
    {
      "id": "7b8d4f40-333e-4d0f-8c34-726ef30ef58a",
      "created_at": "2026-09-06T19:40:00.000Z",
      "expires_at": 1788723600000,
      "tool": "email.send",
      "preview": "{\"to\":\"[REDACTED:email]\",\"subject\":\"Status Update\",\"body\":\"Project milestone completed.\"}",
      "status": "pending"
    }
  ],
  "toolPolicies": [
    { "name": "knowledge.search", "action": "allow", "description": "Search a knowledge base; query only." },
    { "name": "email.send", "action": "require_approval", "description": "Requires an administrator decision for exact arguments." },
    { "name": "*", "action": "block", "description": "Every unlisted tool is denied." }
  ],
  "policyVersion": "2026-09-06.1"
}
```

---

### `POST /api/approvals/:id`
Approves or denies a pending tool request. Requires `ADMIN_API_KEY`.

#### Request Body
```json
{
  "decision": "approved"
}
```
`decision`: `'approved' | 'denied'`.

#### Response `200 OK`
```json
{
  "id": "7b8d4f40-333e-4d0f-8c34-726ef30ef58a",
  "status": "approved"
}
```

#### Error Response `409 Conflict`
Returned if the approval has expired or has already been decided:
```json
{
  "error": "Approval is no longer pending"
}
```
