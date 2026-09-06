# Contributing to Aegis Gateway

Thank you for your interest in contributing to Aegis Gateway! We welcome contributions that improve policy accuracy, expand the evaluation corpus, enhance documentation, or strengthen security perimeters.

---

## 1. Development Prerequisites

- **Node.js**: Version 24.0.0 or higher is required (due to native `node:sqlite` and modern ECMAScript features).
- **Package Manager**: `npm` (v10 or v11).

---

## 2. Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Taha1778/aegis-gateway.git
   cd aegis-gateway
   ```

2. Install dependencies:
   ```bash
   npm ci
   ```

3. Launch the development server:
   ```bash
   npm run dev
   ```
   Open `http://127.0.0.1:4310/` to view the local dashboard.

---

## 3. Local Verification & Quality Commands

Before submitting a pull request, ensure all local checks pass:

| Command | Purpose |
|---|---|
| `npm run typecheck` | Validates TypeScript compiler checks with zero emit (`tsc --noEmit`) |
| `npm test` | Runs the Vitest test suite (`tests/**/*.test.ts`) |
| `npm run evaluate` | Executes the evaluation harness against `eval/corpus.json` |
| `npm run check` | Runs typecheck, test, and evaluate in sequence |
| `npm run build` | Compiles TypeScript into `dist/` |

---

## 4. Contributing to the Evaluation Corpus

We maintain an honest evaluation benchmark in `eval/corpus.json`. When adding new test cases, adhere to the following taxonomy:

- **`benign`**: Legitimate user prompts without adversarial patterns or sensitive tokens (`expectedAction: "allow"`).
- **`adversarial_injection`**: Known attack strings targeted by our regex rules (`expectedAction: "block"`).
- **`sensitive_data`**: Prompts containing recognizable credentials or email addresses (`expectedAction: "redact"`).
- **`known_bypass`**: Real-world bypass techniques (e.g. multilingual prompts, base64 payloads, semantic evasion) that evade regex detection (`expectedAction: "allow"`, `isChallenge: true`).
- **`known_false_positive`**: Benign inputs that match our strict regex patterns due to lack of natural-language context (`expectedAction: "block"`, `isChallenge: true`).

> [!NOTE]
> When adding documented challenges (`known_bypass` or `known_false_positive`), set `"isChallenge": true`. This ensures the test output documents the challenge without causing CI regression failures.

---

## 5. Security & Bug Reports

If you discover a security issue or vulnerability, please follow our [Security Policy](SECURITY.md) and report it privately via GitHub Security Advisories rather than filing a public issue.
