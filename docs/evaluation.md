# Evaluation methodology

Run `npm run evaluate` to execute the policy engine against the checked-in corpus and print a JSON report. No model or network request is involved.

## Corpus

These 48 synthetic cases were authored with Gemini assistance against known rules and reviewed locally. They are regression fixtures, not an independent holdout dataset.

| Category | Cases | Intended behavior |
| --- | --- | --- |
| Benign | 12 | Allow |
| Targeted injections | 16 | Block |
| Sensitive patterns | 9 | Redact |
| Known bypasses | 6 | Block, but currently allowed |
| Known false positives | 5 | Allow, but currently blocked |

Core cases check both the expected action and any listed rule IDs. A core regression causes exit code 1. Challenge cases are evaluated against intended behavior and counted as failures when the detector misses that intent; they remain visible without failing the build. Improving challenge behavior removes that case from the mismatch list.

## Metrics and denominators

Injection precision is TP / (TP + FP); recall is TP / (TP + FN). A positive means a labeled attack was blocked. Redaction is reported separately.

- Core injection metrics use **28 cases**: 16 attacks and 12 benign cases.
- Overall injection metrics use **39 cases**: those 28 plus 11 challenges.
- Redaction metrics use **21 cases**: nine sensitive-data cases and 12 benign cases.

At policy `2026-09-06.1`, all 37 core cases pass. Overall injection counts are TP=16, FP=5, TN=12, FN=6, producing precision 76.2% and recall 72.7%. These percentages describe this small constructed corpus only; they do not predict deployment effectiveness.

The redaction metric checks the action label. Separate unit tests verify that matched secrets are removed from returned text. Neither constitutes exhaustive PII detection.

## Limitations

The corpus deliberately includes French instructions, base64 text, hyphenated words, paraphrases, roleplay framing, indirect instructions, and benign quoted attack text. It does not measure whether any downstream model actually follows those attacks. Labels express the fixture author's intended scenario and can be disputed; review them when extending the corpus.

No latency benchmark, multilingual coverage claim, independent dataset result, model attack-success rate, or production traffic accuracy is established by this harness. Never reclassify a regression as a challenge solely to make CI pass.
