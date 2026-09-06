import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { inspect, POLICY_VERSION } from "../src/policy.js";
import type {
  CaseCategory,
  CaseMismatch,
  EvalCase,
  EvaluationMetrics,
  EvaluationReport,
} from "../eval/types.js";

function runEvaluation(): EvaluationReport {
  const corpusPath = resolve(process.cwd(), "eval", "corpus.json");
  const rawCorpus = readFileSync(corpusPath, "utf8");
  const cases: EvalCase[] = JSON.parse(rawCorpus);

  let corePassed = 0;
  let coreFailed = 0;
  const mismatches: CaseMismatch[] = [];

  const byCategory: EvaluationMetrics["byCategory"] = {
    benign: {
      total: 0,
      passed: 0,
      failed: 0,
      actualDistribution: { allow: 0, block: 0, redact: 0 },
    },
    adversarial_injection: {
      total: 0,
      passed: 0,
      failed: 0,
      actualDistribution: { allow: 0, block: 0, redact: 0 },
    },
    sensitive_data: {
      total: 0,
      passed: 0,
      failed: 0,
      actualDistribution: { allow: 0, block: 0, redact: 0 },
    },
    known_bypass: {
      total: 0,
      passed: 0,
      failed: 0,
      actualDistribution: { allow: 0, block: 0, redact: 0 },
    },
    known_false_positive: {
      total: 0,
      passed: 0,
      failed: 0,
      actualDistribution: { allow: 0, block: 0, redact: 0 },
    },
  };

  // Metrics for the full synthetic corpus, including deliberate challenges.
  let overallTp = 0; // Malicious input correctly blocked
  let overallFp = 0; // Benign input incorrectly blocked
  let overallTn = 0; // Benign input correctly allowed
  let overallFn = 0; // Malicious input incorrectly allowed (bypasses)

  // Metrics accumulators for core-only evaluation
  let coreTp = 0;
  let coreFp = 0;
  let coreTn = 0;
  let coreFn = 0;

  // Redaction accumulators
  let redTp = 0;
  let redFp = 0;
  let redTn = 0;
  let redFn = 0;

  for (const testCase of cases) {
    const result = inspect(testCase.input);
    const categoryStats = byCategory[testCase.category];
    categoryStats.total++;
    categoryStats.actualDistribution[result.action]++;

    const matchesExpected =
      result.action === testCase.expectedAction &&
      (testCase.expectedRules ?? []).every((rule) =>
        result.findings.some((finding) => finding.rule === rule),
      );

    if (!testCase.isChallenge) {
      if (matchesExpected) {
        corePassed++;
        categoryStats.passed++;
      } else {
        coreFailed++;
        categoryStats.failed++;
        mismatches.push({
          id: testCase.id,
          category: testCase.category,
          isChallenge: false,
          description: testCase.description,
          input: testCase.input,
          expectedAction: testCase.expectedAction,
          actualAction: result.action,
          targetIntentAction: testCase.targetIntentAction,
          findings: result.findings,
          note: "Core regression: inspection result deviated from expected policy action",
        });
      }
    } else {
      // Documented challenge case
      const matchesIntent = result.action === testCase.targetIntentAction;
      if (matchesIntent) categoryStats.passed++;
      else categoryStats.failed++;
      if (!matchesIntent)
        mismatches.push({
          id: testCase.id,
          category: testCase.category,
          isChallenge: true,
          challengeType: testCase.challengeType,
          description: testCase.description,
          input: testCase.input,
          expectedAction: testCase.expectedAction,
          actualAction: result.action,
          targetIntentAction: testCase.targetIntentAction,
          findings: result.findings,
          note:
            testCase.category === "known_bypass"
              ? "Documented heuristic bypass: regex pattern failed to capture adversarial intent without semantic parser"
              : "Documented false positive: benign text matched strict regex pattern without contextual disambiguation",
        });
    }

    // Injection detection evaluation (Positive = hostile injection intent, Negative = benign intent)
    const isHostileIntent =
      testCase.category === "adversarial_injection" ||
      testCase.category === "known_bypass";
    const isBlockedByHeuristic = result.action === "block";

    if (isHostileIntent) {
      if (isBlockedByHeuristic) {
        overallTp++;
        if (!testCase.isChallenge) coreTp++;
      } else {
        overallFn++;
        if (!testCase.isChallenge) coreFn++;
      }
    } else if (
      testCase.category === "benign" ||
      testCase.category === "known_false_positive"
    ) {
      if (isBlockedByHeuristic) {
        overallFp++;
        if (!testCase.isChallenge) coreFp++;
      } else {
        overallTn++;
        if (!testCase.isChallenge) coreTn++;
      }
    }

    // Redaction detection evaluation
    if (testCase.category === "sensitive_data") {
      if (result.action === "redact") {
        redTp++;
      } else {
        redFn++;
      }
    } else if (testCase.category === "benign") {
      if (result.action === "redact") {
        redFp++;
      } else {
        redTn++;
      }
    }
  }

  const calcScore = (tp: number, fp: number, fn: number, tn: number) => {
    const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
    const f1Score =
      precision + recall === 0
        ? 0
        : (2 * precision * recall) / (precision + recall);
    const total = tp + fp + fn + tn;
    const accuracy = total === 0 ? 1 : (tp + tn) / total;
    return {
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1Score: Math.round(f1Score * 1000) / 1000,
      accuracy: Math.round(accuracy * 1000) / 1000,
    };
  };

  const coreCount = cases.filter((c) => !c.isChallenge).length;
  const challengeCount = cases.filter((c) => c.isChallenge).length;

  const limitations = [
    "Heuristic regex rules lack natural language understanding and semantic comprehension.",
    "Multilingual injection attacks (e.g. French, Spanish, Russian, Chinese) bypass English-only regex keywords.",
    "Encoded payloads (base64, hex, rot13, binary) bypass string inspection unless pre-decoded before inspection.",
    "Character-spaced and hyphen-delimited attacks evade word-boundary constraints despite Unicode NFKC normalization.",
    "Context-blind pattern matching flags legitimate security research, configuration guides, and quotes as false positives.",
    "The gateway does not track multi-turn conversational state, leaving it vulnerable to split-payload injections across multiple turns.",
    "Indirect prompt injection via external retrieval (RAG) or referenced URLs cannot be prevented by input inspection alone.",
    "Tool authorization decisions are strictly advisory; the calling application remains responsible for enforcing execution boundaries.",
  ];

  const report: EvaluationReport = {
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    status: coreFailed === 0 ? "passed" : "failed",
    counts: {
      total: cases.length,
      core: coreCount,
      challenges: challengeCount,
      corePassed,
      coreFailed,
    },
    metrics: {
      total: cases.length,
      coreCases: coreCount,
      challengeCases: challengeCount,
      corePassed,
      coreFailed,
      byCategory,
      injectionDetection: [
        { dataset: "core_only", ...calcScore(coreTp, coreFp, coreFn, coreTn) },
        {
          dataset: "overall",
          ...calcScore(overallTp, overallFp, overallFn, overallTn),
        },
      ],
      redactionDetection: {
        truePositives: redTp,
        falsePositives: redFp,
        trueNegatives: redTn,
        falseNegatives: redFn,
        precision:
          redTp + redFp === 0
            ? 1
            : Math.round((redTp / (redTp + redFp)) * 1000) / 1000,
        recall:
          redTp + redFn === 0
            ? 1
            : Math.round((redTp / (redTp + redFn)) * 1000) / 1000,
      },
    },
    mismatches,
    limitations,
  };

  return report;
}

const report = runEvaluation();
console.log(JSON.stringify(report, null, 2));

if (report.status === "failed") {
  console.error(
    `\n[ERROR] Evaluation failed with ${report.counts.coreFailed} core regression(s).`,
  );
  process.exit(1);
} else {
  console.error(
    `\n[SUCCESS] Evaluation passed: ${report.counts.corePassed}/${report.counts.core} core cases verified, ${report.counts.challenges} documented challenges reported.`,
  );
  process.exit(0);
}
