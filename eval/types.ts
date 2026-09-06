export type CaseCategory =
  | "benign"
  | "adversarial_injection"
  | "sensitive_data"
  | "known_bypass"
  | "known_false_positive";

export type EvalCase = {
  id: string;
  category: CaseCategory;
  input: string;
  expectedAction: "allow" | "block" | "redact";
  expectedRules?: string[];
  targetIntentAction: "allow" | "block" | "redact";
  isChallenge: boolean;
  challengeType?:
    | "foreign_language"
    | "encoding_obfuscation"
    | "character_delimiter"
    | "semantic_paraphrase"
    | "persona_roleplay"
    | "indirect_injection"
    | "educational_quote"
    | "technical_documentation"
    | "markup_configuration"
    | "support_query";
  description: string;
};

export type EvaluationMetrics = {
  total: number;
  coreCases: number;
  challengeCases: number;
  corePassed: number;
  coreFailed: number;
  byCategory: Record<
    CaseCategory,
    {
      total: number;
      passed: number;
      failed: number;
      actualDistribution: Record<"allow" | "block" | "redact", number>;
    }
  >;
  injectionDetection: {
    dataset: "overall" | "core_only";
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1Score: number;
    accuracy: number;
  }[];
  redactionDetection: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
  };
};

export type CaseMismatch = {
  id: string;
  category: CaseCategory;
  isChallenge: boolean;
  challengeType?: string;
  description: string;
  input: string;
  expectedAction: "allow" | "block" | "redact";
  actualAction: "allow" | "block" | "redact";
  targetIntentAction: "allow" | "block" | "redact";
  findings: Array<{ rule: string; category: string; severity: string }>;
  note: string;
};

export type EvaluationReport = {
  timestamp: string;
  policyVersion: string;
  status: "passed" | "failed";
  counts: {
    total: number;
    core: number;
    challenges: number;
    corePassed: number;
    coreFailed: number;
  };
  metrics: EvaluationMetrics;
  mismatches: CaseMismatch[];
  limitations: string[];
};
