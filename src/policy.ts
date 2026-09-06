import { z } from 'zod';

export const POLICY_VERSION = '2026-09-06.1';
export const textSchema = z.string().min(1).max(32_000);
export const inspectionSchema = z.object({
  text: textSchema,
  stage: z.enum(['input', 'output', 'document']).default('input'),
}).strict();
export const toolSchema = z.object({
  name: z.string().min(1).max(80),
  arguments: z.record(z.string().max(80), z.string().max(4000)).refine(
    value => Object.keys(value).length <= 12, 'Too many arguments'),
}).strict();
export type ToolCall = z.infer<typeof toolSchema>;
export type Finding = { rule: string; category: 'injection' | 'sensitive'; severity: 'high' | 'medium'; description: string };
export type Inspection = { action: 'allow' | 'redact' | 'block'; text: string | null; findings: Finding[]; policyVersion: string };

const injections = [
  { rule: 'instruction-override', pattern: /\b(?:ignore|disregard|forget|override)\b.{0,60}\b(?:previous|prior|above|system|all)\b.{0,40}\b(?:instructions?|rules?|prompts?)\b/i, description: 'Attempt to override instruction hierarchy' },
  { rule: 'role-spoofing', pattern: /(?:<\|(?:im_start|system|start_header_id)\|>|\[INST\]|<\/?system>)/i, description: 'Embedded role or instruction delimiters' },
  { rule: 'prompt-extraction', pattern: /\b(?:reveal|print|show|repeat|disclose)\b.{0,50}\b(?:system|developer|hidden)\s+(?:prompt|instructions?)\b/i, description: 'Request to disclose internal instructions' },
  { rule: 'data-exfiltration', pattern: /\b(?:send|upload|forward|export)\b.{0,80}\b(?:secrets?|credentials?|api keys?|private (?:data|documents?)|database)\b.{0,60}(?:https?:\/\/|\bto\b)/i, description: 'Possible instruction to export sensitive data' },
];
const sensitive = [
  { rule: 'private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$)/g, description: 'Private key material' },
  { rule: 'api-token', pattern: /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b/g, description: 'Recognizable API credential pattern' },
  { rule: 'email', pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, description: 'Email address' },
];

export function inspect(text: string): Inspection {
  const normalized = text.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/\s+/g, ' ');
  const findings: Finding[] = injections.filter(rule => rule.pattern.test(normalized)).map(rule => ({
    rule: rule.rule, category: 'injection', severity: 'high', description: rule.description,
  }));
  let sanitized = text.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '');
  for (const rule of sensitive) {
    const matcher = new RegExp(rule.pattern.source, rule.pattern.flags);
    if (matcher.test(sanitized)) {
      findings.push({ rule: rule.rule, category: 'sensitive', severity: 'medium', description: rule.description });
      sanitized = sanitized.replace(new RegExp(rule.pattern.source, rule.pattern.flags), `[REDACTED:${rule.rule}]`);
    }
  }
  const action = findings.some(f => f.category === 'injection') ? 'block' : findings.length ? 'redact' : 'allow';
  return { action, text: action === 'block' ? null : sanitized, findings, policyVersion: POLICY_VERSION };
}

export const toolPolicies = [
  { name: 'knowledge.search', action: 'allow', description: 'Search a knowledge base; query only.' },
  { name: 'email.send', action: 'require_approval', description: 'Requires an administrator decision for exact arguments.' },
  { name: '*', action: 'block', description: 'Every unlisted tool is denied.' },
] as const;

export function authorizeTool(call: ToolCall) {
  const keys = Object.keys(call.arguments).sort().join(',');
  if (call.name === 'knowledge.search' && keys === 'query' && call.arguments.query?.trim()) {
    const result = inspect(call.arguments.query);
    // Do not silently change tool arguments; the caller must resubmit sanitized values.
    return result.action === 'allow' ? 'allow' : 'block';
  }
  if (call.name === 'email.send' && keys === 'body,subject,to' &&
      z.email().safeParse(call.arguments.to).success && call.arguments.subject?.trim() && call.arguments.body?.trim()) {
    const content = inspect(`${call.arguments.subject}\n${call.arguments.body}`);
    return content.action === 'allow' ? 'require_approval' : 'block';
  }
  return 'block';
}
