import Fastify, { LogController } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import staticFiles from "@fastify/static";
import { createHash, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { z, ZodError } from "zod";
import {
  authorizeTool,
  inspect,
  inspectionSchema,
  POLICY_VERSION,
  textSchema,
  toolPolicies,
  toolSchema,
} from "./policy.js";
import { Store } from "./store.js";
import { demoProvider, type Provider } from "./provider.js";

export type Options = {
  database?: string;
  apiKey?: string;
  adminKey?: string;
  provider?: Provider;
  logger?: boolean;
};
export async function buildApp(options: Options = {}) {
  if (
    Boolean(options.apiKey) !== Boolean(options.adminKey) ||
    (options.apiKey &&
      (options.apiKey.length < 24 ||
        options.adminKey!.length < 24 ||
        options.apiKey === options.adminKey))
  ) {
    throw new Error("Configure two distinct keys of at least 24 characters");
  }
  const app = Fastify({
    bodyLimit: 128_000,
    logger: options.logger
      ? { level: "info", redact: ["req.headers.authorization"] }
      : false,
    logController: new LogController({ disableRequestLogging: true }),
  });
  const store = new Store(options.database ?? ":memory:");
  const provider = options.provider ?? demoProvider;
  app.addHook("onClose", async () => store.close());
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        upgradeInsecureRequests: null,
      },
    },
  });
  await app.register(rateLimit, { max: 90, timeWindow: "1 minute" });
  app.addHook("onRequest", async (request, reply) => {
    // Apply checks globally, including alternate URL spellings handled by plugins.
    const host = request.headers.host ?? "";
    if (
      !options.apiKey &&
      !/^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host)
    ) {
      return reply
        .code(403)
        .send({ error: "Local demo requires a loopback Host header" });
    }
    const origin = request.headers.origin;
    if (origin && origin !== `http://${host}` && origin !== `https://${host}`) {
      return reply
        .code(403)
        .send({ error: "Cross-origin requests are not allowed" });
    }
    reply.header("cache-control", "no-store");
  });
  const auth =
    (admin = false) =>
    async (
      request: { headers: { authorization?: string } },
      reply: { code: (n: number) => { send: (body: unknown) => unknown } },
    ) => {
      const expected = admin ? options.adminKey : options.apiKey;
      if (!expected) return;
      const supplied = request.headers.authorization ?? "";
      const digest = (value: string) =>
        createHash("sha256").update(value).digest();
      if (!timingSafeEqual(digest(supplied), digest(`Bearer ${expected}`)))
        return reply.code(401).send({ error: "Unauthorized" });
    };
  const principal = (authorization?: string) =>
    createHash("sha256")
      .update(authorization ?? "local-demo")
      .digest("hex");
  app.setErrorHandler((error, _request, reply) => {
    const code =
      error && typeof error === "object" && "statusCode" in error
        ? error.statusCode
        : undefined;
    const status =
      error instanceof ZodError ? 400 : typeof code === "number" ? code : 500;
    reply
      .code(status)
      .send({
        error:
          status === 400
            ? "Invalid request. Check the documented schema."
            : status === 413
              ? "Request too large"
              : status === 429
                ? "Rate limit exceeded"
                : "Request failed",
      });
  });
  app.get("/health", async () => ({ status: "ok" }));
  app.get("/api/status", async () => ({
    mode: options.provider ? "connected" : "demo",
    authentication: Boolean(options.apiKey),
    policyVersion: POLICY_VERSION,
  }));
  app.post("/v1/inspect", { preHandler: auth() }, async (request) => {
    const body = inspectionSchema.parse(request.body);
    const start = performance.now();
    const result = inspect(body.text);
    const eventId = store.record(
      body.stage,
      result.action,
      result.findings.map((f) => f.rule),
      performance.now() - start,
    );
    return { ...result, eventId };
  });
  app.post(
    "/v1/chat/completions",
    { preHandler: auth() },
    async (request, reply) => {
      const body = z
        .object({
          messages: z
            .array(
              z
                .object({
                  role: z.enum(["user", "assistant"]),
                  content: textSchema,
                })
                .strict(),
            )
            .min(1)
            .max(16),
        })
        .strict()
        .parse(request.body);
      const start = performance.now();
      const results = body.messages.map((message) => ({
        message,
        result: inspect(message.content),
      }));
      const rules = [
        ...new Set(
          results.flatMap((item) => item.result.findings.map((f) => f.rule)),
        ),
      ];
      if (results.some((item) => item.result.action === "block")) {
        const eventId = store.record(
          "input",
          "block",
          rules,
          performance.now() - start,
        );
        return reply
          .code(422)
          .send({ error: "Input blocked by policy", eventId, rules });
      }
      store.record(
        "input",
        rules.length ? "redact" : "allow",
        rules,
        performance.now() - start,
      );
      let output: string;
      try {
        output = await provider(
          results.map(({ message, result }) => ({
            role: message.role,
            content: result.text!,
          })),
        );
      } catch {
        store.record("provider", "error", [], performance.now() - start);
        return reply
          .code(502)
          .send({
            error: "Provider unavailable or returned unsupported content",
          });
      }
      if (typeof output !== "string" || output.length > 32_000)
        return reply.code(502).send({ error: "Invalid provider response" });
      const result = inspect(output);
      const eventId = store.record(
        "output",
        result.action,
        result.findings.map((f) => f.rule),
        performance.now() - start,
      );
      if (result.action === "block")
        return reply
          .code(422)
          .send({
            error: "Output blocked by policy",
            eventId,
            rules: result.findings.map((f) => f.rule),
          });
      return {
        id: eventId,
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: result.text },
            finish_reason: "stop",
          },
        ],
        gateway: {
          inputRedacted: rules.length > 0,
          outputRedacted: result.action === "redact",
          policyVersion: POLICY_VERSION,
        },
      };
    },
  );
  app.post("/v1/tools/authorize", { preHandler: auth() }, async (request) => {
    const call = toolSchema.parse(request.body);
    const start = performance.now();
    const action = authorizeTool(call);
    const approvalId =
      action === "require_approval"
        ? store.requestApproval(call, principal(request.headers.authorization))
        : undefined;
    const eventId = store.record("tool", action, [], performance.now() - start);
    return {
      action,
      approvalId,
      eventId,
      policyVersion: POLICY_VERSION,
      execution:
        "Caller must enforce this decision; gateway executes no tools.",
    };
  });
  app.post(
    "/v1/tools/consume",
    { preHandler: auth() },
    async (request, reply) => {
      const body = z
        .object({ approvalId: z.uuid(), call: toolSchema })
        .strict()
        .parse(request.body);
      if (
        authorizeTool(body.call) !== "require_approval" ||
        !store.consume(
          body.approvalId,
          body.call,
          principal(request.headers.authorization),
        )
      ) {
        return reply
          .code(409)
          .send({
            error:
              "Approval unavailable, expired, already used, or arguments changed",
          });
      }
      store.record("tool", "approved", [], 0);
      return {
        action: "allow",
        execution:
          "Authorization consumed once. Caller is responsible for execution.",
      };
    },
  );
  app.get("/api/overview", { preHandler: auth(true) }, async () => ({
    events: store.events(),
    stats: store.stats(),
    approvals: store.approvals(),
    toolPolicies,
    policyVersion: POLICY_VERSION,
  }));
  app.post(
    "/api/approvals/:id",
    { preHandler: auth(true) },
    async (request, reply) => {
      const { id } = z.object({ id: z.uuid() }).parse(request.params);
      const { decision } = z
        .object({ decision: z.enum(["approved", "denied"]) })
        .strict()
        .parse(request.body);
      if (!store.decide(id, decision))
        return reply.code(409).send({ error: "Approval is no longer pending" });
      store.record("approval", decision, [], 0);
      return { id, status: decision };
    },
  );
  await app.register(staticFiles, {
    root: resolve("public"),
    index: "index.html",
    dotfiles: "deny",
  });
  return app;
}
