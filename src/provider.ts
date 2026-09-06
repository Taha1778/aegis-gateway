import { z } from "zod";

export type Message = { role: "user" | "assistant"; content: string };
export type Provider = (messages: Message[]) => Promise<string>;
export const demoProvider: Provider = async (messages) => {
  const last = messages.at(-1)?.content ?? "";
  return `Demo assistant: your request passed the gateway.\n\nReceived: ${last}\n\nThis is a deterministic demonstration, not a language-model response. Connect a provider to use a real model.`;
};
export function remoteProvider(
  url: string,
  key: string,
  model: string,
): Provider {
  const endpoint = new URL(url);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash ||
    endpoint.search
  ) {
    throw new Error(
      "UPSTREAM_URL must be a fixed HTTPS URL without credentials, query, or fragment",
    );
  }
  return async (messages) => {
    const response = await fetch(endpoint, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: {
        authorization: `Bearer ${key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        max_tokens: 1024,
      }),
    });
    if (!response.ok || !response.body) throw new Error("Provider unavailable");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 256_000)
          throw new Error("Provider response exceeded limit");
        chunks.push(value);
      }
    } finally {
      await reader.cancel();
    }
    const result = z
      .object({
        choices: z
          .array(
            z.object({
              message: z.object({
                content: z.string().max(32_000),
                tool_calls: z.never().optional(),
              }),
            }),
          )
          .min(1)
          .max(1),
      })
      .parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    return result.choices[0]!.message.content;
  };
}
