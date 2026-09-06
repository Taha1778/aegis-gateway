import { afterEach, expect, it, vi } from "vitest";
import { remoteProvider } from "../src/provider.js";
afterEach(() => vi.unstubAllGlobals());
const messages = [{ role: "user" as const, content: "Hello" }];
it("only accepts fixed HTTPS endpoints", () => {
  for (const url of [
    "http://localhost",
    "https://user:pass@example.com",
    "https://example.com?key=secret",
  ]) {
    expect(() => remoteProvider(url, "key", "model")).toThrow();
  }
});
it("forwards a bounded nonstreaming request without accepting redirects", async () => {
  const fetcher = vi.fn(
    async () =>
      new Response(
        JSON.stringify({ choices: [{ message: { content: "Hello" } }] }),
      ),
  );
  vi.stubGlobal("fetch", fetcher);
  expect(
    await remoteProvider(
      "https://provider.example/v1/chat/completions",
      "key",
      "model",
    )(messages),
  ).toBe("Hello");
  expect(fetcher).toHaveBeenCalledWith(
    expect.any(URL),
    expect.objectContaining({
      redirect: "error",
      method: "POST",
      body: expect.stringContaining('"stream":false'),
    }),
  );
});
it.each([
  JSON.stringify({ choices: [{ message: { content: "Hi", tool_calls: [] } }] }),
  JSON.stringify({ choices: [{ message: { content: null } }] }),
  "invalid JSON",
  "x".repeat(256_001),
])("fails closed on unsupported or oversized responses", async (body) => {
  vi.stubGlobal("fetch", async () => new Response(body));
  await expect(
    remoteProvider("https://provider.example", "key", "model")(messages),
  ).rejects.toThrow();
});
it("rejects upstream errors", async () => {
  vi.stubGlobal(
    "fetch",
    async () => new Response("private provider details", { status: 500 }),
  );
  await expect(
    remoteProvider("https://provider.example", "key", "model")(messages),
  ).rejects.toThrow("Provider unavailable");
});
