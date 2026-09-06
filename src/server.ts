import { buildApp } from './app.js';
import { remoteProvider } from './provider.js';

const host = process.env.HOST ?? '127.0.0.1';
if (!['127.0.0.1', 'localhost', '::1'].includes(host) && (!process.env.GATEWAY_API_KEY || !process.env.ADMIN_API_KEY)) {
  throw new Error('Non-loopback binding requires both API keys');
}
const upstream = [process.env.UPSTREAM_URL, process.env.UPSTREAM_API_KEY, process.env.UPSTREAM_MODEL];
if (upstream.some(Boolean) && !upstream.every(Boolean)) throw new Error('Configure all three UPSTREAM variables');
const app = await buildApp({
  database: process.env.DATABASE_PATH ?? 'data/aegis.sqlite',
  apiKey: process.env.GATEWAY_API_KEY, adminKey: process.env.ADMIN_API_KEY,
  provider: upstream.every(Boolean) ? remoteProvider(upstream[0]!, upstream[1]!, upstream[2]!) : undefined,
  logger: true,
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void app.close(); });
await app.listen({ host, port: Number(process.env.PORT ?? 4310) });
