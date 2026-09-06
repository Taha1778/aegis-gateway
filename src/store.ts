import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { inspect, POLICY_VERSION, type ToolCall } from './policy.js';

export function callHash(call: ToolCall) {
  return createHash('sha256').update(JSON.stringify([call.name,
    Object.entries(call.arguments).sort(([a], [b]) => a.localeCompare(b)), POLICY_VERSION])).digest('hex');
}
export class Store {
  readonly db: DatabaseSync;
  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, stage TEXT NOT NULL,
        action TEXT NOT NULL, rules TEXT NOT NULL, duration_ms REAL NOT NULL, policy_version TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL,
        tool TEXT NOT NULL, preview TEXT NOT NULL, call_hash TEXT NOT NULL,
        principal TEXT NOT NULL, status TEXT NOT NULL
      );`);
  }
  record(stage: string, action: string, rules: string[], duration: number) {
    const id = randomUUID();
    this.db.prepare('INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      id, new Date().toISOString(), stage, action, JSON.stringify(rules), Math.round(duration * 100) / 100, POLICY_VERSION);
    this.db.exec('DELETE FROM events WHERE rowid NOT IN (SELECT rowid FROM events ORDER BY rowid DESC LIMIT 1000)');
    return id;
  }
  events() { return this.db.prepare('SELECT * FROM events ORDER BY rowid DESC LIMIT 100').all(); }
  stats() {
    return this.db.prepare('SELECT action, count(*) AS count FROM events GROUP BY action').all();
  }
  requestApproval(call: ToolCall, principal: string) {
    this.db.prepare('DELETE FROM approvals WHERE expires_at <= ?').run(Date.now());
    const count = this.db.prepare('SELECT count(*) AS n FROM approvals').get() as { n: number };
    if (count.n >= 1000) throw new Error('Approval queue full');
    const id = randomUUID();
    // The administrator sees redacted text. Exact arguments stay with the caller.
    const preview = Object.fromEntries(Object.entries(call.arguments).map(([key, value]) => [key, inspect(value).text]));
    this.db.prepare('INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      id, new Date().toISOString(), Date.now() + 600_000, call.name, JSON.stringify(preview), callHash(call), principal, 'pending');
    return id;
  }
  approvals() {
    return this.db.prepare(`SELECT id, created_at, expires_at, tool, preview,
      CASE WHEN expires_at <= ? THEN 'expired' ELSE status END AS status
      FROM approvals ORDER BY rowid DESC LIMIT 100`).all(Date.now());
  }
  decide(id: string, status: 'approved' | 'denied') {
    return this.db.prepare("UPDATE approvals SET status = ? WHERE id = ? AND status = 'pending' AND expires_at > ? RETURNING id").get(status, id, Date.now());
  }
  consume(id: string, call: ToolCall, principal: string) {
    return this.db.prepare(`UPDATE approvals SET status = 'consumed' WHERE id = ? AND call_hash = ?
      AND principal = ? AND status = 'approved' AND expires_at > ? RETURNING id`).get(id, callHash(call), principal, Date.now());
  }
  close() { this.db.close(); }
}
