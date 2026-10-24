// サイトごとの Durable Object(設計 §4.6.3 / §13.2 S13 方式 A): kintone への fetch を代行し、
//   - 同時接続をサイト(= kintone ドメイン)あたり SITE_CONCURRENCY 本に抑える(超えた分は短く待たせ、待ちきれなければ 503)
//   - アプリごとの 1 日の回数(kintone の上限 10,000 回/日の半分が既定)を SQLite で数える(添付のアップロード・ダウンロードは数えない)
// トークン・レコードの内容はメモリ上を通るだけで、ここでも保存・ログ出力しない
import { SITE_CONCURRENCY, SITE_QUEUE_WAIT_MS, KINTONE_TIMEOUT_MS } from './config.js';
import { utcDay } from './util.js';

export const GATE_HEADER = 'X-Kintauros-Gate';
const jsonRes = (body, status) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

export class SiteGate {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.inflight = 0;
    this.waiters = [];
    this.sql = state.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS usage (app TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (app, day))');
  }

  usage(app, day) {
    const row = this.sql.exec('SELECT n FROM usage WHERE app = ? AND day = ?', app, day).toArray()[0];
    return row ? Number(row.n) : 0;
  }

  acquire() {
    if (this.inflight < SITE_CONCURRENCY) {
      this.inflight++;
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      const w = { resolve, timer: setTimeout(() => { this.waiters = this.waiters.filter((x) => x !== w); resolve(false); }, SITE_QUEUE_WAIT_MS) };
      this.waiters.push(w);
    });
  }
  release() {
    const w = this.waiters.shift();
    if (w) {
      clearTimeout(w.timer);
      w.resolve(true); // inflight はそのまま引き継ぐ
    } else {
      this.inflight = Math.max(0, this.inflight - 1);
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    // 制御用(Worker からの問い合わせ): https://gate/usage?app=
    if (url.hostname === 'gate') {
      if (url.pathname === '/usage') {
        const day = utcDay();
        const apps = url.searchParams.getAll('app');
        const out = {};
        for (const a of apps) out[a] = this.usage(a, day);
        return jsonRes({ day, usage: out, inflight: this.inflight }, 200);
      }
      if (url.pathname === '/purge') {
        this.sql.exec('DELETE FROM usage WHERE day < ?', utcDay(new Date(Date.now() - 3 * 24 * 60 * 60 * 1000)));
        return jsonRes({ ok: true }, 200);
      }
      return jsonRes({ error: 'not_found' }, 404);
    }
    let meta = {};
    try {
      meta = JSON.parse(request.headers.get(GATE_HEADER) || '{}');
    } catch { /* 無視 */ }
    const headers = new Headers(request.headers);
    headers.delete(GATE_HEADER);
    if (meta.count && meta.app) {
      const day = utcDay();
      const n = this.usage(String(meta.app), day);
      if (n >= Number(meta.limit || 0)) return jsonRes({ code: 'KINTAUROS_DAILY_LIMIT', message: 'daily limit reached', n }, 429);
      this.sql.exec('INSERT INTO usage (app, day, n) VALUES (?, ?, 1) ON CONFLICT(app, day) DO UPDATE SET n = n + 1', String(meta.app), day);
    }
    if (!(await this.acquire())) return jsonRes({ code: 'KINTAUROS_BUSY', message: 'too many concurrent requests' }, 503);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Number(meta.timeoutMs) || KINTONE_TIMEOUT_MS);
    try {
      const res = await fetch(request.url, { method: request.method, headers, body: request.body, signal: ctrl.signal });
      return new Response(res.body, { status: res.status, headers: res.headers });
    } catch (err) {
      return jsonRes({ code: 'KINTAUROS_NETWORK', message: String((err && err.message) || err).slice(0, 200) }, 502);
    } finally {
      clearTimeout(timer);
      this.release();
    }
  }
}

export const gateStub = (env, siteId) => env.SITE_GATE.get(env.SITE_GATE.idFromName(siteId));
export async function gateUsage(env, siteId, appIds) {
  const stub = gateStub(env, siteId);
  const res = await stub.fetch(`https://gate/usage?${appIds.map((a) => `app=${encodeURIComponent(a)}`).join('&')}`);
  return res.json();
}
