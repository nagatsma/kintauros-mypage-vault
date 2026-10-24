// テスト用の代役: D1(Node の node:sqlite に migrations を当てたもの)・Durable Object のゲート・kintone
import { readdirSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { sha256Hex } from '../src/util.js';

const MIGRATIONS = new URL('../migrations/', import.meta.url);

// D1 の prepare / bind / first / all / run / batch だけを実装する
export function createD1() {
  const sqlite = new DatabaseSync(':memory:');
  for (const f of readdirSync(MIGRATIONS).filter((n) => n.endsWith('.sql')).sort()) sqlite.exec(readFileSync(new URL(f, MIGRATIONS), 'utf8'));
  const plain = (row) => (row ? { ...row } : null);
  const stmt = (sql, args) => ({
    first: async () => plain(sqlite.prepare(sql).get(...args)),
    all: async () => ({ results: sqlite.prepare(sql).all(...args).map(plain) }),
    run: async () => (sqlite.prepare(sql).run(...args), { success: true }),
  });
  return {
    sqlite,
    rows: (sql, ...args) => sqlite.prepare(sql).all(...args).map(plain),
    prepare: (sql) => ({ ...stmt(sql, []), bind: (...args) => stmt(sql, args) }),
    batch: async (list) => Promise.all(list.map((s) => s.run())),
  };
}

// kintone の代役。perms: トークンごとに { read, edit, del, manage, add }。reachable: false なら接続できない
export function fakeKintone({ perms = {}, reachable = true, fields = { 数値: { type: 'NUMBER', code: '数値', label: '数値' }, メール: { type: 'SINGLE_LINE_TEXT', code: 'メール', label: 'メール' } } } = {}) {
  const calls = [];
  const res = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const denied = () => res(403, { code: 'GAIA_NO01', message: 'denied' });
  const handle = async (url, init = {}) => {
    const u = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const token = new Headers(init.headers).get('X-Cybozu-API-Token');
    calls.push({ method, path: u.pathname, host: u.hostname });
    if (!reachable) throw new Error('network down');
    const p = perms[token];
    if (!p) return res(401, { code: 'CB_AU01', message: 'invalid token' });
    const path = u.pathname.replace(/^\/k\/v1\//, '');
    if (method === 'GET' && path === 'records.json') return p.read ? res(200, { records: [], totalCount: '0' }) : denied();
    if (method === 'PUT' && path === 'record.json') return p.edit ? res(404, { code: 'GAIA_RE01' }) : denied();
    if (method === 'DELETE' && path === 'records.json') return p.del ? res(404, { code: 'GAIA_RE01' }) : denied();
    if (method === 'GET' && path === 'preview/app/form/fields.json') return p.manage ? res(200, { properties: fields }) : denied();
    if (method === 'GET' && path === 'app/form/fields.json') return p.read ? res(200, { properties: fields }) : denied();
    if (method === 'GET' && path === 'app/form/layout.json') return p.read ? res(200, { layout: [] }) : denied();
    if (method === 'POST' && path === 'record.json') return p.add ? res(400, { code: 'CB_VA01', message: 'invalid' }) : denied();
    return res(404, { code: 'NOT_FOUND' });
  };
  return { calls, handle };
}

// SiteGate の代役: 制御用(https://gate/...)は空の使用回数、それ以外は kintone の代役へ
export function fakeGate(kintone) {
  return {
    idFromName: (n) => n,
    get: () => ({
      fetch: async (url, init) => {
        const u = new URL(typeof url === 'string' ? url : url.url);
        if (u.hostname === 'gate') return new Response(JSON.stringify({ day: null, usage: {}, inflight: 0 }), { status: 200 });
        return kintone.handle(u.toString(), init);
      },
    }),
  };
}

export const KEK = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
export const keyOf = (id) => `k${id.replace(/-/g, '')}`; // 32 文字以上のページ鍵

export function envOf(db, kintone = fakeKintone(), extra = {}) {
  return { DB: db, SITE_GATE: fakeGate(kintone), VAULT_KEK: extra.VAULT_KEK || KEK(), API_HOST: 'api.kintauros-vault.com', AUTH_HOST: 'auth.kintauros.me', PUBLIC_BASE_DOMAIN: 'kintauros.me', LICENSE_API_BASE: 'https://license.test', ...extra };
}

export const ctx = { waitUntil: () => {} };
export const nowIso = () => new Date().toISOString();

// 管理 API を呼ぶ。応答は { status, body(JSON), text(生の本文) }
export async function call(worker, env, method, path, { key, body, origin } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['X-Kintauros-Mypage-Key'] = key;
  if (origin) headers.Origin = origin;
  const res = await worker.fetch(new Request(`https://api.kintauros-vault.com${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, ctx);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 本文なし */ }
  return { status: res.status, body: json, text, headers: res.headers };
}

// サイトとページを直接入れる(ページ鍵は keyOf(id))
export async function seedSite(db, site) {
  const s = { slug: 'sample', domain: 'sample.cybozu.com', settings: JSON.stringify({ name: '本物の会社' }), session_epoch: 1, status: 'active', license_status: 'active', license_checked_at: nowIso(), created_at: nowIso(), updated_at: nowIso(), ...site };
  const cols = Object.keys(s);
  db.sqlite.prepare(`INSERT INTO sites (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`).run(...cols.map((c) => s[c]));
  return s;
}
export async function seedPage(db, page) {
  const p = { slug: `app${page.app_id}`, key_hash: await sha256Hex(keyOf(page.id)), dek_wrapped: 'unused', status: 'active', created_at: nowIso(), updated_at: nowIso(), ...page };
  if (typeof p.settings !== 'string') p.settings = JSON.stringify(p.settings || { name: `App ${p.app_id}`, enabled: false, member: { field: 'メール', table: '' }, line: { field: 'LINE' } });
  const cols = Object.keys(p);
  db.sqlite.prepare(`INSERT INTO pages (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`).run(...cols.map((c) => p[c]));
  return p;
}
