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

// 本物の D1 のように 1 回ごとに待ち時間を入れる(並列の呼び出しが交互に進むので、「読んでから書く」競合を再現できる)
export function slowD1(db) {
  const wait = () => new Promise((r) => setTimeout(r, Math.random() * 3));
  const slow = (st) => ({ first: async () => (await wait(), st.first()), all: async () => (await wait(), st.all()), run: async () => (await wait(), st.run()) });
  return { ...db, prepare: (sql) => { const p = db.prepare(sql); return { ...slow(p), bind: (...a) => slow(p.bind(...a)) }; } };
}

// kintone の代役。perms: トークンごとに { read, edit, del, manage, add }。reachable: false なら接続できない。
//   records: GET records.json が返すレコード(クエリは見ない。保管庫が取得後に再照合する)。指定すると、その中のレコード番号への PUT は 200
export function fakeKintone({ perms = {}, reachable = true, records = null, fields = { 数値: { type: 'NUMBER', code: '数値', label: '数値' }, メール: { type: 'SINGLE_LINE_TEXT', code: 'メール', label: 'メール' } } } = {}) {
  const calls = [];
  const res = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const denied = () => res(403, { code: 'GAIA_NO01', message: 'denied' });
  const handle = async (url, init = {}) => {
    const u = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const token = new Headers(init.headers).get('X-Cybozu-API-Token');
    calls.push({ method, path: u.pathname, host: u.hostname, query: u.searchParams.get('query'), body: typeof init.body === 'string' ? JSON.parse(init.body) : null });
    if (!reachable) throw new Error('network down');
    const p = perms[token];
    if (!p) return res(401, { code: 'CB_AU01', message: 'invalid token' });
    const path = u.pathname.replace(/^\/k\/v1\//, '');
    if (method === 'GET' && path === 'records.json') return p.read ? res(200, { records: records || [], totalCount: String((records || []).length) }) : denied();
    if (method === 'PUT' && path === 'record.json') {
      if (!p.edit) return denied();
      const id = JSON.parse(init.body || '{}').id;
      return records && records.some((r) => String(r.$id.value) === String(id)) ? res(200, { revision: '2' }) : res(404, { code: 'GAIA_RE01' });
    }
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

export const FRONT_KEY = 'front-key-for-tests-0000000000000000000000';
export function envOf(db, kintone = fakeKintone(), extra = {}) {
  return { DB: db, SITE_GATE: fakeGate(kintone), VAULT_KEK: extra.VAULT_KEK || KEK(), VAULT_SESSION_KEY: KEK(), VAULT_FRONT_KEY: FRONT_KEY, API_HOST: 'api.kintauros-vault.com', AUTH_HOST: 'auth.kintauros.me', PUBLIC_BASE_DOMAIN: 'kintauros.me', LICENSE_API_BASE: 'https://license.test', ...extra };
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

// メンバー向け API(/v1)を画面側として呼ぶ。応答は { status, body, text }
//   rawBody: JSON でない本文(添付のアップロード)。headers: 追加のヘッダー
export async function v1(worker, env, method, path, { host = 'sample.kintauros.me', session, body, rawBody, headers: extra = {}, frontKey = FRONT_KEY, ip = '203.0.113.1', ctx: c = ctx } = {}) {
  const headers = { 'Content-Type': 'application/json', ...extra };
  if (frontKey) headers['X-Mypage-Front-Key'] = frontKey;
  if (host) headers['X-Mypage-Host'] = host;
  if (session) headers['X-Mypage-Session'] = session;
  if (ip) headers['X-Mypage-Client-IP'] = ip;
  const payload = rawBody !== undefined ? rawBody : body === undefined ? undefined : JSON.stringify(body);
  const res = await worker.fetch(new Request(`https://api.kintauros-vault.com${path}`, { method, headers, body: payload }), env, c);
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
