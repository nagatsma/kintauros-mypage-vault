// メンバーのデータ(P3。閲覧・編集・添付・自己登録・LINE 連携・量の上限)。
// 前提: 画面側(mypage-worker)は乗っ取られていて、攻撃者は画面側との共有の鍵と、その間にログインしたメンバー(被害者)のセッションを持ち、
//       /v1 を任意の内容で呼べる。それでも「他人のレコードを読めない・書けない」「照合に使うフィールドを書き換えられない」
//       「閲覧を許していないフィールドが応答に出ない」「署名の無い・別のレコードの添付の識別子は使えない」「共有レコードの他人の行を消せない」
//       「量の上限を超えられない」「どの応答にもトークン・秘密が出ない」ことを確かめる。
// kintone の代役はクエリの照合条件を見ない(本人以外のレコードも返す)。保管庫が取得後に再照合していることを確かめるため
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index.js';
import { INFO, encryptSecret, encryptToken, hmacHex, newWrappedDek, sign } from '../src/crypto.js';
import { getSiteById, insertCode } from '../src/db.js';
import { signIdTokenForTest } from '../src/line.js';
import { issueSession, signSignup } from '../src/session.js';
import { validatePageSettings } from '../src/settings.js';
import { createD1, envOf, fakeGate, seedPage, seedSite, slowD1, v1 } from './helpers.js';

const SITE = '11111111-1111-4111-8111-111111111111';
const PAGE = '22222222-2222-4222-8222-222222222222';
const TEAM_PAGE = '55555555-5555-4555-8555-555555555555';
const HOST = 'sample.kintauros.me';
const TOKEN = 'ViewEditToken0000000000000000000000001';
const TEAM_TOKEN = 'ViewEditToken0000000000000000000000002';
const ADD_TOKEN = 'AddOnlyToken00000000000000000000000003';
const VICTIM = 'victim@gmail.com';
const COLLEAGUE = 'colleague@gmail.com';
const STRANGER = 'stranger@example.com';
const ATTACKER = 'attacker@evil.example';
const SECRET_MEMO = '社内だけの評価メモ-7f3a';
const SECRET_COST = '原価-918273';
const STRANGER_NAME = '他人の氏名-c0ffee';
const LINE_CHANNEL = '1234567890';
const LINE_SECRET = 'abcdef0123456789abcdef0123456789';
const LINE_ID = 'U0123456789abcdef0123456789abcdef';
const OTHER_LINE = 'Uffffffffffffffffffffffffffffffff';

const FIELDS = {
  氏名: { type: 'SINGLE_LINE_TEXT', code: '氏名', label: '氏名' },
  メール: { type: 'SINGLE_LINE_TEXT', code: 'メール', label: 'メール' },
  LINE: { type: 'SINGLE_LINE_TEXT', code: 'LINE', label: 'LINE 連携 ID' },
  書類: { type: 'FILE', code: '書類', label: '書類' },
  社内メモ: { type: 'MULTI_LINE_TEXT', code: '社内メモ', label: '社内メモ(非公開)' },
  更新者: { type: 'SINGLE_LINE_TEXT', code: '更新者', label: '更新者' },
  明細: { type: 'SUBTABLE', code: '明細', label: '明細', fields: { 品名: { type: 'SINGLE_LINE_TEXT', code: '品名', label: '品名' }, 作成者: { type: 'SINGLE_LINE_TEXT', code: '作成者', label: '作成者' }, 原価: { type: 'NUMBER', code: '原価', label: '原価(非公開)' } } },
  担当者: { type: 'SUBTABLE', code: '担当者', label: '担当者', fields: { メール: { type: 'SINGLE_LINE_TEXT', code: 'メール', label: 'メール' }, LINE: { type: 'SINGLE_LINE_TEXT', code: 'LINE', label: 'LINE' }, 名前: { type: 'SINGLE_LINE_TEXT', code: '名前', label: '名前' } } },
};
const LAYOUT = [
  { type: 'ROW', fields: [{ type: 'LABEL', label: '基本情報' }, { type: 'SINGLE_LINE_TEXT', code: '氏名' }, { type: 'SINGLE_LINE_TEXT', code: 'メール' }] },
  { type: 'ROW', fields: [{ type: 'MULTI_LINE_TEXT', code: '社内メモ' }] },
  { type: 'ROW', fields: [{ type: 'FILE', code: '書類' }] },
  { type: 'SUBTABLE', code: '明細', fields: [{ type: 'SINGLE_LINE_TEXT', code: '品名' }, { type: 'SINGLE_LINE_TEXT', code: '作成者' }, { type: 'NUMBER', code: '原価' }] },
];
const v = (value) => ({ value });
const file = (k, name = 'a.pdf') => ({ fileKey: k, name, contentType: 'application/pdf', size: '3' });
const row = (id, value) => ({ id: String(id), value: Object.fromEntries(Object.entries(value).map(([c, x]) => [c, v(x)])) });
const RECORDS = () => [
  { $id: v('5'), $revision: v('3'), 氏名: v('被害者'), メール: v('Victim@Gmail.com'), LINE: v(''), 書類: v([file('fk-victim-0001')]), 社内メモ: v(SECRET_MEMO), 更新者: v(''), 明細: v([row(100, { 品名: 'A', 作成者: VICTIM, 原価: SECRET_COST })]) },
  { $id: v('6'), $revision: v('1'), 氏名: v(STRANGER_NAME), メール: v(STRANGER), LINE: v(''), 書類: v([file('fk-stranger-0002', 'secret.pdf')]), 社内メモ: v('他人のメモ'), 更新者: v(''), 明細: v([]) },
  // 単語の一致(like)で拾われるが、完全一致ではないアドレス
  { $id: v('8'), $revision: v('1'), 氏名: v('似たアドレス'), メール: v(`x.${VICTIM}`), LINE: v(''), 書類: v([]), 社内メモ: v('似た人のメモ'), 更新者: v(''), 明細: v([]) },
];
// メンバー表のページ(共有レコード): 被害者と同僚が同じレコードに入る
const TEAM_RECORDS = () => [
  { $id: v('7'), $revision: v('4'), 氏名: v('共有の取引先'), 社内メモ: v(SECRET_MEMO), 更新者: v(''), 書類: v([]),
    担当者: v([row(200, { メール: VICTIM, LINE: '', 名前: '被害者' }), row(201, { メール: COLLEAGUE, LINE: '', 名前: '同僚' })]),
    明細: v([row(300, { 品名: '被害者の行', 作成者: VICTIM, 原価: SECRET_COST }), row(301, { 品名: '同僚の行', 作成者: COLLEAGUE, 原価: '1' }), row(302, { 品名: '社内の行', 作成者: '', 原価: '2' })]) },
];

const PAGE_RAW = {
  name: '提出', enabled: true, member: { field: 'メール', table: '' }, line: { field: 'LINE' }, condition: '', checkScope: 'all', checkPages: [],
  // 照合に使うフィールド(メール・LINE)に「編集」を付けても、保管庫は書き換えさせない
  fields: { 氏名: { view: true, edit: true }, メール: { view: true, edit: true }, LINE: { view: true, edit: true }, 書類: { view: true, edit: true }, 更新者: { view: true, edit: true } },
  tables: { 明細: { all: { view: true, add: true }, owner: { edit: true, del: true }, ownerColumn: '作成者', deleteMode: 'remove', columns: { 品名: { view: true, edit: true }, 作成者: { view: true, edit: true } } } },
  list: { fields: ['氏名', '書類'], sort: { field: '', order: 'desc' }, search: ['氏名'] },
  record: { updaterField: '更新者', lastLoginField: '' },
  attachments: { mode: 'list', extensions: ['pdf', 'png'] },
  signup: { enabled: true, fields: ['氏名', 'メール'], defaults: [{ field: '更新者', value: '自己登録' }, { field: 'LINE', value: OTHER_LINE }] },
};
const TEAM_RAW = {
  name: '取引先', enabled: true, member: { field: 'メール', table: '担当者' }, line: { field: 'LINE' }, condition: '', checkScope: 'all', checkPages: [],
  fields: { 氏名: { view: true } },
  tables: {
    担当者: { all: { view: true, add: true, edit: true, del: true }, owner: {}, ownerColumn: '', deleteMode: 'remove', columns: { メール: { view: true, edit: true }, LINE: { view: true, edit: true }, 名前: { view: true, edit: true } } },
    明細: { all: { view: true, add: true }, owner: { edit: true, del: true }, ownerColumn: '作成者', deleteMode: 'remove', columns: { 品名: { view: true, edit: true }, 作成者: { view: true, edit: true } } },
  },
  list: { fields: ['氏名'], sort: { field: '', order: 'desc' }, search: [] },
  record: { updaterField: '', lastLoginField: '' },
};

// ---- kintone の代役: 照合の条件は見ない(全件返す)。$id = N だけは絞る。fields の指定は本物と同じく従う(honorFields) ----
function fakeApp() {
  const apps = { 10: { token: TOKEN, records: RECORDS() }, 20: { token: TEAM_TOKEN, records: TEAM_RECORDS() } };
  const calls = [];
  let uploads = 0;
  const state = { honorFields: true, apps, calls };
  const res = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const appOf = (id) => apps[String(id)];
  state.handle = async (url, init = {}) => {
    const u = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const token = new Headers(init.headers).get('X-Cybozu-API-Token');
    const path = u.pathname.replace(/^\/k\/v1\//, '');
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : null;
    const fieldsParam = [...u.searchParams.entries()].filter(([k]) => /^fields\[\d+\]$/.test(k)).map(([, x]) => x);
    calls.push({ method, path, token, query: u.searchParams.get('query'), fields: fieldsParam, body, isForm: init.body instanceof FormData });
    if (path === 'file.json' && method === 'POST') return [TOKEN, TEAM_TOKEN].includes(token) ? res(200, { fileKey: `up-key-${++uploads}` }) : res(401, { code: 'CB_AU01' });
    if (path === 'file.json' && method === 'GET') return [TOKEN, TEAM_TOKEN].includes(token) ? new Response(`BYTES:${u.searchParams.get('fileKey')}`, { status: 200 }) : res(401, { code: 'CB_AU01' });
    const a = appOf(u.searchParams.get('app') || (body && body.app));
    if (!a) return res(404, { code: 'GAIA_AP01' });
    if (method === 'POST' && path === 'record.json') {
      if (token !== ADD_TOKEN) return res(403, { code: 'GAIA_NO01' });
      const id = String(100 + a.records.length);
      a.records.push({ $id: v(id), $revision: v('1'), ...body.record });
      return res(200, { id, revision: '1' });
    }
    if (token !== a.token) return res(401, { code: 'CB_AU01' });
    if (method === 'GET' && path === 'app/form/fields.json') return res(200, { properties: FIELDS });
    if (method === 'GET' && path === 'app/form/layout.json') return res(200, { layout: LAYOUT });
    if (method === 'GET' && path === 'records.json') {
      const q = u.searchParams.get('query') || '';
      const m = /\$id = (\d+)/.exec(q);
      let list = a.records.filter((r) => !m || r.$id.value === m[1]);
      if (state.honorFields && fieldsParam.length) list = list.map((r) => Object.fromEntries(Object.entries(r).filter(([c]) => fieldsParam.includes(c))));
      return res(200, { records: JSON.parse(JSON.stringify(list)), totalCount: null });
    }
    if (method === 'PUT' && path === 'record.json') {
      const r = a.records.find((x) => x.$id.value === String(body.id));
      if (!r) return res(404, { code: 'GAIA_RE01' });
      if (body.revision && body.revision !== r.$revision.value) return res(409, { code: 'GAIA_CO02' });
      for (const [code, cell] of Object.entries(body.record)) {
        if (Array.isArray(cell.value) && r[code] && Array.isArray(r[code].value) && cell.value.every((x) => x && typeof x === 'object' && !x.fileKey)) {
          const old = new Map(r[code].value.map((x) => [x.id, x]));
          r[code].value = cell.value.map((x, i) => (x.id ? { id: x.id, value: { ...old.get(x.id).value, ...(x.value || {}) } } : { id: String(900 + i), value: x.value }));
        } else r[code] = { value: cell.value };
      }
      r.$revision.value = String(Number(r.$revision.value) + 1);
      return res(200, { revision: r.$revision.value });
    }
    if (method === 'POST' && path === 'record/comment.json') return res(200, { id: '1' });
    return res(404, { code: 'NOT_FOUND' });
  };
  state.puts = () => calls.filter((c) => c.method === 'PUT' && c.path === 'record.json');
  return state;
}

let db, app, env, texts, secrets, jobs, site;
const ctx = { waitUntil: (p) => jobs.push(p) };
const LIMITS = { LIMIT_MEMBER_REQUESTS_PER_MIN: '1000', LIMIT_RECORDS_PER_SESSION_HOUR: '1000' };
beforeEach(async () => {
  db = createD1();
  app = fakeApp();
  env = envOf(db, app, { ...LIMITS });
  env.SITE_GATE = fakeGate(app);
  texts = [];
  jobs = [];
  await seedSite(db, { id: SITE, slug: 'sample', domain: 'sample.cybozu.com', settings: JSON.stringify({ name: '本物の会社', login: { email: true }, sessionDays: 90, topCheckScope: 'all', topCheckPages: [], line: { enabled: true, selfLink: true }, lang: 'ja' }) });
  const dek = await newWrappedDek(env);
  await seedPage(db, { id: PAGE, site_id: SITE, app_id: '10', slug: 'app10', settings: JSON.stringify(validatePageSettings(PAGE_RAW).value), dek_wrapped: dek, token_enc: await encryptToken(env, dek, TOKEN), add_token_enc: await encryptToken(env, dek, ADD_TOKEN), token_verified_at: new Date().toISOString() });
  const dek2 = await newWrappedDek(env);
  await seedPage(db, { id: TEAM_PAGE, site_id: SITE, app_id: '20', slug: 'team', settings: JSON.stringify(validatePageSettings(TEAM_RAW).value), dek_wrapped: dek2, token_enc: await encryptToken(env, dek2, TEAM_TOKEN), token_verified_at: new Date().toISOString() });
  site = await getSiteById(db, SITE);
  secrets = new Set([TOKEN, TEAM_TOKEN, ADD_TOKEN, LINE_SECRET, env.VAULT_KEK, env.VAULT_SESSION_KEY, env.VAULT_FRONT_KEY, 'fk-victim-0001', 'fk-stranger-0002', 'up-key-']);
});
afterEach(() => vi.unstubAllGlobals());
// どの応答にもトークン・秘密・fileKey・他人のデータ・閲覧を許していない値が出ないこと(各テストの最後に確かめる)
afterEach(() => {
  const all = texts.join('\n');
  for (const s of secrets) if (s) expect(all.includes(s), `応答に秘密が含まれている: ${s.slice(0, 8)}…`).toBe(false);
  for (const s of [SECRET_MEMO, SECRET_COST, STRANGER_NAME, STRANGER, '社内メモ(非公開)', '原価(非公開)', '似た人のメモ', '他人のメモ']) expect(all.includes(s), `応答に見せてはいけない値: ${s}`).toBe(false);
  for (const t of texts) expect(t).not.toMatch(/"(fileKey|token|token_enc|dek_wrapped|key_hash)"\s*:/);
});

const sessionOf = async (id = VICTIM, extra = {}) => (await issueSession(env, site, { ident: typeof id === 'string' ? { kind: 'email', id } : id, method: 'email', ...extra })).value;
async function call(method, path, opts = {}) {
  const r = await v1(worker, env, method, path, { ctx, ...opts });
  texts.push(r.text);
  return r;
}
const get = (path, session) => call('GET', path, { session });
const post = (path, session, body) => call('POST', path, { session, body });
const detail = async (session, slug = 'app10', id = '5') => (await get(`/v1/pages/${slug}/records/${id}`, session)).body;
const handlesOf = (vals) => (vals || []).map((f) => f.handle);

describe('一覧・詳細: 本人のレコードの、閲覧を許したものだけ', () => {
  it('照合の条件は保管庫が組み立て、kintone が他人のレコードを返しても再照合で落とす(1 件だけなら詳細)', async () => {
    const s = await sessionOf();
    const r = await get('/v1/pages/app10/records', s);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, single: true, record: { id: '5', values: { 氏名: { value: '被害者' } } } });
    const q = app.calls.find((c) => c.path === 'records.json').query;
    expect(q).toContain('(メール = "victim@gmail.com" or メール like "victim@gmail.com")');
  });

  it('検索語はエスケープし、任意のクエリにならない', async () => {
    const s = await sessionOf();
    await get(`/v1/pages/app10/records?keyword=${encodeURIComponent('" or $id > 0 or 氏名 like "')}`, s);
    const q = app.calls.filter((c) => c.path === 'records.json').pop().query;
    expect(q).toMatch(/^\(メール = "victim@gmail\.com" or メール like "victim@gmail\.com"\) and \(氏名 like "\\" or \$id > 0 or 氏名 like \\""\) order by/);
  });

  it('他人のレコード番号を指定しても開けない(クエリにも本人の条件を入れ、kintone が返しても本人の条件で落とす)', async () => {
    const s = await sessionOf();
    await get('/v1/pages/app10/records/6', s);
    expect(app.calls.filter((c) => c.path === 'records.json').pop().query).toBe('$id = 6 and (メール = "victim@gmail.com" or メール like "victim@gmail.com") limit 1');
    for (const id of ['6', '8', '999']) {
      const r = await get(`/v1/pages/app10/records/${id}`, s);
      expect(r.status).toBe(404);
      expect(r.body.error).toBe('record_not_found');
    }
  });

  it('閲覧を許していないフィールドは kintone に要求せず、返されても応答から削る(定義・レイアウトも)', async () => {
    const s = await sessionOf();
    await detail(s);
    const req = app.calls.filter((c) => c.path === 'records.json').pop();
    expect(req.fields).not.toContain('社内メモ');
    app.honorFields = false; // kintone が fields の指定を無視しても
    const d = await detail(s);
    expect(Object.keys(d.record.values).sort()).toEqual(['LINE', 'メール', '更新者', '書類', '氏名'].sort());
    expect(Object.keys(d.record.tables.明細.rows[0].values).sort()).toEqual(['作成者', '品名']);
    expect(d.fields.社内メモ).toBeUndefined();
    expect(Object.keys(d.fields.明細.fields).sort()).toEqual(['作成者', '品名']);
    expect(JSON.stringify(d.layout)).not.toContain('社内メモ');
    expect(JSON.stringify(d.layout)).not.toContain('原価');
  });

  it('保存済みの設定に「閲覧なし」の項目が混ざっていても(設定の検証を経ていない値)、返さない・書かせない', async () => {
    const raw = validatePageSettings(PAGE_RAW).value;
    raw.fields.社内メモ = { view: false, edit: true };
    raw.tables.明細.columns.原価 = { view: false, edit: true };
    db.sqlite.prepare('UPDATE pages SET settings = ? WHERE id = ?').run(JSON.stringify(raw), PAGE);
    app.honorFields = false;
    const s = await sessionOf();
    const d = await detail(s);
    expect(d.record.values.社内メモ).toBeUndefined();
    expect(d.record.tables.明細.rows[0].values.原価).toBeUndefined();
    expect(d.editable.fields).not.toContain('社内メモ');
    expect(d.editable.tables.明細.edit).not.toContain('原価');
    await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', fields: { values: { 社内メモ: 'x' } }, ops: [{ op: 'edit', table: '明細', row: '100', values: { 品名: 'B', 原価: '0' } }] });
    const put = app.puts()[0].body.record;
    expect(put.社内メモ).toBeUndefined();
    expect(put.明細.value[0].value).toEqual({ 品名: v('B') });
  });

  it('添付は fileKey を返さず、保管庫が署名した識別子だけを返す。一覧には添付の値を出さない', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    expect(d.record.values.書類.value).toEqual([{ name: 'a.pdf', contentType: 'application/pdf', size: '3', handle: expect.any(String) }]);
    const r = await post('/v1/pages/app10/records/5/rows', s, {}); // 何も読まない呼び出し(csrf 無し)
    expect(r.status).toBe(403);
    // 検索で一覧にする(1 件でも一覧)
    const list = (await get('/v1/pages/app10/records?keyword=x', s)).body;
    expect(list.rows[0].cells.find((c) => c.code === '書類').value).toBeNull();
  });

  it('セッションが無い・偽物なら、どのデータの API も 401', async () => {
    const forged = `${Buffer.from(JSON.stringify({ v: 1, s: SITE, k: 'email', e: VICTIM, m: 'email', ep: 1, sid: 'A'.repeat(22), iat: Date.now(), exp: Date.now() + 1e6 })).toString('base64url')}.${'A'.repeat(43)}`;
    for (const session of [undefined, forged]) {
      for (const [m, p] of [['GET', '/v1/pages/app10/records'], ['GET', '/v1/pages/app10/records/5'], ['POST', '/v1/pages/app10/records/5/save'], ['POST', '/v1/pages/app10/records/5/rows'], ['POST', '/v1/pages/app10/files'], ['GET', `/v1/files/${'A'.repeat(30)}.${'B'.repeat(43)}`]]) {
        expect((await call(m, p, { session, body: m === 'POST' ? {} : undefined })).status).toBe(401);
      }
    }
    expect(app.calls.filter((c) => c.path === 'records.json')).toHaveLength(0);
  });
});

describe('編集: 入力値だけを受け取り、保管庫が検証して PUT を組み立てる', () => {
  it('照合に使うフィールド(メール・LINE)・閲覧を許していないフィールド・記録用のフィールドは書き換えられない(編集を付けていても)', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    expect(d.editable.fields.sort()).toEqual(['書類', '氏名'].sort());
    const r = await post('/v1/pages/app10/records/5/save', s, {
      csrf: d.csrf, revision: d.record.revision,
      fields: { values: { 氏名: '新しい名前', メール: ATTACKER, LINE: OTHER_LINE, 社内メモ: '書き換え', 更新者: '偽の更新者' } },
      record: { メール: { value: ATTACKER } }, // 組み立て済みの本文は読まない
    });
    expect(r.body).toMatchObject({ ok: true });
    const put = app.puts()[0].body;
    expect(put).toMatchObject({ app: '10', id: '5', revision: '3' });
    expect(Object.keys(put.record).sort()).toEqual(['書類', '氏名', '更新者'].sort());
    expect(put.record.氏名.value).toBe('新しい名前');
    expect(put.record.更新者.value).toBe(VICTIM); // 保管庫が本人の識別子を書く
    expect(put.record.書類.value).toEqual([{ fileKey: 'fk-victim-0001' }]);
  });

  it('他人のレコードには書けない(レコード番号だけでは書けない)', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    for (const id of ['6', '8']) {
      const r = await post(`/v1/pages/app10/records/${id}/save`, s, { csrf: d.csrf, revision: '1', fields: { values: { 氏名: 'x' } } });
      expect(r.status).toBe(404);
    }
    expect(app.puts()).toHaveLength(0);
  });

  it('フォームのトークンは別のレコード・別のセッションのものでは通らない。revision が違えば 409', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    const other = await sessionOf();
    const team = await detail(s, 'team', '7');
    for (const [session, csrf] of [[s, undefined], [s, 'x.y'], [s, team.csrf], [other, d.csrf]]) {
      expect((await post('/v1/pages/app10/records/5/save', session, { csrf, revision: '3', fields: { values: { 氏名: 'x' } } })).body.error).toBe('csrf');
    }
    expect((await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '2', fields: { values: { 氏名: 'x' } } })).status).toBe(409);
    expect(app.puts()).toHaveLength(0);
  });

  it('入力の検証は保管庫で行う(値の形・選択肢・文字数。不正な形の入力は捨てずに断る)', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    expect((await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', fields: { values: { 氏名: { $ne: 1 } } } })).body.error).toBe('invalid_body');
    expect((await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', ops: [{ op: 'del', table: '社内メモ', row: '1' }] })).body.error).toBe('input');
    expect(app.puts()).toHaveLength(0);
  });

  it('メンバー表: 自分の行・同僚の行のアドレスと LINE 連携 ID は書き換えられない。追加(招待)の新しい行にだけアドレスを入れられる', async () => {
    const s = await sessionOf();
    const d = await detail(s, 'team', '7');
    expect(d.editable.tables.担当者).toEqual({ add: ['メール', '名前'], edit: ['名前'] });
    const r = await post('/v1/pages/team/records/7/save', s, {
      csrf: d.csrf, revision: d.record.revision,
      ops: [
        { op: 'edit', table: '担当者', row: '200', values: { メール: ATTACKER, LINE: OTHER_LINE, 名前: '被害者(改)' } },
        { op: 'edit', table: '担当者', row: '201', values: { メール: ATTACKER, 名前: '同僚(改)' } },
        { op: 'add', table: '担当者', values: { メール: 'invited@example.com', LINE: OTHER_LINE, 名前: '招待' } },
      ],
    });
    expect(r.body).toMatchObject({ ok: true });
    const rows = app.puts()[0].body.record.担当者.value;
    expect(rows).toEqual([
      { id: '200', value: { 名前: { value: '被害者(改)' } } },
      { id: '201', value: { 名前: { value: '同僚(改)' } } },
      { value: { メール: { value: 'invited@example.com' }, 名前: { value: '招待' } } },
    ]);
  });

  it('共有レコード: 同僚の行・社内の行は消せない(行の作成者だけ)。自分の行は消せて、他の行は id だけで送る', async () => {
    const s = await sessionOf();
    const d = await detail(s, 'team', '7');
    const rows = d.record.tables.明細.rows;
    expect(rows.map((x) => [x.id, x.canDel])).toEqual([['300', true], ['301', false], ['302', false]]);
    for (const rowId of ['301', '302']) {
      const r = await post('/v1/pages/team/records/7/rows', s, { csrf: d.csrf, op: 'del', table: '明細', row: rowId });
      expect(r.status).toBe(400);
      expect(r.body.error).toBe('input');
    }
    // 一括保存に混ぜても通らない
    expect((await post('/v1/pages/team/records/7/save', s, { csrf: d.csrf, revision: d.record.revision, ops: [{ op: 'del', table: '明細', row: '300' }, { op: 'del', table: '明細', row: '301' }] })).body.error).toBe('input');
    expect(app.puts()).toHaveLength(0);
    const ok = await post('/v1/pages/team/records/7/rows', s, { csrf: d.csrf, op: 'del', table: '明細', row: '300' });
    expect(ok.body).toMatchObject({ ok: true });
    expect(app.puts()[0].body.record).toEqual({ 明細: { value: [{ id: '301' }, { id: '302' }] } });
  });

  it('メンバー表: 自分の行と最後の 1 行は消せない。同僚の行の編集で行の作成者の列も書けない', async () => {
    const s = await sessionOf();
    const d = await detail(s, 'team', '7');
    const own = await post('/v1/pages/team/records/7/rows', s, { csrf: d.csrf, op: 'del', table: '担当者', row: '200' });
    expect(own.body.errors.rows[0]._).toContain('自分の行は削除できません');
    const edit = await post('/v1/pages/team/records/7/rows', s, { csrf: d.csrf, revision: d.record.revision, op: 'edit', table: '明細', row: '300', values: { 品名: '直した', 作成者: COLLEAGUE } });
    expect(edit.body.ok).toBe(true);
    expect(app.puts()[0].body.record.明細.value[0]).toEqual({ id: '300', value: { 品名: { value: '直した' } } });
  });

  it('操作の記録(レコードのコメント)は保管庫が書く', async () => {
    const s = await sessionOf();
    const d = await detail(s, 'team', '7');
    await post('/v1/pages/team/records/7/rows', s, { csrf: d.csrf, op: 'del', table: '担当者', row: '201', comment: '画面側の文面' });
    await Promise.all(jobs);
    const c = app.calls.find((x) => x.path === 'record/comment.json');
    expect(c.body.comment.text).toBe(`[KINTAUROS マイページ] マイページから ${VICTIM} が「担当者」のメンバーの行を削除しました: メール: ${COLLEAGUE} / 名前: 同僚`);
  });
});

describe('添付: 保管庫が署名した識別子だけ', () => {
  it('表示中のレコードの添付は、同じセッションの識別子でだけ取得できる', async () => {
    const s = await sessionOf();
    const [h] = handlesOf((await detail(s)).record.values.書類.value);
    const r = await v1(worker, env, 'GET', `/v1/files/${h}`, { session: s, ctx });
    expect(r.status).toBe(200);
    expect(r.text).toBe('BYTES:fk-victim-0001');
    expect(r.headers.get('Content-Disposition')).toContain("attachment; filename*=UTF-8''a.pdf");
    // 別のセッション(同じ本人でも)・署名の無い値・書き換えた値は 404
    const other = await sessionOf();
    expect((await get(`/v1/files/${h}`, other)).status).toBe(404);
    const payload = JSON.parse(Buffer.from(h.split('.')[0], 'base64url').toString());
    const tampered = `${Buffer.from(JSON.stringify({ ...payload, k: 'fk-stranger-0002' })).toString('base64url')}.${h.split('.')[1]}`;
    expect((await get(`/v1/files/${tampered}`, s)).status).toBe(404);
    expect((await get(`/v1/files/${h.split('.')[0]}.${'A'.repeat(43)}`, s)).status).toBe(404);
    expect(app.calls.filter((c) => c.path === 'file.json' && c.method === 'GET')).toHaveLength(1);
  });

  it('編集で消す添付・足す添付も、このレコード・このセッションの識別子だけ', async () => {
    const s = await sessionOf();
    const d = await detail(s);
    const sid = JSON.parse(Buffer.from(s.split('.')[0], 'base64url').toString()).sid;
    // 保管庫の鍵で正しく署名されていても、別のレコードの添付の識別子は使えない
    const otherRecord = await sign(env, { v: 1, s: SITE, sid, p: PAGE, r: '6', k: 'fk-stranger-0002', n: 'secret.pdf', t: '', exp: Date.now() + 1e6 }, INFO.file);
    expect((await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', fields: { values: {}, removeFiles: { 書類: [otherRecord] } } })).body.error).toBe('invalid_body');
    // 他人がアップロードした(別のセッションの)識別子・ダウンロード用の識別子をアップロードとして使うのも不可
    const foreignUpload = await sign(env, { v: 1, s: SITE, sid: 'B'.repeat(22), p: PAGE, k: 'up-key-x', n: 'x.pdf', z: 1, t: '', exp: Date.now() + 1e6 }, INFO.upload);
    for (const h of [foreignUpload, d.record.values.書類.value[0].handle]) {
      expect((await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', fields: { values: {}, addFiles: { 書類: [h] } } })).body.error).toBe('invalid_body');
    }
    expect(app.puts()).toHaveLength(0);
  });

  it('アップロードは中継だけ(規則を保管庫で確かめる)。識別子を保存に使うと、残す添付と合わせて PUT する', async () => {
    const s = await sessionOf();
    const up = (name, bytes = 'PDFDATA') => v1(worker, env, 'POST', '/v1/pages/app10/files', { session: s, ctx, rawBody: bytes, headers: { 'X-File-Name': encodeURIComponent(name), 'Content-Type': 'application/pdf' } });
    expect((await up('virus.exe')).body.error).toBe('file_blocked');
    expect((await up('photo.gif')).body.error).toBe('file_ext');
    const ok = await up('見積.pdf');
    texts.push(ok.text);
    expect(ok.body).toMatchObject({ ok: true, upload: { name: '見積.pdf', size: 7 } });
    expect(app.calls.filter((c) => c.path === 'file.json' && c.method === 'POST')).toHaveLength(1);
    const d = await detail(s);
    const r = await post('/v1/pages/app10/records/5/save', s, { csrf: d.csrf, revision: '3', fields: { values: { 氏名: '被害者' }, addFiles: { 書類: [ok.body.upload.handle] } } });
    expect(r.body.ok).toBe(true);
    expect(app.puts()[0].body.record.書類.value).toEqual([{ fileKey: 'fk-victim-0001' }, { fileKey: 'up-key-1' }]);
    // 消す: 識別子で指定(1 つ目だけ消すと、残りの 1 つを送る)
    const d2 = await detail(s);
    expect(d2.record.values.書類.value).toHaveLength(2);
    await post('/v1/pages/app10/records/5/save', s, { csrf: d2.csrf, revision: d2.record.revision, fields: { values: { 氏名: '被害者' }, removeFiles: { 書類: [d2.record.values.書類.value[0].handle] } } });
    expect(app.puts()[1].body.record.書類.value).toEqual([{ fileKey: 'up-key-1' }]);
  });

  it('添付を入力できるところが無いページにはアップロードできない', async () => {
    const s = await sessionOf();
    const r = await v1(worker, env, 'POST', '/v1/pages/team/files', { session: s, ctx, rawBody: 'x', headers: { 'X-File-Name': 'a.png', 'Content-Type': 'image/png' } });
    expect(r.status).toBe(403);
  });
});

describe('自己登録: 本人のレコード 1 件だけ・決めたフィールドと固定値だけ', () => {
  const tokenFor = (e = 'newcomer@example.com', extra = {}) => signSignup(env, { s: SITE, k: 'email', e, n: '', p: PAGE, next: '/app10/', exp: Date.now() + 60000, ...extra });

  it('追加専用トークンで作る。照合に使うフィールドにはトークンの本人だけ。指定外のフィールドは捨てる。固定値は照合のフィールドに入れない', async () => {
    const t = await tokenFor();
    const form = await post('/v1/signup/form', null, { token: t });
    expect(form.body.codes).toEqual(['氏名']);
    const r = await post('/v1/signup', null, { token: t, values: { 氏名: '新人', メール: ATTACKER, LINE: OTHER_LINE, 社内メモ: 'よろしく', 書類: 'x' } });
    expect(r.body).toMatchObject({ ok: true, result: 'login', next: '/app10/' });
    const created = app.calls.filter((c) => c.method === 'POST' && c.path === 'record.json');
    expect(created).toHaveLength(1);
    expect(created[0].token).toBe(ADD_TOKEN);
    expect(created[0].body.record).toEqual({ 氏名: v('新人'), メール: v('newcomer@example.com'), 更新者: v('自己登録') });
  });

  it('同じトークンを並列に送っても 1 件だけ。偽のトークン・期限切れ・別のサイトのものは不可', async () => {
    env.DB = slowD1(db);
    const t = await tokenFor();
    const rs = await Promise.all(Array.from({ length: 4 }, () => post('/v1/signup', null, { token: t, values: { 氏名: '新人' } })));
    expect(app.calls.filter((c) => c.method === 'POST' && c.path === 'record.json')).toHaveLength(1);
    expect(rs.filter((r) => r.body.result === 'login').length).toBeGreaterThanOrEqual(1);
    const forged = `${t.split('.')[0]}.${'A'.repeat(43)}`;
    for (const token of [forged, await tokenFor('x@example.com', { exp: Date.now() - 1 }), await tokenFor('y@example.com', { s: 'other-site' })]) {
      expect((await post('/v1/signup', null, { token, values: { 氏名: 'x' } })).body.error).toBe('signup_expired');
    }
  });

  it('既にレコードがある人は作らずにログインする', async () => {
    const r = await post('/v1/signup', null, { token: await tokenFor(VICTIM), values: { 氏名: '二重' } });
    expect(r.body.result).toBe('login');
    expect(app.calls.filter((c) => c.method === 'POST' && c.path === 'record.json')).toHaveLength(0);
  });
});

describe('LINE 連携', () => {
  let pending;
  beforeEach(async () => {
    const dek = await newWrappedDek(env);
    db.sqlite.prepare('UPDATE sites SET line_channel_id = ?, line_secret_enc = ?, dek_wrapped = ? WHERE id = ?').run(LINE_CHANNEL, await encryptSecret(env, dek, LINE_SECRET), dek, SITE);
    site = await getSiteById(db, SITE);
    vi.stubGlobal('fetch', async (url, init = {}) => {
      if (String(url) === 'https://api.line.me/oauth2/v2.1/token') {
        return new Response(JSON.stringify({ id_token: await signIdTokenForTest({ channelSecret: LINE_SECRET, claims: { iss: 'https://access.line.me', aud: LINE_CHANNEL, sub: LINE_ID, name: 'ライン', nonce: pending.nonce, exp: Math.floor(Date.now() / 1000) + 600 } }) }), { status: 200 });
      }
      throw new Error(`unexpected fetch ${url}`);
    });
  });
  const startLine = async (body, session) => {
    const r = await call('POST', '/v1/login/line/start', { session, body: { next: '/', ...body } });
    if (r.body.url) pending = { state: new URL(r.body.url).searchParams.get('state'), nonce: new URL(r.body.url).searchParams.get('nonce'), bind: r.body.bind };
    return r;
  };
  const finishLine = () => call('POST', '/v1/login/line/finish', { host: null, body: { state: pending.state, code: 'auth-code', bind: pending.bind } });

  it('メンバー自身の連携: 開始と同じセッションでだけ書ける。本人のレコードにだけ書く', async () => {
    const s = await sessionOf();
    expect((await startLine({ connect: true })).body.error).toBe('connect_unavailable'); // セッションなしでは始められない
    await startLine({ connect: true }, s);
    const f = await finishLine();
    expect(f.body).toMatchObject({ ok: true, result: 'line_connect', host: HOST });
    expect(f.body.session).toBeUndefined(); // ここではログインしない
    const other = await sessionOf();
    expect((await post('/v1/line/connect', other, { ticket: f.body.ticket })).body.error).toBe('session_mismatch');
    // 引換券は 1 回限り(上の失敗で消えている)。やり直す
    await startLine({ connect: true }, s);
    const f2 = await finishLine();
    const r = await post('/v1/line/connect', s, { ticket: f2.body.ticket });
    // 本人のレコード(提出の 5 と、メンバー表の自分の行)にだけ書く。他人のレコード 6・似たアドレスの 8・同僚の行には書かない
    expect(r.body).toMatchObject({ ok: true, result: 'connected', n: 2 });
    const puts = app.puts();
    expect(puts.map((p) => [p.body.app, p.body.id, p.body.record])).toEqual([['10', '5', { LINE: v(LINE_ID) }], ['20', '7', { 担当者: { value: [{ id: '200', value: { LINE: v(LINE_ID) } }, { id: '201' }] } }]]);
    expect((await post('/v1/line/connect', s, { ticket: f2.body.ticket })).body.error).toBe('ticket_invalid');
  });

  it('メンバー自身の連携は、別の LINE が入っているレコードを上書きしない', async () => {
    app.apps[10].records[0].LINE.value = OTHER_LINE;
    const s = await sessionOf();
    await startLine({ connect: true }, s);
    const r = await post('/v1/line/connect', s, { ticket: (await finishLine()).body.ticket });
    expect(r.body.n).toBe(1);
    expect(app.puts().map((p) => p.body.app)).toEqual(['20']);
  });

  it('連携用リンク: リンクの行に書いてから LINE でログインする。リンクは 1 回限り', async () => {
    const id = 'L'.repeat(16);
    const secret = 'S'.repeat(32);
    await insertCode(db, { id, siteId: SITE, kind: 'line_link', hash: await hmacHex(env, secret, INFO.code), data: { p: TEAM_PAGE, r: '7', row: '201' }, expiresAt: new Date(Date.now() + 60000).toISOString() });
    expect((await post('/v1/line/link', null, { c: `${id}.${secret}` })).body.valid).toBe(true);
    await startLine({ link: `${id}.${secret}` });
    const f = await finishLine();
    const r = await post('/v1/line/connect', null, { ticket: f.body.ticket });
    expect(r.body).toMatchObject({ ok: true, result: 'login', method: 'line', next: '/team/7' });
    expect(app.puts()[0].body.record).toEqual({ 担当者: { value: [{ id: '200' }, { id: '201', value: { LINE: v(LINE_ID) } }] } });
    expect((await post('/v1/line/link', null, { c: `${id}.${secret}` })).body.valid).toBe(false);
  });
});

describe('量の上限(環境変数)', () => {
  it('上限の環境変数が無ければ、データの API は開かない', async () => {
    delete env.LIMIT_RECORDS_PER_SESSION_HOUR;
    expect((await get('/v1/pages/app10/records/5', await sessionOf())).body.error).toBe('limits_not_configured');
    expect(app.calls.filter((c) => c.path === 'records.json')).toHaveLength(0);
  });

  it('メンバーごとの 1 分の回数を超えたら 429。同じ本人の別のセッションも同じ枠。並列でも超えない', async () => {
    env.LIMIT_MEMBER_REQUESTS_PER_MIN = '5';
    const s = await sessionOf();
    const seq = [];
    for (let i = 0; i < 6; i++) seq.push((await get('/v1/pages/app10/records/5', s)).status);
    expect(seq).toEqual([200, 200, 200, 200, 200, 429]);
    expect((await get('/v1/pages/app10/records/5', await sessionOf())).body.error).toBe('rate_limited');
    env.DB = slowD1(db);
    const c = await sessionOf(COLLEAGUE);
    const rs = await Promise.all(Array.from({ length: 12 }, () => get('/v1/pages/team/records/7', c)));
    expect(rs.filter((r) => r.status === 200).length).toBeLessThanOrEqual(5);
  });

  it('1 セッションが 1 時間に取得するレコード数を超えたら 429(並列でも超えない)。別のセッションは別に数える', async () => {
    env.LIMIT_RECORDS_PER_SESSION_HOUR = '3';
    env.DB = slowD1(db);
    const s = await sessionOf();
    const rs = await Promise.all(Array.from({ length: 8 }, () => get('/v1/pages/app10/records/5', s)));
    expect(rs.filter((r) => r.status === 200)).toHaveLength(3);
    expect(rs.filter((r) => r.body.error === 'record_limit')).toHaveLength(5);
    expect((await get('/v1/pages/app10/records', s)).body.error).toBe('record_limit');
    expect((await get('/v1/pages/app10/records/5', await sessionOf())).status).toBe(200);
  });

  it('一覧は返した件数だけ数える(確保した残りは戻す)', async () => {
    env.LIMIT_RECORDS_PER_SESSION_HOUR = '25';
    const s = await sessionOf();
    expect((await get('/v1/pages/app10/records', s)).status).toBe(200); // 21 件確保 → 1 件だけ返す
    expect((await get('/v1/pages/app10/records', s)).status).toBe(200);
    const n = db.rows('SELECT n FROM usage_counters')[0].n;
    expect(n).toBe(2);
  });
});

describe('メニュー', () => {
  it('入れるページとメンバー証の対象を返す(レコードの内容は返さない)', async () => {
    db.sqlite.prepare('UPDATE sites SET settings = json_set(settings, \'$.card\', json(?)) WHERE id = ?').run(JSON.stringify({ enabled: true, page: PAGE, field: '氏名', fields: ['社内メモ'], name: '会員証' }), SITE);
    const r = await get('/v1/me/pages', await sessionOf());
    expect(r.body).toMatchObject({ ok: true, pageIds: [PAGE, TEAM_PAGE], card: { page: 'app10', field: '氏名', fields: [], name: '会員証' } });
  });
});
