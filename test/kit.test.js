// 複製元: kintauros-plugins の packages/worker-kit/test/kit.test.js(scripts/sync-vault-kit.mjs が書き出す)。
// このファイルは直接直さない。直すときは複製元を直して同期し、どちらを直したかを PR に書く
import { describe, expect, it } from 'vitest';
import { normalizeKintoneDomain } from '../src/kit/domain.js';
import { createEnvelope, decryptJson, eciesDecrypt, eciesEncrypt, encryptJson } from '../src/kit/crypto.js';
import { createKintone, invalidRecordBody } from '../src/kit/kintone.js';

const KEK = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=';

describe('domain', () => {
  it('kintone の 3 リージョンとセキュアアクセス', () => {
    expect(normalizeKintoneDomain('https://Foo.cybozu.com/k/1/')).toBe('foo.cybozu.com');
    expect(normalizeKintoneDomain('foo.s.cybozu.com')).toBe('foo.cybozu.com');
    expect(normalizeKintoneDomain('example.com')).toBeNull();
  });
});

describe('crypto envelope', () => {
  const env = { MYKEK: KEK };
  const e = createEnvelope({ kekVar: 'MYKEK', hmacInfo: 'test/hmac' });
  it('DEK を包んで戻し、JSON を暗号化・復号できる', async () => {
    const wrapped = await e.newWrappedDek(env);
    const dek = await e.unwrapDek(env, wrapped);
    const ct = await encryptJson(dek, { token: 'abc' });
    expect(JSON.parse(ct).alg).toBe('A256GCM');
    expect(await decryptJson(dek, ct)).toEqual({ token: 'abc' });
  });
  it('HMAC は info ごとに違う鍵になる', async () => {
    const a = await e.hmacHex(env, 'x');
    const b = await e.hmacHex(env, 'x', 'other');
    expect(a).not.toBe(b);
    expect(a).toBe(await e.hmacHex(env, 'x'));
    expect((await e.hmacB64url(env, 'x')).length).toBe(43);
  });
  it('KEK 未設定は判定できる', () => {
    expect(e.kekConfigured({})).toBe(false);
    expect(e.kekConfigured(env)).toBe(true);
  });
  it('ECIES は info が違うと復号できない', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const ct = await eciesEncrypt(pub, { a: 1 }, 'info/v1');
    expect(await eciesDecrypt(priv, ct, 'info/v1')).toEqual({ a: 1 });
    await expect(eciesDecrypt(priv, ct, 'info/v2')).rejects.toThrow();
  });
});

const respond = (status, body) => new Response(body === undefined ? '' : JSON.stringify(body), { status });
const fetchOf = (table) => async (url, init) => {
  const u = new URL(url);
  const key = `${init.method} ${u.pathname}`;
  const f = table[key];
  if (!f) throw new Error(`unexpected ${key}`);
  return typeof f === 'function' ? f(u, init) : f;
};

describe('kintone client', () => {
  it('User-Agent とトークンヘッダーを付けて呼ぶ', async () => {
    let seen = null;
    const k = createKintone({ userAgent: 'ua-test', fetchImpl: async (url, init) => { seen = { url, init }; return respond(200, { records: [], totalCount: '0' }); } });
    const r = await k.getRecords('foo.cybozu.com', '5', 'TOKEN', { query: 'limit 1', fields: ['$id', 'メール'], totalCount: true });
    expect(r.ok).toBe(true);
    expect(seen.url).toBe('https://foo.cybozu.com/k/v1/records.json?app=5&query=limit%201&fields[0]=%24id&fields[1]=%E3%83%A1%E3%83%BC%E3%83%AB&totalCount=true');
    expect(seen.init.headers['X-Cybozu-API-Token']).toBe('TOKEN');
    expect(seen.init.headers['User-Agent']).toBe('ua-test');
  });
  it('checkTokenPermissions(publish): 読めるトークンは拒否', async () => {
    const k = createKintone({ fetchImpl: fetchOf({ 'GET /k/v1/records.json': respond(200, { records: [] }) }) });
    expect((await k.checkTokenPermissions('foo.cybozu.com', '5', 't')).error).toBe('token_can_read');
  });
  const addOnlyTable = (over = {}) => ({
    'GET /k/v1/records.json': respond(403, { code: 'GAIA_NO01' }),
    'PUT /k/v1/record.json': respond(403, { code: 'GAIA_NO01' }),
    'DELETE /k/v1/records.json': respond(403, { code: 'GAIA_NO01' }),
    'GET /k/v1/preview/app/form/fields.json': respond(403, { code: 'GAIA_NO01' }),
    ...over,
  });
  it('checkTokenPermissions(publish): 追加だけなら ok(追加の試験はしない)', async () => {
    const calls = [];
    const table = addOnlyTable();
    const k = createKintone({ fetchImpl: async (url, init) => { calls.push(`${init.method} ${new URL(url).pathname}`); return fetchOf(table)(url, init); } });
    expect(await k.checkTokenPermissions('foo.cybozu.com', '5', 't')).toEqual({ ok: true });
    expect(calls).not.toContain('POST /k/v1/record.json');
  });
  it('checkTokenPermissions(publish): 編集・削除・アプリ管理ができるトークンは拒否', async () => {
    const check = async (over) => (await createKintone({ fetchImpl: fetchOf(addOnlyTable(over)) }).checkTokenPermissions('foo.cybozu.com', '5', 't')).error;
    expect(await check({ 'PUT /k/v1/record.json': respond(404, { code: 'GAIA_RE01' }) })).toBe('token_can_edit');
    expect(await check({ 'DELETE /k/v1/records.json': respond(404, { code: 'GAIA_RE01' }) })).toBe('token_can_delete');
    expect(await check({ 'GET /k/v1/preview/app/form/fields.json': respond(200, { properties: {} }) })).toBe('token_can_manage');
    expect(await check({ 'GET /k/v1/records.json': respond(401, { code: 'CB_AU01' }) })).toBe('token_invalid');
    expect(await check({ 'GET /k/v1/records.json': respond(520, { code: 'GAIA_IA02' }) })).toBe('token_not_enabled');
  });
  const okTable = (over = {}) => ({
    'GET /k/v1/records.json': respond(200, { records: [] }),
    'PUT /k/v1/record.json': respond(404, { code: 'GAIA_RE01' }),
    'DELETE /k/v1/records.json': respond(403, { code: 'GAIA_NO01' }),
    'GET /k/v1/preview/app/form/fields.json': respond(403, { code: 'GAIA_NO01' }),
    'GET /k/v1/app/form/fields.json': respond(200, { properties: { 区分: { code: '区分', type: 'DROP_DOWN' } } }),
    'POST /k/v1/record.json': respond(403, { code: 'GAIA_NO01' }),
    ...over,
  });
  it('checkViewEditOnly: 閲覧+編集だけなら ok', async () => {
    const k = createKintone({ fetchImpl: fetchOf(okTable()) });
    const r = await k.checkViewEditOnly('foo.cybozu.com', '5', 't');
    expect(r.ok).toBe(true);
    expect(r.fields.区分.type).toBe('DROP_DOWN');
  });
  it('checkViewEditOnly: 追加・削除・管理ができるトークンは拒否', async () => {
    const k1 = createKintone({ fetchImpl: fetchOf(okTable({ 'POST /k/v1/record.json': respond(400, { code: 'CB_VA01' }) })) });
    expect((await k1.checkViewEditOnly('foo.cybozu.com', '5', 't')).error).toBe('token_can_add');
    const k2 = createKintone({ fetchImpl: fetchOf(okTable({ 'DELETE /k/v1/records.json': respond(404, { code: 'GAIA_RE01' }) })) });
    expect((await k2.checkViewEditOnly('foo.cybozu.com', '5', 't')).error).toBe('token_can_delete');
    const k3 = createKintone({ fetchImpl: fetchOf(okTable({ 'GET /k/v1/preview/app/form/fields.json': respond(200, { properties: {} }) })) });
    expect((await k3.checkViewEditOnly('foo.cybozu.com', '5', 't')).error).toBe('token_can_manage');
    const k4 = createKintone({ fetchImpl: fetchOf(okTable({ 'PUT /k/v1/record.json': respond(403, { code: 'GAIA_NO01' }) })) });
    expect((await k4.checkViewEditOnly('foo.cybozu.com', '5', 't')).error).toBe('token_cannot_edit');
    const k5 = createKintone({ fetchImpl: fetchOf(okTable({ 'GET /k/v1/records.json': respond(400, { code: 'GAIA_IA02' }) })) });
    expect((await k5.checkViewEditOnly('foo.cybozu.com', '5', 't')).error).toBe('token_not_enabled');
  });
  it('invalidRecordBody: 検証エラーになる本文を選ぶ', () => {
    expect(invalidRecordBody({ a: { code: 'a', type: 'SINGLE_LINE_TEXT', maxLength: '10' } })).toEqual({ a: { value: 'x'.repeat(11) } });
    expect(invalidRecordBody({ a: { code: 'a', type: 'NUMBER' }, b: { code: 'b', type: 'DROP_DOWN' } })).toEqual({ b: { value: '__kintauros_invalid_option__' } });
    expect(invalidRecordBody({ a: { code: 'a', type: 'FILE' } })).toBeNull();
  });
  it('putRecord: revision 不一致は conflict', async () => {
    const k = createKintone({ fetchImpl: fetchOf({ 'PUT /k/v1/record.json': respond(409, { code: 'GAIA_CO02', message: 'x' }) }) });
    const r = await k.putRecord('foo.cybozu.com', '5', 't', { id: '1', revision: '3', record: {} });
    expect(r.ok).toBe(false);
    expect(r.conflict).toBe(true);
  });
});
