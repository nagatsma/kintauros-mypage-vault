// API トークンの登録・検証・毎日の再検証(設計 §4)。保管庫はトークンを外へ返さない
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker, { runTokenRecheck } from '../src/index.js';
import { decryptToken, newWrappedDek } from '../src/crypto.js';
import { call, createD1, envOf, fakeKintone, keyOf, seedPage, seedSite } from './helpers.js';

const SITE_ID = '11111111-1111-4111-8111-111111111111';
const PAGE = '22222222-2222-4222-8222-222222222222';
const VIEW_EDIT = 'ViewEditToken0000000000000000000000001';
const TOO_WIDE = 'WideToken000000000000000000000000000002'; // 削除もできる
const ADD_ONLY = 'AddOnlyToken00000000000000000000000003';
const GOOD = { read: true, edit: true };

let db, kintone, env;
beforeEach(async () => {
  db = createD1();
  kintone = fakeKintone({ perms: { [VIEW_EDIT]: GOOD, [TOO_WIDE]: { read: true, edit: true, del: true }, [ADD_ONLY]: { add: true } } });
  env = envOf(db, kintone);
  await seedSite(db, { id: SITE_ID });
  await seedPage(db, { id: PAGE, site_id: SITE_ID, app_id: '10', dek_wrapped: await newWrappedDek(env) });
});
afterEach(() => vi.unstubAllGlobals());

const page = () => db.rows('SELECT * FROM pages WHERE id = ?', PAGE)[0];
const api = (method, sub, body) => call(worker, env, method, `/api/pages/${PAGE}${sub}`, { key: keyOf(PAGE), body });
// 応答とDBのどこにもトークンの平文が無いこと
const leaks = (text, token) => text.includes(token) || text.includes(token.slice(0, 20));

describe('閲覧+編集のトークンの登録', () => {
  it('閲覧+編集だけのトークンを受け付け、暗号化して保存する。応答には末尾 4 文字だけ', async () => {
    const r = await api('POST', '/token', { token: VIEW_EDIT });
    expect(r.status).toBe(200);
    expect(r.body.page.token).toMatchObject({ set: true, last4: VIEW_EDIT.slice(-4), error: null });
    expect(leaks(r.text, VIEW_EDIT)).toBe(false);
    const row = page();
    expect(row.token_enc).toBeTruthy();
    expect(leaks(JSON.stringify(row), VIEW_EDIT)).toBe(false);
    expect(await decryptToken(env, row.dek_wrapped, row.token_enc)).toBe(VIEW_EDIT);
    expect(r.body.page.siteAdmin).toBe(true);
    expect(kintone.calls.every((c) => c.host === 'sample.cybozu.com')).toBe(true); // 接続先は契約ドメインだけ
  });

  it('権限が広すぎる・無効なトークンは保存しない', async () => {
    const wide = await api('POST', '/token', { token: TOO_WIDE });
    expect(wide.status).toBe(400);
    expect(wide.body.error).toBe('token_can_delete');
    const invalid = await api('POST', '/token', { token: 'Unknown000000000000000000000000000000' });
    expect(invalid.body.error).toBe('token_invalid');
    expect(page().token_enc).toBeNull();
    expect(db.rows("SELECT action FROM ops_log WHERE action = 'token_check'").length).toBe(2);
  });

  it('kintone に届かないときは 503 で保存しない', async () => {
    env = envOf(db, fakeKintone({ reachable: false }), { VAULT_KEK: env.VAULT_KEK });
    const r = await api('POST', '/token', { token: VIEW_EDIT });
    expect(r.status).toBe(503);
    expect(r.body.error).toBe('unreachable');
    expect(page().token_enc).toBeNull();
  });

  it('KEK が無ければ登録できない', async () => {
    const r = await call(worker, { ...env, VAULT_KEK: undefined }, 'POST', `/api/pages/${PAGE}/token`, { key: keyOf(PAGE), body: { token: VIEW_EDIT } });
    expect(r.status).toBe(503);
    expect(r.body.error).toBe('kek_not_configured');
  });

  it('トークンを返す API は無い(どの応答にも平文が出ない・GET /token は 404)', async () => {
    await api('POST', '/token', { token: VIEW_EDIT });
    const responses = [
      await api('GET', ''),
      await api('PUT', '', { settings: { name: 'ご契約', enabled: true, member: { field: 'メール' }, fields: { メール: { view: true } } } }),
      await api('PUT', '/site', { settings: { name: 'サイト' } }),
      await api('POST', '/test', { email: 'a@example.com' }),
      await api('GET', '/token'),
    ];
    for (const r of responses) expect(leaks(r.text, VIEW_EDIT)).toBe(false);
    expect(responses[4].status).toBe(404);
    expect(responses[1].body.page.settings.enabled).toBe(true);
  });

  it('トークンの破棄で、ページの利用も止まる', async () => {
    await api('POST', '/token', { token: VIEW_EDIT });
    await api('PUT', '', { settings: { name: 'ご契約', enabled: true, member: { field: 'メール' } } });
    const r = await api('DELETE', '/token');
    expect(r.body.page.token.set).toBe(false);
    expect(r.body.page.settings.enabled).toBe(false);
    expect(page().token_enc).toBeNull();
  });

  it('トークンが無いページは有効にできない', async () => {
    const r = await api('PUT', '', { settings: { name: 'ご契約', enabled: true, member: { field: 'メール' } } });
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('token_required');
  });
});

describe('追加専用トークン(自己登録)', () => {
  it('閲覧トークンの登録が先。追加だけのトークンを受け付け、閲覧できるトークンは拒否', async () => {
    expect((await api('POST', '/add-token', { token: ADD_ONLY })).body.error).toBe('token_required');
    await api('POST', '/token', { token: VIEW_EDIT });
    const wrong = await api('POST', '/add-token', { token: VIEW_EDIT });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toBe('token_can_read');
    const r = await api('POST', '/add-token', { token: ADD_ONLY });
    expect(r.status).toBe(200);
    expect(r.body.page.addToken).toMatchObject({ set: true, last4: ADD_ONLY.slice(-4) });
    expect(leaks(r.text, ADD_ONLY)).toBe(false);
    expect(await decryptToken(env, page().dek_wrapped, page().add_token_enc)).toBe(ADD_ONLY);
  });
});

describe('毎日の再検証(cron)', () => {
  const stale = () => db.sqlite.prepare("UPDATE pages SET token_verified_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(PAGE);

  it('権限が広げられていたら破棄して利用を止める', async () => {
    await api('POST', '/token', { token: VIEW_EDIT });
    await api('PUT', '', { settings: { name: 'ご契約', enabled: true, member: { field: 'メール' } } });
    stale();
    kintone = fakeKintone({ perms: { [VIEW_EDIT]: { read: true, edit: true, manage: true } } });
    await runTokenRecheck(envOf(db, kintone, { VAULT_KEK: env.VAULT_KEK }));
    const row = page();
    expect(row.token_enc).toBeNull();
    expect(row.token_error).toBe('token_can_manage');
    expect(JSON.parse(row.settings).enabled).toBe(false);
    expect(db.rows("SELECT action FROM ops_log WHERE action = 'token_revoked'").length).toBe(1);
  });

  it('権限が変わっていなければ検証日時だけ更新する。届かないときは次回に回す', async () => {
    await api('POST', '/token', { token: VIEW_EDIT });
    stale();
    await runTokenRecheck(envOf(db, fakeKintone({ reachable: false }), { VAULT_KEK: env.VAULT_KEK }));
    expect(page().token_enc).toBeTruthy();
    expect(page().token_verified_at).toBe('2000-01-01T00:00:00.000Z');
    await runTokenRecheck(env);
    expect(page().token_enc).toBeTruthy();
    expect(page().token_verified_at > '2000-01-01').toBe(true);
  });
});
