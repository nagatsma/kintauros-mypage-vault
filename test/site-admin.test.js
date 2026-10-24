// サイト全体に効く操作の認可(設計 §7。mypage-worker の bd82d3f をそのまま保管庫へ移したもの)。管理 API をルーティングごと通す
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index.js';
import { isSiteAdmin, SITE_ADMIN_ERROR } from '../src/auth.js';
import { call, createD1, envOf, keyOf, nowIso, seedPage, seedSite } from './helpers.js';

const SITE_ID = '11111111-1111-4111-8111-111111111111';
const OWNER = '22222222-2222-4222-8222-222222222222'; // トークン登録済み
const STRANGER = '33333333-3333-4333-8333-333333333333'; // トークン無し(第三者が登録したかもしれないページ)
const REVOKED = '44444444-4444-4444-8444-444444444444'; // トークンが検証に落ちて破棄された

let db, env;
beforeEach(async () => {
  db = createD1();
  env = envOf(db);
  await seedSite(db, { id: SITE_ID, settings: JSON.stringify({ name: '本物の会社', contact: 'support@sample.example' }), line_channel_id: '1234567890', line_secret_enc: 'enc' });
  await seedPage(db, { id: OWNER, site_id: SITE_ID, app_id: '10', token_enc: 'enc', token_last4: 'abcd', token_verified_at: nowIso(), settings: { name: 'App 10', enabled: true, member: { field: 'メール', table: '' }, line: { field: 'LINE' } } });
  await seedPage(db, { id: STRANGER, site_id: SITE_ID, app_id: '99' });
  await seedPage(db, { id: REVOKED, site_id: SITE_ID, app_id: '11', token_error: 'token_can_add' });
});
afterEach(() => vi.unstubAllGlobals());

const site = () => db.rows('SELECT * FROM sites WHERE id = ?', SITE_ID)[0];
const opsCount = () => db.rows('SELECT COUNT(*) AS n FROM ops_log')[0].n;

describe('isSiteAdmin', () => {
  it('閲覧+編集のトークンが登録済みで、検証のエラーが無いページだけ', () => {
    expect(isSiteAdmin({ token_enc: 'x', token_error: null })).toBe(true);
    expect(isSiteAdmin({ token_enc: null, token_error: null })).toBe(false);
    expect(isSiteAdmin({ token_enc: null, token_error: 'token_can_add' })).toBe(false);
    expect(isSiteAdmin({ token_enc: 'x', token_error: 'token_invalid' })).toBe(false);
    expect(isSiteAdmin(null)).toBe(false);
  });
});

describe('サイト全体の操作は、トークンを登録したページの鍵だけ', () => {
  const siteOps = [
    ['PUT', 'site', { settings: { name: '偽の会社', contact: 'evil@example.com', privacyUrl: 'https://evil.example/' }, slug: 'evil-site', line: { channelId: '9999999999', channelSecret: 'abcdefghijklmnopqrstuvwxyz012345' } }],
    ['POST', 'site/logout-all', undefined],
    ['POST', 'site/line-test', { channelId: '9999999999', channelSecret: 'abcdefghijklmnopqrstuvwxyz012345' }],
  ];
  for (const pageId of [STRANGER, REVOKED]) {
    for (const [method, sub, body] of siteOps) {
      it(`${pageId === STRANGER ? 'トークン無し' : 'トークン破棄済み'}のページ: ${method} ${sub} は 403 で何も変えない`, async () => {
        const before = site();
        const r = await call(worker, env, method, `/api/pages/${pageId}/${sub}`, { key: keyOf(pageId), body });
        expect(r.status).toBe(403);
        expect(r.body).toEqual({ ok: false, error: SITE_ADMIN_ERROR });
        expect(site()).toEqual(before);
        expect(opsCount()).toBe(0);
      });
    }
  }

  it('トークン登録済みのページ: サイト全体の設定を保存できる', async () => {
    const r = await call(worker, env, 'PUT', `/api/pages/${OWNER}/site`, { key: keyOf(OWNER), body: { settings: { name: '本物の会社(新)', contact: 'support@sample.example' } } });
    expect(r.status).toBe(200);
    expect(r.body.site.settings.name).toBe('本物の会社(新)');
    expect(r.body.page.siteAdmin).toBe(true);
    expect(site().settings_updated_by).toBe(OWNER);
  });

  it('トークン登録済みのページ: 一斉ログアウトできる', async () => {
    const r = await call(worker, env, 'POST', `/api/pages/${OWNER}/site/logout-all`, { key: keyOf(OWNER) });
    expect(r.status).toBe(200);
    expect(site().session_epoch).toBe(2);
  });

  it('LINE 連携用リンクもトークンの無いページからは発行できない', async () => {
    db.sqlite.prepare('UPDATE pages SET settings = ? WHERE id = ?').run(JSON.stringify({ name: 'x', enabled: true, member: { field: 'メール' }, line: { field: 'LINE' } }), STRANGER); // 設定を直接いじっても
    db.sqlite.prepare('UPDATE sites SET settings = ? WHERE id = ?').run(JSON.stringify({ name: '本物の会社', line: { enabled: true } }), SITE_ID);
    const r = await call(worker, env, 'POST', `/api/pages/${STRANGER}/line-link`, { key: keyOf(STRANGER), body: { recordId: '1' } });
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('page_disabled');
    expect(db.rows('SELECT * FROM codes')).toEqual([]);
  });

  it('状態(GET)に siteAdmin を返す。ページ鍵が違えば 401', async () => {
    expect((await call(worker, env, 'GET', `/api/pages/${STRANGER}`, { key: keyOf(STRANGER) })).body.page.siteAdmin).toBe(false);
    expect((await call(worker, env, 'GET', `/api/pages/${OWNER}`, { key: keyOf(OWNER) })).body.page.siteAdmin).toBe(true);
    expect((await call(worker, env, 'PUT', `/api/pages/${OWNER}/site`, { key: keyOf(STRANGER), body: { settings: { name: 'x' } } })).status).toBe(401);
    expect((await call(worker, env, 'GET', `/api/pages/${OWNER}`)).status).toBe(401);
  });
});

describe('ページの登録(POST /api/pages)', () => {
  const stubLicense = (status = 'active') => vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ status, plan: 'standard' }), { status: 200 })));

  it('サイトを作るときも、本文のサイト名・サイトの URL は受け取らない。作ったページはトークン登録までサイト全体を変えられない', async () => {
    stubLicense();
    const key = 'n'.repeat(43);
    const r = await call(worker, env, 'POST', '/api/pages', { body: { domain: 'victim.cybozu.com', appId: '5', key, name: 'x', siteName: '偽の会社', siteSlug: 'phish' } });
    expect(r.status).toBe(200);
    expect(r.body.site.slug).toBe('victim');
    expect(r.body.site.settings.name).toBe('');
    expect(r.body.page.siteAdmin).toBe(false);
    expect(r.body.apiBase).toBe('https://api.kintauros-vault.com/api/');
    expect(r.body.page.url).toBe('https://victim.kintauros.me/app5/');
    const put = await call(worker, env, 'PUT', `/api/pages/${r.body.page.id}/site`, { key, body: { settings: { name: '偽の会社' } } });
    expect(put.status).toBe(403);
    expect(put.body.error).toBe(SITE_ADMIN_ERROR);
    expect(db.rows('SELECT key_hash FROM pages WHERE id = ?', r.body.page.id)[0].key_hash).not.toContain(key); // ページ鍵は SHA-256 だけ
  });

  it('既存のサイトに未登録のアプリ番号で登録しても、サイト全体は変えられない', async () => {
    stubLicense();
    const key = 'm'.repeat(43);
    const r = await call(worker, env, 'POST', '/api/pages', { body: { domain: 'sample.cybozu.com', appId: '500', key, name: 'x' } });
    expect(r.status).toBe(200);
    const out = await call(worker, env, 'POST', `/api/pages/${r.body.page.id}/site/logout-all`, { key });
    expect(out.status).toBe(403);
    expect(site().session_epoch).toBe(1);
  });

  it('ライセンスが無いドメインは登録できない。登録済みのアプリは 409', async () => {
    stubLicense('none');
    const r = await call(worker, env, 'POST', '/api/pages', { body: { domain: 'other.cybozu.com', appId: '1', key: 'x'.repeat(40), name: 'x' } });
    expect(r.status).toBe(403);
    expect(r.body.error).toBe('license_required');
    stubLicense();
    const dup = await call(worker, env, 'POST', '/api/pages', { body: { domain: 'sample.cybozu.com', appId: '10', key: 'y'.repeat(40), name: 'x' } });
    expect(dup.status).toBe(409);
    expect(dup.body.error).toBe('already_registered');
  });
});
