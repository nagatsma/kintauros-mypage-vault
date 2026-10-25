// ルーティング・CORS・設定の検証(純関数)
import { describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { corsHeaders } from '../src/cors.js';
import { cardForPage, validatePageSettings, validateSiteSettings } from '../src/settings.js';
import { membershipQuery, sanitizeCondition } from '../src/match.js';
import { qrSvg } from '../src/qr.js';
import { call, createD1, envOf } from './helpers.js';

describe('ルーティング', () => {
  const env = envOf(createD1());
  it('health と slug-check(認証なし)', async () => {
    expect((await call(worker, env, 'GET', '/health')).body).toEqual({ ok: true });
    expect((await call(worker, env, 'GET', '/api/slug-check?slug=acme')).body).toEqual({ ok: true, available: true, reason: null });
    expect((await call(worker, env, 'GET', '/api/slug-check?slug=api')).body.available).toBe(false);
  });
  it('知らないパスは 404。画面(HTML)は返さない', async () => {
    for (const p of ['/', '/api/', '/api/pages', '/v1/me/pages', '/sample/app10/']) {
      const r = await call(worker, env, 'GET', p);
      expect(r.status).toBe(404);
      expect(r.headers.get('Content-Type')).toMatch(/^application\/json/);
    }
  });
  it('CORS は kintone のドメインと自社サイトだけ', () => {
    const of = (origin) => corsHeaders(new Request('https://api.kintauros-vault.com/api/pages', { headers: { Origin: origin } }));
    expect(of('https://sample.cybozu.com')['Access-Control-Allow-Origin']).toBe('https://sample.cybozu.com');
    expect(of('https://sample.s.kintone.com')['Access-Control-Allow-Headers']).toContain('X-Kintauros-Mypage-Key');
    expect(of('https://kintauros.com')['Access-Control-Allow-Origin']).toBe('https://kintauros.com');
    expect(of('https://evil.example')).toEqual({});
    expect(of('https://sample.cybozu.com.evil.example')).toEqual({});
  });
});

describe('設定の検証', () => {
  it('ページ: 編集で閲覧が付き、一覧は閲覧フィールドだけ。有効化にはメールのフィールドとページ名が要る', () => {
    const v = validatePageSettings({ name: 'ご契約', enabled: true, member: { field: 'メール' }, fields: { 会社名: { view: true }, 金額: { edit: true } }, list: { fields: ['会社名', '秘密', '金額'] } });
    expect(v.ok).toBe(true);
    expect(v.value.fields.金額).toEqual({ view: true, edit: true });
    expect(v.value.list.fields).toEqual(['会社名', '金額']);
    expect(validatePageSettings({ enabled: true }).errors.map((e) => e.path).sort()).toEqual(['member.field', 'name']);
  });
  it('サイト: 既定値と検証', () => {
    const v = validateSiteSettings({ name: 'テスト', privacyUrl: 'http://x', sessionDays: 400 });
    expect(v.ok).toBe(false);
    expect(v.value.sessionDays).toBe(90);
    expect(validateSiteSettings({ login: { google: false, email: false } }).ok).toBe(false);
  });
  it('メンバー証は対象のページで閲覧を付けたフィールドだけ', () => {
    const PID = '11111111-2222-4333-8444-555555555555';
    const site = validateSiteSettings({ card: { enabled: true, page: PID, field: 'no', fields: ['x', 'secret'] } }).value;
    const page = { id: PID, settings: validatePageSettings({ fields: { no: { view: true }, x: { view: true } } }).value };
    expect(cardForPage(site.card, page)).toEqual({ field: 'no', fields: ['x'], name: '' });
    expect(cardForPage({ ...site.card, field: 'secret' }, page)).toBeNull();
  });
  it('照合のテストのクエリ: メンバーの入力はエスケープし、対象の条件の order by / limit は落とす', () => {
    const page = { settings: validatePageSettings({ member: { field: 'メール' }, condition: '状態 in ("契約中")' }).value };
    expect(membershipQuery(page, 'A"b@example.com')).toBe('(メール = "a\\"b@example.com" or メール like "a\\"b@example.com") and (状態 in ("契約中")) limit 1');
    expect(sanitizeCondition('状態 = "x" order by $id')).toBe('');
  });
  it('LINE 連携用リンクの QR(SVG)', () => {
    expect(qrSvg('https://sample.kintauros.me/_line/link?c=x')).toMatch(/^<svg /);
    expect(qrSvg('')).toBe('');
  });
});
