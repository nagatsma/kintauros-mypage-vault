// KINTAUROS マイページ 保管庫(mypage-vault)— エントリポイント
//
// 閲覧+編集の API トークンと本人確認の秘密を、画面側(mypage-worker)とは別の Cloudflare アカウントで持つ Worker。
// トークンを外へ返す API は持たない。kintone への呼び出しは保管庫が自分で行い、結果だけを返す。
//
//   GET  /health   死活確認
//   /api/*         管理 API(マイページ プラグインの設定画面から kintone.plugin.app.proxy / fetch で直接。src/api.js)
//   /v1/*          メンバー向け(画面側からサーバー間で。src/v1.js。P2: 本人確認・セッション / P3: 閲覧・編集・添付・自己登録・LINE 連携。src/member-data.js)
//
// 日次 cron: 一時データの掃除・ライセンスの再確認・トークンの権限の再検証・使用回数の古い日の掃除
import { authenticatePage, isSiteAdmin, SITE_ADMIN_ERROR } from './auth.js';
import { corsHeaders } from './cors.js';
import { deleteAddToken, deletePageApi, deleteToken, getPageState, getSlugCheck, postAddToken, postCreatePage, postLineLink, postLineTest, postLogoutAll, postTest, postToken, putPage, putSite, refreshLicenseIfStale } from './api.js';
import { cleanup, clearPageAddToken, clearPageToken, deleteSite, getSiteById, listPages, logOp, markAddTokenVerified, markTokenVerified, updatePageSettings } from './db.js';
import { invalidRecordBody } from './kit/kintone.js';
import { gateStub, SiteGate } from './gate.js';
import { formDef, kintoneFor, pageAddToken, pageToken } from './kintone.js';
import { checkMypageLicense, licenseServeState } from './license.js';
import { json, nowIso } from './util.js';
import { handleV1 } from './v1.js';

export { SiteGate };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/health' && request.method === 'GET') return json({ ok: true }, 200, corsHeaders(request));
      if (url.pathname.startsWith('/api/')) return await handleApi(request, env, ctx, url);
      if (url.pathname.startsWith('/v1/')) return await handleV1(request, env, ctx, url);
      return json({ error: 'not_found' }, 404);
    } catch (err) {
      console.error(`[${url.pathname}] ${err.stack || err}`);
      return json({ error: 'internal_error' }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanup(env.DB).catch((err) => console.error(`[cron cleanup] ${err.stack || err}`)));
    ctx.waitUntil(runLicenseRefresh(env).catch((err) => console.error(`[cron license] ${err.stack || err}`)));
    ctx.waitUntil(runTokenRecheck(env).catch((err) => console.error(`[cron token] ${err.stack || err}`)));
  },
};

async function handleApi(request, env, ctx, url) {
  const cors = corsHeaders(request);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const path = url.pathname;
  const method = request.method;
  if (path === '/api/pages' && method === 'POST') return postCreatePage(request, env, cors);
  if (path === '/api/slug-check' && method === 'GET') return getSlugCheck(url, env, cors);

  const m = path.match(/^\/api\/pages\/([0-9a-f-]{36})(?:\/([a-z-]+)(?:\/([a-z-]+))?)?$/);
  if (!m) return json({ error: 'not_found' }, 404, cors);
  const [, pageId, sub, action] = m;
  const page = await authenticatePage(request, env, pageId);
  if (!page) return json({ ok: false, error: 'unauthorized' }, 401, cors);
  const site = await getSiteById(env.DB, page.site_id);
  if (!site) return json({ ok: false, error: 'site_missing' }, 500, cors);
  ctx.waitUntil(refreshLicenseIfStale(env, site).catch((e) => console.error(`[license refresh] ${e}`)));
  // サイト全体の設定・一斉ログアウト・LINE は、トークンを登録して検証に通ったページの鍵だけ(auth.js isSiteAdmin。設計 §7)
  if (sub === 'site' && !isSiteAdmin(page)) return json({ ok: false, error: SITE_ADMIN_ERROR }, 403, cors);

  if (!sub) {
    if (method === 'GET') return getPageState(env, page, site, cors);
    if (method === 'PUT') return putPage(request, env, page, site, cors);
    if (method === 'DELETE') return deletePageApi(env, page, site, cors);
  } else if (sub === 'token' && method === 'POST') {
    return postToken(request, env, page, site, cors);
  } else if (sub === 'token' && method === 'DELETE') {
    return deleteToken(env, page, site, cors);
  } else if (sub === 'add-token' && method === 'POST') {
    return postAddToken(request, env, page, site, cors);
  } else if (sub === 'add-token' && method === 'DELETE') {
    return deleteAddToken(env, page, site, cors);
  } else if (sub === 'test' && method === 'POST') {
    return postTest(request, env, page, site, cors);
  } else if (sub === 'site' && !action && method === 'PUT') {
    return putSite(request, env, page, site, cors);
  } else if (sub === 'site' && action === 'logout-all' && method === 'POST') {
    return postLogoutAll(env, page, site, cors);
  } else if (sub === 'site' && action === 'line-test' && method === 'POST') {
    return postLineTest(request, env, page, site, cors);
  } else if (sub === 'line-link' && !action && method === 'POST') {
    return postLineLink(request, env, page, site, cors);
  }
  return json({ error: 'not_found' }, 404, cors);
}

// ライセンスの日次再確認。失効したサイトには purge_after(失効から 30 日)を設定し、期限が来たらトークン・設定を消す
export async function runLicenseRefresh(env) {
  const now = Date.now();
  const rows = await env.DB.prepare("SELECT * FROM sites WHERE status = 'active' AND (license_checked_at IS NULL OR license_checked_at < ?) LIMIT 200").bind(new Date(now - 23 * 60 * 60 * 1000).toISOString()).all();
  for (const row of rows.results) {
    const lic = await checkMypageLicense(env, row.domain);
    if (lic.ok === null) continue;
    await env.DB.prepare('UPDATE sites SET license_status = ?, license_plan = ?, license_expires_at = ?, license_checked_at = ? WHERE id = ?').bind(lic.status, lic.plan, lic.expiresAt, nowIso(), row.id).run();
    const st = licenseServeState({ licenseStatus: lic.status, licenseExpiresAt: lic.expiresAt, now });
    await env.DB.prepare('UPDATE sites SET purge_after = ? WHERE id = ?').bind(st.purgeAfter, row.id).run();
  }
  // 完全削除の期限が来たサイト: トークンと設定を消す(トークンは猶予後の停止時点でも破棄する)
  const due = await env.DB.prepare('SELECT id FROM sites WHERE purge_after IS NOT NULL AND purge_after < ? LIMIT 50').bind(nowIso()).all();
  for (const s of due.results) {
    await logOp(env.DB, s.id, null, 'system', 'purged', null);
    await deleteSite(env.DB, s.id);
  }
  const lapsed = await env.DB.prepare("SELECT id, license_status, license_expires_at FROM sites WHERE status = 'active' AND license_status NOT IN ('active', 'trial')").all();
  for (const s of lapsed.results) {
    const st = licenseServeState({ licenseStatus: s.license_status, licenseExpiresAt: s.license_expires_at, now });
    if (st.serve) continue;
    for (const p of await listPages(env.DB, s.id)) if (p.token_enc) await clearPageToken(env.DB, p.id, 'license_lapsed');
  }
}

// 毎日 1 回、トークンの権限を再検証する(権限が広げられたら破棄して利用を止める)
export async function runTokenRecheck(env) {
  const rows = await env.DB.prepare("SELECT * FROM pages WHERE token_enc IS NOT NULL AND status = 'active' AND (token_verified_at IS NULL OR token_verified_at < ?) LIMIT 100").bind(new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString()).all();
  let stopped = 0;
  for (const row of rows.results) {
    const page = { ...row, settings: JSON.parse(row.settings) };
    const site = await getSiteById(env.DB, page.site_id);
    if (!site) continue;
    const token = await pageToken(env, page).catch(() => null);
    if (!token) continue;
    const k = kintoneFor(env, site, page);
    const r = await k.checkViewEditOnly(site.domain, page.app_id, token);
    if (r.ok) {
      await markTokenVerified(env.DB, page.id);
      continue;
    }
    if (r.error === 'unreachable' || r.error === 'unexpected' || r.error === 'cannot_test_add') continue; // 一時的な問題は次回に回す
    await clearPageToken(env.DB, page.id, r.error);
    if (page.settings.enabled) {
      page.settings.enabled = false;
      await updatePageSettings(env.DB, page.id, page.settings);
    }
    await logOp(env.DB, site.id, page.id, 'system', 'token_revoked', { error: r.error });
    stopped++;
  }
  // 追加専用トークン(自己登録)も毎日、追加だけであることを再検証する
  const addRows = await env.DB.prepare("SELECT * FROM pages WHERE add_token_enc IS NOT NULL AND status = 'active' AND (add_token_verified_at IS NULL OR add_token_verified_at < ?) LIMIT 100").bind(new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString()).all();
  for (const row of addRows.results) {
    const page = { ...row, settings: JSON.parse(row.settings) };
    const site = await getSiteById(env.DB, page.site_id);
    if (!site) continue;
    const [viewToken, addToken] = await Promise.all([pageToken(env, page).catch(() => null), pageAddToken(env, page).catch(() => null)]);
    if (!viewToken || !addToken) continue;
    const k = kintoneFor(env, site, page);
    const def = await formDef(env, site, page, k, viewToken);
    if (!def.ok) continue;
    const r = await k.checkAddOnly(site.domain, page.app_id, addToken, invalidRecordBody(def.fields));
    if (r.ok) { await markAddTokenVerified(env.DB, page.id); continue; }
    if (r.error === 'unreachable' || r.error === 'unexpected' || r.error === 'cannot_test_add') continue;
    await clearPageAddToken(env.DB, page.id, r.error);
    await logOp(env.DB, site.id, page.id, 'system', 'add_token_revoked', { error: r.error });
  }
  if (stopped) console.log(`[cron token] ${stopped} page(s) stopped`);
  // 使用回数の古い日の掃除(サイトごと)
  const sites = await env.DB.prepare('SELECT id FROM sites LIMIT 500').all();
  for (const s of sites.results) await gateStub(env, s.id).fetch('https://gate/purge').catch(() => null);
}
