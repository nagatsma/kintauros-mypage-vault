// メンバー向け API(/v1/*。VAULT 設計 §6.1・§8)。画面側(mypage-worker)からサーバー間で呼ぶ。JSON だけを返す(HTML・CORS なし)。
//
// ヘッダー:
//   X-Mypage-Front-Key  画面側との共有の鍵(VAULT_FRONT_KEY)。インターネットからの雑多な呼び出しを減らすためだけのもので、防御の根拠にはしない
//                       (画面側が乗っ取られれば漏れる前提。権限の根拠はセッションと本人確認だけ)。未設定なら /v1 は 503(無効)
//   X-Mypage-Host       メンバーが開いているサイトのホスト名({slug}.kintauros.me か独自ドメイン)。保管庫が D1 でサイトを引き直す
//   X-Mypage-Session    セッション(__Host-kmp の中身。保管庫が署名したもの)
//   X-Mypage-Client-IP  メンバーの IP(レート制限の目安。画面側の申告なので信頼しない)
//
//   GET  /v1/site                     サイトの表示用の情報(ログイン方法など。秘密なし)
//   POST /v1/login/email              確認コードの送信 { email, next, su, lang, turnstile } → { codeId }(登録の有無で応答を変えない)
//   GET  /v1/login/email/code?c=      確認コードの入力画面用 → { email, next }
//   POST /v1/login/email/verify       照合 { c, code } → 結果(下記)
//   POST /v1/login/{google,line}/start  { next, hint, su, lang } → { url, bind }
//   POST /v1/login/{google,line}/finish { state, code, bind } → 結果+{ host, next, lang, su }(X-Mypage-Host は不要。state からサイトを決める)
//   POST /v1/session/renew            セッションの確認と延長 → { member, method, renewed: { value, maxAge, exp } | null }
//   POST /v1/logout                   セッションを無効にする(延長した写しも)→ { ok }
//   GET  /v1/me/pages?next=           本人が入れるページ → { pageIds, pages }
// 結果: { result: 'login', session: { value, maxAge, exp }, member, method, pageIds, next }
//       | { result: 'no_pages', member, signupAvailable, next } | { result: 'signup', signup: { token, page }, member, next }
import { hostBelongs, resolveSiteByHost, siteServing } from './hosts.js';
import { emailCodeInfo, finishGoogle, finishLine, myPages, siteInfo, startEmail, startGoogle, startLine, verifyEmail } from './member-auth.js';
import { renewIfStale, revokeSession, sessionKeyConfigured, verifySession } from './session.js';
import { logOp } from './db.js';
import { identHash, identLabel } from './ident.js';
import { json, readJson, timingSafeEqual } from './util.js';

export const FRONT_KEY_HEADER = 'X-Mypage-Front-Key';
const NO_STORE = { 'Cache-Control': 'no-store' };
const reply = ({ status, body }) => json(body, status, NO_STORE);
const fail = (status, error) => json({ ok: false, error }, status, NO_STORE);
const MAX_BODY = 16 * 1024;

export async function handleV1(request, env, ctx, url) {
  if (!env.VAULT_FRONT_KEY || String(env.VAULT_FRONT_KEY).length < 32) return fail(503, 'front_key_not_configured');
  const key = request.headers.get(FRONT_KEY_HEADER) || '';
  if (!timingSafeEqual(key, env.VAULT_FRONT_KEY)) return fail(401, 'unauthorized');
  if (!sessionKeyConfigured(env)) return fail(503, 'session_key_not_configured');
  const path = url.pathname;
  const method = request.method;
  const ip = String(request.headers.get('X-Mypage-Client-IP') || '').slice(0, 64);

  // 完了(auth ホストから): サイトは state から決める
  if (method === 'POST' && (path === '/v1/login/google/finish' || path === '/v1/login/line/finish')) {
    const input = await body(request);
    if (!input) return fail(400, 'invalid_body');
    return reply(await (path.includes('google') ? finishGoogle : finishLine)(env, ctx, input, { ip }));
  }

  const host = String(request.headers.get('X-Mypage-Host') || '').trim().toLowerCase();
  const site = await resolveSiteByHost(env, host);
  if (!site || !hostBelongs(env, site, host)) return fail(404, 'site_not_found');
  if (!siteServing(site)) return fail(403, 'site_stopped');

  if (method === 'GET' && path === '/v1/site') return reply(await siteInfo(env, site));
  if (method === 'GET' && path === '/v1/login/email/code') return reply(await emailCodeInfo(env, site, url.searchParams.get('c')));
  if (method === 'POST' && path.startsWith('/v1/login/')) {
    const input = await body(request);
    if (!input) return fail(400, 'invalid_body');
    if (path === '/v1/login/email') return reply(await startEmail(env, site, host, input, { ip }));
    if (path === '/v1/login/email/verify') return reply(await verifyEmail(env, site, ctx, input, { ip }));
    if (path === '/v1/login/google/start') return reply(await startGoogle(env, site, host, input, { ip }));
    if (path === '/v1/login/line/start') return reply(await startLine(env, site, host, input, { ip }));
    return fail(404, 'not_found');
  }

  // ここから先はセッション必須
  const raw = request.headers.get('X-Mypage-Session') || '';
  if (method === 'POST' && path === '/v1/logout') {
    const v = await verifySession(env, site, raw);
    if (v.ok) {
      await revokeSession(env, site, v.session);
      await logOp(env.DB, site.id, null, 'member', 'logout', { m: (await identHash(env, v.ident)).slice(0, 16) });
    }
    return json({ ok: true }, 200, NO_STORE); // 無効なセッションでも同じ(画面側は Cookie を消すだけ)
  }
  const v = await verifySession(env, site, raw);
  if (!v.ok) return fail(401, 'session_invalid');
  if (method === 'POST' && path === '/v1/session/renew') {
    const renewed = await renewIfStale(env, site, v.session);
    return json({ ok: true, member: { kind: v.ident.kind, label: identLabel(v.ident) }, method: v.session.m, renewed }, 200, NO_STORE);
  }
  if (method === 'GET' && path === '/v1/me/pages') return reply(await myPages(env, site, v.ident, url.searchParams.get('next')));
  return fail(404, 'not_found');
}

async function body(request) {
  const b = await readJson(request, MAX_BODY);
  return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
}
