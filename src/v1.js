// メンバー向け API(/v1/*。VAULT 設計 §6.1・§8)。画面側(mypage-worker)からサーバー間で呼ぶ。JSON だけを返す(HTML・CORS なし)。
//
// ヘッダー:
//   X-Mypage-Front-Key  画面側との共有の鍵(VAULT_FRONT_KEY)。インターネットからの雑多な呼び出しを減らすためだけのもので、防御の根拠にはしない
//                       (画面側が乗っ取られれば漏れる前提。権限の根拠はセッションと本人確認だけ)。未設定なら /v1 は 503(無効)
//   X-Mypage-Host       メンバーが開いているサイトのホスト名({slug}.kintauros.me か独自ドメイン)。保管庫が D1 でサイトを引き直す
//   X-Mypage-Session    セッション(__Host-kmp の中身。保管庫が署名したもの)
//   X-Mypage-Client-IP  メンバーの IP(レート制限の目安。画面側の申告なので信頼しない)
//
//   GET  /v1/site                     サイトの表示用の情報(ログイン方法・ページの並び・メンバー証の対象など。秘密なし)
//   POST /v1/login/email              確認コードの送信 { email, next, su, lang, turnstile } → { codeId }(登録の有無で応答を変えない)
//   GET  /v1/login/email/code?c=      確認コードの入力画面用 → { email, next }
//   POST /v1/login/email/verify       照合 { c, code } → 結果(下記)
//   POST /v1/login/{google,line}/start  { next, hint, su, lang } → { url, bind }
//   POST /v1/login/{google,line}/finish { state, code, bind } → 結果+{ host, next, lang, su }(X-Mypage-Host は不要。state からサイトを決める)
//   POST /v1/session/renew            セッションの確認と延長 → { member, method, renewed: { value, maxAge, exp } | null }
//   POST /v1/logout                   セッションを無効にする(延長した写しも)→ { ok }
//   GET  /v1/me/pages?next=           本人が入れるページ → { pageIds, pages, card }
//  P3(メンバーのデータ。src/member-data.js。セッション必須のものはメンバーごとの 1 分の回数を数える):
//   GET  /v1/pages/{p}/records?keyword=&offset=   本人のレコードの一覧(1 件だけなら詳細 single)
//   GET  /v1/pages/{p}/records/{id}               詳細(閲覧を許した値・定義・レイアウト・編集できる範囲・フォームのトークン)
//   POST /v1/pages/{p}/records/{id}/save          編集の一括保存(入力値だけ。保管庫が検証して PUT)
//   POST /v1/pages/{p}/records/{id}/rows          行の操作 1 つ
//   POST /v1/pages/{p}/files                      添付のアップロード(本文はファイル。X-File-Name)→ { upload: { handle } }
//   GET  /v1/files/{handle}                       添付のダウンロード(保管庫が署名した識別子だけ)
//   POST /v1/signup/form { token } / POST /v1/signup { token, values }   自己登録(セッションなし。本人確認の直後のトークン)
//   POST /v1/line/link { c }                      連携用リンクが使えるか
//   POST /v1/line/connect { ticket }              LINE の連携の書き込み(メンバー自身の連携はセッション必須)
// 結果: { result: 'login', session: { value, maxAge, exp }, member, method, pageIds, next }
//       | { result: 'no_pages', member, signupAvailable, next } | { result: 'signup', signup: { token, page }, member, next }
import { hostBelongs, resolveSiteByHost, siteServing } from './hosts.js';
import { emailCodeInfo, finishGoogle, finishLine, myPages, siteInfo, startEmail, startGoogle, startLine, tooManyFromIp, verifyEmail } from './member-auth.js';
import { cardOf, downloadFile, getRecord, lineConnect, lineLinkInfo, listRecords, saveRecord, signup, signupForm, uploadFile } from './member-data.js';
import { dataLimitsConfigured, memberOverRate } from './quota.js';
import { SAVE_BODY_MAX } from './config.js';
import { renewIfStale, revokeSession, sessionKeyConfigured, verifySession } from './session.js';
import { listPages, logOp } from './db.js';
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

  if (method === 'GET' && path === '/v1/site') return reply(await siteInfo(env, site, { cardOf }));
  if (method === 'GET' && path === '/v1/login/email/code') return reply(await emailCodeInfo(env, site, url.searchParams.get('c')));
  if (method === 'POST' && path.startsWith('/v1/login/')) {
    const input = await body(request);
    if (!input) return fail(400, 'invalid_body');
    if (path === '/v1/login/email') return reply(await startEmail(env, site, host, input, { ip }));
    if (path === '/v1/login/email/verify') return reply(await verifyEmail(env, site, ctx, input, { ip }));
    if (path === '/v1/login/google/start') return reply(await startGoogle(env, site, host, input, { ip }));
    if (path === '/v1/login/line/start') return reply(await startLine(env, site, host, input, { ip, session: request.headers.get('X-Mypage-Session') || '' }));
    return fail(404, 'not_found');
  }
  // 自己登録・LINE の連携用リンク(セッションなし。自己登録のトークン・連携用リンクの値が根拠)
  if (method === 'POST' && (path === '/v1/signup' || path === '/v1/signup/form' || path === '/v1/line/link' || path === '/v1/line/connect')) {
    if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many');
    const input = await body(request);
    if (!input) return fail(400, 'invalid_body');
    if (path === '/v1/signup/form') return reply(await signupForm(env, site, input));
    if (path === '/v1/signup') return reply(await signup(env, ctx, site, input));
    if (path === '/v1/line/link') return reply(await lineLinkInfo(env, site, input));
    return reply(await lineConnect(env, ctx, site, input, request.headers.get('X-Mypage-Session') || ''));
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
  if (method === 'GET' && path === '/v1/me/pages') {
    const r = await myPages(env, site, v.ident, url.searchParams.get('next'));
    if (r.status === 200) r.body.card = cardOf(site, await listPages(env.DB, site.id));
    return reply(r);
  }

  // ---- メンバーのデータ(P3)----
  const pm = /^\/v1\/pages\/([a-z0-9-]{1,40})\/(?:records(?:\/(\d{1,12})(?:\/(save|rows))?)?|(files))$/.exec(path);
  const fm = /^\/v1\/files\/([A-Za-z0-9_.-]{20,8192})$/.exec(path);
  if (!pm && !fm) return fail(404, 'not_found');
  // 量の上限が設定されていなければ開かない(上限なしで kintone のデータを返さない)
  if (!dataLimitsConfigured(env)) return fail(503, 'limits_not_configured');
  if (await memberOverRate(env, site, await identHash(env, v.ident))) return fail(429, 'rate_limited');
  if (fm) return method === 'GET' ? downloadFile(env, site, v, fm[1]) : fail(404, 'not_found');
  const [, slug, recordId, action, files] = pm;
  if (files) return method === 'POST' ? reply(await uploadFile(env, site, v, slug, request, { lang: url.searchParams.get('lang') || '' })) : fail(404, 'not_found');
  if (!recordId) return method === 'GET' ? reply(await listRecords(env, ctx, site, v, slug, { keyword: url.searchParams.get('keyword') || '', offset: url.searchParams.get('offset') || 0 })) : fail(404, 'not_found');
  if (!action) return method === 'GET' ? reply(await getRecord(env, ctx, site, v, slug, recordId)) : fail(404, 'not_found');
  if (method !== 'POST') return fail(404, 'not_found');
  const input = await readJson(request, SAVE_BODY_MAX);
  if (!input || typeof input !== 'object' || Array.isArray(input)) return fail(400, 'invalid_body');
  return reply(await saveRecord(env, ctx, site, v, slug, recordId, input, { single: action === 'rows' }));
}

async function body(request) {
  const b = await readJson(request, MAX_BODY);
  return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
}
