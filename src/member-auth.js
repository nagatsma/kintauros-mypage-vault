// メンバーの本人確認(VAULT 設計 §5・§6.1。mypage-worker の login.js から移したもの)。
// 画面側(mypage-worker)から呼ばれるが、画面側は乗っ取られている前提で信頼しない。本人確認の根拠は次だけ:
//   メールの確認コード: 保管庫が発行して HMAC で保存し、保管庫の RESEND_API_KEY で本人の受信箱にだけ送る。照合は保管庫で、
//                      コードごとの回数(原子的に確保)・アドレスごとの回数(コードをまたぐ)・サイト全体の失敗数(環境変数)で総当たりを止める
//   Google / LINE: state・PKCE の verifier・nonce を保管庫の D1 に置き(1 回限り・10 分)、コードの交換と ID トークンの検証を保管庫で行う。
//                  リダイレクト先は画面側の auth.kintauros.me のまま(V4)。画面側はコードと state を渡すだけで、自分では交換できない
//   Turnstile: 設定されていれば保管庫で検証する
// 本人確認の後: あわせて確認するページの範囲でメンバーかどうかを照合し(match.js)、セッションを保管庫の鍵で署名して返す(session.js)。
//   MAU・操作ログ・最終ログイン日時の書き込みも保管庫で行う。メニュー(入れるページの一覧)の Cookie は画面側が作る
// 応答に確認コード・コードのハッシュ・state の検証用の値・verifier・シークレット・トークンを含めない。
import { sendEmail } from './kit/email.js';
import {
  EMAIL_CODE_ATTEMPTS, EMAIL_CODE_TRIES_PER_ADDRESS_HOUR, EMAIL_CODE_TTL_MS, EMAIL_SENDS_PER_ADDRESS_10MIN, EMAIL_SENDS_PER_SITE_HOUR, LANGS, LAST_LOGIN_MAX_RECORDS,
  LINE_DONE_TTL_MS, LOGIN_ATTEMPTS_PER_IP_10MIN, OAUTH_BIND_MIN, OAUTH_STATE_TTL_MS, SIGNUP_TOKEN_TTL_MS,
} from './config.js';
import { INFO, decryptSecret, hmacHex, ipHash, newEmailCode, normalizeEmail } from './crypto.js';
import { addRate, countRate, deleteCode, getCode, getSiteById, insertCode, listPages, logOp, orderPages, reserveCodeAttempt, takeCode, touchMau } from './db.js';
import { acceptEmail, authorizeUrl, exchangeCode, googleConfigured, pkcePair, verifyIdToken } from './google.js';
import { hostBelongs, siteServing } from './hosts.js';
import { asIdent, identHash, identLabel, isLine } from './ident.js';
import { kintoneFor, pageToken } from './kintone.js';
import * as line from './line.js';
import { identMatches, isEmail, matchSpec, membershipQuery, pageAcceptsIdent } from './match.js';
import { issueSession, signSignup, verifySession } from './session.js';
import { overLimit, siteLimit } from './quota.js';
import { turnstileOk } from './turnstile.js';
import { nowIso, randomToken, safeNext, timingSafeEqual, utcMonth } from './util.js';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const since = (ms) => new Date(Date.now() - ms).toISOString();
const out = (status, body) => ({ status, body });
const fail = (status, error, extra = {}) => out(status, { ok: false, error, ...extra });
const langOf = (v) => (LANGS.includes(v) ? v : '');
export const STATE_RE = /^([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{32})$/;
const member = (ident) => ({ kind: asIdent(ident).kind, label: identLabel(ident) });

// ---- メンバーかどうかの照合(入れるページの ID を返す。レコードの内容は取らない)----
export const usablePage = (p) => !!(p.settings.enabled && p.token_enc && !p.token_error && p.status === 'active');
// 入口のページの「あわせて確認するページ」(無ければサイトのトップの設定)の範囲
export function scopePages(site, pages, entry) {
  const usable = pages.filter(usablePage);
  if (entry) {
    if (entry.settings.checkScope === 'pages') {
      const ids = new Set([entry.id, ...entry.settings.checkPages]);
      return usable.filter((p) => ids.has(p.id));
    }
    return usable;
  }
  if (site.settings.topCheckScope === 'pages') {
    const ids = new Set(site.settings.topCheckPages);
    return usable.filter((p) => ids.has(p.id));
  }
  return usable;
}
export async function checkMembership(env, site, pages, ident) {
  const results = await Promise.all(
    pages.map(async (page) => {
      try {
        if (!pageAcceptsIdent(page, ident)) return null; // LINE 連携 ID のフィールドが無いページは LINE では入れない
        const token = await pageToken(env, page);
        if (!token) return null;
        const k = kintoneFor(env, site, page);
        const m = matchSpec(page, ident);
        const r = await k.getRecords(site.domain, page.app_id, token, { query: membershipQuery(page, ident), fields: ['$id', m.table || m.field] });
        if (!r.ok) return null;
        return identMatches(r.records, page, ident).length > 0 ? page.id : null;
      } catch (err) {
        console.error(`[membership ${page.id}] ${err.message}`);
        return null;
      }
    })
  );
  return results.filter(Boolean);
}
// next(戻り先)から入口のページを求める
export const entryPageOf = (pages, next) => {
  const m = /^\/([a-z0-9-]+)\//.exec(next || '');
  return m ? pages.find((p) => p.slug === m[1]) || null : null;
};

// 「最終ログイン日時」フィールド(設定済みのページだけ)に本人のレコードへ書き込む。revision は付けない(閲覧中の衝突検出と干渉させない)
export async function writeLastLogin(env, site, pages, pageIds, ident) {
  const at = nowIso();
  for (const page of pages) {
    const f = page.settings.record && page.settings.record.lastLoginField;
    if (!f || !pageIds.includes(page.id) || !usablePage(page) || !pageAcceptsIdent(page, ident)) continue;
    try {
      const token = await pageToken(env, page);
      if (!token) continue;
      const k = kintoneFor(env, site, page);
      const m = matchSpec(page, ident);
      const r = await k.getRecords(site.domain, page.app_id, token, { query: membershipQuery(page, ident).replace(/ limit 1$/, ` limit ${LAST_LOGIN_MAX_RECORDS}`), fields: ['$id', m.table || m.field] });
      if (!r.ok) continue;
      for (const rec of identMatches(r.records, page, ident)) await k.putRecord(site.domain, page.app_id, token, { id: rec.$id.value, record: { [f]: { value: at } } });
    } catch (err) {
      console.error(`[last-login ${page.id}] ${err.message}`);
    }
  }
}

// ---- 自己登録を受け付けるページ(§19)。登録そのもの(/v1/signup)は P3 ----
export const signupCapable = (p, ident) => {
  const s = p.settings;
  if (!usablePage(p) || !s.signup || !s.signup.enabled || !p.add_token_enc || p.add_token_error) return false;
  return asIdent(ident).kind === 'line' ? !!(s.line && s.line.field) : !!(s.member.field && !s.member.table);
};
export const signupPageFor = (site, pages, entry, ident) => (entry && signupCapable(entry, ident) ? entry : pages.find((p) => signupCapable(p, ident)) || null);
export const siteHasSignup = (pages) => pages.some((p) => usablePage(p) && p.settings.signup && p.settings.signup.enabled && !!p.add_token_enc && !p.add_token_error);

// ---- サイトの表示用の情報(ログイン画面の組み立て用。秘密は含まない)----
export const lineConfigured = (site) => !!(site.settings.line && site.settings.line.enabled && site.line_channel_id && site.line_secret_enc && site.dek_wrapped);
export const loginMethods = (env, site) => ({ email: !!site.settings.login.email, google: !!site.settings.login.google && googleConfigured(env), line: lineConfigured(site) });
//   pages: 使えるページの並び(名前と URL だけ。メニューの表示用。どのページに入れるかは本人ごとに /v1/me/pages・ログインの結果の pageIds)
//   card: メンバー証の対象(ページ・フィールドのコード・名前。値は一覧・詳細の API で取る)/ lineSelfLink: メンバー自身の LINE 連携を出すか
//   画面側はこれを短時間キャッシュして、画面の枠(サイト名・テーマ・メニュー・ヘッダーのメンバー証)を組み立てる(VAULT 設計 §8)
export async function siteInfo(env, site, { cardOf } = {}) {
  const st = site.settings;
  const pages = await listPages(env.DB, site.id);
  return out(200, {
    ok: true,
    site: {
      slug: site.slug, name: st.name || '', themeColor: st.themeColor, contact: st.contact || '', privacyUrl: st.privacyUrl || '', lang: st.lang || 'ja', trial: site.license_status === 'trial', login: loginMethods(env, site), signup: siteHasSignup(pages),
      pages: orderPages(site, pages).filter(usablePage).map((p) => ({ id: p.id, slug: p.slug, name: p.settings.name || '' })),
      card: cardOf ? cardOf(site, pages) : null,
      lineSelfLink: lineConfigured(site) && !!(st.line && st.line.selfLink),
    },
  });
}

// ---- 共通: レート制限(quota.js。先に数を入れてから数えるので、並列に送られても上限を超えない)----
// IP は画面側が渡す値(X-Mypage-Client-IP)なので目安。無いときはサイトで 1 つの枠になる
export const tooManyFromIp = async (env, site, ip) => overLimit(env, site, 'login_ip', await ipHash(env, ip || ''), 10 * MIN, LOGIN_ATTEMPTS_PER_IP_10MIN);

// ---- 本人確認の後(メール・Google・LINE 共通)----
// ログイン成功: セッションを署名して返し、MAU・ログ・最終ログイン日時を記録する
export async function completeLogin(env, site, ctx, { ident, method, pageIds, next, pages }) {
  const i = asIdent(ident);
  const session = await issueSession(env, site, { ident: i, method });
  const h = await identHash(env, i);
  await touchMau(env.DB, site.id, utcMonth(), h);
  await logOp(env.DB, site.id, null, 'member', 'login', { method, pages: pageIds.length, m: h.slice(0, 16) });
  if (pages.some((p) => p.settings.record && p.settings.record.lastLoginField)) ctx.waitUntil(writeLastLogin(env, site, pages, pageIds, i));
  return out(200, { ok: true, result: 'login', session, member: member(i), method, pageIds, next: safeNext(next) });
}
// su = 新規登録の入口から来た(§19)
//   ログインの入口: レコードがあればログイン / 無ければ no_pages(新規登録への案内だけ)
//   新規登録の入口: レコードが無ければ自己登録のトークン(signup)/ 既にあればレコードを作らずログインして「既に登録されています」
export async function afterVerify(env, site, ctx, { ident, method, pageIds, pages, next, su }) {
  const i = asIdent(ident);
  if (!pageIds.length) {
    const sp = su ? signupPageFor(site, pages, entryPageOf(pages, next), i) : null;
    if (sp) {
      const token = await signSignup(env, { s: site.id, k: i.kind, e: i.id, n: i.name || '', p: sp.id, next: safeNext(next), exp: Date.now() + SIGNUP_TOKEN_TTL_MS });
      return out(200, { ok: true, result: 'signup', signup: { token, page: sp.slug }, member: member(i), method, next: safeNext(next) });
    }
    return out(200, { ok: true, result: 'no_pages', member: member(i), method, signupAvailable: !su && siteHasSignup(pages), next: safeNext(next) });
  }
  return completeLogin(env, site, ctx, { ident: i, method, pageIds, next: su ? '/?already=1' : next, pages });
}

// ---- メールの確認コード ----
// POST /v1/login/email  { email, next, su, lang, turnstile }。登録の有無に関わらず同じ応答(列挙の防止)
export async function startEmail(env, site, host, input, { ip }) {
  const email = normalizeEmail(input.email);
  const next = safeNext(input.next);
  const su = input.su === true || input.su === 1 || input.su === '1';
  if (!site.settings.login.email) return fail(403, 'login_disabled');
  if (!isEmail(email)) return fail(400, 'invalid_email');
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many');
  if (!(await turnstileOk(env, site, { token: input.turnstile, ip }))) return fail(403, 'turnstile_failed');
  const addrKey = await identHash(env, email);
  if (await overLimit(env, site, 'email_addr', addrKey, 10 * MIN, EMAIL_SENDS_PER_ADDRESS_10MIN)) return fail(429, 'too_many');
  if ((await countRate(env.DB, site.id, 'email_site', 'site', since(HOUR))) >= EMAIL_SENDS_PER_SITE_HOUR) return fail(429, 'too_many');

  const pages = await listPages(env.DB, site.id);
  const entry = entryPageOf(pages, next);
  const pageIds = await checkMembership(env, site, scopePages(site, pages, entry), email);
  const code = newEmailCode();
  const id = randomToken(12);
  await insertCode(env.DB, { id, siteId: site.id, kind: 'email', hash: await hmacHex(env, code, INFO.code), data: { email, pages: pageIds, next, su }, expiresAt: new Date(Date.now() + EMAIL_CODE_TTL_MS).toISOString() });
  // 新規登録の入口から来たときだけ、レコードが無いアドレスにも送る(登録画面へ進めるため)。ログインの入口では登録済みのアドレスにだけ送る
  if (pageIds.length || (su && signupPageFor(site, pages, entry, email))) {
    await addRate(env.DB, site.id, 'email_site', 'site');
    const name = site.settings.name || site.slug;
    const mail = codeMail(langOf(input.lang) || site.settings.lang || 'ja', { siteName: name, code, url: `https://${host}` });
    // 送信キーが無いときは送らない(kit の sendEmail は件名をログに出す。件名にコードが入るため)
    if (env.RESEND_API_KEY) await sendEmail(env, { to: email, subject: mail.subject, text: mail.text, from: fromOf(env, name) }, { defaultFrom: 'KINTAUROS マイページ <noreply@kintauros.com>', logTo: false });
    else console.log('[email skipped] RESEND_API_KEY is not configured');
  }
  return out(200, { ok: true, codeId: id });
}
const fromOf = (env, siteName) => {
  const addr = /<([^>]+)>/.exec(env.MAIL_FROM || '');
  return `${String(siteName).replace(/[<>"\r\n]/g, ' ').trim() || 'KINTAUROS'} (KINTAUROS) <${addr ? addr[1] : 'noreply@kintauros.com'}>`;
};
export function codeMail(lang, { siteName, code, url }) {
  const M = {
    ja: { subject: `【${siteName}】確認コード: ${code}`, text: `${siteName} のマイページにログインするための確認コードです。\n\n確認コード: ${code}\n\nこのコードは 10 分間有効です。心当たりがない場合は、このメールを破棄してください(コードを知らない人はログインできません)。\n\n${url}\n\n--\nこのメールは KINTAUROS マイページから自動送信しています。返信しても届きません。` },
    en: { subject: `[${siteName}] Verification code: ${code}`, text: `Use this code to sign in to the member page of ${siteName}.\n\nVerification code: ${code}\n\nThe code is valid for 10 minutes. If you did not request it, please discard this message (no one can sign in without the code).\n\n${url}\n\n--\nThis message was sent automatically by KINTAUROS My Page. Replies are not delivered.` },
    zh: { subject: `【${siteName}】验证码: ${code}`, text: `这是登录 ${siteName} 会员页面的验证码。\n\n验证码: ${code}\n\n验证码 10 分钟内有效。如果您没有请求，请忽略本邮件(不知道验证码的人无法登录)。\n\n${url}\n\n--\n本邮件由 KINTAUROS 我的页面自动发送。回复本邮件不会送达。` },
    'zh-TW': { subject: `【${siteName}】驗證碼: ${code}`, text: `這是登入 ${siteName} 會員頁面的驗證碼。\n\n驗證碼: ${code}\n\n驗證碼 10 分鐘內有效。若您未曾要求，請忽略本郵件(不知道驗證碼的人無法登入)。\n\n${url}\n\n--\n本郵件由 KINTAUROS 我的頁面自動發送。回覆本郵件不會送達。` },
  };
  return M[lang] || M.ja;
}

// GET /v1/login/email/code?c=  確認コードの入力画面用(送った先のアドレスと戻り先。コードそのものは返さない)
export async function emailCodeInfo(env, site, id) {
  const row = /^[A-Za-z0-9_-]{16}$/.test(String(id || '')) ? await getCode(env.DB, id, 'email') : null;
  if (!row || row.site_id !== site.id || Date.parse(row.expires_at) < Date.now()) return fail(404, 'code_expired');
  return out(200, { ok: true, email: row.data.email, next: safeNext(row.data.next) });
}

// POST /v1/login/email/verify  { c, code }
export async function verifyEmail(env, site, ctx, input, { ip }) {
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many');
  const limit = siteLimit(env, 'codeFailsPerSiteHour');
  if (limit && (await countRate(env.DB, site.id, 'code_fail_site', 'site', since(HOUR))) >= limit) return fail(429, 'too_many');
  const id = String(input.c || '');
  const code = String(input.code || '').replace(/\s/g, '');
  const row = /^[A-Za-z0-9_-]{16}$/.test(id) ? await getCode(env.DB, id, 'email') : null;
  if (!row || row.site_id !== site.id) return fail(400, 'code_expired');
  if (Date.parse(row.expires_at) < Date.now()) {
    await deleteCode(env.DB, row.id);
    return fail(400, 'code_expired');
  }
  // アドレスごとの照合の回数(コードをまたいで数える。コードを何度も送らせて総当たりするのを止める)
  if (await overLimit(env, site, 'code_try_addr', await identHash(env, row.data.email), HOUR, EMAIL_CODE_TRIES_PER_ADDRESS_HOUR)) {
    await deleteCode(env.DB, row.id);
    return fail(429, 'too_many');
  }
  // このコードの照合を 1 回分確保してから比べる(並列に送られても 5 回を超えない)
  const reserved = await reserveCodeAttempt(env.DB, row.id, EMAIL_CODE_ATTEMPTS);
  if (!reserved) {
    await deleteCode(env.DB, row.id);
    return fail(429, 'too_many');
  }
  const ok = /^\d{6}$/.test(code) && timingSafeEqual(await hmacHex(env, code, INFO.code), row.hash);
  if (!ok) {
    await addRate(env.DB, site.id, 'code_fail_site', 'site');
    const left = Math.max(0, EMAIL_CODE_ATTEMPTS - Number(reserved.attempts));
    if (!left) await deleteCode(env.DB, row.id);
    return fail(400, 'code_invalid', { attemptsLeft: left });
  }
  const taken = await takeCode(env.DB, row.id, 'email'); // 1 回限り(並列に正しいコードが届いても 1 つだけ)
  if (!taken) return fail(400, 'code_expired');
  const pageIds = Array.isArray(taken.data.pages) ? taken.data.pages : [];
  const pages = await listPages(env.DB, site.id);
  return afterVerify(env, site, ctx, { ident: taken.data.email, method: 'email', pageIds, pages, next: taken.data.next, su: !!taken.data.su });
}

// ---- Google / LINE ----
const callbackUrl = (env, provider) => `https://${env.AUTH_HOST}/${provider}/callback`;
// 開始: state(識別子+秘密)・verifier・nonce を保管庫に置き、認可 URL と bind(ブラウザとの結び付け)を返す。
//   bind は画面側が auth ホストの Cookie に入れ、完了のときに一緒に渡す(他人が始めた流れを別のブラウザで完了させない)
async function startOAuth(env, site, host, provider, input, extra = {}) {
  const { verifier, challenge } = await pkcePair();
  const nonce = randomToken(16);
  const id = randomToken(12);
  const secret = randomToken(24);
  const bind = randomToken(32);
  await insertCode(env.DB, {
    id, siteId: site.id, kind: 'oauth', hash: await hmacHex(env, secret, INFO.state),
    data: { p: provider, v: verifier, nonce, b: await hmacHex(env, bind, INFO.state), h: host, n: safeNext(input.next), l: langOf(input.lang), su: input.su === true || input.su === 1 || input.su === '1' ? 1 : 0, ...extra },
    expiresAt: new Date(Date.now() + OAUTH_STATE_TTL_MS).toISOString(),
  });
  return { state: `${id}.${secret}`, nonce, challenge, bind };
}
// POST /v1/login/google/start  { next, hint, su, lang }
export async function startGoogle(env, site, host, input, { ip }) {
  if (!site.settings.login.google || !googleConfigured(env)) return fail(403, 'login_disabled');
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many');
  const st = await startOAuth(env, site, host, 'google', input);
  const hint = normalizeEmail(input.hint);
  const url = authorizeUrl(env, { redirectUri: callbackUrl(env, 'google'), state: st.state, nonce: st.nonce, challenge: st.challenge, loginHint: isEmail(hint) ? hint : '' });
  return out(200, { ok: true, url, bind: st.bind });
}
// POST /v1/login/line/start  { next, su, lang, link?, connect? }
//   link: 社内が発行した連携用リンクの値(完了の後、/v1/line/connect でそのレコードに LINE 連携 ID を書いてから LINE でログイン)
//   connect: メンバー自身の連携(セッション必須・メールアドレスで入っている人だけ。完了の後、/v1/line/connect で同じセッションから書き込む)
export async function startLine(env, site, host, input, { ip, session }) {
  if (!lineConfigured(site)) return fail(403, 'login_disabled');
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many');
  const extra = {};
  if (input.connect === true || input.connect === 1 || input.connect === '1') {
    const v = await verifySession(env, site, session || '');
    if (!v.ok || isLine(v.ident) || !site.settings.line.selfLink) return fail(403, 'connect_unavailable');
    extra.cn = { sid: v.session.sid, e: v.ident.id };
  } else if (input.link !== undefined) {
    if (!STATE_RE.test(String(input.link || ''))) return fail(400, 'link_invalid');
    extra.lk = String(input.link);
  }
  const st = await startOAuth(env, site, host, 'line', extra.cn || extra.lk ? { ...input, su: 0 } : input, extra);
  const url = line.authorizeUrl(site.line_channel_id, { redirectUri: callbackUrl(env, 'line'), state: st.state, nonce: st.nonce, challenge: st.challenge });
  return out(200, { ok: true, url, bind: st.bind });
}

// state を取り出して消す(1 回限り)。秘密・提供元・bind・期限・サイトとホストを確かめる。戻り値: { site, data } | null
async function consumeOAuth(env, provider, state, bind) {
  const m = STATE_RE.exec(String(state || ''));
  if (!m) return null;
  const row = await takeCode(env.DB, m[1], 'oauth');
  if (!row || Date.parse(row.expires_at) < Date.now()) return null;
  if (!timingSafeEqual(await hmacHex(env, m[2], INFO.state), row.hash)) return null;
  const d = row.data;
  if (d.p !== provider || typeof bind !== 'string' || bind.length < OAUTH_BIND_MIN || bind.length > 256 || !timingSafeEqual(await hmacHex(env, bind, INFO.state), d.b)) return null;
  const site = await getSiteById(env.DB, row.site_id);
  if (!site || !siteServing(site) || !hostBelongs(env, site, d.h)) return null;
  return { site, data: d };
}
// 完了の応答には、画面側が戻る先(サイトのホスト・戻り先・言語・新規登録の入口か)を付ける
const back = (d) => ({ host: d.h, next: d.n || '/', lang: d.l || '', su: !!d.su });

// POST /v1/login/google/finish  { state, code, bind }
export async function finishGoogle(env, ctx, input, { ip }) {
  const c = await consumeOAuth(env, 'google', input.state, input.bind);
  if (!c) return fail(400, 'invalid_state');
  const { site, data } = c;
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many', back(data));
  if (!site.settings.login.google || !googleConfigured(env) || typeof input.code !== 'string' || !input.code || input.code.length > 2048) return fail(400, 'google_failed', back(data));
  const ex = await exchangeCode(env, { code: input.code, redirectUri: callbackUrl(env, 'google'), verifier: data.v });
  if (!ex.ok) return fail(400, 'google_failed', back(data));
  const v = await verifyIdToken(env, ex.idToken, data.nonce);
  if (!v.ok) return fail(400, 'google_failed', back(data));
  const acc = acceptEmail(v.claims);
  if (!acc.accepted) return fail(400, 'google_unverified', { ...back(data), email: acc.email });
  const pages = await listPages(env.DB, site.id);
  const pageIds = await checkMembership(env, site, scopePages(site, pages, entryPageOf(pages, data.n)), acc.email);
  const r = await afterVerify(env, site, ctx, { ident: acc.email, method: 'google', pageIds, pages, next: data.n, su: !!data.su });
  return out(r.status, { ...r.body, ...back(data), next: r.body.next });
}
// POST /v1/login/line/finish  { state, code, bind }。契約者のチャネル(シークレットはサイト DEK で暗号化して保管庫にだけある)
export async function finishLine(env, ctx, input, { ip }) {
  const c = await consumeOAuth(env, 'line', input.state, input.bind);
  if (!c) return fail(400, 'invalid_state');
  const { site, data } = c;
  if (await tooManyFromIp(env, site, ip)) return fail(429, 'too_many', back(data));
  if (!lineConfigured(site) || typeof input.code !== 'string' || !input.code || input.code.length > 2048) return fail(400, 'line_failed', back(data));
  const secret = await decryptSecret(env, site.dek_wrapped, site.line_secret_enc).catch(() => null);
  if (!secret) return fail(400, 'line_failed', back(data));
  const ex = await line.exchangeCode({ channelId: site.line_channel_id, channelSecret: secret, code: input.code, redirectUri: callbackUrl(env, 'line'), verifier: data.v });
  if (!ex.ok) return fail(400, 'line_failed', back(data));
  const v = await line.verifyIdToken({ idToken: ex.idToken, channelId: site.line_channel_id, channelSecret: secret, nonce: data.nonce });
  if (!v.ok) return fail(400, 'line_failed', back(data));
  const ident = asIdent({ kind: 'line', id: v.claims.sub, name: String(v.claims.name || '').slice(0, 80) });
  // 連携(連携用リンク・メンバー自身の連携): ここではログインせず、書き込みの引換券を返す(書き込みはサイトのホストから /v1/line/connect で)
  if (data.lk || data.cn) {
    const id = randomToken(12);
    const secret = randomToken(24);
    await insertCode(env.DB, { id, siteId: site.id, kind: 'line_done', hash: await hmacHex(env, secret, INFO.code), data: { id: ident.id, name: ident.name, lk: data.lk || null, cn: data.cn || null }, expiresAt: new Date(Date.now() + LINE_DONE_TTL_MS).toISOString() });
    return out(200, { ok: true, result: 'line_connect', ticket: `${id}.${secret}`, ...back(data) });
  }
  const pages = await listPages(env.DB, site.id);
  const pageIds = await checkMembership(env, site, scopePages(site, pages, entryPageOf(pages, data.n)), ident);
  const r = await afterVerify(env, site, ctx, { ident, method: 'line', pageIds, pages, next: data.n, su: !!data.su });
  return out(r.status, { ...r.body, ...back(data), next: r.body.next });
}

// GET /v1/me/pages?next=  本人が入れるページ(入口のページの「あわせて確認するページ」に従う。メニューの Cookie の作り直し用)
export async function myPages(env, site, ident, next) {
  const pages = await listPages(env.DB, site.id);
  const ids = await checkMembership(env, site, scopePages(site, pages, entryPageOf(pages, safeNext(next))), ident);
  const list = orderPages(site, pages).filter((p) => ids.includes(p.id)).map((p) => ({ id: p.id, slug: p.slug, name: p.settings.name || '' }));
  return out(200, { ok: true, pageIds: list.map((p) => p.id), pages: list, member: member(ident), line: isLine(ident) });
}
