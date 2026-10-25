// メンバーのセッション(VAULT 設計 §5)。保管庫だけが持つシークレット VAULT_SESSION_KEY で署名する。
//   画面側(mypage-worker)は受け取った値を Cookie(__Host-kmp)に出し入れするだけで、中身を作れない・書き換えられない。
//   保管庫はメンバーの呼び出しのたびに、署名・サイト・有効期限・一斉ログアウトの世代(sites.session_epoch)・ログアウト済みかを確かめる。
//   値: base64url(JSON) + '.' + HMAC。JSON = { v, s: サイト, k: 'email' | 'line', e: 識別子, n: LINE の表示名, m: 方法, ep: 世代, sid, iat, exp }
//   中身は暗号化しない(画面側が表示に使ってよい。権限の根拠は保管庫の検証だけ)。
//   VAULT_SESSION_KEY は KEK とは別の値なので、入れ替えれば全員のログインを無効にできる(KEK は入れ替えられない)
import { createEnvelope, unb64 } from './kit/crypto.js';
import { SESSION_DAYS_DEFAULT, SESSION_DAYS_MAX, SESSION_RENEW_AFTER_MS } from './config.js';
import { createSigner } from './crypto.js';
import { asIdent } from './ident.js';
import { randomToken, sha256Hex } from './util.js';

const keys = createEnvelope({ kekVar: 'VAULT_SESSION_KEY', hmacInfo: 'kintauros-mypage-vault/session' });
const signer = createSigner(keys.hmacB64url);

export const SESSION_INFO = {
  session: 'kintauros-mypage-vault/session/v1', // メンバーのセッション
  signup: 'kintauros-mypage-vault/signup/v1',   // 自己登録の画面のトークン(本人確認した識別子・ページ・30 分。P3 の /v1/signup で受け取る)
};
export const METHODS = new Set(['email', 'google', 'line']);
const SID_RE = /^[A-Za-z0-9_-]{22}$/;
const DAY_MS = 24 * 60 * 60 * 1000;

export function sessionKeyConfigured(env) {
  if (!keys.kekConfigured(env)) return false;
  try {
    return unb64(env.VAULT_SESSION_KEY).length >= 32;
  } catch {
    return false;
  }
}

// ident: { kind, id, name? }。sid は延長のときだけ引き継ぐ(ログアウトで延長した写しもまとめて無効にするため)
export async function issueSession(env, site, { ident, method, sid, now = Date.now() }) {
  const days = site.settings.sessionDays || SESSION_DAYS_DEFAULT;
  const i = asIdent(ident);
  const payload = { v: 1, s: site.id, k: i.kind, e: i.id, ...(i.kind === 'line' ? { n: i.name || '' } : {}), m: method, ep: site.session_epoch, sid: sid || randomToken(16), iat: now, exp: now + days * DAY_MS };
  return { value: await signer.sign(env, payload, SESSION_INFO.session), maxAge: days * 24 * 60 * 60, exp: payload.exp };
}

// 戻り値: { ok: true, session, ident } | { ok: false, error }。error は記録用で、画面側への応答は区別しない(session_invalid)
export async function verifySession(env, site, value, { now = Date.now() } = {}) {
  if (!sessionKeyConfigured(env)) return { ok: false, error: 'session_key_not_configured' };
  const s = await signer.verify(env, value, SESSION_INFO.session);
  if (!s) return { ok: false, error: 'signature' };
  if (s.v !== 1 || s.s !== site.id) return { ok: false, error: 'site' };
  if ((s.k !== 'email' && s.k !== 'line') || typeof s.e !== 'string' || !s.e || !METHODS.has(s.m) || typeof s.sid !== 'string' || !SID_RE.test(s.sid)) return { ok: false, error: 'shape' };
  if (!Number.isFinite(s.exp) || s.exp <= now || !Number.isFinite(s.iat) || s.iat > now + 60 * 1000) return { ok: false, error: 'expired' };
  if (s.ep !== site.session_epoch) return { ok: false, error: 'epoch' };
  const revoked = await env.DB.prepare('SELECT 1 AS x FROM revoked_sessions WHERE sid_hash = ?').bind(await sha256Hex(s.sid)).first();
  if (revoked) return { ok: false, error: 'revoked' };
  return { ok: true, session: s, ident: asIdent({ kind: s.k, id: s.e, name: s.n }) };
}

// 1 日以上前に発行したセッションは延長して返す(sid と方法は同じ)。戻り値: issueSession の結果 | null
export async function renewIfStale(env, site, s, { now = Date.now() } = {}) {
  if (now - s.iat < SESSION_RENEW_AFTER_MS) return null;
  return issueSession(env, site, { ident: { kind: s.k, id: s.e, name: s.n }, method: s.m, sid: s.sid, now });
}

// ログアウト: sid を無効にする。延長した写しの期限はこの値より後のことがあるので、最長の有効期間+1 日まで残す
export async function revokeSession(env, site, s, { now = Date.now() } = {}) {
  const until = new Date(now + (SESSION_DAYS_MAX + 1) * DAY_MS).toISOString();
  await env.DB.prepare('INSERT OR IGNORE INTO revoked_sessions (sid_hash, site_id, expires_at) VALUES (?, ?, ?)').bind(await sha256Hex(s.sid), site.id, until).run();
}

// ---- 自己登録のトークン(本人確認の直後に、レコードが無い人へ。P3 の /v1/signup で検証する)----
export const signSignup = (env, obj) => signer.sign(env, { v: 1, ...obj }, SESSION_INFO.signup);
export async function verifySignup(env, site, text, { now = Date.now() } = {}) {
  if (!sessionKeyConfigured(env)) return null;
  const t = await signer.verify(env, text, SESSION_INFO.signup);
  if (!t || t.v !== 1 || t.s !== site.id || !Number.isFinite(t.exp) || t.exp <= now || (t.k !== 'email' && t.k !== 'line') || typeof t.e !== 'string' || !t.e) return null;
  return t;
}
