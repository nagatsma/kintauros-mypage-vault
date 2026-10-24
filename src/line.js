// LINE ログイン(設計 §4.2.10)。契約者自身の LINE ログインのチャネル(チャネル ID・シークレット)を使い、auth.kintauros.me に集約する。
//   スコープは openid profile(メールアドレスの権限は申請しない)。ID トークンはウェブログインでは HS256(鍵 = チャネルシークレット)なので
//   ローカルで検証する(§13.2 S24)。得るのは sub(LINE のユーザー ID)と name(表示名。連携時の確認用にだけ使い、当社は保存しない)
import { LINE_CHANNEL_ID_RE, LINE_SECRET_RE } from './config.js';

const AUTH_URL = 'https://access.line.me/oauth2/v2.1/authorize';
const TOKEN_URL = 'https://api.line.me/oauth2/v2.1/token';
const ISSUER = 'https://access.line.me';

const enc = new TextEncoder();
const b64url = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64url = (text) => {
  const t = String(text).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const isChannelId = (v) => typeof v === 'string' && LINE_CHANNEL_ID_RE.test(v);
export const isChannelSecret = (v) => typeof v === 'string' && LINE_SECRET_RE.test(v);
export const lineCallbackUrl = (env) => `https://${env.AUTH_HOST}/line/callback`;

export function authorizeUrl(channelId, { redirectUri, state, nonce, challenge }) {
  const p = new URLSearchParams({ response_type: 'code', client_id: channelId, redirect_uri: redirectUri, state, scope: 'openid profile', nonce, code_challenge: challenge, code_challenge_method: 'S256' });
  return `${AUTH_URL}?${p}`;
}

export async function exchangeCode({ channelId, channelSecret, code, redirectUri, verifier }) {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: channelId, client_secret: channelSecret, code_verifier: verifier }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.id_token) return { ok: false, error: body.error || `http_${res.status}` };
  return { ok: true, idToken: body.id_token };
}

// ID トークンの検証(HS256・iss・aud・exp・nonce)。戻り値: { ok, claims } | { ok: false, error }
export async function verifyIdToken({ idToken, channelId, channelSecret, nonce, now = Date.now() }) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) return { ok: false, error: 'malformed' };
  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(unb64url(parts[0])));
    claims = JSON.parse(new TextDecoder().decode(unb64url(parts[1])));
  } catch {
    return { ok: false, error: 'malformed' };
  }
  if (header.alg !== 'HS256') return { ok: false, error: 'alg' };
  const key = await crypto.subtle.importKey('raw', enc.encode(channelSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, unb64url(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  if (!valid) return { ok: false, error: 'signature' };
  if (claims.iss !== ISSUER) return { ok: false, error: 'iss' };
  if (claims.aud !== channelId) return { ok: false, error: 'aud' };
  if (!claims.exp || claims.exp * 1000 < now - 60 * 1000) return { ok: false, error: 'exp' };
  if (!nonce || claims.nonce !== nonce) return { ok: false, error: 'nonce' };
  if (!claims.sub || typeof claims.sub !== 'string') return { ok: false, error: 'sub' };
  return { ok: true, claims };
}

// 設定画面の「接続テスト」: 無効な認可コードでトークンを要求し、チャネル ID とシークレットが受け付けられるかだけを見る
//   invalid_client → ID かシークレットが違う / invalid_grant・invalid_request → 認証は通った(コードが無効なだけ)
// 戻り値: { ok: true } | { ok: false, error: 'invalid_client' | 'unreachable' | 'unexpected', detail }
export async function testChannel({ channelId, channelSecret, redirectUri }) {
  let res;
  try {
    res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'kintauros-connection-test', redirect_uri: redirectUri, client_id: channelId, client_secret: channelSecret }),
    });
  } catch (e) {
    return { ok: false, error: 'unreachable', detail: String((e && e.message) || e) };
  }
  const body = await res.json().catch(() => ({}));
  const err = String(body.error || '');
  if (err === 'invalid_client' || res.status === 401) return { ok: false, error: 'invalid_client', detail: body.error_description || '' };
  if (err === 'invalid_grant' || err === 'invalid_request') return { ok: true };
  return { ok: false, error: 'unexpected', detail: `${res.status} ${err} ${body.error_description || ''}`.trim() };
}

// テスト用: HS256 の ID トークンを作る
export async function signIdTokenForTest({ channelSecret, claims }) {
  const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const p = b64url(enc.encode(JSON.stringify(claims)));
  const key = await crypto.subtle.importKey('raw', enc.encode(channelSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}
